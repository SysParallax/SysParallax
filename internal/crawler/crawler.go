// Package crawler découvre les endpoints et surfaces d'attaque d'une cible.
// V2 : crawl BFS jusqu'à une profondeur configurable, extraction de formes et paramètres.
package crawler

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/net/html"
)

const (
	defaultMaxDepth = 3
	defaultMaxPages = 150
	requestTimeout  = 15 * time.Second
)

// Crawler effectue un crawl BFS sur la cible.
type Crawler struct {
	store    *storage.Store
	client   *http.Client
	maxDepth int
	maxPages int
	options  models.AuditOptions
}

// New crée un Crawler avec les paramètres par défaut.
func New(store *storage.Store, options models.AuditOptions) *Crawler {
	options = httpx.NormalizeOptions(options)
	return &Crawler{
		store:    store,
		maxDepth: options.MaxDepth,
		maxPages: options.MaxPages,
		options:  options,
		client:   httpx.NewClient(requestTimeout, options),
	}
}

// Run exécute le crawl à partir de baseURL et retourne les assets découverts.
func (c *Crawler) Run(auditRunID, baseURL string) (*models.CrawlResult, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	visited := make(map[string]bool)
	var assets []*models.Asset

	// File BFS : chaque entrée est (url, profondeur)
	type entry struct {
		u     string
		depth int
	}
	queue := []entry{{baseURL, 0}}

	for len(queue) > 0 && len(visited) < c.maxPages {
		item := queue[0]
		queue = queue[1:]

		if visited[item.u] {
			continue
		}
		visited[item.u] = true

		// Créer l'asset endpoint
		asset := &models.Asset{
			ID:           uuid.NewString(),
			AuditRunID:   auditRunID,
			Type:         models.AssetEndpoint,
			Method:       "GET",
			URL:          item.u,
			DiscoveredBy: "crawler",
		}

		// GET la page pour extraire les liens
		links, params, forms, contentType, err := c.fetchPage(item.u)
		if err == nil {
			asset.Params = params
			// Détecter si c'est une API REST
			if strings.Contains(strings.ToLower(contentType), "application/json") {
				asset.Type = models.AssetAPIREST
			}
		}

		assets = append(assets, asset)
		c.store.AppendAsset(asset)

		for _, form := range forms {
			form.AuditRunID = auditRunID
			form.ID = uuid.NewString()
			assets = append(assets, form)
			c.store.AppendAsset(form)
		}

		// Enqueue les liens si on n'est pas trop profond
		if item.depth < c.maxDepth {
			for _, link := range links {
				parsed, err := url.Parse(link)
				if err != nil {
					continue
				}
				resolved := base.ResolveReference(parsed)
				// Même domaine uniquement
				if resolved.Host == base.Host && !visited[resolved.String()] {
					queue = append(queue, entry{resolved.String(), item.depth + 1})
				}
			}
		}
	}

	result := &models.CrawlResult{
		AuditRunID: auditRunID,
		Assets:     assets,
		TotalFound: len(assets),
		CrawledAt:  time.Now(),
	}
	c.store.SaveCrawl(result)
	return result, nil
}

// fetchPage récupère une page et extrait les liens, paramètres et Content-Type.
func (c *Crawler) fetchPage(pageURL string) (links []string, params []string, forms []*models.Asset, contentType string, err error) {
	resp, err := c.client.Get(pageURL)
	if err != nil {
		return nil, nil, nil, "", err
	}
	defer resp.Body.Close()

	contentType = resp.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, nil, nil, contentType, err
	}

	// Extraire les query params de l'URL elle-même
	if u, err2 := url.Parse(pageURL); err2 == nil {
		for k := range u.Query() {
			params = append(params, k)
		}
	}

	links, formParams, forms := extractLinksAndForms(body, pageURL)
	params = append(params, formParams...)
	return links, unique(params), forms, contentType, nil
}

// extractLinksAndForms parse le HTML et retourne les liens et paramètres de formulaires.
func extractLinksAndForms(body []byte, baseURL string) (links []string, formParams []string, forms []*models.Asset) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	seenLinks := make(map[string]bool)
	base, _ := url.Parse(baseURL)

	parseForm := func(form *html.Node) {
		method := "GET"
		action := baseURL
		for _, attr := range form.Attr {
			switch strings.ToLower(attr.Key) {
			case "method":
				if strings.TrimSpace(attr.Val) != "" {
					method = strings.ToUpper(strings.TrimSpace(attr.Val))
				}
			case "action":
				if strings.TrimSpace(attr.Val) != "" {
					action = strings.TrimSpace(attr.Val)
				}
			}
		}
		if base != nil {
			if u, err := url.Parse(action); err == nil {
				action = base.ResolveReference(u).String()
			}
		}
		params := collectInputNames(form)
		bodyTemplate := make(map[string]string)
		for _, p := range params {
			bodyTemplate[p] = ""
		}
		forms = append(forms, &models.Asset{
			Type:         models.AssetForm,
			Method:       method,
			URL:          action,
			Params:       params,
			BodyType:     "form-urlencoded",
			BodyTemplate: bodyTemplate,
			DiscoveredBy: "crawler-form",
		})
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						href := strings.TrimSpace(attr.Val)
						if href != "" && !strings.HasPrefix(href, "#") &&
							!strings.HasPrefix(href, "mailto:") && !strings.HasPrefix(href, "javascript:") {
							if !seenLinks[href] {
								seenLinks[href] = true
								links = append(links, href)
							}
						}
					}
				}
			case "form":
				parseForm(n)
				for _, attr := range n.Attr {
					if attr.Key == "action" && attr.Val != "" {
						if !seenLinks[attr.Val] {
							seenLinks[attr.Val] = true
							links = append(links, attr.Val)
						}
					}
				}
			case "input", "select", "textarea":
				for _, attr := range n.Attr {
					if attr.Key == "name" && attr.Val != "" {
						formParams = append(formParams, attr.Val)
					}
				}
			case "script":
				// Chercher des routes JS exposées (ex: fetch('/api/...'))
				if n.FirstChild != nil {
					jsRoutes := extractJSRoutes(n.FirstChild.Data)
					for _, r := range jsRoutes {
						if !seenLinks[r] {
							seenLinks[r] = true
							links = append(links, r)
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return
}

func collectInputNames(root *html.Node) []string {
	seen := make(map[string]bool)
	var names []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "select", "textarea":
				for _, attr := range n.Attr {
					if strings.ToLower(attr.Key) == "name" && strings.TrimSpace(attr.Val) != "" {
						name := strings.TrimSpace(attr.Val)
						if !seen[name] {
							seen[name] = true
							names = append(names, name)
						}
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return names
}

// extractJSRoutes cherche des patterns d'URL dans le code JS inline.
func extractJSRoutes(js string) []string {
	var routes []string
	// Chercher '/api/...', '/v1/...', '/v2/...' dans les strings JS
	for _, prefix := range []string{`'/api/`, `"/api/`, `'/v1/`, `"/v1/`, `'/v2/`, `"/v2/`} {
		idx := 0
		for {
			pos := strings.Index(js[idx:], prefix)
			if pos < 0 {
				break
			}
			start := idx + pos + 1
			end := strings.IndexAny(js[start:], `'"`)
			if end > 0 && end < 100 {
				route := js[start : start+end]
				if strings.HasPrefix(route, "/") {
					routes = append(routes, route)
				}
			}
			idx += pos + 1
		}
	}
	return routes
}

func unique(s []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
