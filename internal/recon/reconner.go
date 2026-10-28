package recon

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
	"golang.org/x/net/html"
)

// Reconner exécute la phase recon.
type Reconner struct {
	store  *storage.Store
	client *http.Client
}

// NewReconner crée un Reconner.
func NewReconner(store *storage.Store, options models.AuditOptions) *Reconner {
	return &Reconner{
		store:  store,
		client: httpx.NewClient(20*time.Second, options),
	}
}

// Run collecte les informations de recon sur finalURL.
func (r *Reconner) Run(auditRunID, finalURL string) (*models.ReconResult, error) {
	result := &models.ReconResult{
		AuditRunID:  auditRunID,
		FinalURL:    finalURL,
		Headers:     make(map[string]string),
		CollectedAt: time.Now(),
	}

	// ── 1. GET de la page principale ─────────────────────────────────────
	resp, err := r.client.Get(finalURL)
	if err != nil {
		r.store.SaveRecon(result)
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// ── 2. Headers intéressants ──────────────────────────────────────────
	interestingHeaders := []string{
		"Server", "X-Powered-By", "X-Framework",
		"Content-Type", "Content-Length",
		"Strict-Transport-Security", "X-Content-Type-Options",
		"X-Frame-Options", "Content-Security-Policy",
		"Access-Control-Allow-Origin", "Cache-Control",
		"X-Request-Id", "X-RateLimit-Limit",
	}
	for _, h := range interestingHeaders {
		if v := resp.Header.Get(h); v != "" {
			result.Headers[h] = v
		}
	}

	result.Server = resp.Header.Get("Server")
	result.ContentType = resp.Header.Get("Content-Type")
	result.ContentLength = resp.ContentLength

	// ── 3. Détecter si c'est une API JSON ───────────────────────────────
	ct := strings.ToLower(result.ContentType)
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "application/vnd.api") {
		result.LooksLikeAPI = true
	}

	// ── 4. Lire le body (limité à 512 KB) ────────────────────────────────
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err == nil && !result.LooksLikeAPI {
		bodyStr := string(bodyBytes)
		// Détecter API JSON par contenu si Content-Type pas défini
		trimmed := strings.TrimSpace(bodyStr)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			result.LooksLikeAPI = true
		}

		// Extraire le title HTML
		result.Title = extractTitle(bodyStr)

		// Extraire les liens internes
		result.InternalLinks = extractInternalLinks(bodyBytes, finalURL)
	}

	// ── 5. Vérifier robots.txt ───────────────────────────────────────────
	result.HasRobotsTxt = r.urlExists(joinPath(finalURL, "/robots.txt"))

	// ── 6. Vérifier sitemap.xml ──────────────────────────────────────────
	result.HasSitemapXML = r.urlExists(joinPath(finalURL, "/sitemap.xml"))

	r.store.SaveRecon(result)
	return result, nil
}

// urlExists fait un HEAD et retourne true si code < 400.
func (r *Reconner) urlExists(u string) bool {
	resp, err := r.client.Head(u)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 400
}

// extractTitle parse le HTML et retourne le contenu de <title>.
func extractTitle(body string) string {
	reader := strings.NewReader(body)
	doc, err := html.Parse(reader)
	if err != nil {
		return ""
	}
	var title string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil {
				title = strings.TrimSpace(n.FirstChild.Data)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return title
}

// extractInternalLinks extrait les href internes depuis le HTML.
func extractInternalLinks(body []byte, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					href := strings.TrimSpace(attr.Val)
					if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") {
						continue
					}
					parsed, err := url.Parse(href)
					if err != nil {
						continue
					}
					resolved := base.ResolveReference(parsed)
					// Garder uniquement les liens du même domaine
					if resolved.Host == base.Host {
						link := resolved.Scheme + "://" + resolved.Host + resolved.Path
						if !seen[link] {
							seen[link] = true
							links = append(links, link)
						}
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	// Limiter à 30 liens pour V1
	if len(links) > 30 {
		links = links[:30]
	}
	return links
}

// joinPath construit une URL absolue en remplaçant le path.
func joinPath(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	u.Path = path
	u.RawQuery = ""
	return u.String()
}
