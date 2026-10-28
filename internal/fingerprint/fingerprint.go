// Package fingerprint détecte la stack technique d'une cible web.
// Approche : analyse des headers HTTP, cookies, contenu HTML, patterns de réponse.
package fingerprint

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

// Detector effectue la phase de fingerprinting.
type Detector struct {
	store  *storage.Store
	client *http.Client
}

func New(store *storage.Store, options models.AuditOptions) *Detector {
	return &Detector{
		store:  store,
		client: httpx.NewClient(15*time.Second, options),
	}
}

// Run exécute le fingerprinting sur finalURL.
func (d *Detector) Run(auditRunID, finalURL string) (*models.FingerprintResult, error) {
	result := &models.FingerprintResult{
		AuditRunID:  auditRunID,
		HeaderClues: make(map[string]string),
		DetectedAt:  time.Now(),
	}

	resp, err := d.client.Get(finalURL)
	if err != nil {
		d.store.SaveFingerprint(result)
		return result, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyStr := strings.ToLower(string(body))

	// ── Analyse des headers ───────────────────────────────────────────────
	d.analyzeHeaders(resp, result)

	// ── Analyse du corps HTML ─────────────────────────────────────────────
	d.analyzeBody(bodyStr, result)

	// ── Déduction du mécanisme d'auth ─────────────────────────────────────
	d.detectAuth(resp, bodyStr, result)

	d.store.SaveFingerprint(result)
	return result, nil
}

func (d *Detector) analyzeHeaders(resp *http.Response, r *models.FingerprintResult) {
	headers := resp.Header

	// Server
	if sv := headers.Get("Server"); sv != "" {
		r.Server = sv
		r.HeaderClues["Server"] = sv

		svLower := strings.ToLower(sv)
		switch {
		case strings.Contains(svLower, "nginx"):
			r.Technologies = appendUniq(r.Technologies, "Nginx")
		case strings.Contains(svLower, "apache"):
			r.Technologies = appendUniq(r.Technologies, "Apache")
		case strings.Contains(svLower, "iis"):
			r.Technologies = appendUniq(r.Technologies, "IIS")
		case strings.Contains(svLower, "caddy"):
			r.Technologies = appendUniq(r.Technologies, "Caddy")
		case strings.Contains(svLower, "cloudflare"):
			r.Technologies = appendUniq(r.Technologies, "Cloudflare")
		}
	}

	// X-Powered-By
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		r.HeaderClues["X-Powered-By"] = xpb
		xpbLower := strings.ToLower(xpb)
		switch {
		case strings.Contains(xpbLower, "php"):
			r.Language = "PHP"
			r.Technologies = appendUniq(r.Technologies, "PHP")
		case strings.Contains(xpbLower, "asp.net"):
			r.Framework = "ASP.NET"
			r.Language = "C#"
		case strings.Contains(xpbLower, "express"):
			r.Framework = "Express.js"
			r.Language = "Node.js"
		case strings.Contains(xpbLower, "next"):
			r.Framework = "Next.js"
			r.Language = "Node.js"
		}
	}

	// X-Generator, X-Framework
	if gen := headers.Get("X-Generator"); gen != "" {
		r.HeaderClues["X-Generator"] = gen
	}
	if fw := headers.Get("X-Framework"); fw != "" {
		r.HeaderClues["X-Framework"] = fw
		r.Framework = fw
	}

	// Content-Type → JSON API
	ct := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		r.LooksLikeAPI = true
	}

	// Cookies révélateurs
	for _, cookie := range resp.Cookies() {
		nameLower := strings.ToLower(cookie.Name)
		switch {
		case strings.HasPrefix(nameLower, "phpsessid"):
			r.Language = "PHP"
			r.Technologies = appendUniq(r.Technologies, "PHP")
		case strings.HasPrefix(nameLower, "asp.net_sessionid") || nameLower == "aspsessionid":
			r.Framework = "ASP.NET"
			r.Language = "C#"
		case strings.HasPrefix(nameLower, "jsessionid"):
			r.Language = "Java"
			r.Technologies = appendUniq(r.Technologies, "Java/Servlet")
		case nameLower == "laravel_session":
			r.Framework = "Laravel"
			r.Language = "PHP"
		case nameLower == "csrftoken" || nameLower == "django":
			r.Framework = "Django"
			r.Language = "Python"
		case nameLower == "rack.session":
			r.Framework = "Rails/Rack"
			r.Language = "Ruby"
		}
	}
}

func (d *Detector) analyzeBody(body string, r *models.FingerprintResult) {
	// Frameworks front / générateurs
	patterns := map[string][]string{
		"Next.js":     {"__next", "_next/static", "next/router"},
		"React":       {"react-root", "__reactfiber", "data-reactroot"},
		"Vue.js":      {"__vue__", "data-v-", "vue-meta"},
		"Angular":     {"ng-version", "ng-app", "_nghost"},
		"WordPress":   {"wp-content", "wp-includes", "wordpress"},
		"Drupal":      {"drupal.js", "drupal-settings", "/sites/default/files"},
		"Joomla":      {"/components/com_", "joomla"},
		"Laravel":     {"laravel_session", "csrf-token"},
		"Django":      {"csrfmiddlewaretoken", "__admin__"},
		"Rails":       {"csrf-param", "authenticity_token"},
		"FastAPI":     {"/openapi.json", "/docs#/", "swagger-ui"},
		"Spring Boot": {"whitelabel error page", "spring"},
		"GraphQL":     {"/graphql", "__typename", "introspection"},
	}

	for tech, sigs := range patterns {
		for _, sig := range sigs {
			if strings.Contains(body, sig) {
				r.Technologies = appendUniq(r.Technologies, tech)
				if r.Framework == "" && !isLanguage(tech) {
					r.Framework = tech
				}
				break
			}
		}
	}

	// API JSON
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		r.LooksLikeAPI = true
	}
}

func (d *Detector) detectAuth(resp *http.Response, body string, r *models.FingerprintResult) {
	// Header WWW-Authenticate
	if wa := resp.Header.Get("WWW-Authenticate"); wa != "" {
		waLower := strings.ToLower(wa)
		switch {
		case strings.HasPrefix(waLower, "bearer"):
			r.AuthMechanism = "JWT bearer"
		case strings.HasPrefix(waLower, "basic"):
			r.AuthMechanism = "HTTP Basic"
		case strings.HasPrefix(waLower, "digest"):
			r.AuthMechanism = "HTTP Digest"
		default:
			r.AuthMechanism = wa
		}
		return
	}

	// Authorization header hints dans le body
	switch {
	case strings.Contains(body, "bearer") || strings.Contains(body, "jwt") || strings.Contains(body, "access_token"):
		r.AuthMechanism = "JWT bearer (inferred)"
	case strings.Contains(body, "api_key") || strings.Contains(body, "x-api-key"):
		r.AuthMechanism = "API key"
	case strings.Contains(body, "login") && strings.Contains(body, "password"):
		r.AuthMechanism = "Form-based auth"
	case strings.Contains(body, "oauth") || strings.Contains(body, "oauth2"):
		r.AuthMechanism = "OAuth2"
	}
}

func appendUniq(slice []string, val string) []string {
	for _, v := range slice {
		if v == val {
			return slice
		}
	}
	return append(slice, val)
}

func isLanguage(s string) bool {
	langs := map[string]bool{"PHP": true, "Python": true, "Ruby": true, "Java": true, "Node.js": true, "C#": true}
	return langs[s]
}
