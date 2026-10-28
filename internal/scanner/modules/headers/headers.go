// Package headers vérifie la présence des en-têtes de sécurité HTTP.
// Module passif — aucune requête offensive.
package headers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/auditcore/auditcore/internal/models"
)

// headerCheck décrit un header attendu et son finding associé si absent.
type headerCheck struct {
	Header      string
	TaxonomyID  string
	Title       string
	Severity    models.Severity
	CWE         string
	OWASPCat    string
	ASVSMapping string
	Description string
	Impact      string
	Remediation string
}

var securityHeaders = []headerCheck{
	{
		Header:      "Content-Security-Policy",
		TaxonomyID:  "WEB-HDRS-001",
		Title:       "Missing Content-Security-Policy header",
		Severity:    models.SeverityMedium,
		CWE:         "CWE-693",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.4.6",
		Description: "L'en-tête Content-Security-Policy est absent. Sans CSP, le navigateur accepte l'exécution de scripts inline et l'injection de contenu depuis des origines tierces.",
		Impact:      "Facilite les attaques XSS en l'absence de politique de restriction des sources de contenu.",
		Remediation: "Implémenter une CSP stricte : Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
	},
	{
		Header:      "X-Frame-Options",
		TaxonomyID:  "WEB-HDRS-002",
		Title:       "Missing X-Frame-Options header",
		Severity:    models.SeverityMedium,
		CWE:         "CWE-1021",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.4.3",
		Description: "L'en-tête X-Frame-Options est absent. La page peut être chargée dans un iframe par n'importe quelle origine.",
		Impact:       "Expose la cible à des attaques de clickjacking.",
		Remediation: "Ajouter : X-Frame-Options: DENY ou SAMEORIGIN",
	},
	{
		Header:      "X-Content-Type-Options",
		TaxonomyID:  "WEB-HDRS-003",
		Title:       "Missing X-Content-Type-Options header",
		Severity:    models.SeverityLow,
		CWE:         "CWE-693",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.4.1",
		Description: "L'en-tête X-Content-Type-Options est absent. Le navigateur peut sniff le Content-Type et interpréter du contenu différemment du type déclaré.",
		Impact:       "Peut permettre l'exécution de scripts dans des fichiers dont le type MIME est mal déclaré.",
		Remediation: "Ajouter : X-Content-Type-Options: nosniff",
	},
	{
		Header:      "Strict-Transport-Security",
		TaxonomyID:  "WEB-HDRS-004",
		Title:       "Missing Strict-Transport-Security (HSTS) header",
		Severity:    models.SeverityMedium,
		CWE:         "CWE-319",
		OWASPCat:    "A02:2021",
		ASVSMapping: "V9.1.1",
		Description: "L'en-tête HSTS est absent. Sans lui, le navigateur peut accepter une connexion HTTP non sécurisée même si HTTPS est disponible.",
		Impact:       "Expose les utilisateurs aux attaques de type SSL stripping ou MITM.",
		Remediation: "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
	},
	{
		Header:      "Referrer-Policy",
		TaxonomyID:  "WEB-HDRS-005",
		Title:       "Missing Referrer-Policy header",
		Severity:    models.SeverityLow,
		CWE:         "CWE-116",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.4.7",
		Description: "L'en-tête Referrer-Policy est absent. Le navigateur peut transmettre l'URL complète dans le header Referer lors des navigations.",
		Impact:       "Peut fuiter des tokens ou paramètres sensibles présents dans les URLs.",
		Remediation: "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
	},
	{
		Header:      "Permissions-Policy",
		TaxonomyID:  "WEB-HDRS-006",
		Title:       "Missing Permissions-Policy header",
		Severity:    models.SeverityInfo,
		CWE:         "CWE-693",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.4.8",
		Description: "L'en-tête Permissions-Policy (anciennement Feature-Policy) est absent.",
		Impact:       "Les APIs du navigateur (camera, microphone, geolocation) peuvent être accessibles par défaut.",
		Remediation: "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()",
	},
}

// Module implémente engine.Module pour les security headers.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "headers-security" }

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	resp, err := client.Head(ctx.Asset.URL)
	if err != nil {
		// Fallback GET
		resp, err = client.Get(ctx.Asset.URL)
		if err != nil {
			result.Error = err
			return result
		}
	}
	defer resp.Body.Close()

	// Ne tester les headers que sur la racine ou pages principales (pas les assets statiques)
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "image/") || strings.Contains(ct, "font/") ||
		strings.Contains(ct, "text/css") || strings.Contains(ct, "application/javascript") {
		return result
	}

	for _, check := range securityHeaders {
		if resp.Header.Get(check.Header) == "" {
			finding := &models.Finding{
				TaxonomyID:  check.TaxonomyID,
				Type:        "missing-header",
				Title:       check.Title,
				Severity:    check.Severity,
				Confidence:  models.ConfidenceHigh, // Passif = toujours High confidence
				Status:      models.FindingConfirmed,
				CWE:         check.CWE,
				OWASPCat:    check.OWASPCat,
				ASVSMapping: check.ASVSMapping,
				Description: check.Description,
				Impact:      check.Impact,
				Remediation: check.Remediation,
				Replayable:  false,
				Endpoint:    ctx.Asset.URL,
				Evidence: &models.Evidence{
					RequestRaw:    fmt.Sprintf("HEAD %s HTTP/1.1\nHost: %s", ctx.Asset.URL, hostFromURL(ctx.Asset.URL)),
					ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n(header %s absent)", resp.StatusCode, check.Header),
					MatcherResult: fmt.Sprintf("Header '%s' absent de la réponse", check.Header),
				},
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	return result
}

func hostFromURL(u string) string {
	if idx := strings.Index(u, "//"); idx >= 0 {
		rest := u[idx+2:]
		if end := strings.IndexAny(rest, "/?#"); end >= 0 {
			return rest[:end]
		}
		return rest
	}
	return u
}
