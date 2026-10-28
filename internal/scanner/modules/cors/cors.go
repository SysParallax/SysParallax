// Package cors détecte les misconfigurations CORS.
// Teste avec Origin: https://evil.com pour voir si le serveur l'accepte.
package cors

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/auditcore/auditcore/internal/models"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "cors-misconfig" }

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	// Tester uniquement les endpoints qui semblent être des APIs ou des pages principales
	url := ctx.Asset.URL
	if !looksLikeAPIOrRoot(url) {
		return result
	}

	probeOrigin := "https://evil-cors-probe.example.com"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = err
		return result
	}
	req.Header.Set("Origin", probeOrigin)

	resp, err := client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return result // Pas de CORS configuré — normal
	}

	// Cas 1 : wildcard *
	if acao == "*" {
		result.Findings = append(result.Findings, &models.Finding{
			TaxonomyID:  "WEB-CORS-001",
			Type:        "cors-wildcard",
			Title:       "CORS — wildcard origin (Access-Control-Allow-Origin: *)",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Status:      models.FindingConfirmed,
			CWE:         "CWE-942",
			OWASPCat:    "A05:2021",
			ASVSMapping: "V14.5.3",
			Description: "Le serveur retourne Access-Control-Allow-Origin: * ce qui autorise n'importe quelle origine à lire les réponses.",
			Impact:       "N'importe quel site tiers peut lire les données retournées par cet endpoint via XHR/fetch.",
			Remediation: "Restreindre Access-Control-Allow-Origin aux origines de confiance explicites.",
			Replayable:  true,
			Endpoint:    url,
			Evidence: &models.Evidence{
				RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1\nOrigin: %s", url, probeOrigin),
				ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\nAccess-Control-Allow-Origin: *", resp.StatusCode),
				Payload:       probeOrigin,
				MatcherResult: "ACAO = *",
			},
		})
		return result
	}

	// Cas 2 : l'origine de la sonde est reflétée + credentials allowed
	if strings.Contains(acao, probeOrigin) || acao == probeOrigin {
		sev := models.SeverityMedium
		title := "CORS — origine arbitraire reflétée"
		desc := "Le serveur reflète l'origine fournie dans Access-Control-Allow-Origin."

		if strings.ToLower(acac) == "true" {
			sev = models.SeverityCritical
			title = "CORS — origine arbitraire reflétée avec credentials"
			desc = "Le serveur accepte n'importe quelle origine ET retourne Access-Control-Allow-Credentials: true. Un attaquant peut lire les réponses authentifiées."
		}

		result.Findings = append(result.Findings, &models.Finding{
			TaxonomyID:  "WEB-CORS-002",
			Type:        "cors-origin-reflection",
			Title:       title,
			Severity:    sev,
			Confidence:  models.ConfidenceHigh,
			Status:      models.FindingConfirmed,
			CWE:         "CWE-942",
			OWASPCat:    "A05:2021",
			ASVSMapping: "V14.5.3",
			Description: desc,
			Impact:      "Exfiltration de données sensibles depuis un navigateur victime via une page malveillante.",
			Remediation: "Valider l'Origin contre une liste blanche stricte. Ne jamais utiliser un reflet dynamique de l'Origin.",
			Replayable:  true,
			Endpoint:    url,
			Evidence: &models.Evidence{
				RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1\nOrigin: %s", url, probeOrigin),
				ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", resp.StatusCode, acao, acac),
				Payload:       probeOrigin,
				MatcherResult: fmt.Sprintf("ACAO reflète l'origine de la sonde. ACAC=%s", acac),
			},
		})
	}

	return result
}

func looksLikeAPIOrRoot(u string) bool {
	u = strings.ToLower(u)
	return strings.Contains(u, "/api") ||
		strings.Contains(u, "/v1") ||
		strings.Contains(u, "/v2") ||
		strings.Contains(u, "/graphql") ||
		strings.HasSuffix(u, "/") ||
		!strings.Contains(u, ".")
}
