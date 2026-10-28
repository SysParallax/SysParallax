// Package cookies vérifie les flags de sécurité des cookies de session.
package cookies

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/auditcore/auditcore/internal/models"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "cookies-security" }

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	resp, err := client.Get(ctx.Asset.URL)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return result
	}

	for _, cookie := range cookies {
		name := cookie.Name
		nameLower := strings.ToLower(name)

		// Identifier les cookies de session (heuristique)
		isSession := strings.Contains(nameLower, "session") ||
			strings.Contains(nameLower, "sess") ||
			strings.Contains(nameLower, "auth") ||
			strings.Contains(nameLower, "token") ||
			strings.Contains(nameLower, "jwt") ||
			nameLower == "phpsessid" ||
			nameLower == "jsessionid"

		// HttpOnly manquant sur un cookie de session
		if isSession && !cookie.HttpOnly {
			result.Findings = append(result.Findings, &models.Finding{
				TaxonomyID:  "WEB-COOK-001",
				Type:        "cookie-missing-httponly",
				Title:       fmt.Sprintf("Cookie '%s' — flag HttpOnly absent", name),
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				Status:      models.FindingConfirmed,
				CWE:         "CWE-1004",
				OWASPCat:    "A05:2021",
				ASVSMapping: "V3.4.2",
				Description: fmt.Sprintf("Le cookie de session '%s' n'a pas le flag HttpOnly. Il est accessible via JavaScript.", name),
				Impact:      "Un XSS peut voler ce cookie via document.cookie.",
				Remediation: "Ajouter le flag HttpOnly à tous les cookies de session : Set-Cookie: " + name + "=...; HttpOnly",
				Replayable:  false,
				Endpoint:    ctx.Asset.URL,
				Evidence: &models.Evidence{
					ResponseRaw:   fmt.Sprintf("Set-Cookie: %s=... (HttpOnly absent)", name),
					MatcherResult: "HttpOnly flag manquant",
				},
			})
		}

		// Secure manquant
		if isSession && !cookie.Secure {
			result.Findings = append(result.Findings, &models.Finding{
				TaxonomyID:  "WEB-COOK-002",
				Type:        "cookie-missing-secure",
				Title:       fmt.Sprintf("Cookie '%s' — flag Secure absent", name),
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				Status:      models.FindingConfirmed,
				CWE:         "CWE-614",
				OWASPCat:    "A02:2021",
				ASVSMapping: "V3.4.1",
				Description: fmt.Sprintf("Le cookie '%s' n'a pas le flag Secure. Il peut être transmis sur une connexion HTTP non chiffrée.", name),
				Impact:      "Interception possible du cookie en clair sur un réseau non sécurisé.",
				Remediation: "Ajouter le flag Secure : Set-Cookie: " + name + "=...; Secure",
				Replayable:  false,
				Endpoint:    ctx.Asset.URL,
				Evidence: &models.Evidence{
					ResponseRaw:   fmt.Sprintf("Set-Cookie: %s=... (Secure absent)", name),
					MatcherResult: "Secure flag manquant",
				},
			})
		}

		// SameSite manquant ou None sans Secure
		if isSession {
			sameSite := cookie.SameSite
			if sameSite == http.SameSiteDefaultMode || sameSite == 0 {
				result.Findings = append(result.Findings, &models.Finding{
					TaxonomyID:  "WEB-COOK-003",
					Type:        "cookie-missing-samesite",
					Title:       fmt.Sprintf("Cookie '%s' — attribut SameSite absent", name),
					Severity:    models.SeverityLow,
					Confidence:  models.ConfidenceHigh,
					Status:      models.FindingConfirmed,
					CWE:         "CWE-352",
					OWASPCat:    "A05:2021",
					ASVSMapping: "V3.4.3",
					Description: fmt.Sprintf("Le cookie '%s' n'a pas d'attribut SameSite défini explicitement.", name),
					Impact:      "Peut contribuer aux attaques CSRF selon le comportement du navigateur.",
					Remediation: "Ajouter SameSite=Strict ou SameSite=Lax selon le besoin.",
					Replayable:  false,
					Endpoint:    ctx.Asset.URL,
					Evidence: &models.Evidence{
						ResponseRaw:   fmt.Sprintf("Set-Cookie: %s=... (SameSite absent)", name),
						MatcherResult: "SameSite attribute manquant",
					},
				})
			}
		}
	}

	return result
}
