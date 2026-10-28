// Package replay rejoue une requête de preuve et vérifie que le comportement est toujours présent.
// Principe : suspected → validated → confirmed grâce aux replays successifs.
package replay

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
)

// Result est retourné après un replay.
type Result struct {
	FindingID    string                    `json:"finding_id"`
	Success      bool                      `json:"success"`
	StatusCode   int                       `json:"status_code,omitempty"`
	ResponseSnip string                    `json:"response_snippet,omitempty"`
	MatcherHit   bool                      `json:"matcher_hit"`
	Message      string                    `json:"message"`
	NewStatus    models.FindingStatus      `json:"new_status"`
	ReplayState  models.FindingReplayState `json:"replay_state"`
	ReplayedAt   time.Time                 `json:"replayed_at"`
}

// Run rejoue la preuve d'un finding et retourne le résultat.
func Run(f *models.Finding, options models.AuditOptions) *Result {
	r := &Result{
		FindingID:   f.ID,
		NewStatus:   f.Status,
		ReplayState: models.FindingReplayNotRun,
		ReplayedAt:  time.Now(),
	}

	if !f.Replayable || f.Evidence == nil {
		r.Success = false
		r.Message = "finding non replayable — pas de preuve HTTP stockée"
		r.ReplayState = models.FindingReplayUnavailable
		return r
	}

	// Construire et exécuter la requête de replay
	resp, body, err := executeProbe(f, options)
	if err != nil {
		r.Success = false
		r.Message = fmt.Sprintf("replay échoué : %v", err)
		r.ReplayState = models.FindingReplayFailed
		return r
	}
	r.StatusCode = resp.StatusCode
	r.Success = true

	// Vérifier le matcher
	matched := checkMatcher(body, resp, f.Type, f.Evidence)
	r.MatcherHit = matched
	r.ResponseSnip = snip(body, 300)

	if matched {
		r.ReplayState = models.FindingReplayConfirmed
		r.Message = fmt.Sprintf("Replay confirmé — pattern détecté (code %d)", resp.StatusCode)
		// Escalade du statut
		switch f.Status {
		case models.FindingSuspected:
			r.NewStatus = models.FindingValidated
		case models.FindingValidated:
			r.NewStatus = models.FindingConfirmed
		default:
			r.NewStatus = f.Status
		}
	} else {
		r.ReplayState = models.FindingReplayNotReproduced
		r.Message = fmt.Sprintf("Replay : requête OK (code %d) mais pattern non retrouvé — potentiellement corrigé", resp.StatusCode)
	}

	return r
}

// executeProbe envoie une requête HTTP adaptée au type de finding.
func executeProbe(finding *models.Finding, options models.AuditOptions) (*http.Response, string, error) {
	endpoint := finding.Endpoint
	payload := ""
	if finding.Evidence != nil {
		payload = finding.Evidence.Payload
	}
	if endpoint == "" {
		return nil, "", fmt.Errorf("endpoint vide")
	}

	var req *http.Request
	var err error
	method, exactTarget := requestTarget(finding.Evidence)
	if exactTarget != "" {
		endpoint = exactTarget
	}
	if method == "" {
		method = "GET"
	}

	switch {
	case strings.Contains(finding.Type, "cors"):
		req, err = http.NewRequest(method, endpoint, nil)
		if err == nil {
			req.Header.Set("Origin", "https://evil-cors-probe.example.com")
		}
	case strings.Contains(finding.Type, "sqli") && payload != "":
		targetURL := endpoint
		if exactTarget == "" {
			targetURL = addParam(endpoint, finding.Parameter, payload)
		}
		req, err = http.NewRequest(method, targetURL, nil)
	case strings.Contains(finding.Type, "xss") && payload != "":
		targetURL := endpoint
		if exactTarget == "" {
			targetURL = addParam(endpoint, finding.Parameter, payload)
		}
		req, err = http.NewRequest(method, targetURL, nil)
	case strings.Contains(finding.Type, "ssrf") && payload != "":
		req, err = http.NewRequest("POST", endpoint, strings.NewReader(
			fmt.Sprintf(`{"url":"%s"}`, payload),
		))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	default:
		req, err = http.NewRequest("GET", endpoint, nil)
	}

	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "AuditCore-Replay/2.0")

	client := httpx.NewClient(15*time.Second, options)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp, string(bodyBytes), nil
}

func requestTarget(ev *models.Evidence) (string, string) {
	if ev == nil {
		return "", ""
	}
	fields := strings.Fields(ev.RequestRaw)
	if len(fields) < 2 || !strings.Contains(fields[1], "://") {
		return "", ""
	}
	return strings.ToUpper(fields[0]), fields[1]
}

// checkMatcher vérifie si le pattern de la preuve est toujours présent dans la réponse.
func checkMatcher(body string, resp *http.Response, findingType string, ev *models.Evidence) bool {
	bodyLower := strings.ToLower(body)

	switch {
	case strings.Contains(findingType, "cors"):
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		return acao == "*" || strings.Contains(acao, "evil-cors-probe")

	case strings.Contains(findingType, "sqli"):
		// Erreurs SQL typiques
		for _, pattern := range []string{
			"syntax error", "mysql_fetch", "ora-", "postgresql",
			"sqlite3.", "microsoft sql", "unclosed quotation",
			"you have an error in your sql", "warning: mysql",
		} {
			if strings.Contains(bodyLower, pattern) {
				return true
			}
		}
		// Code 500 = probable erreur serveur
		return resp.StatusCode == 500

	case strings.Contains(findingType, "xss"):
		if ev.Payload != "" {
			return strings.Contains(body, ev.Payload)
		}
		return strings.Contains(bodyLower, "<script") || strings.Contains(bodyLower, "onerror=")

	case strings.Contains(findingType, "ssrf"):
		// Réponse interne AWS metadata ou autre
		for _, pattern := range []string{"ami-id", "instance-id", "169.254", "metadata"} {
			if strings.Contains(bodyLower, pattern) {
				return true
			}
		}
		return resp.StatusCode == 200 && len(body) > 10

	case strings.Contains(findingType, "missing-header"):
		// Vérifier que le header est toujours absent
		headerName := extractHeaderName(ev.MatcherResult)
		if headerName != "" {
			return resp.Header.Get(headerName) == ""
		}
		return true

	case strings.Contains(findingType, "cookie"):
		// Vérifier que le cookie défectueux est toujours présent
		for _, cookie := range resp.Cookies() {
			name := strings.ToLower(cookie.Name)
			if strings.Contains(name, "session") || strings.Contains(name, "auth") {
				if strings.Contains(findingType, "httponly") && !cookie.HttpOnly {
					return true
				}
				if strings.Contains(findingType, "secure") && !cookie.Secure {
					return true
				}
			}
		}
		return false

	default:
		if ev.MatcherResult != "" {
			return strings.Contains(bodyLower, strings.ToLower(ev.MatcherResult))
		}
		return resp.StatusCode < 500
	}
}

func addParam(endpoint, parameter, payload string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if parameter == "" {
		parameter = "q"
	}
	query := parsed.Query()
	query.Set(parameter, payload)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func extractHeaderName(matcherResult string) string {
	// "Header 'X-Frame-Options' absent de la réponse"
	start := strings.Index(matcherResult, "'")
	if start < 0 {
		return ""
	}
	end := strings.Index(matcherResult[start+1:], "'")
	if end < 0 {
		return ""
	}
	return matcherResult[start+1 : start+1+end]
}

func snip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
