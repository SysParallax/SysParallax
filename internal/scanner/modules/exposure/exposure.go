package exposure

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
)

var sensitivePaths = []string{
	"/.env",
	"/.git/config",
	"/.svn/entries",
	"/backup.zip",
	"/backup.sql",
	"/db.sql",
	"/dump.sql",
	"/config.php.bak",
	"/wp-config.php.bak",
	"/phpinfo.php",
	"/server-status",
}

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "sensitive-exposure" }

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}
	if ctx.Asset == nil || ctx.Asset.URL == "" || ctx.Asset.Method != "GET" {
		return result
	}
	u, err := url.Parse(ctx.Asset.URL)
	if err != nil || u.Host == "" {
		return result
	}

	if f := checkDirectoryListing(ctx, client); f != nil {
		result.Findings = append(result.Findings, f)
	}

	if u.Path != "" && u.Path != "/" {
		return result
	}
	for _, path := range sensitivePaths {
		probe := *u
		probe.Path = path
		probe.RawQuery = ""
		req, err := http.NewRequest("GET", probe.String(), nil)
		if err != nil {
			continue
		}
		resp, err := matchers.Fetch(client, req)
		if err != nil {
			continue
		}
		if hit, evidence := sensitiveHit(path, resp); hit {
			result.Findings = append(result.Findings, &models.Finding{
				TaxonomyID:  "WEB-EXP-001",
				Type:        "sensitive-file-exposure",
				Title:       fmt.Sprintf("Sensitive file exposed: %s", path),
				Severity:    severityForPath(path),
				Confidence:  models.ConfidenceHigh,
				Status:      models.FindingConfirmed,
				CWE:         "CWE-200",
				OWASPCat:    "A05:2021",
				ASVSMapping: "V14.3.3",
				Description: fmt.Sprintf("A sensitive or administrative resource is reachable at %s. %s", probe.String(), evidence),
				Impact:      "Disclosure of configuration, source control metadata, credentials, backups, or operational internals.",
				Remediation: "Remove sensitive files from the web root, deny access at the web server, and rotate any exposed credentials.",
				Replayable:  true,
				Endpoint:    probe.String(),
				Evidence: &models.Evidence{
					RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1", probe.String()),
					ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, snip(resp.Body, 400)),
					MatcherResult: evidence,
				},
			})
		}
	}
	return result
}

func checkDirectoryListing(ctx *models.ModuleContext, client *http.Client) *models.Finding {
	req, err := http.NewRequest("GET", ctx.Asset.URL, nil)
	if err != nil {
		return nil
	}
	resp, err := matchers.Fetch(client, req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	body := strings.ToLower(resp.Body)
	if !strings.Contains(body, "index of /") && !strings.Contains(body, "parent directory") {
		return nil
	}
	return &models.Finding{
		TaxonomyID:  "WEB-EXP-002",
		Type:        "directory-listing",
		Title:       "Directory listing enabled",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceHigh,
		Status:      models.FindingConfirmed,
		CWE:         "CWE-548",
		OWASPCat:    "A05:2021",
		ASVSMapping: "V14.3.3",
		Description: "The server exposes a browsable directory index.",
		Impact:      "Attackers can enumerate files, backups, source artifacts, or unpublished resources.",
		Remediation: "Disable autoindex/directory browsing and publish only intended static files.",
		Replayable:  true,
		Endpoint:    ctx.Asset.URL,
		Evidence: &models.Evidence{
			RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1", ctx.Asset.URL),
			ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, snip(resp.Body, 400)),
			MatcherResult: "directory index markers found",
		},
	}
}

func sensitiveHit(path string, resp *matchers.Response) (bool, string) {
	if resp.StatusCode != 200 || len(strings.TrimSpace(resp.Body)) < 8 {
		return false, ""
	}
	body := strings.ToLower(resp.Body)
	switch path {
	case "/.env":
		return strings.Contains(body, "app_key=") || strings.Contains(body, "db_password") || strings.Contains(body, "secret"), ".env-like keys found"
	case "/.git/config":
		return strings.Contains(body, "[core]") || strings.Contains(body, "repositoryformatversion"), "git config markers found"
	case "/phpinfo.php":
		return strings.Contains(body, "php version") && strings.Contains(body, "phpinfo"), "phpinfo output found"
	default:
		return !strings.Contains(body, "<html") || strings.Contains(body, "backup") || strings.Contains(body, "dump"), "non-empty sensitive path response"
	}
}

func severityForPath(path string) models.Severity {
	if strings.Contains(path, ".env") || strings.Contains(path, ".git") || strings.Contains(path, ".sql") {
		return models.SeverityHigh
	}
	return models.SeverityMedium
}

func snip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
