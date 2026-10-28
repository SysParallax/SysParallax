package xss

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/browser"
)

func runXSSActive(t *testing.T, handler http.Handler) *models.ActiveTestResult {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	asset := &models.Asset{ID: "asset-xss", AuditRunID: "audit-xss", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "?q=hello", Params: []string{"q"}}
	options := models.AuditOptions{ActiveMaxRequestsPerTest: 32, ActiveMaxResponseBytes: 32 * 1024}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-xss", Asset: asset, Options: options}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "q", Location: models.EntryPointQuery, OriginalValue: "hello"}}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "xss-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(context.Background(), moduleCtx, plan, executor)
}

func TestXSSActiveConfirmsHTMLScriptContext(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><div>" + r.URL.Query().Get("q") + "</div></body></html>"))
	}))
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !result.Evidence.MinimumProofReached || !strings.Contains(result.Evidence.Observed, "html-text") {
		t.Fatalf("missing HTML context evidence: %+v", result.Evidence)
	}
}

func TestXSSActiveConfirmsAttributeBreakout(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<input value="` + r.URL.Query().Get("q") + `">`))
	}))
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected attribute breakout CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !strings.Contains(result.Evidence.Observed, "attribut HTML") {
		t.Fatalf("missing attribute context evidence: %+v", result.Evidence)
	}
}

func TestXSSActiveRejectsHTMLEscaping(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>" + html.EscapeString(r.URL.Query().Get("q")) + "</div>"))
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected escaped HTML to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !strings.Contains(result.Evidence.Observed, "HTML échappé") {
		t.Fatalf("missing encoding evidence: %+v", result.Evidence)
	}
}

func TestXSSActiveDoesNotConfirmJavaScriptStringReflection(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<script>const query = '" + r.URL.Query().Get("q") + "';</script>"))
	}))
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected JavaScript string reflection to be INCONCLUSIVE, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !strings.Contains(result.Evidence.Observed, "javascript") {
		t.Fatalf("missing JavaScript context evidence: %+v", result.Evidence)
	}
}

func TestXSSActiveRejectsJSONReflection(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"q": r.URL.Query().Get("q")})
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected JSON reflection to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !strings.Contains(result.Evidence.Observed, "json") {
		t.Fatalf("missing JSON context evidence: %+v", result.Evidence)
	}
}

func TestXSSActiveRejectsURLAndCorrectlyEncodedReflection(t *testing.T) {
	result := runXSSActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		value := r.URL.Query().Get("q")
		_, _ = w.Write([]byte("<div>" + url.QueryEscape(value) + "</div>"))
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected URL-encoded reflection to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestBrowserEvidencePreservesMarkerAndRedactsSecrets(t *testing.T) {
	result := &browser.Result{
		FinalURL:       "https://example.com/?token=secret-value",
		FinalOrigin:    "https://example.com",
		DOM:            `<html data-token="secret-value">auditcore-xss-marker</html>`,
		Marker:         "auditcore-xss-marker",
		MarkerObserved: true,
		Navigations:    []string{"https://example.com/?token=secret-value"},
		Events:         []browser.Event{{Type: "marker_observed", URL: "https://example.com/?secret=secret-value", At: time.Now()}},
	}
	evidence := browserEvidenceFromResult(result, nil, result.Marker, models.AuditOptions{})
	if evidence == nil || !evidence.MarkerObserved || evidence.Marker != result.Marker {
		t.Fatalf("browser marker evidence was not preserved: %+v", evidence)
	}
	if strings.Contains(evidence.DOM, "secret-value") || strings.Contains(evidence.FinalURL, "secret-value") {
		t.Fatalf("browser evidence leaked a secret: %+v", evidence)
	}
	if len(evidence.Events) != 1 || evidence.Events[0].Type != "marker_observed" {
		t.Fatalf("browser events were not converted: %+v", evidence.Events)
	}
}
