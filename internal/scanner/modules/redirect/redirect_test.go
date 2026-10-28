package redirect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
)

func runRedirectActive(t *testing.T, handler http.Handler) *models.ActiveTestResult {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	asset := &models.Asset{ID: "asset-redirect", AuditRunID: "audit-redirect", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "/start?url=hello", Params: []string{"url"}}
	options := models.AuditOptions{ActiveMaxRequestsPerTest: 32, ActiveMaxRedirects: 5, ActiveMaxResponseBytes: 32 * 1024}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-redirect", Asset: asset, Options: options}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "url", Location: models.EntryPointQuery, OriginalValue: "hello"}}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "redirect-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(context.Background(), moduleCtx, plan, executor)
}

func TestOpenRedirectConfirmsExternalHTTPDestination(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == probeTarget {
			http.Redirect(w, r, probeTarget, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("safe"))
	}))
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.RedirectType != "http" || result.Evidence.FinalOrigin != requestOrigin(probeTarget) || len(result.Evidence.RedirectChain) != 2 {
		t.Fatalf("missing final HTTP destination evidence: %+v", result.Evidence)
	}
}

func TestOpenRedirectResolvesInternalDestination(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" && r.URL.Query().Get("url") == probeTarget {
			http.Redirect(w, r, "/safe", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("safe internal page"))
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected internal redirect to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.FinalOrigin != requestOrigin(result.Evidence.RedirectChain[0]) || !strings.Contains(result.Evidence.FinalURL, "/safe") {
		t.Fatalf("missing internal final destination evidence: %+v", result.Evidence)
	}
}

func TestOpenRedirectConfirmsMultiHopExternalDestination(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			if r.URL.Query().Get("url") == probeTarget {
				http.Redirect(w, r, "/middle", http.StatusFound)
				return
			}
		case "/middle":
			http.Redirect(w, r, probeTarget, http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("safe"))
	}))
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected multi-hop CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || len(result.Evidence.RedirectChain) != 3 || result.Evidence.FinalOrigin != requestOrigin(probeTarget) {
		t.Fatalf("missing multi-hop chain evidence: %+v", result.Evidence)
	}
}

func TestOpenRedirectDoesNotConfirmDisplayedDestination(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "Continue to %s", r.URL.Query().Get("url"))
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected displayed destination to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestOpenRedirectDifferentiatesJavaScriptRedirect(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<script>window.location.href = %q;</script>`, probeTarget)
	}))
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected static JavaScript redirect to be INCONCLUSIVE, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.RedirectType != "javascript" || result.Evidence.FinalOrigin != requestOrigin(probeTarget) {
		t.Fatalf("missing JavaScript destination evidence: %+v", result.Evidence)
	}
}

func TestOpenRedirectDoesNotConfirmNormalizationToLegitimateOrigin(t *testing.T) {
	result := runRedirectActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == probeTarget {
			http.Redirect(w, r, "/safe", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("safe"))
	}))
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected normalization to legitimate origin to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}
