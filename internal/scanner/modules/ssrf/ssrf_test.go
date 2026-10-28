package ssrf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
)

type callbackCollector struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newCallbackCollector() *callbackCollector {
	return &callbackCollector{seen: make(map[string]bool)}
}

func (c *callbackCollector) handler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.URL.Query().Get("auditcore_token")
	}
	if r.URL.Path == "/hit" && token != "" {
		c.mu.Lock()
		c.seen[token] = true
		c.mu.Unlock()
	}
	if r.URL.Path == "/check" {
		c.mu.Lock()
		observed := c.seen[token]
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"observed":%t,"token":%q}`, observed, token)
		return
	}
	_, _ = fmt.Fprint(w, `{"received":true}`)
}

func runSSRFActive(t *testing.T, target http.Handler, options models.AuditOptions) *models.ActiveTestResult {
	t.Helper()
	collector := newCallbackCollector()
	callbackServer := httptest.NewServer(http.HandlerFunc(collector.handler))
	t.Cleanup(callbackServer.Close)
	if options.ActiveSSRFCallbackURL == "" && options.ActiveSSRFCallbackCheckURL == "" {
		options.ActiveSSRFCallbackURL = callbackServer.URL + "/hit?token={token}"
		options.ActiveSSRFCallbackCheckURL = callbackServer.URL + "/check?token={token}"
	}
	targetServer := httptest.NewServer(target)
	t.Cleanup(targetServer.Close)
	asset := &models.Asset{
		ID: "asset-ssrf", AuditRunID: "audit-ssrf", Type: models.AssetEndpoint,
		Method: http.MethodGet, URL: targetServer.URL + "/fetch?url=hello", Params: []string{"url"},
	}
	if options.ActiveMaxRequestsPerTest == 0 {
		options.ActiveMaxRequestsPerTest = 16
	}
	if options.ActiveMaxResponseBytes == 0 {
		options.ActiveMaxResponseBytes = 32 * 1024
	}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-ssrf", Asset: asset, Options: options}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{
		Endpoint: asset.URL, Method: http.MethodGet, Name: "url", Location: models.EntryPointQuery, OriginalValue: "hello",
	}}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "ssrf-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(context.Background(), moduleCtx, plan, executor)
}

func TestSSRFConfirmsOnlyAfterObservedServerCallback(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbackURL := r.URL.Query().Get("url")
		response, err := http.Get(callbackURL)
		if err == nil {
			_ = response.Body.Close()
		}
		_, _ = fmt.Fprint(w, "resource fetched")
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true})
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED after callback observation, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !result.Evidence.CallbackObserved || result.Evidence.CallbackToken == "" || !result.Evidence.MinimumProofReached {
		t.Fatalf("missing callback proof evidence: %+v", result.Evidence)
	}
	if len(result.Evidence.CallbackObservations) != 2 || result.Evidence.CallbackObservations[0].Token == result.Evidence.CallbackObservations[1].Token || result.Evidence.CallbackPolls < 2 {
		t.Fatalf("missing independent callback reproduction trace: %+v", result.Evidence.CallbackObservations)
	}
	if result.Evidence.CallbackObservations[0].Status != "observed" || result.Evidence.CallbackObservations[1].Status != "observed" {
		t.Fatalf("callback observations were not both confirmed: %+v", result.Evidence.CallbackObservations)
	}
	if !strings.Contains(result.Evidence.CallbackProof, "observed") || len(result.Findings) != 1 || result.Findings[0].Parameter != "url" {
		t.Fatalf("callback proof or finding association missing: %+v", result.Evidence)
	}
}

func TestSSRFDoesNotConfirmDisplayedCallbackURL(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "displayed URL: %s", r.URL.Query().Get("url"))
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for displayed URL, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.CallbackObserved || result.Evidence.MinimumProofReached {
		t.Fatalf("displayed URL produced callback proof: %+v", result.Evidence)
	}
}

func TestSSRFDoesNotFollowHTTPRedirectFromTarget(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == "hello" {
			_, _ = fmt.Fprint(w, "normal resource")
			return
		}
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for target redirect, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.CallbackObserved {
		t.Fatalf("target redirect was mistaken for server callback: %+v", result.Evidence)
	}
}

func TestSSRFDoesNotConfirmClientSideRedirectCode(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<script>window.location=%q</script>`, r.URL.Query().Get("url"))
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for client-side redirect, got %s: %s", result.Status, result.Reason)
	}
}

func TestSSRFAllowsConfiguredDirectProofMarker(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == "hello" {
			_, _ = fmt.Fprint(w, "normal resource")
			return
		}
		_, _ = fmt.Fprint(w, "CALLBACK-DIRECT-PROOF")
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true, ActiveSSRFCallbackMarker: "CALLBACK-DIRECT-PROOF"})
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected direct proof CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.CallbackObserved || !result.Evidence.MinimumProofReached || !strings.Contains(result.Evidence.CallbackProof, "CALLBACK-DIRECT-PROOF") {
		t.Fatalf("missing direct proof evidence: %+v", result.Evidence)
	}
}

func TestSSRFRequiresCallbackConfigurationBeforeAnyProbe(t *testing.T) {
	var requests atomic.Int32
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprint(w, "should not be requested")
	}), models.AuditOptions{ActiveSSRFCallbackCheckURL: "https://callback.invalid/check"})
	if result.Status != models.ActiveTestInconclusive || result.RequestCount != 0 || requests.Load() != 0 {
		t.Fatalf("missing callback config triggered a probe: status=%s requests=%d target=%d", result.Status, result.RequestCount, requests.Load())
	}
}

func TestSSRFRejectsPrivateCallbackByDefault(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "should not be requested")
	}), models.AuditOptions{})
	if result.Status != models.ActiveTestUntestable {
		t.Fatalf("expected UNTESTABLE for private callback without explicit opt-in, got %s: %s", result.Status, result.Reason)
	}
	if result.RequestCount != 0 {
		t.Fatalf("private callback rejection still sent target requests: %d", result.RequestCount)
	}
}

func TestSSRFDoesNotAcceptMismatchedCallbackToken(t *testing.T) {
	if callbackBodyConfirms(`{"observed":true,"token":"other-test"}`, "expected-test") {
		t.Fatal("callback for a different test token was accepted")
	}
	if inspection := inspectCallbackBody(`{"observed":true,"token":"other-test"}`, "expected-test", ""); inspection.Status != callbackStatusMismatched {
		t.Fatalf("expected mismatched callback status, got %+v", inspection)
	}
}

func TestSSRFDoesNotConfirmWithoutIndependentCallbackReproduction(t *testing.T) {
	var probeRequests atomic.Int32
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbackURL := r.URL.Query().Get("url")
		if callbackURL == "hello" || probeRequests.Add(1) > 1 {
			_, _ = fmt.Fprint(w, "normal resource")
			return
		}
		response, err := http.Get(callbackURL)
		if err == nil {
			_ = response.Body.Close()
		}
		_, _ = fmt.Fprint(w, "resource fetched once")
	}), models.AuditOptions{ActiveSSRFAllowPrivateCallback: true})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE without reproduction callback, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || len(result.Evidence.CallbackObservations) != 2 || !result.Evidence.CallbackObservations[0].Observed || result.Evidence.CallbackObservations[1].Observed {
		t.Fatalf("expected first callback only in evidence: %+v", result.Evidence)
	}
}

func TestSSRFRecordsBoundedCallbackPolling(t *testing.T) {
	result := runSSRFActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "resource accepted")
	}), models.AuditOptions{
		ActiveSSRFAllowPrivateCallback:       true,
		ActiveSSRFCallbackWindowMillis:       20,
		ActiveSSRFCallbackPollIntervalMillis: 10,
		ActiveSSRFCallbackMaxPolls:           2,
	})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for absent callback, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || len(result.Evidence.CallbackObservations) != 1 || result.Evidence.CallbackObservations[0].Polls == 0 || result.Evidence.CallbackPolls != result.Evidence.CallbackObservations[0].Polls {
		t.Fatalf("bounded polling was not recorded: %+v", result.Evidence)
	}
	if result.Evidence.CallbackWindowMillis != 20 || result.Evidence.CallbackPollIntervalMillis != 10 {
		t.Fatalf("polling configuration missing from evidence: %+v", result.Evidence)
	}
}
