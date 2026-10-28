package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
)

func runSQLiActive(t *testing.T, handler http.Handler, timeout time.Duration) *models.ActiveTestResult {
	return runSQLiActiveWithOptions(t, handler, timeout, models.AuditOptions{ActiveMaxRequestsPerTest: 32, ActiveMaxResponseBytes: 16 * 1024})
}

func runSQLiActiveWithOptions(t *testing.T, handler http.Handler, timeout time.Duration, options models.AuditOptions) *models.ActiveTestResult {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	asset := &models.Asset{ID: "asset-sqli", AuditRunID: "audit-sqli", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "?id=1", Params: []string{"id"}}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-sqli", Asset: asset, Options: options}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "id", Location: models.EntryPointQuery, OriginalValue: "1"}}
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	executor := active.NewExecutor(ctx, &http.Client{Transport: http.DefaultTransport}, options, "sqli-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(ctx, moduleCtx, plan, executor)
}

func TestSQLiActiveConfirmsReproducibleBooleanDifference(t *testing.T) {
	var requests atomic.Int32
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requests.Add(1)
		value := r.URL.Query().Get("id")
		body := "rows"
		if strings.Contains(value, "1=2") || strings.Contains(value, "1'='2") {
			body = "empty"
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body + "\nrequest_id=" + strconv.Itoa(int(count))))
	}), 0)
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.Baseline == nil || len(result.Evidence.TestExchanges) < 4 || !result.Evidence.MinimumProofReached {
		t.Fatalf("incomplete SQLi evidence: %+v", result.Evidence)
	}
	if len(result.Findings) != 1 || result.Findings[0].Parameter != "id" {
		t.Fatalf("expected finding tied to id parameter: %+v", result.Findings)
	}
	if result.RequestCount < 6 || result.ResponseCount < 6 {
		t.Fatalf("expected baseline, controls and reproduction exchanges: requests=%d responses=%d", result.RequestCount, result.ResponseCount)
	}
}

func TestSQLiActiveDoesNotConfirmFunctionallyIdenticalEndpoint(t *testing.T) {
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("same response"))
	}), 0)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestSQLiActiveTreatsDynamicEndpointAsNotConfirmed(t *testing.T) {
	var requests atomic.Int32
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requests.Add(1)
		_, _ = w.Write([]byte("same response request_id=" + strconv.Itoa(int(id))))
	}), 0)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected dynamic identical endpoint to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestSQLiActiveTreatsSlowHealthyEndpointAsNotConfirmed(t *testing.T) {
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte("same slow response"))
	}), 0)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected slow healthy endpoint to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestSQLiActiveConfirmsStatisticalTimeBasedDifference(t *testing.T) {
	options := models.AuditOptions{
		ActiveMaxRequestsPerTest:            48,
		ActiveMaxResponseBytes:              16 * 1024,
		ActiveMaxRepetitions:                3,
		ActiveSQLiTimingEnabled:             true,
		ActiveSQLiTimingDelayMillis:         200,
		ActiveSQLiTimingBaselineSamples:     2,
		ActiveSQLiTimingControlSamples:      2,
		ActiveSQLiTimingProbeSamples:        2,
		ActiveSQLiTimingReproductionSamples: 1,
	}
	result := runSQLiActiveWithOptions(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "SLEEP(0.2)") {
			time.Sleep(150 * time.Millisecond)
		}
		_, _ = w.Write([]byte("stable response"))
	}), 0, options)
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected time-based CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.Timing == nil || !result.Evidence.Timing.Significant {
		t.Fatalf("missing statistical timing evidence: %+v", result.Evidence)
	}
	timing := result.Evidence.Timing
	if len(timing.BaselineMillis) != 2 || len(timing.ControlMillis) != 2 || len(timing.ProbeMillis) != 2 || len(timing.ReproductionMillis) != 1 {
		t.Fatalf("unexpected timing sample counts: %+v", timing)
	}
	if timing.ProbeMedianMillis <= timing.ControlMedianMillis || timing.ThresholdMillis <= 0 || timing.ReproductionAboveThreshold != 1 {
		t.Fatalf("invalid timing statistics: %+v", timing)
	}
}

func TestSQLiActiveTreatsTimingVarianceAsInconclusive(t *testing.T) {
	var timingRequests atomic.Int32
	options := models.AuditOptions{
		ActiveMaxRequestsPerTest:            48,
		ActiveMaxResponseBytes:              16 * 1024,
		ActiveMaxRepetitions:                3,
		ActiveSQLiTimingEnabled:             true,
		ActiveSQLiTimingDelayMillis:         200,
		ActiveSQLiTimingBaselineSamples:     2,
		ActiveSQLiTimingControlSamples:      2,
		ActiveSQLiTimingProbeSamples:        2,
		ActiveSQLiTimingReproductionSamples: 1,
	}
	result := runSQLiActiveWithOptions(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("id"), "SLEEP(") && timingRequests.Add(1)%2 == 0 {
			time.Sleep(600 * time.Millisecond)
		}
		_, _ = w.Write([]byte("stable response"))
	}), 0, options)
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for high timing variance, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.Timing == nil || result.Evidence.Timing.Significant {
		t.Fatalf("unstable timing produced a confirmed-looking evidence: %+v", result.Evidence)
	}
}

func TestSQLiActiveDoesNotConfirmNaturallySlowEndpointWithTiming(t *testing.T) {
	options := models.AuditOptions{
		ActiveMaxRequestsPerTest:            48,
		ActiveMaxResponseBytes:              16 * 1024,
		ActiveMaxRepetitions:                3,
		ActiveSQLiTimingEnabled:             true,
		ActiveSQLiTimingDelayMillis:         200,
		ActiveSQLiTimingBaselineSamples:     2,
		ActiveSQLiTimingControlSamples:      2,
		ActiveSQLiTimingProbeSamples:        2,
		ActiveSQLiTimingReproductionSamples: 1,
	}
	result := runSQLiActiveWithOptions(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte("same slow response"))
	}), 0, options)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected naturally slow endpoint to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestSQLiActiveDoesNotConfirmGenericServerError(t *testing.T) {
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}), 0)
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for generic HTTP 500, got %s: %s", result.Status, result.Reason)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("generic HTTP 500 produced a finding: %+v", result.Findings)
	}
}

func TestSQLiActiveTimeoutIsNotNotConfirmed(t *testing.T) {
	result := runSQLiActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
			_, _ = w.Write([]byte("late"))
		}
	}), 30*time.Millisecond)
	if result.Status != models.ActiveTestTimeout {
		t.Fatalf("expected TIMEOUT, got %s: %s", result.Status, result.Reason)
	}
}
