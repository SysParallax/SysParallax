package traversal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
)

func runTraversalActive(t *testing.T, handler http.Handler, options models.AuditOptions) *models.ActiveTestResult {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	asset := &models.Asset{ID: "asset-traversal", AuditRunID: "audit-traversal", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "?file=home.txt", Params: []string{"file"}}
	if options.ActiveMaxRequestsPerTest == 0 {
		options.ActiveMaxRequestsPerTest = 32
	}
	if options.ActiveMaxResponseBytes == 0 {
		options.ActiveMaxResponseBytes = 32 * 1024
	}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-traversal", Asset: asset, Options: options}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "file", Location: models.EntryPointQuery, OriginalValue: "home.txt"}}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "traversal-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(context.Background(), moduleCtx, plan, executor)
}

func TestTraversalConfirmsSpecificProofMarker(t *testing.T) {
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		switch {
		case strings.Contains(value, "invalid_path"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		case strings.Contains(value, "etc/passwd"):
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
		default:
			_, _ = w.Write([]byte("normal resource"))
		}
	}), models.AuditOptions{})
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !result.Evidence.MinimumProofReached || !strings.Contains(result.Evidence.Expected, "root:x:0:0") {
		t.Fatalf("missing traversal proof evidence: %+v", result.Evidence)
	}
	if len(result.Findings) != 1 || result.Findings[0].Parameter != "file" {
		t.Fatalf("expected finding tied to file parameter: %+v", result.Findings)
	}
}

func TestTraversalDoesNotConfirmHTTP200OrSizeDifference(t *testing.T) {
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "etc/passwd") {
			_, _ = w.Write([]byte(strings.Repeat("generic content ", 100)))
			return
		}
		_, _ = w.Write([]byte("normal"))
	}), models.AuditOptions{})
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected NOT_CONFIRMED without marker, got %s: %s", result.Status, result.Reason)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("HTTP 200/size difference produced a finding: %+v", result.Findings)
	}
}

func TestTraversalDoesNotConfirmWhenMarkerIsAlreadyInControl(t *testing.T) {
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "root:x:0:0 control content")
	}), models.AuditOptions{})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE with non-discriminating control, got %s: %s", result.Status, result.Reason)
	}
}

func TestTraversalDoesNotConfirmNonReproducibleMarker(t *testing.T) {
	var traversalResponses atomic.Int32
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		if strings.Contains(value, "etc/passwd") {
			if traversalResponses.Add(1) == 1 {
				_, _ = fmt.Fprint(w, "root:x:0:0")
			} else {
				_, _ = fmt.Fprint(w, "generic response")
			}
			return
		}
		_, _ = fmt.Fprint(w, "normal")
	}), models.AuditOptions{})
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for non-reproducible marker, got %s: %s", result.Status, result.Reason)
	}
}

func TestTraversalSupportsConfiguredProofMarker(t *testing.T) {
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "etc/passwd") {
			_, _ = fmt.Fprint(w, "AUDITCORE-TEST-FILE")
			return
		}
		_, _ = fmt.Fprint(w, "normal")
	}), models.AuditOptions{ActiveTraversalProofMarker: "AUDITCORE-TEST-FILE"})
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected configured marker CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestTraversalSupportsConfiguredProofResourceAndLFIType(t *testing.T) {
	result := runTraversalActive(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "audit-proof.txt") {
			_, _ = fmt.Fprint(w, "AUDITCORE-CONFIGURED-FILE")
			return
		}
		_, _ = fmt.Fprint(w, "normal resource")
	}), models.AuditOptions{
		ActiveTraversalProofPath:         "/tmp/audit-proof.txt",
		ActiveTraversalProofMarker:       "AUDITCORE-CONFIGURED-FILE",
		ActiveTraversalProofPlatform:     "unix",
		ActiveTraversalProofResourceType: "lfi",
	})
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected configured LFI CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.Operation != "local-file-inclusion" || len(result.Findings) != 1 || result.Findings[0].Type != "local-file-inclusion" {
		t.Fatalf("configured resource type was not traced: evidence=%+v findings=%+v", result.Evidence, result.Findings)
	}
}

func TestTraversalPayloadSelectionIsBoundedByPlatform(t *testing.T) {
	unixPayloads := traversalPayloadsFor(models.AuditOptions{ActiveTraversalProofPlatform: "unix"})
	windowsPayloads := traversalPayloadsFor(models.AuditOptions{ActiveTraversalProofPlatform: "windows"})
	if len(unixPayloads) == 0 || len(windowsPayloads) == 0 || len(unixPayloads) > 8 || len(windowsPayloads) > 4 {
		t.Fatalf("unexpected platform payload budgets: unix=%d windows=%d", len(unixPayloads), len(windowsPayloads))
	}
	for _, payload := range unixPayloads {
		if strings.Contains(payload, "win.ini") {
			t.Fatalf("Windows proof leaked into Unix selection: %q", payload)
		}
	}
	for _, payload := range windowsPayloads {
		if !strings.Contains(payload, "win.ini") && !strings.Contains(payload, "%5C") {
			t.Fatalf("Windows canonicalization variant missing: %q", payload)
		}
	}
}
