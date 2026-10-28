package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

type activeTraceModule struct {
	name string
}

func (m activeTraceModule) Name() string {
	return m.name
}

func (m activeTraceModule) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	resp, err := client.Get(ctx.Asset.URL)
	if err != nil {
		return &models.ModuleResult{Error: err}
	}
	defer resp.Body.Close()
	return &models.ModuleResult{
		Findings: []*models.Finding{{
			Type:        "active-proof",
			Title:       "Active proof",
			Severity:    models.SeverityMedium,
			Confidence:  models.ConfidenceHigh,
			Status:      models.FindingConfirmed,
			Description: "Confirmed by active trace test.",
			Module:      m.name,
		}},
	}
}

func TestRunActiveModulesRecordsTraceAndFinalStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := storage.New()
	store.AppendAsset(&models.Asset{
		ID:         "asset-1",
		AuditRunID: "audit-1",
		Type:       models.AssetEndpoint,
		Method:     "GET",
		URL:        server.URL,
	})

	e := New(store, models.AuditOptions{ActiveTestTimeoutSeconds: 5})
	e.Register(activeTraceModule{name: "active-proof"})

	err := e.RunModulesContext(context.Background(), "audit-1", models.PhaseActive, nil, func(models.Phase, models.EventLevel, string, string) {})
	if err != nil {
		t.Fatalf("run active modules: %v", err)
	}

	tests := store.GetActiveTests("audit-1")
	if len(tests) != 1 {
		t.Fatalf("expected one active test, got %d", len(tests))
	}
	test := tests[0]
	if test.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected confirmed active test, got %s", test.Status)
	}
	if test.RequestCount != 1 || test.ResponseCount != 1 {
		t.Fatalf("expected one request and response, got request=%d response=%d", test.RequestCount, test.ResponseCount)
	}
	if test.FindingCount != 1 {
		t.Fatalf("expected one finding, got %d", test.FindingCount)
	}

	wantSteps := map[models.ActiveTestStatus]bool{
		models.ActiveTestQueued:           true,
		models.ActiveTestStarted:          true,
		models.ActiveTestRequestSent:      true,
		models.ActiveTestResponseReceived: true,
		models.ActiveTestAnalyzing:        true,
		models.ActiveTestConfirmed:        true,
	}
	for _, step := range test.Steps {
		delete(wantSteps, step.Status)
	}
	if len(wantSteps) > 0 {
		t.Fatalf("missing lifecycle steps: %+v", wantSteps)
	}

	stats := store.GetActiveTestStats("audit-1")
	if stats.Finalized != 1 || stats.ByFinalStatus[models.ActiveTestConfirmed] != 1 || stats.Progress != 1 {
		t.Fatalf("unexpected active stats: %+v", stats)
	}
}
