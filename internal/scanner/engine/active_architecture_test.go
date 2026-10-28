package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/storage"
)

type structuredTestModule struct {
	name   string
	result func(*models.ModuleContext, models.ActiveTestPlan, *active.Executor) *models.ActiveTestResult
}

func (m structuredTestModule) Name() string { return m.name }

func (m structuredTestModule) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.name, ctx, findings)
}

func (m structuredTestModule) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	return m.result(moduleCtx, plan, executor)
}

func TestStructuredResultIsStoredAndLinkedToEntryPoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("stable"))
	}))
	defer server.Close()

	store := storage.New()
	store.AppendAsset(&models.Asset{ID: "asset-structured", AuditRunID: "audit-structured", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "?id=1", Params: []string{"id"}})
	store.AppendFinding(&models.Finding{ID: "passive-source", AuditRunID: "audit-structured", AssetID: "asset-structured", Type: "sqli-suspected", Parameter: "id"})
	module := structuredTestModule{name: "sqli-detection", result: func(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
		baseline, _ := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
		_, _ = executor.DoBaseline(baseline)
		probe, _ := http.NewRequest(http.MethodGet, moduleCtx.Asset.URL+"&probe=1", nil)
		_, _ = executor.Do("test", "probe", probe)
		return &models.ActiveTestResult{Status: models.ActiveTestNotConfirmed, Reason: "réponse stable", RequestCount: executor.Requests(), ResponseCount: executor.Responses(), Executed: true, Analyzed: true, MinimumConditionsMet: true}
	}}
	engine := New(store, models.AuditOptions{ActiveTestTimeoutSeconds: 2, ActiveMaxRequestsPerTest: 4})
	engine.RegisterActive(module)
	if err := engine.RunModulesContext(context.Background(), "audit-structured", models.PhaseActive, nil, func(models.Phase, models.EventLevel, string, string) {}); err != nil {
		t.Fatalf("active phase failed: %v", err)
	}
	tests := store.GetActiveTests("audit-structured")
	if len(tests) != 1 || tests[0].Status != models.ActiveTestNotConfirmed {
		t.Fatalf("unexpected active test: %+v", tests)
	}
	if tests[0].EntryPoint == nil || tests[0].EntryPoint.Name != "id" || tests[0].SourceFindingID != "passive-source" || tests[0].Evidence == nil || tests[0].Evidence.Baseline == nil {
		t.Fatalf("structured trace is incomplete: %+v", tests[0])
	}
}

func TestActiveEngineRejectsNotConfirmedWithoutRequestOrProof(t *testing.T) {
	store := storage.New()
	store.AppendAsset(&models.Asset{ID: "asset-no-request", AuditRunID: "audit-no-request", Type: models.AssetEndpoint, Method: http.MethodGet, URL: "http://127.0.0.1:1/?id=1", Params: []string{"id"}})
	module := structuredTestModule{name: "xss-reflected", result: func(*models.ModuleContext, models.ActiveTestPlan, *active.Executor) *models.ActiveTestResult {
		return &models.ActiveTestResult{Status: models.ActiveTestNotConfirmed, Reason: "aucune probe", Executed: false}
	}}
	engine := New(store, models.AuditOptions{ActiveTestTimeoutSeconds: 2})
	engine.RegisterActive(module)
	if err := engine.RunModulesContext(context.Background(), "audit-no-request", models.PhaseActive, nil, func(models.Phase, models.EventLevel, string, string) {}); err != nil {
		t.Fatalf("active phase failed: %v", err)
	}
	tests := store.GetActiveTests("audit-no-request")
	if len(tests) != 1 || tests[0].Status != models.ActiveTestUntestable {
		t.Fatalf("expected UNTESTABLE without request, got %+v", tests)
	}

	store = storage.New()
	store.AppendAsset(&models.Asset{ID: "asset-no-proof", AuditRunID: "audit-no-proof", Type: models.AssetEndpoint, Method: http.MethodGet, URL: "http://127.0.0.1:1/?id=1", Params: []string{"id"}})
	module = structuredTestModule{name: "sqli-detection", result: func(*models.ModuleContext, models.ActiveTestPlan, *active.Executor) *models.ActiveTestResult {
		return &models.ActiveTestResult{Status: models.ActiveTestConfirmed, Reason: "HTTP 200", RequestCount: 1, ResponseCount: 1, Executed: true, Analyzed: true}
	}}
	engine = New(store, models.AuditOptions{ActiveTestTimeoutSeconds: 2})
	engine.RegisterActive(module)
	if err := engine.RunModulesContext(context.Background(), "audit-no-proof", models.PhaseActive, nil, func(models.Phase, models.EventLevel, string, string) {}); err != nil {
		t.Fatalf("active phase failed: %v", err)
	}
	tests = store.GetActiveTests("audit-no-proof")
	if len(tests) != 1 || tests[0].Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE without proof, got %+v", tests)
	}
}
