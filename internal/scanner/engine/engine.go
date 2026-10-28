// Package engine dispatches passive and active scanner modules.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/storage"
	"github.com/google/uuid"
)

type Module interface {
	Name() string
	Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult
}

type Engine struct {
	store         *storage.Store
	modules       []Module
	activeModules []active.Module
	client        *http.Client
	options       models.AuditOptions
}

func New(store *storage.Store, options models.AuditOptions) *Engine {
	options = httpx.NormalizeOptions(options)
	return &Engine{
		store:   store,
		options: options,
		client:  httpx.NewClient(20*time.Second, options),
	}
}

func (e *Engine) Register(module Module) { e.modules = append(e.modules, module) }

func (e *Engine) RegisterActive(module active.Module) {
	e.activeModules = append(e.activeModules, module)
}

func (e *Engine) RunPassive(auditRunID string, fp *models.FingerprintResult, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	return e.RunModules(auditRunID, models.PhasePassive, fp, emitEvent)
}

func (e *Engine) RunModules(auditRunID string, phase models.Phase, fp *models.FingerprintResult, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	return e.RunModulesContext(context.Background(), auditRunID, phase, fp, emitEvent)
}

func (e *Engine) RunPassiveContext(ctx context.Context, auditRunID string, fp *models.FingerprintResult, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	return e.RunModulesContext(ctx, auditRunID, models.PhasePassive, fp, emitEvent)
}

func (e *Engine) RunModulesContext(ctx context.Context, auditRunID string, phase models.Phase, fp *models.FingerprintResult, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	assets := e.store.GetAssets(auditRunID)
	if len(assets) == 0 {
		precheck, ok := e.store.GetPreCheck(auditRunID)
		if !ok {
			return fmt.Errorf("aucun asset ni pre-check disponible")
		}
		assets = []*models.Asset{{ID: uuid.NewString(), AuditRunID: auditRunID, Type: models.AssetEndpoint, Method: http.MethodGet, URL: precheck.FinalURL, DiscoveredBy: "engine-fallback"}}
	}
	if phase == models.PhaseActive {
		return e.runActiveModulesContext(ctx, auditRunID, fp, assets, emitEvent)
	}

	for _, module := range e.modules {
		if err := ctx.Err(); err != nil {
			return err
		}
		emitEvent(phase, models.LevelInfo, fmt.Sprintf("Module %s - démarré sur %d assets", module.Name(), len(assets)), module.Name())
		findingsCount := 0
		for _, asset := range assets {
			if err := ctx.Err(); err != nil {
				return err
			}
			moduleCtx := &models.ModuleContext{AuditRunID: auditRunID, Asset: asset, Fingerprint: fp, Options: e.options}
			result := module.Run(moduleCtx, e.client)
			e.store.MarkAssetTested(auditRunID, asset.ID, time.Now())
			if result == nil || result.Error != nil {
				if result != nil && result.Error != nil {
					log.Printf("[engine] %s error on %s: %v", module.Name(), asset.URL, result.Error)
				}
				continue
			}
			for _, finding := range result.Findings {
				if finding == nil {
					continue
				}
				finding.ID = uuid.NewString()
				finding.AuditRunID = auditRunID
				finding.AssetID = asset.ID
				finding.Method = asset.Method
				finding.Module = module.Name()
				finding.Source = "passive"
				finding.CreatedAt = time.Now()
				incomingID := finding.ID
				canonical := e.store.AppendFinding(finding)
				if canonical != nil {
					finding.ID = canonical.ID
				}
				if canonical != nil && canonical.ID == incomingID {
					findingsCount++
				}
			}
		}
		level := models.LevelOK
		message := fmt.Sprintf("Module %s - aucun problème détecté", module.Name())
		if findingsCount > 0 {
			level = models.LevelWarn
			message = fmt.Sprintf("Module %s - %d finding(s) détecté(s)", module.Name(), findingsCount)
		}
		emitEvent(phase, level, message, module.Name())
	}
	return nil
}

type structuredQueueItem struct {
	id     string
	module active.Module
	asset  *models.Asset
	plan   models.ActiveTestPlan
}

func (e *Engine) runActiveModulesContext(ctx context.Context, auditRunID string, fp *models.FingerprintResult, assets []*models.Asset, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	if len(e.activeModules) == 0 {
		return e.runLegacyActiveModulesContext(ctx, auditRunID, fp, assets, emitEvent)
	}

	phaseCtx := ctx
	cancel := func() {}
	if e.options.ActivePhaseTimeoutSeconds > 0 {
		phaseCtx, cancel = context.WithTimeout(ctx, time.Duration(e.options.ActivePhaseTimeoutSeconds)*time.Second)
	}
	defer cancel()

	findings := e.store.GetFindings(auditRunID)
	budget := active.NewBudget(e.options)
	tests := e.queueStructuredActiveTests(auditRunID, fp, assets, findings)
	emitEvent(models.PhaseActive, models.LevelInfo, fmt.Sprintf("Tests actifs ciblés en file d'attente : %d test(s)", len(tests)), "active-trace")
	timeout := activeTestTimeout(e.options)

	for _, test := range tests {
		if err := phaseCtx.Err(); err != nil {
			status := models.ActiveTestCancelled
			if errors.Is(err, context.DeadlineExceeded) {
				status = models.ActiveTestTimeout
			}
			recovered := e.store.FinishNonFinalActiveTests(auditRunID, status, err.Error(), time.Now())
			emitEvent(models.PhaseActive, models.LevelWarn, fmt.Sprintf("Tests actifs interrompus : %d test(s) en %s", recovered, status), "active-trace")
			return err
		}

		e.store.TransitionActiveTest(test.id, models.ActiveTestStarted, "test ciblé récupéré par le worker active", time.Now())
		result, err := e.runStructuredActiveTest(phaseCtx, auditRunID, test, fp, budget, timeout)
		now := time.Now()
		if err != nil {
			status := models.ActiveTestFailed
			if errors.Is(err, context.DeadlineExceeded) {
				status = models.ActiveTestTimeout
			}
			if errors.Is(err, context.Canceled) {
				status = models.ActiveTestCancelled
			}
			e.store.FinishActiveTest(test.id, status, err.Error(), 0, now)
			continue
		}
		if result == nil {
			e.store.FinishActiveTest(test.id, models.ActiveTestFailed, "le module n'a retourné aucun résultat", 0, now)
			continue
		}
		normalizeActiveResult(result)
		for _, finding := range result.Findings {
			if finding == nil {
				continue
			}
			finding.ID = uuid.NewString()
			finding.AuditRunID = auditRunID
			finding.AssetID = test.asset.ID
			finding.Method = test.asset.Method
			finding.Module = test.module.Name()
			finding.Source = "active"
			finding.CreatedAt = now
			active.SanitizeFinding(finding, e.options)
			if canonical := e.store.AppendFinding(finding); canonical != nil {
				finding.ID = canonical.ID
			}
		}
		e.store.SaveActiveTestResult(test.id, result, now)
	}

	stats := e.store.GetActiveTestStats(auditRunID)
	emitEvent(models.PhaseActive, models.LevelOK,
		fmt.Sprintf("Tests actifs finalisés : %d/%d · confirmés %d · non confirmés %d · inconclusifs %d · erreurs %d · timeouts %d",
			stats.Finalized, stats.Total,
			stats.ByFinalStatus[models.ActiveTestConfirmed],
			stats.ByFinalStatus[models.ActiveTestNotConfirmed],
			stats.ByFinalStatus[models.ActiveTestInconclusive],
			stats.ByFinalStatus[models.ActiveTestFailed],
			stats.ByFinalStatus[models.ActiveTestTimeout]), "active-trace")
	return nil
}

func normalizeActiveResult(result *models.ActiveTestResult) {
	if result == nil {
		return
	}
	if result.RequestCount == 0 && result.Status == models.ActiveTestNotConfirmed {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucune requête envoyée : un test non confirmé exige une exécution réelle"
		result.Analyzed = false
		result.MinimumConditionsMet = false
	}
	if result.ResponseCount == 0 && result.Status != models.ActiveTestFailed && result.Status != models.ActiveTestTimeout && result.Status != models.ActiveTestCancelled && result.Status != models.ActiveTestUntestable && result.Status != models.ActiveTestSkipped {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "aucune réponse exploitable reçue"
		result.Analyzed = false
		result.MinimumConditionsMet = false
	}
	if result.Status == models.ActiveTestConfirmed && (result.Evidence == nil || !result.Evidence.MinimumProofReached) {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "preuve minimale insuffisante pour confirmer le finding"
		result.MinimumConditionsMet = false
	}
}

func (e *Engine) queueStructuredActiveTests(auditRunID string, fp *models.FingerprintResult, assets []*models.Asset, findings []*models.Finding) []structuredQueueItem {
	now := time.Now()
	var tests []structuredQueueItem
	for _, module := range e.activeModules {
		for _, asset := range assets {
			moduleCtx := &models.ModuleContext{AuditRunID: auditRunID, Asset: asset, Fingerprint: fp, Options: e.options}
			for _, plan := range module.Plan(moduleCtx, findings) {
				id := uuid.NewString()
				entry := plan.EntryPoint
				e.store.SaveActiveTest(&models.ActiveTest{
					ID: id, AuditRunID: auditRunID, AssetID: asset.ID, SourceFindingID: plan.SourceFindingID,
					Module: module.Name(), Method: asset.Method, URL: asset.URL, EntryPoint: &entry,
					AuthContext: authContextLabel(e.options),
					Status:      models.ActiveTestQueued, QueuedAt: now,
					Steps: []models.ActiveTestStep{{Status: models.ActiveTestQueued, Message: plan.Reason, Timestamp: now}},
				})
				tests = append(tests, structuredQueueItem{id: id, module: module, asset: asset, plan: plan})
			}
		}
	}
	return tests
}

func authContextLabel(options models.AuditOptions) string {
	if len(options.ActiveIDORIdentities) >= 2 {
		return "idor-identities"
	}
	if options.BearerToken != "" {
		return "bearer"
	}
	if options.BasicUsername != "" {
		return "basic"
	}
	if len(options.Cookies) > 0 {
		return "configured-cookies"
	}
	return "anonymous"
}

func (e *Engine) runStructuredActiveTest(parent context.Context, auditRunID string, test structuredQueueItem, fp *models.FingerprintResult, budget *active.Budget, timeout time.Duration) (*models.ActiveTestResult, error) {
	testCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	moduleCtx := &models.ModuleContext{AuditRunID: auditRunID, Asset: test.asset, Fingerprint: fp, Options: e.options}
	step := func(status models.ActiveTestStatus, message string) {
		switch status {
		case models.ActiveTestBaselineRequestSent, models.ActiveTestTestRequestSent:
			e.store.IncrementActiveRequest(test.id)
		case models.ActiveTestBaselineResponseReceived, models.ActiveTestTestResponseReceived:
			e.store.IncrementActiveResponse(test.id)
		}
		e.store.TransitionActiveTest(test.id, status, message, time.Now())
	}
	executor := active.NewExecutor(testCtx, e.client, e.options, test.id, test.module.Name(), test.plan.EntryPoint, budget, step)
	resultCh := make(chan *models.ActiveTestResult, 1)
	go func() { resultCh <- test.module.RunActive(testCtx, moduleCtx, test.plan, executor) }()
	select {
	case <-testCtx.Done():
		return nil, testCtx.Err()
	case result := <-resultCh:
		e.store.MarkAssetTested(auditRunID, test.asset.ID, time.Now())
		e.store.TransitionActiveTest(test.id, models.ActiveTestAnalyzing, "conclusion structurée du module", time.Now())
		if result != nil {
			result.RequestCount = executor.Requests()
			result.ResponseCount = executor.Responses()
			result.Executed = result.RequestCount > 0
			result.Analyzed = result.ResponseCount > 0
			if result.Evidence == nil && result.RequestCount > 0 {
				result.Evidence = executor.EvidenceFor(result)
			}
		}
		return result, nil
	}
}

func activeTestTimeout(options models.AuditOptions) time.Duration {
	if options.ActiveTestTimeoutSeconds > 0 {
		return time.Duration(options.ActiveTestTimeoutSeconds) * time.Second
	}
	return 60 * time.Second
}

// Legacy path is intentionally limited to compatibility with third-party test modules.
type legacyQueueItem struct {
	id     string
	module Module
	asset  *models.Asset
}

func (e *Engine) runLegacyActiveModulesContext(ctx context.Context, auditRunID string, fp *models.FingerprintResult, assets []*models.Asset, emitEvent func(models.Phase, models.EventLevel, string, string)) error {
	tests := e.queueLegacyActiveTests(auditRunID, assets)
	emitEvent(models.PhaseActive, models.LevelInfo, fmt.Sprintf("Tests actifs historiques en file : %d", len(tests)), "active-trace")
	for _, test := range tests {
		if err := ctx.Err(); err != nil {
			e.store.FinishNonFinalActiveTests(auditRunID, models.ActiveTestCancelled, err.Error(), time.Now())
			return err
		}
		e.store.TransitionActiveTest(test.id, models.ActiveTestStarted, "module historique", time.Now())
		moduleCtx := &models.ModuleContext{AuditRunID: auditRunID, Asset: test.asset, Fingerprint: fp, Options: e.options}
		result := test.module.Run(moduleCtx, e.instrumentedClient(test.id))
		if result == nil || result.Error != nil {
			message := "résultat vide du module historique"
			if result != nil && result.Error != nil {
				message = result.Error.Error()
			}
			e.store.FinishActiveTest(test.id, models.ActiveTestFailed, message, 0, time.Now())
			continue
		}
		e.store.TransitionActiveTest(test.id, models.ActiveTestAnalyzing, "analyse historique", time.Now())
		for _, finding := range result.Findings {
			if finding == nil {
				continue
			}
			finding.ID = uuid.NewString()
			finding.AuditRunID = auditRunID
			finding.AssetID = test.asset.ID
			finding.Method = test.asset.Method
			finding.Source = "active"
			finding.CreatedAt = time.Now()
			if canonical := e.store.AppendFinding(finding); canonical != nil {
				finding.ID = canonical.ID
			}
		}
		status := models.ActiveTestNotConfirmed
		if len(result.Findings) > 0 {
			status = models.ActiveTestConfirmed
		}
		e.store.FinishActiveTest(test.id, status, "compatibilité module historique", len(result.Findings), time.Now())
	}
	return nil
}

func (e *Engine) queueLegacyActiveTests(auditRunID string, assets []*models.Asset) []legacyQueueItem {
	now := time.Now()
	var tests []legacyQueueItem
	for _, module := range e.modules {
		for _, asset := range assets {
			id := uuid.NewString()
			e.store.SaveActiveTest(&models.ActiveTest{ID: id, AuditRunID: auditRunID, AssetID: asset.ID, Module: module.Name(), Method: asset.Method, URL: asset.URL, Status: models.ActiveTestQueued, QueuedAt: now})
			tests = append(tests, legacyQueueItem{id: id, module: module, asset: asset})
		}
	}
	return tests
}

func (e *Engine) instrumentedClient(testID string) *http.Client {
	client := *e.client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = activeTraceTransport{base: transport, store: e.store, testID: testID}
	return &client
}

type activeTraceTransport struct {
	base   http.RoundTripper
	store  *storage.Store
	testID string
}

func (t activeTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.store.IncrementActiveRequest(t.testID)
	t.store.TransitionActiveTest(t.testID, models.ActiveTestRequestSent, req.Method+" "+req.URL.String(), time.Now())
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		t.store.IncrementActiveResponse(t.testID)
		t.store.TransitionActiveTest(t.testID, models.ActiveTestResponseReceived, fmt.Sprintf("HTTP %d", resp.StatusCode), time.Now())
	}
	return resp, err
}
