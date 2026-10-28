// Package storage — store en mémoire thread-safe V2.
// Pour migrer vers PostgreSQL : remplacer les méthodes par des requêtes SQL.
package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

type Store struct {
	mu           sync.RWMutex
	audits       map[string]*models.AuditRun
	events       map[string][]*models.ScanEvent
	preChecks    map[string]*models.PreCheckResult
	networks     map[string]*models.NetworkResult
	reconResults map[string]*models.ReconResult
	crawlResults map[string]*models.CrawlResult
	fingerprints map[string]*models.FingerprintResult
	reports      map[string]*models.AuditReport
	activeTests  map[string][]*models.ActiveTest
	activeByID   map[string]*models.ActiveTest
	activeSum    map[string]*models.ActivePhaseSummary
	assets       map[string][]*models.Asset   // clé = audit_run_id
	findings     map[string][]*models.Finding // clé = audit_run_id
}

func New() *Store {
	return &Store{
		audits:       make(map[string]*models.AuditRun),
		events:       make(map[string][]*models.ScanEvent),
		preChecks:    make(map[string]*models.PreCheckResult),
		networks:     make(map[string]*models.NetworkResult),
		reconResults: make(map[string]*models.ReconResult),
		crawlResults: make(map[string]*models.CrawlResult),
		fingerprints: make(map[string]*models.FingerprintResult),
		reports:      make(map[string]*models.AuditReport),
		activeTests:  make(map[string][]*models.ActiveTest),
		activeByID:   make(map[string]*models.ActiveTest),
		activeSum:    make(map[string]*models.ActivePhaseSummary),
		assets:       make(map[string][]*models.Asset),
		findings:     make(map[string][]*models.Finding),
	}
}

// ─── AuditRun ──────────────────────────────────────────────────────────────

func (s *Store) SaveAudit(a *models.AuditRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits[a.ID] = a
}

func (s *Store) GetAudit(id string) (*models.AuditRun, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.audits[id]
	if !ok {
		return nil, fmt.Errorf("audit %s not found", id)
	}
	return a, nil
}

func (s *Store) ListAudits() []*models.AuditRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.AuditRun, 0, len(s.audits))
	for _, a := range s.audits {
		list = append(list, a)
	}
	return list
}

func (s *Store) UpdateAuditStatus(id string, status models.AuditStatus, phase models.Phase) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.audits[id]
	if !ok {
		return fmt.Errorf("audit %s not found", id)
	}
	a.Status = status
	a.Phase = phase
	return nil
}

func (s *Store) MarkAuditFinished(id string, status models.AuditStatus, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.audits[id]
	if !ok {
		return fmt.Errorf("audit %s not found", id)
	}
	a.Status = status
	a.Phase = models.PhaseIdle
	a.Error = errMsg
	now := time.Now()
	a.FinishedAt = &now
	return nil
}

// ─── ScanEvent ─────────────────────────────────────────────────────────────

func (s *Store) AppendEvent(e *models.ScanEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[e.AuditRunID] = append(s.events[e.AuditRunID], e)
}

func (s *Store) GetEvents(auditRunID string) []*models.ScanEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	evts := s.events[auditRunID]
	result := make([]*models.ScanEvent, len(evts))
	copy(result, evts)
	return result
}

// ─── PreCheckResult ────────────────────────────────────────────────────────

func (s *Store) SavePreCheck(r *models.PreCheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preChecks[r.AuditRunID] = r
}

func (s *Store) GetPreCheck(auditRunID string) (*models.PreCheckResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.preChecks[auditRunID]
	return r, ok
}

func (s *Store) SaveNetwork(r *models.NetworkResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.networks[r.AuditRunID] = r
}

func (s *Store) GetNetwork(auditRunID string) (*models.NetworkResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.networks[auditRunID]
	return r, ok
}

// ─── ReconResult ───────────────────────────────────────────────────────────

func (s *Store) SaveRecon(r *models.ReconResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconResults[r.AuditRunID] = r
}

func (s *Store) GetRecon(auditRunID string) (*models.ReconResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reconResults[auditRunID]
	return r, ok
}

// ─── CrawlResult ───────────────────────────────────────────────────────────

func (s *Store) SaveCrawl(r *models.CrawlResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crawlResults[r.AuditRunID] = r
}

func (s *Store) GetCrawl(auditRunID string) (*models.CrawlResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.crawlResults[auditRunID]
	return r, ok
}

// ─── FingerprintResult ─────────────────────────────────────────────────────

func (s *Store) SaveFingerprint(r *models.FingerprintResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fingerprints[r.AuditRunID] = r
}

func (s *Store) GetFingerprint(auditRunID string) (*models.FingerprintResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.fingerprints[auditRunID]
	return r, ok
}

func (s *Store) SaveReport(r *models.AuditReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[r.AuditRunID] = r
}

func (s *Store) GetReport(auditRunID string) (*models.AuditReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.reports[auditRunID]
	return r, ok
}

// ─── Assets ────────────────────────────────────────────────────────────────

func (s *Store) AppendAsset(a *models.Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[a.AuditRunID] = append(s.assets[a.AuditRunID], a)
}

func (s *Store) GetAssets(auditRunID string) []*models.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.assets[auditRunID]
	result := make([]*models.Asset, len(list))
	for i, asset := range list {
		snapshot := *asset
		result[i] = &snapshot
	}
	return result
}

func (s *Store) MarkAssetTested(auditRunID, assetID string, testedAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, asset := range s.assets[auditRunID] {
		if asset.ID == assetID {
			t := testedAt
			asset.TestedAt = &t
			return true
		}
	}
	return false
}

// ─── Findings ──────────────────────────────────────────────────────────────

func (s *Store) AppendFinding(f *models.Finding) *models.Finding {
	if f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeFindingBeforeStore(f)
	findings := s.findings[f.AuditRunID]
	exactKey := findingExactKey(f)
	correlationKey := findingCorrelationKey(f)
	aggregateKey := ""
	if isAggregateableFinding(f) {
		aggregateKey = aggregateFindingKey(f)
	}
	for _, existing := range findings {
		if existing == nil {
			continue
		}
		if (exactKey != "" && findingExactKey(existing) == exactKey) || (correlationKey != "||||" && findingCorrelationKey(existing) == correlationKey) || (aggregateKey != "" && isAggregateableFinding(existing) && aggregateFindingKey(existing) == aggregateKey) {
			mergeFinding(existing, f)
			return existing
		}
	}
	s.findings[f.AuditRunID] = append(findings, f)
	return f
}

func (s *Store) GetFindings(auditRunID string) []*models.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := s.findings[auditRunID]
	result := make([]*models.Finding, len(list))
	for i, finding := range list {
		result[i] = cloneFinding(finding)
	}
	return result
}

func (s *Store) CountFindings(auditRunID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.findings[auditRunID])
}

// UpdateFindingStatus met à jour le statut de qualification d'un finding.
func (s *Store) UpdateFindingStatus(auditRunID, findingID string, status models.FindingStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.findings[auditRunID] {
		if f.ID == findingID {
			f.Status = status
			updatedAt := time.Now().UTC()
			f.UpdatedAt = &updatedAt
			return nil
		}
	}
	return fmt.Errorf("finding %s not found in audit %s", findingID, auditRunID)
}

// UpdateFindingReplay conserve le dernier état de validation sans écraser
// la qualification historique obtenue pendant le scan.
func (s *Store) UpdateFindingReplay(auditRunID, findingID string, state models.FindingReplayState, replayedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.findings[auditRunID] {
		if f.ID == findingID {
			f.ReplayState = state
			at := replayedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			f.LastReplayAt = &at
			updatedAt := time.Now().UTC()
			f.UpdatedAt = &updatedAt
			return nil
		}
	}
	return fmt.Errorf("finding %s not found in audit %s", findingID, auditRunID)
}

// GetFinding retourne un finding précis par ID.
func (s *Store) GetFinding(auditRunID, findingID string) (*models.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.findings[auditRunID] {
		if f.ID == findingID {
			return cloneFinding(f), nil
		}
	}
	return nil, fmt.Errorf("finding %s not found in audit %s", findingID, auditRunID)
}

func (s *Store) SaveActiveTest(t *models.ActiveTest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.QueuedAt.IsZero() {
		t.QueuedAt = time.Now().UTC()
	}
	if len(t.Steps) == 0 {
		t.Steps = append(t.Steps, models.ActiveTestStep{
			Status:    t.Status,
			Message:   "queued",
			Timestamp: t.QueuedAt,
		})
	}
	s.activeTests[t.AuditRunID] = append(s.activeTests[t.AuditRunID], t)
	s.activeByID[t.ID] = t
}

func (s *Store) TransitionActiveTest(testID string, status models.ActiveTestStatus, message string, at time.Time) (*models.ActiveTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.activeByID[testID]
	if !ok {
		return nil, false
	}
	transitionActiveTest(t, status, message, at)
	return cloneActiveTest(t), true
}

func (s *Store) IncrementActiveRequest(testID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.activeByID[testID]; ok {
		t.RequestCount++
	}
}

func (s *Store) IncrementActiveResponse(testID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.activeByID[testID]; ok {
		t.ResponseCount++
	}
}

func (s *Store) FinishActiveTest(testID string, status models.ActiveTestStatus, message string, findings int, at time.Time) (*models.ActiveTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.activeByID[testID]
	if !ok {
		return nil, false
	}
	t.FindingCount = findings
	t.StatusReason = message
	if message != "" && (status == models.ActiveTestFailed || status == models.ActiveTestTimeout || status == models.ActiveTestCancelled || status == models.ActiveTestUntestable) {
		t.Error = message
	}
	transitionActiveTest(t, status, message, at)
	if t.StartedAt != nil {
		t.DurationMillis = at.Sub(*t.StartedAt).Milliseconds()
	}
	finishedAt := at
	t.FinishedAt = &finishedAt
	return cloneActiveTest(t), true
}

// SaveActiveTestResult applique la conclusion explicite produite par un module.
// Le moteur ne recalcule pas le statut à partir du nombre de findings.
func (s *Store) SaveActiveTestResult(testID string, result *models.ActiveTestResult, at time.Time) (*models.ActiveTest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.activeByID[testID]
	if !ok || result == nil {
		return nil, false
	}
	if result.RequestCount > t.RequestCount {
		t.RequestCount = result.RequestCount
	}
	if result.ResponseCount > t.ResponseCount {
		t.ResponseCount = result.ResponseCount
	}
	t.Executed = result.Executed
	t.Analyzed = result.Analyzed
	t.MinimumConditionsMet = result.MinimumConditionsMet
	t.StatusReason = result.Reason
	t.LimitReached = result.LimitReached
	t.FindingCount = 0
	t.FindingIDs = t.FindingIDs[:0]
	seenFindingIDs := make(map[string]struct{}, len(result.Findings))
	for _, finding := range result.Findings {
		if finding != nil && finding.ID != "" {
			if _, seen := seenFindingIDs[finding.ID]; seen {
				continue
			}
			seenFindingIDs[finding.ID] = struct{}{}
			t.FindingIDs = append(t.FindingIDs, finding.ID)
		}
	}
	t.FindingCount = len(t.FindingIDs)
	if result.Evidence != nil {
		t.Evidence = cloneActiveEvidence(result.Evidence)
	}
	if result.Status == models.ActiveTestFailed || result.Status == models.ActiveTestTimeout || result.Status == models.ActiveTestCancelled || result.Status == models.ActiveTestUntestable {
		t.Error = result.Reason
	}
	transitionActiveTest(t, result.Status, result.Reason, at)
	if t.StartedAt != nil {
		t.DurationMillis = at.Sub(*t.StartedAt).Milliseconds()
	}
	finishedAt := at
	t.FinishedAt = &finishedAt
	return cloneActiveTest(t), true
}

func (s *Store) FinishNonFinalActiveTests(auditRunID string, status models.ActiveTestStatus, message string, at time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, t := range s.activeTests[auditRunID] {
		if isFinalActiveStatus(t.Status) {
			continue
		}
		if message != "" {
			t.Error = message
		}
		transitionActiveTest(t, status, message, at)
		if t.StartedAt != nil {
			t.DurationMillis = at.Sub(*t.StartedAt).Milliseconds()
		}
		finishedAt := at
		t.FinishedAt = &finishedAt
		count++
	}
	return count
}

func (s *Store) GetActiveTests(auditRunID string) []*models.ActiveTest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tests := s.activeTests[auditRunID]
	result := make([]*models.ActiveTest, len(tests))
	for i, t := range tests {
		result[i] = cloneActiveTest(t)
	}
	return result
}

func (s *Store) GetActiveTestStats(auditRunID string) models.ActiveTestStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return activeTestStatsLocked(s.activeTests[auditRunID])
}

func (s *Store) SaveActiveSummary(summary *models.ActivePhaseSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeSum[summary.AuditRunID] = summary
}

func (s *Store) GetActiveSummary(auditRunID string) (*models.ActivePhaseSummary, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	summary, ok := s.activeSum[auditRunID]
	if !ok {
		return nil, false
	}
	snapshot := *summary
	snapshot.StatusCounts = copyActiveStatusMap(summary.StatusCounts)
	snapshot.TopErrors = append([]string(nil), summary.TopErrors...)
	return &snapshot, true
}

func (s *Store) BuildActiveSummary(auditRunID string, startedAt time.Time, finishedAt time.Time) *models.ActivePhaseSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tests := s.activeTests[auditRunID]
	stats := activeTestStatsLocked(tests)
	statusCounts := make(map[models.ActiveTestStatus]int, len(stats.ByFinalStatus))
	for status, count := range stats.ByFinalStatus {
		statusCounts[status] = count
	}
	var totalDuration int64
	errors := make(map[string]int)
	for _, t := range tests {
		totalDuration += t.DurationMillis
		if t.Error != "" {
			errors[t.Error]++
		}
	}
	avg := int64(0)
	if stats.Finalized > 0 {
		avg = totalDuration / int64(stats.Finalized)
	}
	return &models.ActivePhaseSummary{
		AuditRunID:         auditRunID,
		GeneratedTests:     stats.Total,
		FinalizedTests:     stats.Finalized,
		StartedTests:       stats.Started,
		TestsWithRequests:  stats.Total - stats.WithoutRequest,
		TestsWithResponses: stats.Total - stats.WithoutResponse,
		AnalyzedTests:      stats.Analyzed,
		TotalRequests:      stats.RequestsSent,
		TotalResponses:     stats.Responses,
		StatusCounts:       statusCounts,
		ModuleCounts:       stats.ByModule,
		DurationMillis:     finishedAt.Sub(startedAt).Milliseconds(),
		AverageTestMillis:  avg,
		NonFinalTests:      stats.NonFinal,
		TopErrors:          topErrors(errors, 5),
		GeneratedAt:        time.Now().UTC(),
	}
}

func transitionActiveTest(t *models.ActiveTest, status models.ActiveTestStatus, message string, at time.Time) {
	t.Status = status
	if status == models.ActiveTestStarted && t.StartedAt == nil {
		startedAt := at
		t.StartedAt = &startedAt
	}
	t.Steps = append(t.Steps, models.ActiveTestStep{
		Status:    status,
		Message:   message,
		Timestamp: at,
	})
}

func activeTestStatsLocked(tests []*models.ActiveTest) models.ActiveTestStats {
	stats := models.ActiveTestStats{
		Total:         len(tests),
		ByStatus:      make(map[models.ActiveTestStatus]int),
		ByFinalStatus: make(map[models.ActiveTestStatus]int),
		ByModule:      make(map[string]int),
	}
	for _, t := range tests {
		stats.ByModule[t.Module]++
		stats.ByStatus[t.Status]++
		stats.RequestsSent += t.RequestCount
		stats.Responses += t.ResponseCount
		if t.StartedAt != nil {
			stats.Started++
		}
		if t.Analyzed {
			stats.Analyzed++
		}
		if t.RequestCount == 0 {
			stats.WithoutRequest++
		}
		if t.ResponseCount == 0 {
			stats.WithoutResponse++
		}
		if isFinalActiveStatus(t.Status) {
			stats.Finalized++
			stats.ByFinalStatus[t.Status]++
		} else {
			stats.NonFinal++
			if t.Status == models.ActiveTestQueued {
				stats.Queued++
			} else {
				stats.Running++
			}
		}
	}
	if stats.Total > 0 {
		stats.Progress = float64(stats.Finalized) / float64(stats.Total)
	}
	return stats
}

func isFinalActiveStatus(status models.ActiveTestStatus) bool {
	switch status {
	case models.ActiveTestConfirmed,
		models.ActiveTestNotConfirmed,
		models.ActiveTestFalsePositive,
		models.ActiveTestInconclusive,
		models.ActiveTestFailed,
		models.ActiveTestTimeout,
		models.ActiveTestUntestable,
		models.ActiveTestSkipped,
		models.ActiveTestCancelled:
		return true
	default:
		return false
	}
}

func cloneActiveTest(t *models.ActiveTest) *models.ActiveTest {
	if t == nil {
		return nil
	}
	snapshot := *t
	snapshot.Steps = append([]models.ActiveTestStep(nil), t.Steps...)
	snapshot.FindingIDs = append([]string(nil), t.FindingIDs...)
	snapshot.EntryPoint = cloneEntryPoint(t.EntryPoint)
	snapshot.Evidence = cloneActiveEvidence(t.Evidence)
	if t.StartedAt != nil {
		startedAt := *t.StartedAt
		snapshot.StartedAt = &startedAt
	}
	if t.FinishedAt != nil {
		finishedAt := *t.FinishedAt
		snapshot.FinishedAt = &finishedAt
	}
	return &snapshot
}

func cloneEntryPoint(entry *models.EntryPoint) *models.EntryPoint {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
	return &copyEntry
}

func cloneActiveEvidence(evidence *models.ActiveEvidence) *models.ActiveEvidence {
	if evidence == nil {
		return nil
	}
	copyEvidence := *evidence
	if evidence.Baseline != nil {
		baseline := *evidence.Baseline
		baseline.Exchanges = cloneExchanges(evidence.Baseline.Exchanges)
		copyEvidence.Baseline = &baseline
	}
	copyEvidence.TestExchanges = cloneExchanges(evidence.TestExchanges)
	copyEvidence.Differences = append([]models.ResponseDifference(nil), evidence.Differences...)
	copyEvidence.RedirectChain = append([]string(nil), evidence.RedirectChain...)
	if evidence.Browser != nil {
		browserEvidence := *evidence.Browser
		browserEvidence.Navigations = append([]string(nil), evidence.Browser.Navigations...)
		browserEvidence.BlockedURLs = append([]string(nil), evidence.Browser.BlockedURLs...)
		browserEvidence.Events = append([]models.BrowserEventEvidence(nil), evidence.Browser.Events...)
		copyEvidence.Browser = &browserEvidence
	}
	return &copyEvidence
}

func cloneExchanges(exchanges []models.HTTPExchange) []models.HTTPExchange {
	result := make([]models.HTTPExchange, len(exchanges))
	for i, exchange := range exchanges {
		result[i] = exchange
		result[i].Request.Headers = copyStringsMap(exchange.Request.Headers)
		if exchange.Response != nil {
			response := *exchange.Response
			response.Headers = copyStringsMap(exchange.Response.Headers)
			response.Redirects = append([]string(nil), exchange.Response.Redirects...)
			result[i].Response = &response
		}
	}
	return result
}

func copyStringsMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func copyActiveStatusMap(src map[models.ActiveTestStatus]int) map[models.ActiveTestStatus]int {
	if src == nil {
		return nil
	}
	dst := make(map[models.ActiveTestStatus]int, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func topErrors(errors map[string]int, limit int) []string {
	result := make([]string, 0, len(errors))
	for errText := range errors {
		result = append(result, errText)
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if errors[result[j]] > errors[result[i]] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
