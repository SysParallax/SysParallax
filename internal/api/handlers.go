package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/audit"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/report"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/replay"
	"github.com/auditcore/auditcore/internal/storage"
	"github.com/go-chi/chi/v5"
)

// Handler regroupe les dépendances des handlers HTTP.
type Handler struct {
	store  *storage.Store
	runner *audit.Runner
}

func New(store *storage.Store, runner *audit.Runner) *Handler {
	return &Handler{store: store, runner: runner}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ─── GET /api/health ──────────────────────────────────────────────────────

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"time":    time.Now().Format(time.RFC3339),
		"version": "2.0.0",
	})
}

// ─── POST /api/audits ─────────────────────────────────────────────────────

func (h *Handler) CreateAudit(w http.ResponseWriter, r *http.Request) {
	var req models.CreateAuditRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	if req.TargetURL == "" {
		writeError(w, http.StatusBadRequest, "target_url requis")
		return
	}
	a, err := h.runner.CreateAndRun(req.TargetURL, req.Options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

// ─── GET /api/audits ──────────────────────────────────────────────────────

func (h *Handler) ListAudits(w http.ResponseWriter, r *http.Request) {
	audits := h.store.ListAudits()
	// Tri décroissant par StartedAt
	for i := 0; i < len(audits); i++ {
		for j := i + 1; j < len(audits); j++ {
			if audits[j].StartedAt.After(audits[i].StartedAt) {
				audits[i], audits[j] = audits[j], audits[i]
			}
		}
	}
	publicAudits := make([]*models.AuditRun, 0, len(audits))
	for _, audit := range audits {
		publicAudits = append(publicAudits, sanitizedAudit(audit))
	}
	writeJSON(w, http.StatusOK, publicAudits)
}

// ─── GET /api/audits/:id ─────────────────────────────────────────────────

func (h *Handler) GetAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, err := h.store.GetAudit(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	publicAudit := sanitizedAudit(a)
	detail := models.AuditDetail{
		Audit:        *publicAudit,
		EventCount:   len(h.store.GetEvents(id)),
		FindingCount: h.store.CountFindings(id),
	}
	if pc, ok := h.store.GetPreCheck(id); ok {
		detail.PreCheck = pc
	}
	if nr, ok := h.store.GetNetwork(id); ok {
		detail.Network = nr
	}
	if rc, ok := h.store.GetRecon(id); ok {
		detail.Recon = rc
	}
	if cr, ok := h.store.GetCrawl(id); ok {
		detail.Crawl = cr
	}
	if fp, ok := h.store.GetFingerprint(id); ok {
		detail.Fingerprint = fp
	}
	if report, ok := h.store.GetReport(id); ok {
		detail.Report = report
	}
	activeStats := h.store.GetActiveTestStats(id)
	if activeStats.Total > 0 {
		detail.ActiveStats = &activeStats
	}
	if activeSummary, ok := h.store.GetActiveSummary(id); ok {
		detail.ActiveSummary = activeSummary
	}
	writeJSON(w, http.StatusOK, detail)
}

func sanitizedAudit(audit *models.AuditRun) *models.AuditRun {
	if audit == nil {
		return nil
	}
	publicAudit := *audit
	publicAudit.Options.BearerToken = ""
	publicAudit.Options.BasicPassword = ""
	publicAudit.Options.BasicUsername = ""
	publicAudit.Options.Headers = nil
	publicAudit.Options.Cookies = nil
	publicAudit.Options.ActiveSSRFCallbackURL = active.RedactURL(publicAudit.Options.ActiveSSRFCallbackURL, publicAudit.Options)
	publicAudit.Options.ActiveSSRFCallbackCheckURL = active.RedactURL(publicAudit.Options.ActiveSSRFCallbackCheckURL, publicAudit.Options)
	publicAudit.Options.ActiveIDOROwnerResource = active.RedactURL(publicAudit.Options.ActiveIDOROwnerResource, publicAudit.Options)
	publicAudit.Options.ActiveIDORNonOwnerResource = active.RedactURL(publicAudit.Options.ActiveIDORNonOwnerResource, publicAudit.Options)
	for i := range publicAudit.Options.ActiveIDORIdentities {
		publicAudit.Options.ActiveIDORIdentities[i].Headers = nil
		publicAudit.Options.ActiveIDORIdentities[i].Cookies = nil
		publicAudit.Options.ActiveIDORIdentities[i].BearerToken = ""
		publicAudit.Options.ActiveIDORIdentities[i].BasicUsername = ""
		publicAudit.Options.ActiveIDORIdentities[i].BasicPassword = ""
	}
	return &publicAudit
}

// ─── GET /api/audits/:id/events ──────────────────────────────────────────
// Supporte ?since=<RFC3339Nano> pour polling incrémental.

func (h *Handler) GetEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	events := h.store.GetEvents(id)
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if since, err := time.Parse(time.RFC3339Nano, sinceStr); err == nil {
			var filtered []*models.ScanEvent
			for _, e := range events {
				if e.Timestamp.After(since) {
					filtered = append(filtered, e)
				}
			}
			events = filtered
		}
	}
	if events == nil {
		events = []*models.ScanEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

// ─── GET /api/audits/:id/precheck ────────────────────────────────────────

func (h *Handler) GetPreCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	pc, ok := h.store.GetPreCheck(id)
	if !ok {
		writeError(w, http.StatusNotFound, "pre-check pas encore disponible")
		return
	}
	writeJSON(w, http.StatusOK, pc)
}

func (h *Handler) GetNetwork(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	nr, ok := h.store.GetNetwork(id)
	if !ok {
		writeError(w, http.StatusNotFound, "network pas encore disponible")
		return
	}
	writeJSON(w, http.StatusOK, nr)
}

func (h *Handler) GetTrends(w http.ResponseWriter, r *http.Request) {
	audits := h.store.ListAudits()
	sort.Slice(audits, func(i, j int) bool {
		return audits[i].StartedAt.Before(audits[j].StartedAt)
	})
	trends := &models.AuditTrends{
		GeneratedAt:       time.Now().UTC(),
		Runs:              make([]*models.AuditTrendRun, 0, len(audits)),
		RecurringFindings: make([]*models.RecurringFindingTrend, 0),
	}
	recurring := make(map[string]*models.RecurringFindingTrend)

	for _, audit := range audits {
		findings := h.store.GetFindings(audit.ID)
		severityCounts := make(map[models.Severity]int)
		occurrences := 0
		for _, finding := range findings {
			if finding == nil {
				continue
			}
			severityCounts[finding.Severity]++
			count := finding.OccurrenceCount
			if count <= 0 {
				count = 1
			}
			occurrences += count

			key := trendFindingKey(finding)
			if key == "" {
				continue
			}
			entry, exists := recurring[key]
			if !exists {
				entry = &models.RecurringFindingTrend{
					Key: key, Type: finding.Type, Title: finding.Title,
					Severity: finding.Severity, Audits: make([]string, 0), Endpoints: make([]string, 0),
				}
				recurring[key] = entry
			}
			entry.FindingCount++
			entry.Occurrences += count
			entry.Severity = higherTrendSeverity(entry.Severity, finding.Severity)
			if entry.Title == "" {
				entry.Title = finding.Title
			}
			if !containsString(entry.Audits, audit.ID) {
				entry.Audits = append(entry.Audits, audit.ID)
				entry.AuditCount++
			}
			if finding.Endpoint != "" && !containsString(entry.Endpoints, finding.Endpoint) {
				entry.Endpoints = append(entry.Endpoints, finding.Endpoint)
			}
		}
		trends.Runs = append(trends.Runs, &models.AuditTrendRun{
			AuditID: audit.ID, TargetURL: audit.TargetURL, Status: audit.Status,
			StartedAt: audit.StartedAt, FinishedAt: audit.FinishedAt,
			RiskScore: report.RiskScore(findings), RiskLevel: report.RiskLevel(report.RiskScore(findings)),
			FindingCount: len(findings), OccurrenceCount: occurrences, SeverityCounts: severityCounts,
		})
	}

	for _, entry := range recurring {
		trends.RecurringFindings = append(trends.RecurringFindings, entry)
	}
	sort.Slice(trends.RecurringFindings, func(i, j int) bool {
		left, right := trends.RecurringFindings[i], trends.RecurringFindings[j]
		if left.AuditCount != right.AuditCount {
			return left.AuditCount > right.AuditCount
		}
		if left.FindingCount != right.FindingCount {
			return left.FindingCount > right.FindingCount
		}
		return left.Title < right.Title
	})
	writeJSON(w, http.StatusOK, trends)
}

func trendFindingKey(finding *models.Finding) string {
	if finding == nil {
		return ""
	}
	endpoint := strings.TrimSpace(finding.Endpoint)
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Path != "" {
		endpoint = strings.ToLower(parsed.Path)
	} else {
		endpoint = strings.ToLower(endpoint)
	}
	family := strings.ToLower(strings.TrimSpace(finding.TaxonomyID))
	if family == "" {
		family = strings.ToLower(strings.TrimSpace(finding.Type))
	}
	return strings.Join([]string{family, endpoint, strings.ToLower(strings.TrimSpace(finding.Parameter))}, "|")
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func higherTrendSeverity(left, right models.Severity) models.Severity {
	rank := func(value models.Severity) int {
		switch value {
		case models.SeverityCritical:
			return 5
		case models.SeverityHigh:
			return 4
		case models.SeverityMedium:
			return 3
		case models.SeverityLow:
			return 2
		case models.SeverityInfo:
			return 1
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

// ─── GET /api/audits/:id/recon ───────────────────────────────────────────

func (h *Handler) GetRecon(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	rc, ok := h.store.GetRecon(id)
	if !ok {
		writeError(w, http.StatusNotFound, "recon pas encore disponible")
		return
	}
	writeJSON(w, http.StatusOK, rc)
}

// ─── GET /api/audits/:id/fingerprint ─────────────────────────────────────

func (h *Handler) GetFingerprint(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	fp, ok := h.store.GetFingerprint(id)
	if !ok {
		writeError(w, http.StatusNotFound, "fingerprint pas encore disponible")
		return
	}
	writeJSON(w, http.StatusOK, fp)
}

// ─── GET /api/audits/:id/crawl ───────────────────────────────────────────

func (h *Handler) GetCrawl(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	cr, ok := h.store.GetCrawl(id)
	if !ok {
		writeError(w, http.StatusNotFound, "crawl pas encore disponible")
		return
	}
	writeJSON(w, http.StatusOK, cr)
}

// ─── GET /api/audits/:id/assets ──────────────────────────────────────────
// Supporte ?method=GET|POST, ?type=api-rest, ?q=<search>

func (h *Handler) GetAssets(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	assets := h.store.GetAssets(id)

	method := strings.ToUpper(r.URL.Query().Get("method"))
	assetType := r.URL.Query().Get("type")
	q := strings.ToLower(r.URL.Query().Get("q"))

	if method != "" || assetType != "" || q != "" {
		var filtered []*models.Asset
		for _, a := range assets {
			if method != "" && a.Method != method {
				continue
			}
			if assetType != "" && string(a.Type) != assetType {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(a.URL), q) {
				continue
			}
			filtered = append(filtered, a)
		}
		assets = filtered
	}
	if assets == nil {
		assets = []*models.Asset{}
	}
	writeJSON(w, http.StatusOK, assets)
}

// ─── GET /api/audits/:id/findings ────────────────────────────────────────
// Supporte ?severity=critical|high|..., ?status=confirmed|suspected|..., ?q=search

func (h *Handler) GetFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvé")
		return
	}
	findings := h.store.GetFindings(id)

	sev := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	q := strings.ToLower(r.URL.Query().Get("q"))

	if sev != "" || status != "" || q != "" {
		var filtered []*models.Finding
		for _, f := range findings {
			if sev != "" && string(f.Severity) != sev {
				continue
			}
			if status != "" && string(f.Status) != status {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(f.Title), q) &&
				!strings.Contains(strings.ToLower(f.Description), q) &&
				!strings.Contains(strings.ToLower(f.Endpoint), q) &&
				!strings.Contains(strings.ToLower(f.Category), q) &&
				!strings.Contains(strings.ToLower(f.Module), q) &&
				!strings.Contains(strings.ToLower(f.Type), q) {
				continue
			}
			filtered = append(filtered, f)
		}
		findings = filtered
	}
	if findings == nil {
		findings = []*models.Finding{}
	}
	writeJSON(w, http.StatusOK, findings)
}

// ─── PATCH /api/audits/:id/findings/:fid ─────────────────────────────────
// Permet de qualifier un finding (false_positive, accepted_risk, confirmed…)

func (h *Handler) GetActiveTests(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvÃ©")
		return
	}
	tests := h.store.GetActiveTests(id)
	status := strings.ToUpper(r.URL.Query().Get("status"))
	module := strings.ToLower(r.URL.Query().Get("module"))
	q := strings.ToLower(r.URL.Query().Get("q"))
	if status != "" || module != "" || q != "" {
		var filtered []*models.ActiveTest
		for _, t := range tests {
			if status != "" && string(t.Status) != status {
				continue
			}
			if module != "" && strings.ToLower(t.Module) != module {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(t.URL), q) && !strings.Contains(strings.ToLower(t.Error), q) {
				continue
			}
			filtered = append(filtered, t)
		}
		tests = filtered
	}
	if tests == nil {
		tests = []*models.ActiveTest{}
	}
	writeJSON(w, http.StatusOK, tests)
}

func (h *Handler) GetActiveStats(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvÃ©")
		return
	}
	writeJSON(w, http.StatusOK, h.store.GetActiveTestStats(id))
}

func (h *Handler) GetActiveSummary(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvÃ©")
		return
	}
	if summary, ok := h.store.GetActiveSummary(id); ok {
		writeJSON(w, http.StatusOK, summary)
		return
	}
	writeError(w, http.StatusNotFound, "resume active pas encore disponible")
}

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.store.GetAudit(id); err != nil {
		writeError(w, http.StatusNotFound, "audit non trouvÃ©")
		return
	}
	if existing, ok := h.store.GetReport(id); ok {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	generated, err := report.Build(h.store, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, generated)
}

func (h *Handler) StopAudit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.runner.Stop(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stopping": id})
}

func (h *Handler) PatchFinding(w http.ResponseWriter, r *http.Request) {
	auditID := chi.URLParam(r, "id")
	findingID := chi.URLParam(r, "fid")

	var body struct {
		Status models.FindingStatus `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	valid := map[models.FindingStatus]bool{
		models.FindingSuspected:     true,
		models.FindingValidated:     true,
		models.FindingConfirmed:     true,
		models.FindingFalsePositive: true,
		models.FindingAcceptedRisk:  true,
	}
	if !valid[body.Status] {
		writeError(w, http.StatusBadRequest, "statut invalide")
		return
	}
	if err := h.store.UpdateFindingStatus(auditID, findingID, body.Status); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"updated": findingID, "status": string(body.Status)})
}

// ─── POST /api/audits/:id/findings/:fid/replay ───────────────────────────

func (h *Handler) ReplayFinding(w http.ResponseWriter, r *http.Request) {
	auditID := chi.URLParam(r, "id")
	findingID := chi.URLParam(r, "fid")

	f, err := h.store.GetFinding(auditID, findingID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	auditRun, err := h.store.GetAudit(auditID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	result := replay.Run(f, auditRun.Options)

	if result.ReplayState != models.FindingReplayNotRun {
		_ = h.store.UpdateFindingReplay(auditID, findingID, result.ReplayState, result.ReplayedAt)
	}

	// Mettre à jour le statut si le replay a escaladé la qualification
	if result.NewStatus != f.Status {
		h.store.UpdateFindingStatus(auditID, findingID, result.NewStatus)
	}

	writeJSON(w, http.StatusOK, result)
}

// ─── GET /api/stats ──────────────────────────────────────────────────────
// Stats globales pour le portfolio.

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	audits := h.store.ListAudits()
	total := len(audits)
	running := 0
	done := 0
	failed := 0
	totalFindings := 0

	for _, a := range audits {
		switch a.Status {
		case models.StatusRunning:
			running++
		case models.StatusDone:
			done++
		case models.StatusFailed:
			failed++
		}
		totalFindings += h.store.CountFindings(a.ID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total_audits":   total,
		"running":        running,
		"done":           done,
		"failed":         failed,
		"total_findings": totalFindings,
	})
}
