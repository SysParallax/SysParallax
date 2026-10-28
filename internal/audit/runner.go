// Package audit — orchestrateur V2 complet.
// Pipeline : pre-check → recon → crawl → fingerprint → passive → active → done
// Règle fondamentale : le runner ne parle jamais directement au dashboard.
// Il écrit dans le store, le dashboard lit depuis l'API.
package audit

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/auditcore/auditcore/internal/crawler"
	"github.com/auditcore/auditcore/internal/fingerprint"
	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/network"
	"github.com/auditcore/auditcore/internal/recon"
	"github.com/auditcore/auditcore/internal/report"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/engine"
	"github.com/auditcore/auditcore/internal/scanner/modules/cookies"
	"github.com/auditcore/auditcore/internal/scanner/modules/cors"
	"github.com/auditcore/auditcore/internal/scanner/modules/exposure"
	"github.com/auditcore/auditcore/internal/scanner/modules/headers"
	"github.com/auditcore/auditcore/internal/scanner/modules/idor"
	"github.com/auditcore/auditcore/internal/scanner/modules/redirect"
	"github.com/auditcore/auditcore/internal/scanner/modules/sqli"
	"github.com/auditcore/auditcore/internal/scanner/modules/ssrf"
	"github.com/auditcore/auditcore/internal/scanner/modules/traversal"
	"github.com/auditcore/auditcore/internal/scanner/modules/xss"
	"github.com/auditcore/auditcore/internal/storage"
	"github.com/google/uuid"
)

// Runner orchestre l'exécution d'un audit par phases.
type Runner struct {
	store   *storage.Store
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func New(store *storage.Store) *Runner {
	return &Runner{
		store:   store,
		cancels: make(map[string]context.CancelFunc),
	}
}

// CreateAndRun crée un AuditRun et démarre l'exécution en goroutine.
// Retourne immédiatement — le dashboard poll l'état via l'API.
func (r *Runner) CreateAndRun(targetURL string, options models.AuditOptions) (*models.AuditRun, error) {
	options = httpx.MergeOptions(targetURL, options)
	a := &models.AuditRun{
		ID:        uuid.NewString(),
		TargetURL: targetURL,
		Options:   options,
		Status:    models.StatusPending,
		Phase:     models.PhaseIdle,
		StartedAt: time.Now(),
	}
	r.store.SaveAudit(a)
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancels[a.ID] = cancel
	r.mu.Unlock()
	go r.run(ctx, a.ID, targetURL, options)
	return a, nil
}

func (r *Runner) Stop(auditID string) error {
	a, err := r.store.GetAudit(auditID)
	if err != nil {
		return err
	}
	if a.Status != models.StatusRunning && a.Status != models.StatusPending {
		return fmt.Errorf("audit %s is not running", auditID)
	}
	r.mu.Lock()
	cancel, ok := r.cancels[auditID]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("audit %s cannot be stopped", auditID)
	}
	cancel()
	return nil
}

func (r *Runner) run(ctx context.Context, auditID, targetURL string, options models.AuditOptions) {
	defer func() {
		r.mu.Lock()
		delete(r.cancels, auditID)
		r.mu.Unlock()
	}()
	log.Printf("[runner] audit %s started for %s", auditID, targetURL)
	startTime := time.Now()
	if r.stopIfCanceled(ctx, auditID) {
		return
	}

	// ── Phase 1 : Pre-check ──────────────────────────────────────────────
	r.setPhase(auditID, models.PhasePreCheck)
	r.emit(auditID, models.PhasePreCheck, models.LevelInfo, "", "Pre-check démarré — validation connectivité")

	finalURL := targetURL
	if phaseEnabled(options, models.PhasePreCheck) {
		pcResult, err := recon.NewPreChecker(r.store, options).Run(auditID, targetURL)
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		if err != nil || !pcResult.Reachable {
			msg := "Pre-check : cible injoignable"
			if err != nil {
				msg = fmt.Sprintf("Pre-check échoué : %v", err)
			} else {
				msg = fmt.Sprintf("Pre-check : code HTTP %d — cible considérée injoignable", pcResult.StatusCode)
			}
			r.emit(auditID, models.PhasePreCheck, models.LevelError, "", msg)
			r.store.MarkAuditFinished(auditID, models.StatusFailed, msg)
			return
		}
		r.emit(auditID, models.PhasePreCheck, models.LevelOK, "",
			fmt.Sprintf("Pre-check OK — HTTP %d, %dms, URL finale : %s",
				pcResult.StatusCode, pcResult.ResponseTime.Milliseconds(), pcResult.FinalURL))
		finalURL = pcResult.FinalURL
	} else {
		r.emit(auditID, models.PhasePreCheck, models.LevelInfo, "profile-skip", "Pre-check ignoré par le scan profile")
	}

	// Phase 2 : Network footprint
	r.setPhase(auditID, models.PhaseNetwork)
	if phaseEnabled(options, models.PhaseNetwork) {
		r.emit(auditID, models.PhaseNetwork, models.LevelInfo, "", "Network footprint - DNS, ports TCP, certificat TLS")

		networkResult, err := network.New(r.store).Run(auditID, finalURL)
		if err != nil {
			r.emit(auditID, models.PhaseNetwork, models.LevelWarn, "", fmt.Sprintf("Network partiel : %v", err))
		} else {
			openPorts := 0
			for _, p := range networkResult.Ports {
				if p.Open {
					openPorts++
					r.emit(auditID, models.PhaseNetwork, models.LevelInfo, "", fmt.Sprintf("Port TCP %d ouvert", p.Port))
				}
			}
			r.emit(auditID, models.PhaseNetwork, models.LevelOK, "",
				fmt.Sprintf("Network OK - host %s, %d IP(s), %d port(s) ouvert(s)",
					networkResult.Host, len(networkResult.DNS.A)+len(networkResult.DNS.AAAA), openPorts))
			if networkResult.TLS != nil && networkResult.TLS.Checked {
				if networkResult.TLS.Valid {
					r.emit(auditID, models.PhaseNetwork, models.LevelOK, "",
						fmt.Sprintf("TLS valide - expire dans %d jour(s)", networkResult.TLS.DaysToExpiry))
				} else if networkResult.TLS.Error != "" {
					r.emit(auditID, models.PhaseNetwork, models.LevelWarn, "",
						fmt.Sprintf("TLS non valide : %s", networkResult.TLS.Error))
				}
			}
		}
	} else {
		r.emit(auditID, models.PhaseNetwork, models.LevelInfo, "profile-skip", "Network ignoré par le scan profile")
	}
	if r.stopIfCanceled(ctx, auditID) {
		return
	}

	// ── Phase 3 : Recon ──────────────────────────────────────────────────
	r.setPhase(auditID, models.PhaseRecon)
	if phaseEnabled(options, models.PhaseRecon) {
		r.emit(auditID, models.PhaseRecon, models.LevelInfo, "", "Reconnaissance passive — headers, title, robots, sitemap")

		reconResult, err := recon.NewReconner(r.store, options).Run(auditID, finalURL)
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		if err != nil {
			r.emit(auditID, models.PhaseRecon, models.LevelWarn, "", fmt.Sprintf("Recon partielle : %v", err))
		} else {
			r.emit(auditID, models.PhaseRecon, models.LevelOK, "",
				fmt.Sprintf("Recon OK — titre: %q · serveur: %q · %d liens internes",
					reconResult.Title, reconResult.Server, len(reconResult.InternalLinks)))
			if reconResult.HasRobotsTxt {
				r.emit(auditID, models.PhaseRecon, models.LevelInfo, "", "robots.txt détecté")
			}
			if reconResult.HasSitemapXML {
				r.emit(auditID, models.PhaseRecon, models.LevelInfo, "", "sitemap.xml détecté")
			}
			if reconResult.LooksLikeAPI {
				r.emit(auditID, models.PhaseRecon, models.LevelInfo, "", "Cible détectée comme API JSON — modules adaptés")
			}
		}

		// ── Phase 4 : Crawl ──────────────────────────────────────────────────
	} else {
		r.emit(auditID, models.PhaseRecon, models.LevelInfo, "profile-skip", "Recon ignoree par le scan profile")
	}
	r.setPhase(auditID, models.PhaseCrawl)
	if phaseEnabled(options, models.PhaseCrawl) {
		r.emit(auditID, models.PhaseCrawl, models.LevelInfo, "", "Crawl BFS démarré (profondeur max 3, 150 pages)")

		crawlResult, err := crawler.New(r.store, options).Run(auditID, finalURL)
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		if err != nil {
			r.emit(auditID, models.PhaseCrawl, models.LevelWarn, "", fmt.Sprintf("Crawl partiel : %v", err))
		} else {
			r.emit(auditID, models.PhaseCrawl, models.LevelOK, "",
				fmt.Sprintf("Crawl terminé — %d assets découverts", crawlResult.TotalFound))
		}

		// ── Phase 5 : Fingerprint ────────────────────────────────────────────
	} else {
		r.emit(auditID, models.PhaseCrawl, models.LevelInfo, "profile-skip", "Crawl ignore par le scan profile")
	}
	fpResult := &models.FingerprintResult{AuditRunID: auditID, HeaderClues: make(map[string]string)}
	r.setPhase(auditID, models.PhaseFingerprint)
	if phaseEnabled(options, models.PhaseFingerprint) {
		r.emit(auditID, models.PhaseFingerprint, models.LevelInfo, "", "Fingerprinting de la stack technique")

		var err error
		fpResult, err = fingerprint.New(r.store, options).Run(auditID, finalURL)
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		if err != nil {
			r.emit(auditID, models.PhaseFingerprint, models.LevelWarn, "", fmt.Sprintf("Fingerprint partiel : %v", err))
			// Créer un résultat vide pour ne pas bloquer la suite
			fpResult = &models.FingerprintResult{AuditRunID: auditID, HeaderClues: make(map[string]string)}
		} else {
			techs := buildTechList(fpResult)
			r.emit(auditID, models.PhaseFingerprint, models.LevelOK, "",
				fmt.Sprintf("Stack détectée : %v · Auth : %q", techs, fpResult.AuthMechanism))
		}

		// ── Phase 6 : Priorisation ───────────────────────────────────────────
	} else {
		r.emit(auditID, models.PhaseFingerprint, models.LevelInfo, "profile-skip", "Fingerprint ignore par le scan profile")
	}
	r.setPhase(auditID, models.PhasePrioritize)
	if phaseEnabled(options, models.PhasePrioritize) {
		assets := r.store.GetAssets(auditID)
		r.emit(auditID, models.PhasePrioritize, models.LevelInfo, "",
			fmt.Sprintf("Priorisation : %d surfaces à tester — sélection selon fingerprint", len(assets)))
		// Pause courte pour lisibilité dans l'event stream
		time.Sleep(200 * time.Millisecond)
	} else {
		r.emit(auditID, models.PhasePrioritize, models.LevelInfo, "profile-skip", "Priorisation ignoree par le scan profile")
	}
	if r.stopIfCanceled(ctx, auditID) {
		return
	}

	// ── Phase 7 : Tests passifs ──────────────────────────────────────────
	passiveCount := r.store.CountFindings(auditID)
	r.setPhase(auditID, models.PhasePassive)
	if phaseEnabled(options, models.PhasePassive) {
		r.emit(auditID, models.PhasePassive, models.LevelInfo, "", "Tests passifs : security headers, CORS, cookies")

		passiveEngine := engine.New(r.store, options)
		passiveModules := registerPassiveModules(passiveEngine, options)

		if passiveModules == 0 {
			r.emit(auditID, models.PhasePassive, models.LevelInfo, "profile-skip", "Aucun module passif active par le scan profile")
		} else if err := passiveEngine.RunPassiveContext(ctx, auditID, fpResult, r.makeEmitFn(auditID)); err != nil {
			r.emit(auditID, models.PhasePassive, models.LevelWarn, "", fmt.Sprintf("Tests passifs partiels : %v", err))
		}
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		passiveCount = r.store.CountFindings(auditID)
		r.emit(auditID, models.PhasePassive, models.LevelOK, "",
			fmt.Sprintf("Tests passifs terminés — %d finding(s)", passiveCount))

		// ── Phase 8 : Tests actifs ───────────────────────────────────────────
		// Ne s'exécute que s'il y a des assets ET que la cible n'est pas une API pure
		// (les modules offensifs respectent le contexte fingerprint)
	} else {
		r.emit(auditID, models.PhasePassive, models.LevelInfo, "profile-skip", "Tests passifs ignores par le scan profile")
	}
	r.setPhase(auditID, models.PhaseActive)
	if phaseEnabled(options, models.PhaseActive) {
		r.emit(auditID, models.PhaseActive, models.LevelInfo, "", "Tests actifs ciblés : SQLi, XSS, traversal, SSRF, IDOR")

		activeEngine := engine.New(r.store, options)
		activeModules := registerActiveModules(activeEngine, options)

		activeStartedAt := time.Now()
		if activeModules == 0 {
			r.emit(auditID, models.PhaseActive, models.LevelInfo, "profile-skip", "Aucun module actif active par le scan profile")
		} else if err := activeEngine.RunModulesContext(ctx, auditID, models.PhaseActive, fpResult, r.makeEmitFn(auditID)); err != nil {
			r.emit(auditID, models.PhaseActive, models.LevelWarn, "", fmt.Sprintf("Tests actifs partiels : %v", err))
		}
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		activeFinishedAt := time.Now()
		activeSummary := r.store.BuildActiveSummary(auditID, activeStartedAt, activeFinishedAt)
		r.store.SaveActiveSummary(activeSummary)
		activeCount := r.store.CountFindings(auditID) - passiveCount
		r.emit(auditID, models.PhaseActive, models.LevelOK, "active-summary",
			fmt.Sprintf("Active summary - %d/%d finalises - %d confirmed - %d not_confirmed - %d timeout(s) - %d failed",
				activeSummary.FinalizedTests,
				activeSummary.GeneratedTests,
				activeSummary.StatusCounts[models.ActiveTestConfirmed],
				activeSummary.StatusCounts[models.ActiveTestNotConfirmed],
				activeSummary.StatusCounts[models.ActiveTestTimeout],
				activeSummary.StatusCounts[models.ActiveTestFailed]))
		r.emit(auditID, models.PhaseActive, models.LevelOK, "",
			fmt.Sprintf("Tests actifs terminés — %d finding(s) supplémentaire(s)", activeCount))

		// ── Phase 9 : Scoring ────────────────────────────────────────────────
	} else {
		r.emit(auditID, models.PhaseActive, models.LevelInfo, "profile-skip", "Tests actifs ignores par le scan profile")
	}
	total := r.store.CountFindings(auditID)
	r.setPhase(auditID, models.PhaseScoring)
	if phaseEnabled(options, models.PhaseScoring) {
		r.emit(auditID, models.PhaseScoring, models.LevelInfo, "", "Scoring et qualification des findings")
		time.Sleep(100 * time.Millisecond)
		if r.stopIfCanceled(ctx, auditID) {
			return
		}
		total = r.store.CountFindings(auditID)
		r.emit(auditID, models.PhaseScoring, models.LevelOK, "",
			fmt.Sprintf("Scoring terminé — %d finding(s) qualifiés (sévérité × confiance × statut)", total))

	} else {
		r.emit(auditID, models.PhaseScoring, models.LevelInfo, "profile-skip", "Scoring ignore par le scan profile")
	}
	r.setPhase(auditID, models.PhaseReport)
	if !phaseEnabled(options, models.PhaseReport) {
		r.emit(auditID, models.PhaseReport, models.LevelInfo, "profile-skip", "Report ignore par le scan profile")
	} else if auditReport, err := report.Build(r.store, auditID); err == nil {
		r.emit(auditID, models.PhaseReport, models.LevelOK, "",
			fmt.Sprintf("Rapport JSON prêt — risque %s (%d/100)", auditReport.RiskLevel, auditReport.RiskScore))
	} else {
		r.emit(auditID, models.PhaseReport, models.LevelWarn, "", fmt.Sprintf("Rapport partiel : %v", err))
	}

	// ── Fin ──────────────────────────────────────────────────────────────
	elapsed := time.Since(startTime)
	r.store.MarkAuditFinished(auditID, models.StatusDone, "")
	r.emit(auditID, models.PhaseIdle, models.LevelOK, "",
		fmt.Sprintf("Audit terminé en %s — %d finding(s) total · pipeline V2 complet", elapsed.Round(time.Second), total))
	log.Printf("[runner] audit %s done in %s — %d findings", auditID, elapsed.Round(time.Second), total)
}

// makeEmitFn retourne une closure d'émission d'événement compatible avec engine.RunPassive.
func (r *Runner) makeEmitFn(auditID string) func(models.Phase, models.EventLevel, string, string) {
	return func(phase models.Phase, level models.EventLevel, msg, module string) {
		r.emit(auditID, phase, level, module, msg)
	}
}

func (r *Runner) setPhase(id string, p models.Phase) {
	r.store.UpdateAuditStatus(id, models.StatusRunning, p)
}

func (r *Runner) stopIfCanceled(ctx context.Context, auditID string) bool {
	select {
	case <-ctx.Done():
		r.store.MarkAuditFinished(auditID, models.StatusStopped, "stopped by user")
		r.emit(auditID, models.PhaseIdle, models.LevelWarn, "", "Audit stoppé par l'utilisateur")
		log.Printf("[runner] audit %s stopped", auditID)
		return true
	default:
		return false
	}
}

func phaseEnabled(options models.AuditOptions, phase models.Phase) bool {
	if len(options.EnabledPhases) == 0 {
		return true
	}
	for _, enabled := range options.EnabledPhases {
		if enabled == phase {
			return true
		}
	}
	return false
}

func registerPassiveModules(e *engine.Engine, options models.AuditOptions) int {
	available := []struct {
		name   string
		module engine.Module
	}{
		{name: "headers-security", module: headers.New()},
		{name: "cors-misconfig", module: cors.New()},
		{name: "cookies-security", module: cookies.New()},
		{name: "sensitive-exposure", module: exposure.New()},
	}
	return registerModules(e, options.PassiveModules, available)
}

func registerActiveModules(e *engine.Engine, options models.AuditOptions) int {
	available := []struct {
		name   string
		module active.Module
	}{
		{name: "sqli-detection", module: sqli.New()},
		{name: "xss-reflected", module: xss.New()},
		{name: "path-traversal", module: traversal.New()},
		{name: "ssrf-basic", module: ssrf.New()},
		{name: "idor-simple", module: idor.New()},
		{name: "open-redirect", module: redirect.New()},
	}
	count := 0
	for _, candidate := range available {
		if moduleEnabled(options.ActiveModules, candidate.name) {
			e.RegisterActive(candidate.module)
			count++
		}
	}
	return count
}

func registerModules(e *engine.Engine, allowlist []string, available []struct {
	name   string
	module engine.Module
}) int {
	count := 0
	for _, candidate := range available {
		if moduleEnabled(allowlist, candidate.name) {
			e.Register(candidate.module)
			count++
		}
	}
	return count
}

func moduleEnabled(allowlist []string, moduleName string) bool {
	if allowlist == nil {
		return true
	}
	if len(allowlist) == 0 {
		return false
	}
	want := canonicalModuleName(moduleName)
	for _, item := range allowlist {
		if canonicalModuleName(item) == want {
			return true
		}
	}
	return false
}

func canonicalModuleName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	switch name {
	case "headers":
		return "headers-security"
	case "cors":
		return "cors-misconfig"
	case "cookies":
		return "cookies-security"
	case "exposure", "sensitive":
		return "sensitive-exposure"
	case "sqli", "sql":
		return "sqli-detection"
	case "xss":
		return "xss-reflected"
	case "traversal", "path":
		return "path-traversal"
	case "ssrf":
		return "ssrf-basic"
	case "idor":
		return "idor-simple"
	case "redirect", "openredirect":
		return "open-redirect"
	default:
		return name
	}
}

func (r *Runner) emit(auditID string, phase models.Phase, level models.EventLevel, module, msg string) {
	r.store.AppendEvent(&models.ScanEvent{
		ID:         uuid.NewString(),
		AuditRunID: auditID,
		Phase:      phase,
		Module:     module,
		Level:      level,
		Message:    msg,
		Timestamp:  time.Now(),
	})
}

func buildTechList(fp *models.FingerprintResult) []string {
	var list []string
	if fp.Framework != "" {
		list = append(list, fp.Framework)
	}
	list = append(list, fp.Technologies...)
	if len(list) == 0 {
		list = []string{"inconnu"}
	}
	return list
}
