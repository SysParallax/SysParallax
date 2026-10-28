// Package traversal détecte les path traversal (lecture de fichiers système).
package traversal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
	"github.com/auditcore/auditcore/internal/scanner/modules/sqli"
	"github.com/google/uuid"
)

// Payloads path traversal — Unix + Windows + encodages.
var traversalPayloads = []string{
	// Unix direct
	"../../../etc/passwd",
	"../../../../etc/passwd",
	"../../../../../etc/passwd",
	// Encodé URL
	"..%2F..%2F..%2Fetc%2Fpasswd",
	"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
	// Double encodé
	"..%252F..%252F..%252Fetc%252Fpasswd",
	// Windows
	"..\\..\\..\\windows\\win.ini",
	"..%5C..%5C..%5Cwindows%5Cwin.ini",
	// Null byte (legacy)
	"../../../etc/passwd%00",
}

// Paramètres typiquement vulnérables.
var suspectParams = []string{"file", "path", "dir", "folder", "include", "page", "template", "view", "load", "doc", "document", "img", "image"}

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "path-traversal" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.Name(), ctx, findings)
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestFailed, Reason: "validation path traversal non finalisée"}
	if moduleCtx == nil || moduleCtx.Asset == nil || plan.EntryPoint.Name == "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucun paramètre de chemin contrôlable"
		return result
	}
	marker := expectedProofMarker(moduleCtx.Options)
	operation := proofResourceType(moduleCtx.Options)
	if marker == "" {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "aucun marqueur de ressource de preuve configuré pour ce chemin"
		return result
	}

	baselineRequest, err := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête normale impossible à construire: " + err.Error()
		return result
	}
	if _, err = executor.DoBaseline(baselineRequest); err != nil {
		return finishTraversalError(result, executor, err)
	}
	normal := lastTraversalExchange(executor.Exchanges(), "baseline")

	invalidRequest, invalidErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, "__auditcore_invalid_path_7f3c__")
	if invalidErr != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "chemin invalide impossible à construire: " + invalidErr.Error()
		return finishTraversalEvidence(result, executor, plan, marker, false, operation)
	}
	if _, invalidErr = executor.Do("test", "invalid-path", invalidRequest); invalidErr != nil && executor.LimitReached() == "" {
		return finishTraversalError(result, executor, invalidErr)
	}
	invalid := lastTraversalExchange(executor.Exchanges(), "test")

	var suspectReason string
	for _, payload := range traversalPayloadsFor(moduleCtx.Options) {
		probeRequest, requestErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if requestErr != nil {
			continue
		}
		if _, requestErr = executor.Do("test", "traversal:"+payload, probeRequest); requestErr != nil {
			if executor.LimitReached() != "" {
				break
			}
			if errors.Is(requestErr, context.Canceled) || errors.Is(requestErr, context.DeadlineExceeded) {
				return finishTraversalError(result, executor, requestErr)
			}
			continue
		}
		traversal := lastTraversalExchange(executor.Exchanges(), "test")
		if traversal == nil || traversal.Response == nil {
			continue
		}
		if traversal.Response.StatusCode >= 500 {
			continue
		}
		observedMarker := containsMarker(traversal.Response.BodyPreview, marker)
		if !observedMarker {
			continue
		}
		normalContains := normal != nil && normal.Response != nil && containsMarker(normal.Response.BodyPreview, marker)
		invalidContains := invalid != nil && invalid.Response != nil && containsMarker(invalid.Response.BodyPreview, marker)
		executor.Step(models.ActiveTestComparing, "comparaison chemin normal / invalide / traversal")
		if normalContains || invalidContains {
			suspectReason = "le marqueur de preuve est déjà présent dans un contrôle"
			continue
		}

		repeatRequest, repeatErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if repeatErr != nil {
			continue
		}
		if _, repeatErr = executor.Do("test", "traversal-reproduction:"+payload, repeatRequest); repeatErr != nil {
			break
		}
		repeated := lastTraversalExchange(executor.Exchanges(), "test")
		if repeated == nil || repeated.Response == nil || repeated.Response.StatusCode >= 500 || !containsMarker(repeated.Response.BodyPreview, marker) {
			suspectReason = "le marqueur de preuve n'est pas reproductible"
			continue
		}

		executor.Step(models.ActiveTestReproducing, "marqueur de ressource reproduit")
		executor.Step(models.ActiveTestValidating, "résolution d'un chemin non prévu validée")
		reason := fmt.Sprintf("le marqueur spécifique %q est absent des contrôles et présent deux fois dans la réponse traversal", marker)
		result.Status = models.ActiveTestConfirmed
		result.Reason = reason
		result.Findings = []*models.Finding{buildTraversalFinding(moduleCtx, plan.EntryPoint.Name, payload, operation, reason, repeated)}
		result.MinimumConditionsMet = true
		executor.MarkMinimumProof()
		return finishTraversalEvidence(result, executor, plan, marker, true, operation)
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
		result.Reason = "aucun marqueur spécifique de ressource résolue n'a été observé"
	}
	return finishTraversalEvidence(result, executor, plan, marker, false, operation)
}

func traversalPayloadsFor(options models.AuditOptions) []string {
	platform := strings.ToLower(strings.TrimSpace(options.ActiveTraversalProofPlatform))
	platforms := []string{"unix", "windows"}
	if platform == "unix" || platform == "linux" {
		platforms = []string{"unix"}
	} else if platform == "windows" || platform == "win" {
		platforms = []string{"windows"}
	}
	proofPath := strings.TrimSpace(options.ActiveTraversalProofPath)
	if proofPath == "" {
		proofPath = "etc/passwd"
	}
	var result []string
	for _, selectedPlatform := range platforms {
		if selectedPlatform == "windows" {
			path := strings.Trim(strings.ReplaceAll(proofPath, "/", "\\"), "\\")
			if path == "" || path == "etc\\passwd" {
				path = "windows\\win.ini"
			}
			result = append(result,
				"..\\..\\..\\"+path,
				"..\\..\\..\\"+path+"%00",
				"..%5C..%5C..%5C"+strings.ReplaceAll(path, "\\", "%5C"),
			)
			continue
		}
		path := strings.Trim(strings.ReplaceAll(proofPath, "\\", "/"), "/")
		if path == "" || path == "windows/win.ini" {
			path = "etc/passwd"
		}
		base := []string{"../../../" + path, "../../../../" + path, "../../../../../" + path}
		result = append(result, base...)
		result = append(result,
			"..%2F..%2F..%2F"+strings.ReplaceAll(path, "/", "%2F"),
			"..%252F..%252F..%252F"+strings.ReplaceAll(path, "/", "%252F"),
			"../../../"+path+"%00",
		)
	}
	return uniquePayloads(result)
}

func uniquePayloads(payloads []string) []string {
	seen := make(map[string]struct{}, len(payloads))
	result := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		if _, exists := seen[payload]; exists {
			continue
		}
		seen[payload] = struct{}{}
		result = append(result, payload)
	}
	return result
}

func expectedProofMarker(options models.AuditOptions) string {
	if options.ActiveTraversalProofMarker != "" {
		return options.ActiveTraversalProofMarker
	}
	if options.ActiveTraversalProofPath != "" {
		return ""
	}
	return "root:x:0:0"
}

func proofResourceType(options models.AuditOptions) string {
	switch strings.ToLower(strings.TrimSpace(options.ActiveTraversalProofResourceType)) {
	case "lfi", "local-file-inclusion":
		return "local-file-inclusion"
	default:
		return "path-traversal"
	}
}

func containsMarker(body, marker string) bool {
	return marker != "" && strings.Contains(strings.ToLower(body), strings.ToLower(marker))
}

func lastTraversalExchange(exchanges []models.HTTPExchange, kind string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if exchanges[i].Kind == kind {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func finishTraversalError(result *models.ActiveTestResult, executor *active.Executor, err error) *models.ActiveTestResult {
	if errors.Is(err, context.Canceled) {
		result.Status = models.ActiveTestCancelled
	} else if errors.Is(err, context.DeadlineExceeded) {
		result.Status = models.ActiveTestTimeout
	} else {
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "échange HTTP traversal interrompu: " + err.Error()
	return finishTraversalEvidence(result, executor, models.ActiveTestPlan{}, "", false)
}

func finishTraversalEvidence(result *models.ActiveTestResult, executor *active.Executor, plan models.ActiveTestPlan, marker string, proof bool, operation ...string) *models.ActiveTestResult {
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
	operationName := "path-traversal"
	if len(operation) > 0 && operation[0] != "" {
		operationName = operation[0]
	}
	result.Evidence = &models.ActiveEvidence{
		Expected:            fmt.Sprintf("le marqueur spécifique %q doit être absent du chemin normal et invalide, puis présent dans la ressource de preuve", marker),
		Observed:            result.Reason,
		Baseline:            executor.Baseline(),
		TestExchanges:       tests,
		Differences:         differences,
		ValidationRule:      "comparaison normal / chemin invalide / traversal + marqueur spécifique reproductible",
		Confidence:          traversalConfidence(result.Status),
		Reproductions:       countTraversalReproductions(tests),
		MinimumProofReached: proof,
		Conclusion:          result.Reason,
		Operation:           operationName,
	}
	_ = plan
	return result
}

func traversalConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func countTraversalReproductions(exchanges []models.HTTPExchange) int {
	count := 0
	for _, exchange := range exchanges {
		if strings.Contains(exchange.Label, "reproduction") {
			count++
		}
	}
	return count
}

func buildTraversalFinding(ctx *models.ModuleContext, param, payload, operation, reason string, exchange *models.HTTPExchange) *models.Finding {
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
	title := "Path traversal"
	if operation == "local-file-inclusion" {
		title = "Local File Inclusion"
	}
	return &models.Finding{
		ID: uuid.NewString(), AuditRunID: ctx.AuditRunID, TaxonomyID: "WEB-PATH-001", Type: operation,
		Title: fmt.Sprintf("%s - paramètre %q", title, param), Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh,
		Status: models.FindingConfirmed, CWE: "CWE-22", OWASPCat: "A01:2021", ASVSMapping: "V12.3.1",
		Description: fmt.Sprintf("Le paramètre %q résout un chemin non prévu et retourne un marqueur de ressource spécifique. %s", param, reason),
		Impact:      "Lecture non autorisée de ressources locales selon les droits du processus.",
		Remediation: "Canonicaliser les chemins et vérifier qu'ils restent dans une liste blanche de ressources autorisées.",
		Replayable:  true, Endpoint: ctx.Asset.URL, Parameter: param, CreatedAt: time.Now(),
		Evidence: &models.Evidence{ID: uuid.NewString(), RequestRaw: requestLine, ResponseRaw: fmt.Sprintf("HTTP/1.1 %d\n\n%s", statusCode, snip(body, 500)), Payload: payload, MatcherResult: reason},
	}
}

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	params := ctx.Asset.Params
	if len(params) == 0 {
		params = sqli.ExtractURLParams(ctx.Asset.URL)
	}

	// Filtrer les paramètres suspects de traversal
	var targets []string
	for _, p := range params {
		pLower := strings.ToLower(p)
		for _, s := range suspectParams {
			if strings.Contains(pLower, s) {
				targets = append(targets, p)
				break
			}
		}
	}
	// Si aucun paramètre suspect, tester quand même avec les premiers paramètres
	if len(targets) == 0 && len(params) > 0 {
		targets = params[:1]
	}
	if len(targets) == 0 {
		return result
	}

	for _, param := range targets {
		for _, payload := range traversalPayloads {
			req, probeURL, err := sqli.NewProbeRequest(ctx.Asset, param, payload)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "AuditCore/2.0")

			resp, err := matchers.Fetch(client, req)
			if err != nil {
				continue
			}

			if hit, evidence := matchers.PathTraversal(resp); hit {
				result.Findings = append(result.Findings, &models.Finding{
					ID:          uuid.NewString(),
					AuditRunID:  ctx.AuditRunID,
					TaxonomyID:  "WEB-PATH-001",
					Type:        "path-traversal",
					Title:       fmt.Sprintf("Path traversal — paramètre %q", param),
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfidenceHigh,
					Status:      models.FindingConfirmed,
					CWE:         "CWE-22",
					OWASPCat:    "A01:2021",
					ASVSMapping: "V12.3.1",
					Description: fmt.Sprintf("Le paramètre %q permet la lecture de fichiers système via traversal de répertoire. Contenu détecté : %s", param, evidence),
					Impact:      "Lecture de fichiers système sensibles (/etc/passwd, clés privées, configuration). Peut mener à la divulgation de credentials ou à une escalade de privilèges.",
					Remediation: "Valider et nettoyer tous les chemins de fichier. Utiliser une liste blanche de chemins autorisés. Résoudre le chemin canonique et vérifier qu'il reste dans le répertoire autorisé.",
					Replayable:  true,
					Endpoint:    probeURL,
					Parameter:   param,
					CreatedAt:   time.Now(),
					Evidence: &models.Evidence{
						ID:            uuid.NewString(),
						RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1", probeURL),
						ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, snip(resp.Body, 400)),
						Payload:       payload,
						MatcherResult: evidence,
					},
				})
				break
			}
		}
	}
	return result
}

func snip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
