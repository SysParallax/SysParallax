// Package xss détecte le Cross-Site Scripting réfléchi.
package xss

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/browser"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
	"github.com/auditcore/auditcore/internal/scanner/modules/sqli"
	"github.com/google/uuid"
	xhtml "golang.org/x/net/html"
)

// Payloads XSS classés par contexte.
var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><script>alert(1)</script>`,
	`'><script>alert(1)</script>`,
	`<img src=x onerror=alert(1)>`,
	`javascript:alert(1)`,
	`<svg onload=alert(1)>`,
}

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "xss-reflected" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	if ctx != nil && ctx.Fingerprint != nil && ctx.Fingerprint.LooksLikeAPI {
		return nil
	}
	return active.PlansForModule(m.Name(), ctx, findings)
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	return m.runContextual(ctx, moduleCtx, plan, executor)
}

type reflectionAnalysis struct {
	Reflected  bool
	Context    string
	Location   string
	Encoding   string
	Executable bool
	Reason     string
}

func (m *Module) runContextual(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestFailed, Reason: "validation XSS non finalisée"}
	if moduleCtx == nil || moduleCtx.Asset == nil || plan.EntryPoint.Name == "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucun point d'entrée contrôlable"
		return result
	}

	baselineRequest, err := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête de référence impossible à construire: " + err.Error()
		return result
	}
	if _, err = executor.DoBaseline(baselineRequest); err != nil {
		return finishXSSExchangeError(result, executor, err)
	}
	baseline := lastXSSExchange(executor.Exchanges(), "baseline")
	if baseline == nil || baseline.Response == nil {
		result.Status = models.ActiveTestFailed
		result.Reason = "la baseline XSS n'a produit aucune réponse exploitable"
		return finishXSSEvidence(result, executor, plan, reflectionAnalysis{}, false)
	}

	var suspect *reflectionAnalysis
	var suspectPayload string
	var observed reflectionAnalysis
	var browserEvidence *models.BrowserEvidence
	for _, payload := range xssPayloads {
		request, requestErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if requestErr != nil {
			continue
		}
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
		if _, requestErr = executor.Do("test", "xss:"+payload, request); requestErr != nil {
			if executor.LimitReached() != "" {
				break
			}
			if ctx.Err() != nil {
				return finishXSSExchangeError(result, executor, ctx.Err())
			}
			continue
		}
		exchange := lastXSSExchange(executor.Exchanges(), "test")
		if exchange == nil || exchange.Response == nil {
			continue
		}
		analysis := analyzeReflection(exchange.Response.BodyPreview, exchange.Response.Headers, payload)
		if !analysis.Reflected {
			continue
		}
		observed = analysis
		executor.Step(models.ActiveTestComparing, fmt.Sprintf("réflexion localisée: %s (%s)", analysis.Context, analysis.Encoding))
		if analysis.Executable && analysis.Context != "javascript" && analysis.Context != "json" {
			repeatRequest, repeatErr := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
			if repeatErr != nil {
				continue
			}
			if _, repeatErr = executor.Do("test", "xss-reproduction:"+payload, repeatRequest); repeatErr != nil {
				break
			}
			repeated := lastXSSExchange(executor.Exchanges(), "test")
			if repeated != nil && repeated.Response != nil {
				repeatedAnalysis := analyzeReflection(repeated.Response.BodyPreview, repeated.Response.Headers, payload)
				if repeatedAnalysis.Executable && repeatedAnalysis.Context == analysis.Context && repeatedAnalysis.Encoding == analysis.Encoding {
					executor.Step(models.ActiveTestReproducing, "contexte XSS interprétable reproduit")
					executor.Step(models.ActiveTestValidating, "preuve XSS minimale validée")
					reason := fmt.Sprintf("la valeur apparaît dans %s, encodage %s : %s", analysis.Location, analysis.Encoding, analysis.Reason)
					result.Status = models.ActiveTestConfirmed
					result.Reason = reason
					result.Findings = []*models.Finding{buildXSSFinding(moduleCtx, plan.EntryPoint.Name, payload, reason, repeated)}
					result.MinimumConditionsMet = true
					executor.MarkMinimumProof()
					return finishXSSEvidence(result, executor, plan, analysis, true)
				}
			}
		}
		if analysis.Encoding == "raw/non encodé" && (analysis.Context == "javascript" || analysis.Context == "css") && suspect == nil {
			copyAnalysis := analysis
			suspect = &copyAnalysis
			suspectPayload = payload
		}
	}

	// Une réflexion JavaScript brute ne devient confirmée qu'après exécution
	// dans un navigateur isolé. Le navigateur est explicitement opt-in, car
	// l'installation de Chromium n'est pas une dépendance obligatoire d'un
	// audit HTTP classique.
	if suspect != nil && suspect.Context == "javascript" && moduleCtx.Options.ActiveBrowserEnabled {
		executor.Step(models.ActiveTestAnalyzing, "validation navigateur du contexte JavaScript")
		var browserConfirmed bool
		var browserPayload string
		browserEvidence, browserConfirmed, browserPayload, err = m.validateInBrowser(ctx, moduleCtx, plan)
		if browserConfirmed {
			executor.Step(models.ActiveTestReproducing, "marqueur DOM reproduit dans deux rendus isolés")
			executor.Step(models.ActiveTestValidating, "preuve XSS JavaScript minimale validée")
			reason := fmt.Sprintf("la valeur est exécutée dans le contexte JavaScript %s et pose le marqueur DOM %q", suspect.Location, browserEvidence.Marker)
			result.Status = models.ActiveTestConfirmed
			result.Reason = reason
			result.Findings = []*models.Finding{buildXSSFinding(moduleCtx, plan.EntryPoint.Name, browserPayload, reason, nil)}
			result.MinimumConditionsMet = true
			executor.MarkMinimumProof()
			return finishXSSEvidence(result, executor, plan, *suspect, true, browserEvidence)
		}
		if ctx.Err() != nil {
			return finishXSSExchangeError(result, executor, ctx.Err())
		}
	}

	if limit := executor.LimitReached(); limit != "" {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "validation XSS interrompue par la limite " + limit
		result.LimitReached = limit
	} else if suspect != nil {
		result.Status = models.ActiveTestInconclusive
		result.Reason = fmt.Sprintf("la valeur %q est réfléchie dans %s (%s), mais la preuve n'est pas interprétable: %s", suspectPayload, suspect.Location, suspect.Encoding, suspect.Reason)
	} else {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "aucune réflexion exploitable détectée dans les contextes testés"
	}
	return finishXSSEvidence(result, executor, plan, observed, false, browserEvidence)
}

func finishXSSExchangeError(result *models.ActiveTestResult, executor *active.Executor, err error) *models.ActiveTestResult {
	if err == context.Canceled {
		result.Status = models.ActiveTestCancelled
	} else if err == context.DeadlineExceeded {
		result.Status = models.ActiveTestTimeout
	} else {
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "échange HTTP XSS interrompu: " + err.Error()
	return finishXSSEvidence(result, executor, models.ActiveTestPlan{}, reflectionAnalysis{}, false)
}

func finishXSSEvidence(result *models.ActiveTestResult, executor *active.Executor, plan models.ActiveTestPlan, analysis reflectionAnalysis, proof bool, browserEvidence ...*models.BrowserEvidence) *models.ActiveTestResult {
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
	contextName := analysis.Context
	encodingName := analysis.Encoding
	location := analysis.Location
	if contextName == "" {
		contextName = "non déterminé"
	}
	if encodingName == "" {
		encodingName = "non déterminé"
	}
	if location == "" {
		location = plan.EntryPoint.Name
	}
	var browserProof *models.BrowserEvidence
	if len(browserEvidence) > 0 {
		browserProof = browserEvidence[0]
	}
	result.Evidence = &models.ActiveEvidence{
		Expected:            "la valeur contrôlée doit être réfléchie dans un contexte interprétable et non correctement encodé",
		Observed:            fmt.Sprintf("contexte=%s, emplacement=%s, encodage=%s: %s", contextName, location, encodingName, result.Reason),
		Baseline:            executor.Baseline(),
		TestExchanges:       tests,
		Differences:         differences,
		Browser:             browserProof,
		ValidationRule:      "réflexion localisée + contexte interprétable + reproduction",
		Confidence:          xssConfidence(result.Status),
		Reproductions:       countXSSReproductions(tests),
		MinimumProofReached: proof,
		Conclusion:          result.Reason,
	}
	return result
}

func (m *Module) validateInBrowser(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan) (*models.BrowserEvidence, bool, string, error) {
	if moduleCtx == nil || moduleCtx.Asset == nil || strings.ToUpper(moduleCtx.Asset.Method) != http.MethodGet {
		return nil, false, "", nil
	}
	if plan.EntryPoint.Location != models.EntryPointQuery && plan.EntryPoint.Location != models.EntryPointPath {
		return nil, false, "", nil
	}

	marker := "auditcore-xss-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	payloads := []string{
		fmt.Sprintf("';document.documentElement.setAttribute('data-auditcore-marker','%s');//", marker),
		fmt.Sprintf(`";document.documentElement.setAttribute('data-auditcore-marker','%s');//`, marker),
	}

	var lastEvidence *models.BrowserEvidence
	for _, payload := range payloads {
		request, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, payload)
		if err != nil || request == nil || request.URL == nil {
			continue
		}
		origin := request.URL.Scheme + "://" + request.URL.Host
		runner := browser.New(browser.Config{
			AllowedOrigins: []string{origin},
			Timeout:        time.Duration(browserTimeout(moduleCtx.Options)) * time.Second,
			MaxPages:       1,
			MaxNavigations: 3,
			MaxDOMBytes:    128 * 1024,
		})
		first, firstErr := runner.Run(ctx, request.URL.String(), marker)
		lastEvidence = browserEvidenceFromResult(first, firstErr, marker, moduleCtx.Options)
		if firstErr != nil {
			continue
		}
		second, secondErr := runner.Run(ctx, request.URL.String(), marker)
		if second != nil {
			lastEvidence = browserEvidenceFromResult(second, secondErr, marker, moduleCtx.Options)
		}
		if secondErr != nil {
			continue
		}
		if first != nil && second != nil && first.MarkerObserved && second.MarkerObserved {
			if lastEvidence == nil {
				lastEvidence = browserEvidenceFromResult(second, nil, marker, moduleCtx.Options)
			}
			lastEvidence.Reproductions = 2
			return lastEvidence, true, payload, nil
		}
	}
	return lastEvidence, false, "", nil
}

func browserTimeout(options models.AuditOptions) int {
	if options.ActiveBrowserTimeoutSeconds > 0 {
		return options.ActiveBrowserTimeoutSeconds
	}
	return 10
}

func browserEvidenceFromResult(result *browser.Result, err error, marker string, options models.AuditOptions) *models.BrowserEvidence {
	evidence := &models.BrowserEvidence{Marker: marker}
	if err != nil {
		evidence.Error = browser.RedactText(active.RedactText(err.Error()))
	}
	if result == nil {
		return evidence
	}
	evidence.FinalURL = browser.RedactURL(active.RedactURL(result.FinalURL, options))
	evidence.FinalOrigin = browser.RedactURL(active.RedactURL(result.FinalOrigin, options))
	evidence.DOM = browser.RedactText(active.RedactText(result.DOM))
	evidence.Marker = result.Marker
	evidence.MarkerObserved = result.MarkerObserved
	evidence.Navigations = make([]string, 0, len(result.Navigations))
	for _, navigation := range result.Navigations {
		evidence.Navigations = append(evidence.Navigations, browser.RedactURL(active.RedactURL(navigation, options)))
	}
	evidence.BlockedURLs = make([]string, 0, len(result.BlockedURLs))
	for _, blocked := range result.BlockedURLs {
		evidence.BlockedURLs = append(evidence.BlockedURLs, browser.RedactURL(active.RedactURL(blocked, options)))
	}
	evidence.Events = make([]models.BrowserEventEvidence, 0, len(result.Events))
	for _, event := range result.Events {
		evidence.Events = append(evidence.Events, models.BrowserEventEvidence{
			Type: event.Type, URL: browser.RedactURL(active.RedactURL(event.URL, options)), Detail: browser.RedactText(active.RedactText(event.Detail)), At: event.At,
		})
	}
	return evidence
}

func xssConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func countXSSReproductions(exchanges []models.HTTPExchange) int {
	count := 0
	for _, exchange := range exchanges {
		if strings.Contains(exchange.Label, "reproduction") {
			count++
		}
	}
	return count
}

func lastXSSExchange(exchanges []models.HTTPExchange, kind string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if kind == "" || exchanges[i].Kind == kind {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func analyzeReflection(body string, headers map[string]string, payload string) reflectionAnalysis {
	analysis := reflectionAnalysis{}
	if payload == "" {
		return analysis
	}
	contentType := strings.ToLower(headers["Content-Type"])
	if contentType == "" {
		for key, value := range headers {
			if strings.EqualFold(key, "Content-Type") {
				contentType = strings.ToLower(value)
				break
			}
		}
	}
	index := strings.Index(body, payload)
	if index >= 0 {
		analysis.Reflected = true
		analysis.Encoding = "raw/non encodé"
		if strings.Contains(contentType, "json") || json.Valid([]byte(strings.TrimSpace(body))) {
			analysis.Context = "json"
			analysis.Location = "valeur JSON"
			analysis.Reason = "la valeur est présente dans une structure JSON, qui n'est pas interprétée comme HTML"
			return analysis
		}
		analysis.Context, analysis.Location = lexicalHTMLContext(body, index)
		analysis.Executable = executableHTMLContext(body, payload, analysis.Context)
		if analysis.Executable {
			analysis.Reason = "le DOM contient un élément script ou un attribut événementiel issu de l'entrée"
		} else if analysis.Context == "javascript" {
			analysis.Reason = "la valeur est dans du JavaScript, mais le payload actuel ne prouve pas une sortie de chaîne interprétable"
		} else {
			analysis.Reason = "la valeur est réfléchie mais aucun élément actif interprétable n'a été identifié"
		}
		return analysis
	}

	encoded := []struct {
		value string
		kind  string
	}{
		{value: html.EscapeString(payload), kind: "HTML échappé"},
		{value: strconv.Quote(payload), kind: "JSON échappé"},
		{value: jsonString(payload), kind: "JSON HTML échappé"},
		{value: url.QueryEscape(payload), kind: "URL encodé"},
		{value: url.PathEscape(payload), kind: "URL path encodé"},
	}
	for _, candidate := range encoded {
		if candidate.value == payload || !strings.Contains(body, candidate.value) {
			continue
		}
		analysis.Reflected = true
		analysis.Encoding = candidate.kind
		if strings.Contains(contentType, "json") || json.Valid([]byte(strings.TrimSpace(body))) {
			analysis.Context = "json"
			analysis.Location = "valeur JSON"
		} else {
			analysis.Context = "html-text"
			analysis.Location = "contenu HTML"
		}
		analysis.Reason = "la valeur a été transformée avant réflexion et ne forme pas un contenu actif brut"
		return analysis
	}
	return analysis
}

func jsonString(payload string) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}

var attributeContextPattern = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_.:-]*)\s*=\s*["'][^"']*$`)

func lexicalHTMLContext(body string, index int) (string, string) {
	lower := strings.ToLower(body)
	if scriptStart := strings.LastIndex(lower[:index], "<script"); scriptStart >= 0 && strings.Index(lower[scriptStart:index], ">") >= 0 {
		if strings.LastIndex(lower[:index], "</script>") < scriptStart {
			return "javascript", "bloc script"
		}
	}
	if styleStart := strings.LastIndex(lower[:index], "<style"); styleStart >= 0 && strings.Index(lower[styleStart:index], ">") >= 0 && strings.LastIndex(lower[:index], "</style>") < styleStart {
		return "css", "bloc style"
	}
	lastOpen := strings.LastIndex(body[:index], "<")
	lastClose := strings.LastIndex(body[:index], ">")
	if lastOpen > lastClose {
		tag := body[lastOpen:index]
		if match := attributeContextPattern.FindStringSubmatch(tag); len(match) == 2 {
			return "attribute", "attribut HTML " + strings.ToLower(match[1])
		}
		return "attribute", "attribut HTML"
	}
	return "html-text", "texte HTML"
}

func executableHTMLContext(body, payload, contextName string) bool {
	if contextName == "javascript" || contextName == "json" || contextName == "css" {
		return false
	}
	activePayload := strings.Contains(payload, "<script") || strings.Contains(strings.ToLower(payload), "onerror=") || strings.Contains(strings.ToLower(payload), "onload=") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(payload)), "javascript:")
	if !activePayload {
		return false
	}
	controlBody := strings.Replace(body, payload, "", 1)
	if controlBody == body {
		return false
	}
	return activeConstructCount(body, payload) > activeConstructCount(controlBody, payload)
}

func activeConstructCount(body, payload string) int {
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return 0
	}
	count := 0
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode {
			if node.Data == "script" && strings.Contains(strings.ToLower(payload), "<script") {
				count++
			}
			for _, attr := range node.Attr {
				key := strings.ToLower(attr.Key)
				value := strings.ToLower(attr.Val)
				if strings.HasPrefix(key, "on") && strings.Contains(value, "alert(1)") {
					count++
				}
				if key == "href" && strings.HasPrefix(strings.TrimSpace(value), "javascript:") {
					count++
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return count
}

func buildXSSFinding(ctx *models.ModuleContext, param, payload, reason string, exchange *models.HTTPExchange) *models.Finding {
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
		ID: uuid.NewString(), AuditRunID: ctx.AuditRunID, TaxonomyID: "WEB-XSS-002", Type: "xss-reflected",
		Title: fmt.Sprintf("Reflected XSS - paramètre %q", param), Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh,
		Status: models.FindingConfirmed, CWE: "CWE-79", OWASPCat: "A03:2021", ASVSMapping: "V5.3.3",
		Description: fmt.Sprintf("Le paramètre %q est réfléchi dans un contexte exploitable. %s", param, reason),
		Impact:      "Exécution de contenu JavaScript dans le navigateur selon le contexte de rendu.",
		Remediation: "Encoder les sorties selon leur contexte et appliquer une Content-Security-Policy stricte.",
		Replayable:  true, Endpoint: ctx.Asset.URL, Parameter: param, CreatedAt: time.Now(),
		Evidence: &models.Evidence{ID: uuid.NewString(), RequestRaw: requestLine, ResponseRaw: fmt.Sprintf("HTTP/1.1 %d\n\n%s", statusCode, snip(body, 500)), Payload: payload, MatcherResult: reason},
	}
}

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	// Tester uniquement les endpoints HTML (pas les API JSON pures)
	if ctx.Fingerprint != nil && ctx.Fingerprint.LooksLikeAPI {
		return result
	}

	params := ctx.Asset.Params
	if len(params) == 0 {
		params = sqli.ExtractURLParams(ctx.Asset.URL)
	}
	if len(params) == 0 {
		return result
	}

	for _, param := range params {
		for _, payload := range xssPayloads {
			req, probeURL, err := sqli.NewProbeRequest(ctx.Asset, param, payload)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "AuditCore/2.0")
			req.Header.Set("Accept", "text/html,application/xhtml+xml")

			resp, err := matchers.Fetch(client, req)
			if err != nil {
				continue
			}

			if hit, evidence := matchers.XSSReflected(resp, payload); hit {
				// Déterminer si le contexte permet l'exécution (confiance) :
				// <script> dans HTML = High, img onerror = Medium, js: = Medium
				confidence := models.ConfidenceMedium
				status := models.FindingSuspected
				if strings.Contains(payload, "<script>") {
					confidence = models.ConfidenceHigh
					status = models.FindingValidated
				}

				result.Findings = append(result.Findings, &models.Finding{
					ID:          uuid.NewString(),
					AuditRunID:  ctx.AuditRunID,
					TaxonomyID:  "WEB-XSS-002",
					Type:        "xss-reflected",
					Title:       fmt.Sprintf("Reflected XSS — paramètre %q", param),
					Severity:    models.SeverityHigh,
					Confidence:  confidence,
					Status:      status,
					CWE:         "CWE-79",
					OWASPCat:    "A03:2021",
					ASVSMapping: "V5.3.3",
					Description: fmt.Sprintf("Le paramètre %q de l'endpoint %s retourne le payload XSS sans encodage dans une réponse HTML. %s", param, ctx.Asset.URL, evidence),
					Impact:      "Exécution de JavaScript arbitraire dans le navigateur victime. Vol de session, redirection malveillante, keylogging.",
					Remediation: "Encoder systématiquement toutes les sorties HTML (htmlspecialchars ou équivalent). Implémenter une Content-Security-Policy stricte. Valider et assainir toutes les entrées.",
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
				break // Un finding par paramètre
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
