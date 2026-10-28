// Package ssrf détecte les Server-Side Request Forgery basiques.
package ssrf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
	"github.com/google/uuid"
)

// Cibles SSRF — metadata endpoints des cloud providers.
// Les anciennes cibles metadata/loopback ne sont plus utilisées par le chemin
// actif. Un test SSRF exige maintenant une destination de callback contrôlée.
var ssrfTargets = []string{}

// Paramètres typiquement vulnérables au SSRF.
var suspectParams = []string{
	"url", "webhook", "callback", "redirect", "src",
	"href", "path", "dest", "destination", "remote",
	"fetch", "load", "import", "endpoint", "service",
}

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "ssrf-basic" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.Name(), ctx, findings)
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestInconclusive, Reason: "aucun callback SSRF contrôlé configuré"}
	if moduleCtx == nil || moduleCtx.Asset == nil || plan.EntryPoint.Name == "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucun point d'entrée URL contrôlable"
		return result
	}
	if moduleCtx.Options.ActiveSSRFCallbackURL == "" || moduleCtx.Options.ActiveSSRFCallbackCheckURL == "" {
		return finishSSRFEvidence(result, executor, ssrfObservation{}, false)
	}

	token := uuid.NewString()
	callbackURL, checkURL, err := callbackPair(moduleCtx.Options, token)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "configuration callback invalide: " + err.Error()
		return finishSSRFEvidence(result, executor, ssrfObservation{Role: "initial", Token: token, CallbackURL: callbackURL, CheckURL: checkURL}, false)
	}
	initialObservation := ssrfObservation{Role: "initial", Token: token, CallbackURL: callbackURL, CheckURL: checkURL, Status: callbackStatusAbsent, WindowMillis: moduleCtx.Options.ActiveSSRFCallbackWindowMillis, PollIntervalMillis: moduleCtx.Options.ActiveSSRFCallbackPollIntervalMillis}

	baselineRequest, err := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête normale impossible à construire: " + err.Error()
		return finishSSRFEvidence(result, executor, initialObservation, false)
	}
	if _, err = executor.DoBaseline(baselineRequest); err != nil {
		return finishSSRFError(result, executor, initialObservation, err)
	}

	probeRequest, err := buildSSRFProbeRequest(moduleCtx.Asset, plan.EntryPoint.Name, callbackURL)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête SSRF impossible à construire: " + err.Error()
		return finishSSRFEvidence(result, executor, initialObservation, false)
	}
	// Une redirection HTTP de la cible ne doit pas être suivie par le scanner :
	// elle ne prouve pas que le serveur cible a émis la requête SSRF.
	_, err = executor.DoNoRedirect("test", "ssrf-callback:"+token, probeRequest)
	if err != nil {
		return finishSSRFError(result, executor, initialObservation, err)
	}
	testExchange := lastSSRFExchange(executor.Exchanges(), "test")
	observation := initialObservation
	if testExchange != nil && testExchange.Response != nil {
		observation.ResponseBody = testExchange.Response.BodyPreview
	}
	poll := waitForCallback(ctx, checkURL, token, callbackURL, moduleCtx.Options)
	applyCallbackPoll(&observation, poll)
	if ctx.Err() != nil {
		return finishSSRFError(result, executor, observation, ctx.Err())
	}
	if observation.CallbackObserved {
		executor.Step(models.ActiveTestReproducing, "premier callback SSRF observé, lancement d'une reproduction indépendante")
		reproductionToken := uuid.NewString()
		reproductionURL, reproductionCheckURL, reproductionErr := callbackPair(moduleCtx.Options, reproductionToken)
		reproduction := ssrfObservation{Role: "reproduction", Token: reproductionToken, CallbackURL: reproductionURL, CheckURL: reproductionCheckURL, Status: callbackStatusAbsent, WindowMillis: moduleCtx.Options.ActiveSSRFCallbackWindowMillis, PollIntervalMillis: moduleCtx.Options.ActiveSSRFCallbackPollIntervalMillis}
		if reproductionErr != nil {
			result.Status = models.ActiveTestInconclusive
			result.Reason = "premier callback observé, mais reproduction impossible: " + reproductionErr.Error()
			return finishSSRFEvidence(result, executor, observation, false, reproduction)
		}
		reproductionRequest, reproductionErr := buildSSRFProbeRequest(moduleCtx.Asset, plan.EntryPoint.Name, reproductionURL)
		if reproductionErr != nil {
			result.Status = models.ActiveTestInconclusive
			result.Reason = "premier callback observé, mais probe de reproduction impossible: " + reproductionErr.Error()
			return finishSSRFEvidence(result, executor, observation, false, reproduction)
		}
		_, reproductionErr = executor.DoNoRedirect("test", "ssrf-reproduction:"+reproductionToken, reproductionRequest)
		if reproductionErr != nil {
			result.Status = models.ActiveTestInconclusive
			result.Reason = "premier callback observé, mais reproduction non exécutable: " + reproductionErr.Error()
			return finishSSRFEvidence(result, executor, observation, false, reproduction)
		}
		reproductionPoll := waitForCallback(ctx, reproductionCheckURL, reproductionToken, reproductionURL, moduleCtx.Options)
		applyCallbackPoll(&reproduction, reproductionPoll)
		if ctx.Err() != nil {
			return finishSSRFError(result, executor, observation, ctx.Err(), reproduction)
		}
		if reproduction.CallbackObserved {
			executor.Step(models.ActiveTestValidating, "deux callbacks SSRF observés avec deux tokens indépendants")
			reason := fmt.Sprintf("deux callbacks contrôlés ont été observés avec les tokens indépendants %s et %s", token, reproductionToken)
			result.Status = models.ActiveTestConfirmed
			result.Reason = reason
			result.Findings = []*models.Finding{buildSSRFFinding(moduleCtx, plan.EntryPoint.Name, reproductionURL, reason, lastSSRFExchange(executor.Exchanges(), "test"))}
			result.MinimumConditionsMet = true
			executor.MarkMinimumProof()
			return finishSSRFEvidence(result, executor, observation, true, reproduction)
		}
		result.Status = models.ActiveTestInconclusive
		result.Reason = "un premier callback SSRF a été observé, mais la reproduction indépendante a échoué (" + reproduction.Status + ")"
		return finishSSRFEvidence(result, executor, observation, false, reproduction)
	}
	if moduleCtx.Options.ActiveSSRFCallbackMarker != "" && strings.Contains(observation.ResponseBody, moduleCtx.Options.ActiveSSRFCallbackMarker) {
		observation.DirectProof = true
		executor.Step(models.ActiveTestValidating, "marqueur de réponse callback observé directement")
		reason := "la réponse cible contient le marqueur unique retourné par la ressource callback contrôlée"
		result.Status = models.ActiveTestConfirmed
		result.Reason = reason
		result.Findings = []*models.Finding{buildSSRFFinding(moduleCtx, plan.EntryPoint.Name, callbackURL, reason, testExchange)}
		result.MinimumConditionsMet = true
		executor.MarkMinimumProof()
		return finishSSRFEvidence(result, executor, observation, true)
	}

	result.Status = models.ActiveTestInconclusive
	result.Reason = "l'URL est acceptée ou réfléchie, mais aucun callback réel ni preuve directe équivalente n'a été observé"
	return finishSSRFEvidence(result, executor, observation, false)
}

type ssrfObservation struct {
	Role                string
	Token               string
	CallbackURL         string
	CheckURL            string
	Status              string
	CallbackObserved    bool
	DirectProof         bool
	CallbackBody        string
	ResponseBody        string
	CheckError          string
	Polls               int
	PollTrace           []models.CallbackPollEvidence
	ObservedDestination string
	ObservedHost        string
	ObservedAddress     string
	WindowMillis        int
	PollIntervalMillis  int
}

const (
	callbackStatusObserved   = "observed"
	callbackStatusAbsent     = "absent"
	callbackStatusMismatched = "mismatched"
	callbackStatusInvalid    = "invalid"
	callbackStatusTimeout    = "timeout"
	callbackStatusFailed     = "failed"
)

type callbackPollResult struct {
	Observed            bool
	Status              string
	Body                string
	Error               string
	ObservedDestination string
	ObservedHost        string
	ObservedAddress     string
	PollTrace           []models.CallbackPollEvidence
}

type callbackInspection struct {
	Observed            bool
	Status              string
	Proof               string
	ObservedDestination string
	ObservedHost        string
	ObservedAddress     string
}

func callbackPair(options models.AuditOptions, token string) (string, string, error) {
	callbackURL, err := callbackURLForToken(options.ActiveSSRFCallbackURL, token)
	if err != nil {
		return "", "", errors.New("URL callback invalide: " + err.Error())
	}
	checkURL, err := callbackURLForToken(options.ActiveSSRFCallbackCheckURL, token)
	if err != nil {
		return callbackURL, "", errors.New("URL de vérification callback invalide: " + err.Error())
	}
	if err := validateCallbackURL(callbackURL, options.ActiveSSRFAllowPrivateCallback); err != nil {
		return callbackURL, checkURL, errors.New("callback refusé hors périmètre contrôlé: " + err.Error())
	}
	if err := validateCallbackURL(checkURL, options.ActiveSSRFAllowPrivateCallback); err != nil {
		return callbackURL, checkURL, errors.New("endpoint de vérification callback refusé: " + err.Error())
	}
	return callbackURL, checkURL, nil
}

func callbackURLForToken(template, token string) (string, error) {
	if strings.Contains(template, "{token}") {
		return strings.ReplaceAll(template, "{token}", url.QueryEscape(token)), nil
	}
	parsed, err := url.Parse(template)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("URL absolue attendue")
	}
	query := parsed.Query()
	query.Set("auditcore_token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validateCallbackURL(raw string, allowPrivate bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return errors.New("URL absolue http(s) attendue")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("schéma callback non autorisé")
	}
	if allowPrivate {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("hôte local/interne refusé par défaut")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return errors.New("adresse privée ou link-local refusée par défaut")
	}
	return nil
}

func buildSSRFProbeRequest(asset *models.Asset, param, callbackURL string) (*http.Request, error) {
	location := models.EntryPointQuery
	if !strings.EqualFold(asset.Method, http.MethodGet) {
		location = models.EntryPointForm
		bodyType := strings.ToLower(asset.BodyType)
		if strings.Contains(bodyType, "json") || strings.Contains(bodyType, "graphql") {
			location = models.EntryPointJSON
		} else if strings.Contains(bodyType, "xml") {
			location = models.EntryPointXML
		} else if strings.Contains(bodyType, "multipart") {
			location = models.EntryPointMultipart
		}
	}
	entry := models.EntryPoint{Endpoint: asset.URL, Method: asset.Method, Name: param, Location: location, OriginalValue: callbackURL, BodyType: asset.BodyType}
	return active.BuildProbeRequest(asset, entry, callbackURL)
}

func waitForCallback(ctx context.Context, checkURL, token, callbackURL string, options models.AuditOptions) callbackPollResult {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	window := options.ActiveSSRFCallbackWindowMillis
	if window <= 0 {
		window = 500
	}
	interval := options.ActiveSSRFCallbackPollIntervalMillis
	if interval <= 0 {
		interval = 100
	}
	maxPolls := options.ActiveSSRFCallbackMaxPolls
	if maxPolls <= 0 {
		maxPolls = 6
	}
	pollContext, cancel := context.WithTimeout(ctx, time.Duration(window)*time.Millisecond)
	defer cancel()
	result := callbackPollResult{Status: callbackStatusAbsent}
	for attempt := 1; attempt <= maxPolls; attempt++ {
		request, err := http.NewRequestWithContext(pollContext, http.MethodGet, checkURL, nil)
		if err != nil {
			result.Status = callbackStatusFailed
			result.Error = err.Error()
			return result
		}
		response, err := client.Do(request)
		if err != nil {
			result.PollTrace = append(result.PollTrace, models.CallbackPollEvidence{Attempt: attempt, Status: callbackStatusFailed})
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				result.Status = callbackStatusTimeout
				result.Error = err.Error()
				return result
			}
			result.Status = callbackStatusFailed
			result.Error = err.Error()
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		_ = response.Body.Close()
		bodyText := string(body)
		inspection := inspectCallbackBody(bodyText, token, callbackURL)
		pollEvidence := models.CallbackPollEvidence{Attempt: attempt, StatusCode: response.StatusCode, Status: inspection.Status, Body: active.RedactText(snip(bodyText, 512))}
		result.PollTrace = append(result.PollTrace, pollEvidence)
		result.Body = bodyText
		result.Status = inspection.Status
		result.ObservedDestination = inspection.ObservedDestination
		result.ObservedHost = inspection.ObservedHost
		result.ObservedAddress = inspection.ObservedAddress
		if readErr != nil {
			result.Status = callbackStatusInvalid
			result.Error = readErr.Error()
		} else if inspection.Observed {
			result.Observed = true
			return result
		} else if inspection.Status == callbackStatusMismatched {
			return result
		}
		if attempt < maxPolls {
			timer := time.NewTimer(time.Duration(interval) * time.Millisecond)
			select {
			case <-pollContext.Done():
				timer.Stop()
				if ctx.Err() != nil {
					result.Status = callbackStatusTimeout
					result.Error = ctx.Err().Error()
				} else {
					result.Status = callbackStatusTimeout
					result.Error = context.DeadlineExceeded.Error()
				}
				return result
			case <-timer.C:
			}
		}
	}
	if pollContext.Err() != nil {
		result.Status = callbackStatusTimeout
		if result.Error == "" {
			result.Error = pollContext.Err().Error()
		}
	}
	return result
}

func callbackBodyConfirms(body, token string) bool {
	return inspectCallbackBody(body, token, "").Observed
}

func inspectCallbackBody(body, token, callbackURL string) callbackInspection {
	var payload map[string]any
	if json.Unmarshal([]byte(body), &payload) == nil {
		inspection := callbackInspection{Status: callbackStatusAbsent, Proof: body}
		for _, key := range []string{"destination", "requested_url", "target", "url"} {
			if value, ok := payload[key].(string); ok && value != "" {
				inspection.ObservedDestination = value
				break
			}
		}
		for _, key := range []string{"hostname", "host", "remote_host"} {
			if value, ok := payload[key].(string); ok && value != "" {
				inspection.ObservedHost = value
				break
			}
		}
		for _, key := range []string{"address", "remote_addr", "ip"} {
			if value, ok := payload[key].(string); ok && value != "" {
				inspection.ObservedAddress = value
				break
			}
		}
		if inspection.ObservedDestination != "" && callbackURL != "" {
			expected, expectedErr := url.Parse(callbackURL)
			observed, observedErr := url.Parse(inspection.ObservedDestination)
			if expectedErr != nil || observedErr != nil || !strings.EqualFold(expected.Hostname(), observed.Hostname()) {
				inspection.Status = callbackStatusMismatched
				return inspection
			}
		}
		for _, key := range []string{"observed", "received", "matched", "callback_received"} {
			if value, ok := payload[key].(bool); ok && value {
				for _, tokenKey := range []string{"token", "auditcore_token", "callback_token"} {
					if observedToken, ok := payload[tokenKey].(string); ok && observedToken != token {
						inspection.Status = callbackStatusMismatched
						return inspection
					}
				}
				inspection.Observed = true
				inspection.Status = callbackStatusObserved
				return inspection
			}
		}
		// Un JSON valide qui ne confirme pas l'observation ne doit pas etre
		// valide uniquement parce qu'il reflete le token de la requete.
		if token != "" && (strings.Contains(body, token) || strings.Contains(body, "mismatched")) {
			inspection.Status = callbackStatusMismatched
		}
		return inspection
	}
	if token != "" && strings.Contains(body, token) {
		return callbackInspection{Observed: true, Status: callbackStatusObserved, Proof: body}
	}
	return callbackInspection{Status: callbackStatusInvalid, Proof: body}
}

func applyCallbackPoll(observation *ssrfObservation, poll callbackPollResult) {
	if observation == nil {
		return
	}
	observation.Status = poll.Status
	observation.CallbackObserved = poll.Observed
	observation.CallbackBody = poll.Body
	observation.CheckError = poll.Error
	observation.Polls = len(poll.PollTrace)
	observation.PollTrace = poll.PollTrace
	observation.ObservedDestination = poll.ObservedDestination
	observation.ObservedHost = poll.ObservedHost
	observation.ObservedAddress = poll.ObservedAddress
}

func lastSSRFExchange(exchanges []models.HTTPExchange, kind string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if exchanges[i].Kind == kind {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func finishSSRFError(result *models.ActiveTestResult, executor *active.Executor, observation ssrfObservation, err error, extra ...ssrfObservation) *models.ActiveTestResult {
	if errors.Is(err, context.Canceled) {
		result.Status = models.ActiveTestCancelled
	} else if errors.Is(err, context.DeadlineExceeded) {
		result.Status = models.ActiveTestTimeout
	} else {
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "échange HTTP SSRF interrompu: " + err.Error()
	return finishSSRFEvidence(result, executor, observation, false, extra...)
}

func finishSSRFEvidence(result *models.ActiveTestResult, executor *active.Executor, observation ssrfObservation, proof bool, extra ...ssrfObservation) *models.ActiveTestResult {
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
	callbackProof := observation.CallbackBody
	if observation.DirectProof {
		callbackProof = observation.ResponseBody
	}
	callbackProof = active.RedactText(snip(callbackProof, 2000))
	observations := append([]ssrfObservation{observation}, extra...)
	var callbackObservations []models.CallbackObservationEvidence
	totalPolls := 0
	for _, item := range observations {
		if item.Token == "" && item.CallbackURL == "" && item.CheckURL == "" {
			continue
		}
		totalPolls += item.Polls
		proofText := item.CallbackBody
		if item.DirectProof {
			proofText = item.ResponseBody
		}
		callbackObservations = append(callbackObservations, models.CallbackObservationEvidence{
			Role:                item.Role,
			Token:               item.Token,
			CallbackURL:         item.CallbackURL,
			CheckURL:            item.CheckURL,
			Status:              item.Status,
			Observed:            item.CallbackObserved,
			Polls:               item.Polls,
			Proof:               active.RedactText(snip(proofText, 2000)),
			Error:               active.RedactText(item.CheckError),
			ObservedDestination: item.ObservedDestination,
			ObservedHost:        item.ObservedHost,
			ObservedAddress:     item.ObservedAddress,
			PollTrace:           item.PollTrace,
		})
	}
	result.Evidence = &models.ActiveEvidence{
		Expected:                   "un callback unique doit être observé par le collecteur ou un marqueur direct contrôlé doit être retourné par la cible",
		Observed:                   result.Reason,
		CallbackToken:              observation.Token,
		CallbackURL:                observation.CallbackURL,
		CallbackCheckURL:           observation.CheckURL,
		CallbackObserved:           observation.CallbackObserved,
		CallbackProof:              callbackProof,
		CallbackError:              active.RedactText(observation.CheckError),
		CallbackObservations:       callbackObservations,
		CallbackPolls:              totalPolls,
		CallbackWindowMillis:       observation.WindowMillis,
		CallbackPollIntervalMillis: observation.PollIntervalMillis,
		Baseline:                   executor.Baseline(),
		TestExchanges:              tests,
		Differences:                differences,
		ValidationRule:             "acceptation/reflet/redirection insuffisants sans observation hors bande ou preuve directe équivalente",
		Confidence:                 ssrfConfidence(result.Status),
		Reproductions:              countSSRFReproductions(tests),
		MinimumProofReached:        proof,
		Conclusion:                 result.Reason,
	}
	return result
}

func ssrfConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func countSSRFReproductions(exchanges []models.HTTPExchange) int {
	count := 0
	for _, exchange := range exchanges {
		if strings.Contains(exchange.Label, "reproduction") {
			count++
		}
	}
	return count
}

func buildSSRFFinding(ctx *models.ModuleContext, param, callbackURL, reason string, exchange *models.HTTPExchange) *models.Finding {
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
		ID: uuid.NewString(), AuditRunID: ctx.AuditRunID, TaxonomyID: "WEB-SSRF-001", Type: "ssrf-out-of-band",
		Title: fmt.Sprintf("SSRF via parameter %q", param), Severity: models.SeverityCritical, Confidence: models.ConfidenceHigh,
		Status: models.FindingConfirmed, CWE: "CWE-918", OWASPCat: "A10:2021", ASVSMapping: "V12.6.1",
		Description: fmt.Sprintf("Le serveur cible a émis une requête vers le callback contrôlé %s. %s", callbackURL, reason),
		Impact:      "Requêtes serveur vers des ressources contrôlées par un attaquant et risque d'accès à des services non exposés.",
		Remediation: "Valider les URLs, appliquer une allowlist stricte et bloquer les adresses privées, loopback, link-local et metadata.",
		Replayable:  true, Endpoint: ctx.Asset.URL, Parameter: param, CreatedAt: time.Now(),
		Evidence: &models.Evidence{ID: uuid.NewString(), RequestRaw: requestLine, ResponseRaw: fmt.Sprintf("HTTP/1.1 %d\n\n%s", statusCode, snip(body, 500)), Payload: callbackURL, MatcherResult: reason},
	}
}

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}

	params := ctx.Asset.Params
	if len(params) == 0 {
		params = extractParams(ctx.Asset.URL)
	}

	// Identifier les paramètres suspects de SSRF
	var targets []string
	for _, p := range params {
		pLower := strings.ToLower(p)
		for _, s := range suspectParams {
			if pLower == s || strings.Contains(pLower, s) {
				targets = append(targets, p)
				break
			}
		}
	}

	if len(targets) == 0 {
		return result
	}

	for _, param := range targets {
		for _, probeTarget := range ssrfTargets {
			var resp *matchers.Response
			var probeURL string
			var err error

			// Adapter selon la méthode HTTP de l'asset
			if ctx.Asset.Method == "POST" {
				resp, probeURL, err = probePost(client, ctx.Asset.URL, param, probeTarget)
			} else {
				probeURL = injectParam(ctx.Asset.URL, param, probeTarget)
				req, reqErr := http.NewRequest("GET", probeURL, nil)
				if reqErr != nil {
					continue
				}
				req.Header.Set("User-Agent", "AuditCore/2.0")
				resp, err = matchers.Fetch(client, req)
			}

			if err != nil {
				continue
			}

			if hit, evidence := matchers.SSRF(resp); hit {
				result.Findings = append(result.Findings, &models.Finding{
					ID:          uuid.NewString(),
					AuditRunID:  ctx.AuditRunID,
					TaxonomyID:  "WEB-SSRF-001",
					Type:        "ssrf-internal-request",
					Title:       fmt.Sprintf("SSRF — accès réseau interne via paramètre %q", param),
					Severity:    models.SeverityCritical,
					Confidence:  models.ConfidenceHigh,
					Status:      models.FindingConfirmed,
					CWE:         "CWE-918",
					OWASPCat:    "A10:2021",
					ASVSMapping: "V12.6.1",
					Description: fmt.Sprintf("Le paramètre %q permet d'effectuer des requêtes HTTP côté serveur vers des ressources internes. Cible testée : %s. %s", param, probeTarget, evidence),
					Impact:      "Accès aux metadata cloud (credentials IAM), scan du réseau interne, accès à des services non exposés publiquement. Peut permettre l'exfiltration de credentials d'infrastructure.",
					Remediation: "Valider et filtrer les URLs fournies par les utilisateurs. Bloquer les plages IP privées (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x). Utiliser une liste blanche de domaines autorisés. Ne pas faire confiance aux redirections.",
					Replayable:  true,
					Endpoint:    probeURL,
					Parameter:   param,
					CreatedAt:   time.Now(),
					Evidence: &models.Evidence{
						ID:            uuid.NewString(),
						RequestRaw:    fmt.Sprintf("%s %s HTTP/1.1\n(param %s = %s)", ctx.Asset.Method, ctx.Asset.URL, param, probeTarget),
						ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, snip(resp.Body, 400)),
						Payload:       probeTarget,
						MatcherResult: evidence,
					},
				})
				goto nextParam // Un finding par paramètre suffit
			}
		}
	nextParam:
	}
	return result
}

func probePost(client *http.Client, endpoint, param, probeTarget string) (*matchers.Response, string, error) {
	body := fmt.Sprintf(`{"%s":"%s"}`, param, probeTarget)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(body))
	if err != nil {
		return nil, endpoint, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AuditCore/2.0")
	resp, err := matchers.Fetch(client, req)
	return resp, endpoint, err
}

func injectParam(baseURL, param, value string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func extractParams(rawURL string) []string {
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

func snip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
