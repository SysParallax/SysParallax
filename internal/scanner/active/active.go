// Package active fournit le contrat commun et l'instrumentation des tests actifs.
// Les modules restent responsables de leur logique de test ; ce package centralise
// la traçabilité, les limites, la baseline, la normalisation et l'annulation.
package active

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

var (
	ErrRequestBudget = errors.New("active request budget reached")
	ErrPhaseStopped  = errors.New("active phase stopped")
	ErrProofReached  = errors.New("minimum active proof reached")
)

// Module est le nouveau contrat des modules actifs. Run reste disponible dans
// les modules pour conserver la compatibilité avec les modules passifs/tests.
type Module interface {
	Name() string
	Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan
	RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *Executor) *models.ActiveTestResult
}

type Budget struct {
	mu          sync.Mutex
	perEndpoint map[string]int
	perModule   map[string]int
	maxEndpoint int
	maxModule   int
}

func NewBudget(options models.AuditOptions) *Budget {
	return &Budget{
		perEndpoint: make(map[string]int),
		perModule:   make(map[string]int),
		maxEndpoint: options.ActiveMaxRequestsPerEndpoint,
		maxModule:   options.ActiveMaxRequestsPerModule,
	}
}

func (b *Budget) reserve(endpoint, module string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxEndpoint > 0 && b.perEndpoint[endpoint] >= b.maxEndpoint {
		return false
	}
	if b.maxModule > 0 && b.perModule[module] >= b.maxModule {
		return false
	}
	b.perEndpoint[endpoint]++
	b.perModule[module]++
	return true
}

type contextKey string

const (
	exchangeKindKey  contextKey = "auditcore-active-exchange-kind"
	exchangeLabelKey contextKey = "auditcore-active-exchange-label"
)

// Executor instrumente un client existant. Il conserve les échanges sans
// changer la logique de payload des modules appelants.
type Executor struct {
	ctx          context.Context
	options      models.AuditOptions
	testID       string
	module       string
	entry        models.EntryPoint
	budget       *Budget
	base         *http.Client
	client       *http.Client
	step         func(models.ActiveTestStatus, string)
	mu           sync.Mutex
	exchanges    []models.HTTPExchange
	baseline     *models.Baseline
	requests     int
	responses    int
	limit        string
	repetitions  map[string]int
	proofReached bool
}

func NewExecutor(ctx context.Context, base *http.Client, options models.AuditOptions, testID, module string, entry models.EntryPoint, budget *Budget, step func(models.ActiveTestStatus, string)) *Executor {
	if base == nil {
		base = &http.Client{Transport: http.DefaultTransport}
	}
	if budget == nil {
		budget = NewBudget(options)
	}
	e := &Executor{
		ctx: ctx, options: options, testID: testID, module: module,
		entry: entry, budget: budget, base: base, step: step, repetitions: make(map[string]int),
	}
	client := *base
	client.Transport = &recordingTransport{executor: e, base: base.Transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		max := options.ActiveMaxRedirects
		if max <= 0 {
			max = 5
		}
		if len(via) >= max {
			e.mu.Lock()
			e.limit = "max_redirects"
			e.mu.Unlock()
			return http.ErrUseLastResponse
		}
		return nil
	}
	e.client = &client
	return e
}

func (e *Executor) Client() *http.Client { return e.client }

func (e *Executor) Requests() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests
}

func (e *Executor) Responses() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.responses
}

func (e *Executor) LimitReached() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.limit
}

// MarkMinimumProof demande l'arrêt de toute nouvelle probe pour ce test.
// Les modules spécialisés pourront l'appeler dès qu'une preuve suffisante est obtenue.
func (e *Executor) MarkMinimumProof() {
	e.mu.Lock()
	e.proofReached = true
	e.mu.Unlock()
}

func (e *Executor) ProofReached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.proofReached
}

// Step permet à un module spécialisé de publier une étape métier précise.
func (e *Executor) Step(status models.ActiveTestStatus, message string) {
	if e.step != nil {
		e.step(status, message)
	}
}

func (e *Executor) CompareExchange(exchange models.HTTPExchange) []models.ResponseDifference {
	return e.compare(exchange)
}

func (e *Executor) Exchanges() []models.HTTPExchange {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]models.HTTPExchange(nil), e.exchanges...)
}

func (e *Executor) Baseline() *models.Baseline {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.baseline == nil {
		return nil
	}
	copyBaseline := *e.baseline
	copyBaseline.Exchanges = append([]models.HTTPExchange(nil), e.baseline.Exchanges...)
	return &copyBaseline
}

func (e *Executor) EvidenceFor(result *models.ActiveTestResult) *models.ActiveEvidence {
	if result == nil || e.Requests() == 0 {
		return nil
	}
	return e.buildEvidence(models.ActiveTestPlan{EntryPoint: e.entry}, result, result.Status == models.ActiveTestConfirmed)
}

func (e *Executor) Do(kind, label string, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("nil active request")
	}
	if e.ProofReached() {
		return nil, ErrProofReached
	}
	if e.LimitReached() != "" {
		return nil, ErrRequestBudget
	}
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, exchangeKindKey, kind)
	ctx = context.WithValue(ctx, exchangeLabelKey, label)
	return e.client.Do(req.WithContext(ctx))
}

// DoNoRedirect exécute un échange HTTP sans laisser net/http suivre la
// redirection. Un module peut ainsi inspecter chaque hop et suivre uniquement
// les destinations internes à la cible.
func (e *Executor) DoNoRedirect(kind, label string, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("nil active request")
	}
	if e.ProofReached() {
		return nil, ErrProofReached
	}
	if e.LimitReached() != "" {
		return nil, ErrRequestBudget
	}
	client := *e.client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, exchangeKindKey, kind)
	ctx = context.WithValue(ctx, exchangeLabelKey, label)
	return client.Do(req.WithContext(ctx))
}

func (e *Executor) DoBaseline(req *http.Request) (*http.Response, error) {
	resp, err := e.Do("baseline", "reference request", req)
	if err == nil {
		e.mu.Lock()
		var exchanges []models.HTTPExchange
		for _, exchange := range e.exchanges {
			if exchange.Kind == "baseline" {
				exchanges = append(exchanges, exchange)
			}
		}
		hash := ""
		stable := len(exchanges) > 0
		if len(exchanges) > 0 && exchanges[len(exchanges)-1].Response != nil {
			hash = exchanges[len(exchanges)-1].Response.NormalizedHash
		}
		if len(exchanges) > 1 {
			stable = exchanges[len(exchanges)-1].Response != nil && exchanges[len(exchanges)-2].Response != nil &&
				exchanges[len(exchanges)-1].Response.NormalizedHash == exchanges[len(exchanges)-2].Response.NormalizedHash
		}
		e.baseline = &models.Baseline{Exchanges: exchanges, Stable: stable, NormalizedHash: hash}
		e.mu.Unlock()
	}
	return resp, err
}

func (e *Executor) compare(exchange models.HTTPExchange) []models.ResponseDifference {
	baseline := e.Baseline()
	if baseline == nil || len(baseline.Exchanges) == 0 || exchange.Response == nil {
		return nil
	}
	baseResp := baseline.Exchanges[len(baseline.Exchanges)-1].Response
	diffs := make([]models.ResponseDifference, 0, 3)
	if baseResp.StatusCode != exchange.Response.StatusCode {
		diffs = append(diffs, models.ResponseDifference{Metric: "status_code", Baseline: strconv.Itoa(baseResp.StatusCode), Observed: strconv.Itoa(exchange.Response.StatusCode), Significant: true, Explanation: "codes HTTP différents"})
	}
	if baseResp.NormalizedHash != exchange.Response.NormalizedHash {
		diffs = append(diffs, models.ResponseDifference{Metric: "normalized_body", Baseline: baseResp.NormalizedHash, Observed: exchange.Response.NormalizedHash, Significant: true, Explanation: "contenu normalisé différent"})
	}
	if baseResp.BodySize != exchange.Response.BodySize {
		diffs = append(diffs, models.ResponseDifference{Metric: "body_size", Baseline: strconv.FormatInt(baseResp.BodySize, 10), Observed: strconv.FormatInt(exchange.Response.BodySize, 10), Significant: false, Explanation: "taille brute différente"})
	}
	return diffs
}

// RunLegacy adapte temporairement un module existant au nouveau contrat. Les
// modules conservent leurs payloads et leur logique, mais leur exécution est
// désormais contextualisée, limitée et documentée par une conclusion explicite.
func (e *Executor) RunLegacy(module interface {
	Run(*models.ModuleContext, *http.Client) *models.ModuleResult
}, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestFailed, Reason: "test non finalisé"}
	plannedCtx := *moduleCtx
	plannedCtx.Asset = AssetForPlan(moduleCtx.Asset, plan.EntryPoint)

	baselineReq, err := BuildRequest(plannedCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "point d'entrée non constructible: " + err.Error()
		return result
	}
	if _, err = e.DoBaseline(baselineReq); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			result.Status = models.ActiveTestTimeout
			result.Reason = "requête de référence interrompue: " + err.Error()
		} else {
			result.Status = models.ActiveTestFailed
			result.Reason = "requête de référence échouée: " + err.Error()
		}
		return e.finishResult(result, nil)
	}

	legacyResult := module.Run(&plannedCtx, e.Client())
	if legacyResult == nil {
		result.Status = models.ActiveTestFailed
		result.Reason = "le module a retourné un résultat vide"
		return e.finishResult(result, nil)
	}
	if legacyResult.Error != nil {
		if errors.Is(legacyResult.Error, context.DeadlineExceeded) || errors.Is(legacyResult.Error, context.Canceled) {
			result.Status = models.ActiveTestTimeout
		} else {
			result.Status = models.ActiveTestFailed
		}
		result.Reason = legacyResult.Error.Error()
		return e.finishResult(result, nil)
	}

	result.Findings = legacyResult.Findings
	result.RequestCount = e.Requests()
	result.ResponseCount = e.Responses()
	result.Executed = result.RequestCount > 0
	result.Analyzed = result.ResponseCount > 0
	if limit := e.LimitReached(); limit != "" {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "limite d'exécution atteinte: " + limit
		result.LimitReached = limit
		return e.finishResult(result, legacyResult.Findings)
	}
	if result.RequestCount == 0 {
		result.Status = models.ActiveTestUntestable
		result.Reason = "aucune requête pertinente n'a été envoyée"
		return e.finishResult(result, legacyResult.Findings)
	}
	if result.ResponseCount == 0 {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "des requêtes ont été envoyées mais aucune réponse exploitable n'a été reçue"
		return e.finishResult(result, legacyResult.Findings)
	}

	status := models.ActiveTestNotConfirmed
	reason := "test exécuté et analysé sans preuve suffisante"
	minimalProof := false
	for _, finding := range legacyResult.Findings {
		if finding == nil {
			continue
		}
		switch finding.Status {
		case models.FindingConfirmed, models.FindingValidated:
			if finding.Evidence != nil {
				status = models.ActiveTestConfirmed
				reason = "le module a fourni un finding validé avec une preuve"
				minimalProof = true
			}
		case models.FindingSuspected:
			if status != models.ActiveTestConfirmed {
				status = models.ActiveTestInconclusive
				reason = "comportement suspect sans preuve suffisante"
			}
		}
	}
	result.Status = status
	result.Reason = reason
	result.Analyzed = true
	result.MinimumConditionsMet = result.Executed && result.Analyzed
	result.LimitReached = ""
	result.Evidence = e.buildEvidence(plan, result, minimalProof)
	return e.finishResult(result, legacyResult.Findings)
}

func (e *Executor) buildEvidence(plan models.ActiveTestPlan, result *models.ActiveTestResult, minimumProof bool) *models.ActiveEvidence {
	exchanges := e.Exchanges()
	baseline := e.Baseline()
	var diffs []models.ResponseDifference
	for _, exchange := range exchanges {
		if exchange.Kind != "baseline" {
			diffs = append(diffs, e.compare(exchange)...)
		}
	}
	return &models.ActiveEvidence{
		Expected:            "le comportement de référence doit rester cohérent hors condition testée",
		Observed:            fmt.Sprintf("%d échange(s) enregistré(s), %d réponse(s)", result.RequestCount, result.ResponseCount),
		Baseline:            baseline,
		TestExchanges:       exchanges,
		Differences:         diffs,
		ValidationRule:      "conclusion explicite du module + requête et réponse observées",
		Confidence:          confidenceForStatus(result.Status),
		Reproductions:       0,
		MinimumProofReached: minimumProof,
		Conclusion:          result.Reason,
	}
}

func (e *Executor) finishResult(result *models.ActiveTestResult, findings []*models.Finding) *models.ActiveTestResult {
	result.RequestCount = e.Requests()
	result.ResponseCount = e.Responses()
	result.Executed = result.RequestCount > 0
	result.Analyzed = result.ResponseCount > 0
	if result.Evidence == nil && result.Executed {
		result.Evidence = e.buildEvidence(models.ActiveTestPlan{EntryPoint: e.entry}, result, false)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		SanitizeFinding(finding, e.options)
	}
	return result
}

func confidenceForStatus(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

type recordingTransport struct {
	executor *Executor
	base     http.RoundTripper
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	e := t.executor
	if err := e.ctx.Err(); err != nil {
		return nil, err
	}
	if e.ProofReached() {
		return nil, ErrProofReached
	}
	if e.LimitReached() != "" {
		return nil, ErrRequestBudget
	}
	if e.options.ActiveMaxRequestsPerTest > 0 && e.Requests() >= e.options.ActiveMaxRequestsPerTest {
		e.mu.Lock()
		e.limit = "max_requests_per_test"
		e.mu.Unlock()
		return nil, ErrRequestBudget
	}
	endpoint := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	if !e.budget.reserve(endpoint, e.module) {
		e.mu.Lock()
		if e.budget.maxEndpoint > 0 {
			e.limit = "max_requests_per_endpoint"
		} else {
			e.limit = "max_requests_per_module"
		}
		e.mu.Unlock()
		return nil, ErrRequestBudget
	}

	started := time.Now()
	kind, _ := req.Context().Value(exchangeKindKey).(string)
	if kind == "" {
		kind = "test"
	}
	label, _ := req.Context().Value(exchangeLabelKey).(string)
	requestBody, reqCopy := readRequest(req)
	fingerprint := req.Method + "\n" + RedactURL(req.URL.String(), e.options) + "\n" + RedactText(requestBody)
	e.mu.Lock()
	e.repetitions[fingerprint]++
	repetition := e.repetitions[fingerprint]
	e.mu.Unlock()
	if e.options.ActiveMaxRepetitions > 0 && repetition > e.options.ActiveMaxRepetitions {
		e.mu.Lock()
		e.limit = "max_repetitions"
		e.mu.Unlock()
		return nil, ErrRequestBudget
	}
	if t.executor.step != nil {
		if kind == "baseline" {
			t.executor.step(models.ActiveTestBaselineRequestSent, label)
		} else {
			t.executor.step(models.ActiveTestTestRequestSent, label)
		}
	}
	e.mu.Lock()
	e.requests++
	e.mu.Unlock()

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(reqCopy.WithContext(e.ctx))
	finished := time.Now()
	exchange := models.HTTPExchange{
		Kind: kind, Label: label,
		Request:   models.HTTPRequestRecord{Method: req.Method, URL: RedactURL(req.URL.String(), e.options), Headers: SanitizeHeaders(req.Header, e.options), Body: RedactText(requestBody)},
		StartedAt: started, FinishedAt: finished,
	}
	if err != nil {
		exchange.Error = err.Error()
		e.appendExchange(exchange)
		return nil, err
	}
	body, readErr := readResponse(resp, e.options.ActiveMaxResponseBytes)
	if readErr != nil {
		exchange.Error = readErr.Error()
	}
	normalized := NormalizeBody(string(body))
	exchange.Response = &models.HTTPResponseRecord{
		StatusCode:        resp.StatusCode,
		Headers:           SanitizeHeaders(resp.Header, e.options),
		BodyPreview:       RedactText(string(body)),
		BodySize:          int64(len(body)),
		DurationMillis:    finished.Sub(started).Milliseconds(),
		NormalizedHash:    Hash(normalized),
		NormalizedPreview: RedactText(normalized),
	}
	e.mu.Lock()
	e.responses++
	e.mu.Unlock()
	e.appendExchange(exchange)
	if e.step != nil {
		if kind == "baseline" {
			e.step(models.ActiveTestBaselineResponseReceived, fmt.Sprintf("HTTP %d", resp.StatusCode))
		} else {
			e.step(models.ActiveTestTestResponseReceived, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func (e *Executor) appendExchange(exchange models.HTTPExchange) {
	e.mu.Lock()
	e.exchanges = append(e.exchanges, exchange)
	e.mu.Unlock()
}

func readRequest(req *http.Request) (string, *http.Request) {
	if req.Body == nil {
		return "", req
	}
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	copyReq := req.Clone(req.Context())
	copyReq.Body = io.NopCloser(bytes.NewReader(body))
	return string(body), copyReq
}

func readResponse(resp *http.Response, max int64) ([]byte, error) {
	if max <= 0 {
		max = 256 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	_ = resp.Body.Close()
	if int64(len(body)) > max {
		body = body[:max]
		return body, errors.New("response body limit reached")
	}
	return body, err
}

// BuildRequest construit la requête de référence ou de probe. Il reste le
// point d'entrée historique ; la logique commune est dans BuildProbeRequest.
func BuildRequest(asset *models.Asset, entry models.EntryPoint, value string) (*http.Request, error) {
	return BuildProbeRequest(asset, entry, value)
}

// BuildProbeRequest modifie exactement un emplacement d'entrée sans changer
// le reste de la requête. Les corps bruts permettent de préserver les JSON
// imbriqués, XML et multipart fournis par un collecteur d'assets.
func BuildProbeRequest(asset *models.Asset, entry models.EntryPoint, value string) (*http.Request, error) {
	if asset == nil {
		return nil, errors.New("asset absent")
	}
	method := asset.Method
	if method == "" {
		method = http.MethodGet
	}
	if entry.Method != "" {
		method = entry.Method
	}
	endpoint := entry.Endpoint
	if endpoint == "" {
		endpoint = asset.URL
	}
	location := entry.Location
	if location == "" {
		location = inferEntryPointLocation(asset, method)
	}

	headers := copyStringMap(asset.Headers)
	cookies := copyStringMap(asset.Cookies)
	var body io.Reader
	contentType := ""

	switch location {
	case models.EntryPointQuery:
		var err error
		endpoint, err = replaceQueryValue(endpoint, entry.Name, value)
		if err != nil {
			return nil, err
		}
	case models.EntryPointPath:
		var err error
		endpoint, err = replacePathValue(endpoint, entry.Name, value)
		if err != nil {
			return nil, err
		}
	case models.EntryPointHeader:
		if strings.TrimSpace(entry.Name) == "" {
			return nil, errors.New("nom de header absent")
		}
		headers[entry.Name] = value
	case models.EntryPointCookie:
		if strings.TrimSpace(entry.Name) == "" {
			return nil, errors.New("nom de cookie absent")
		}
		cookies[entry.Name] = value
	case models.EntryPointForm:
		var err error
		body, contentType, err = buildFormBody(asset, entry.Name, value)
		if err != nil {
			return nil, err
		}
	case models.EntryPointJSON, models.EntryPointGraphQL:
		var err error
		body, contentType, err = buildJSONBody(asset, entry.Name, value)
		if err != nil {
			return nil, err
		}
	case models.EntryPointXML:
		var err error
		body, contentType, err = buildXMLBody(asset, entry.Name, value)
		if err != nil {
			return nil, err
		}
	case models.EntryPointMultipart:
		var err error
		body, contentType, err = buildMultipartBody(asset, entry.Name, value)
		if err != nil {
			return nil, err
		}
	default:
		if isBodyMethod(method) {
			body, contentType = bodyFromAsset(asset)
		}
	}
	if body == nil && isBodyMethod(method) && location != models.EntryPointForm && location != models.EntryPointJSON && location != models.EntryPointGraphQL && location != models.EntryPointXML && location != models.EntryPointMultipart {
		body, contentType = bodyFromAsset(asset)
	}

	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	for key, headerValue := range headers {
		request.Header.Set(key, headerValue)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for name, cookieValue := range cookies {
		if strings.TrimSpace(name) != "" {
			request.AddCookie(&http.Cookie{Name: name, Value: cookieValue})
		}
	}
	return request, nil
}

func inferEntryPointLocation(asset *models.Asset, method string) models.EntryPointLocation {
	bodyType := strings.ToLower(strings.TrimSpace(asset.BodyType))
	switch {
	case strings.Contains(bodyType, "graphql"):
		return models.EntryPointGraphQL
	case strings.Contains(bodyType, "xml"):
		return models.EntryPointXML
	case strings.Contains(bodyType, "multipart"):
		return models.EntryPointMultipart
	case strings.Contains(bodyType, "json"):
		return models.EntryPointJSON
	case isBodyMethod(method):
		return models.EntryPointForm
	default:
		return models.EntryPointQuery
	}
}

func isBodyMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func bodyFromAsset(asset *models.Asset) (io.Reader, string) {
	if asset.BodyRaw != "" {
		return strings.NewReader(asset.BodyRaw), contentTypeForAsset(asset)
	}
	if len(asset.BodyTemplate) == 0 {
		return nil, ""
	}
	form := url.Values{}
	keys := make([]string, 0, len(asset.BodyTemplate))
	for key := range asset.BodyTemplate {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		form.Set(key, asset.BodyTemplate[key])
	}
	return strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
}

func buildFormBody(asset *models.Asset, parameter, value string) (io.Reader, string, error) {
	form := url.Values{}
	if asset.BodyRaw != "" {
		parsed, err := url.ParseQuery(asset.BodyRaw)
		if err != nil {
			return nil, "", fmt.Errorf("form body invalide: %w", err)
		}
		form = parsed
	} else {
		for key, original := range asset.BodyTemplate {
			form.Set(key, original)
		}
	}
	if strings.TrimSpace(parameter) == "" {
		return nil, "", errors.New("paramètre de formulaire absent")
	}
	form.Set(parameter, value)
	return strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", nil
}

func buildJSONBody(asset *models.Asset, parameter, value string) (io.Reader, string, error) {
	var document any
	if asset.BodyRaw != "" {
		if err := json.Unmarshal([]byte(asset.BodyRaw), &document); err != nil {
			return nil, "", fmt.Errorf("JSON body invalide: %w", err)
		}
	} else {
		root := make(map[string]any, len(asset.BodyTemplate))
		for key, original := range asset.BodyTemplate {
			if err := setJSONPath(root, key, original); err != nil {
				return nil, "", err
			}
		}
		document = root
	}
	if strings.TrimSpace(parameter) == "" {
		return nil, "", errors.New("paramètre JSON absent")
	}
	if err := setJSONPath(document, parameter, value); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, "", err
	}
	contentType := contentTypeForAsset(asset)
	if contentType == "" {
		contentType = "application/json"
	}
	return bytes.NewReader(encoded), contentType, nil
}

func setJSONPath(document any, path, value any) error {
	tokens := jsonPathTokens(fmt.Sprint(path))
	if len(tokens) == 0 {
		return errors.New("chemin JSON absent")
	}
	return setJSONTokens(document, tokens, value)
}

func jsonPathTokens(path string) []string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.ReplaceAll(path, "[", ".")
	path = strings.ReplaceAll(path, "]", "")
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '.' || r == '/' })
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			result = append(result, strings.TrimSpace(part))
		}
	}
	return result
}

func setJSONTokens(current any, tokens []string, value any) error {
	if len(tokens) == 0 {
		return errors.New("chemin JSON incomplet")
	}
	switch node := current.(type) {
	case map[string]any:
		key := tokens[0]
		if len(tokens) == 1 {
			node[key] = value
			return nil
		}
		next, ok := node[key]
		if !ok {
			if _, err := strconv.Atoi(tokens[1]); err == nil {
				return fmt.Errorf("tableau JSON absent pour le chemin %q", strings.Join(tokens, "."))
			}
			next = make(map[string]any)
			node[key] = next
		}
		return setJSONTokens(next, tokens[1:], value)
	case []any:
		index, err := strconv.Atoi(tokens[0])
		if err != nil || index < 0 || index >= len(node) {
			return fmt.Errorf("index de tableau JSON invalide: %q", tokens[0])
		}
		if len(tokens) == 1 {
			node[index] = value
			return nil
		}
		return setJSONTokens(node[index], tokens[1:], value)
	default:
		return fmt.Errorf("chemin JSON non modifiable: %q", strings.Join(tokens, "."))
	}
}

func buildXMLBody(asset *models.Asset, parameter, value string) (io.Reader, string, error) {
	if asset.BodyRaw == "" {
		return nil, "", errors.New("corps XML absent")
	}
	updated, err := replaceXMLValue([]byte(asset.BodyRaw), parameter, value)
	if err != nil {
		return nil, "", err
	}
	contentType := contentTypeForAsset(asset)
	if contentType == "" {
		contentType = "application/xml"
	}
	return bytes.NewReader(updated), contentType, nil
}

func replaceXMLValue(raw []byte, parameter, value string) ([]byte, error) {
	target := jsonPathTokens(parameter)
	if len(target) == 0 {
		return nil, errors.New("chemin XML absent")
	}
	attribute := ""
	if strings.HasPrefix(target[len(target)-1], "@") {
		attribute = strings.TrimPrefix(target[len(target)-1], "@")
		target = target[:len(target)-1]
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	stack := make([]string, 0, len(target))
	replaced := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("XML body invalide: %w", err)
		}
		switch item := token.(type) {
		case xml.StartElement:
			stack = append(stack, item.Name.Local)
			if attribute != "" && xmlPathMatches(stack, target) {
				for i := range item.Attr {
					if item.Attr[i].Name.Local == attribute {
						item.Attr[i].Value = value
						replaced = true
					}
				}
			}
			token = item
		case xml.CharData:
			if attribute == "" && xmlPathMatches(stack, target) && !replaced {
				item = xml.CharData(value)
				replaced = true
			}
			token = item
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
		if err := encoder.EncodeToken(token); err != nil {
			return nil, err
		}
	}
	if err := encoder.Flush(); err != nil {
		return nil, err
	}
	if !replaced {
		return nil, fmt.Errorf("chemin XML introuvable: %s", parameter)
	}
	return output.Bytes(), nil
}

func xmlPathMatches(stack, target []string) bool {
	if len(stack) < len(target) {
		return false
	}
	start := len(stack) - len(target)
	for i := range target {
		if !strings.EqualFold(stack[start+i], target[i]) {
			return false
		}
	}
	return true
}

func buildMultipartBody(asset *models.Asset, parameter, value string) (io.Reader, string, error) {
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	if asset.BodyRaw != "" {
		contentType := contentTypeForAsset(asset)
		_, params, err := mime.ParseMediaType(contentType)
		if err != nil || params["boundary"] == "" {
			return nil, "", errors.New("boundary multipart absent")
		}
		reader := multipart.NewReader(strings.NewReader(asset.BodyRaw), params["boundary"])
		for {
			part, readErr := reader.NextPart()
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return nil, "", fmt.Errorf("multipart body invalide: %w", readErr)
			}
			partBody, readErr := io.ReadAll(io.LimitReader(part, 8*1024*1024))
			if readErr != nil {
				return nil, "", readErr
			}
			if part.FormName() == parameter && part.FileName() == "" {
				partBody = []byte(value)
			}
			created, createErr := writer.CreatePart(part.Header)
			if createErr != nil {
				return nil, "", createErr
			}
			if _, writeErr := created.Write(partBody); writeErr != nil {
				return nil, "", writeErr
			}
		}
	} else {
		keys := make([]string, 0, len(asset.BodyTemplate))
		for key := range asset.BodyTemplate {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		found := false
		for _, key := range keys {
			fieldValue := asset.BodyTemplate[key]
			if key == parameter {
				fieldValue = value
				found = true
			}
			if err := writer.WriteField(key, fieldValue); err != nil {
				return nil, "", err
			}
		}
		if !found && parameter != "" {
			if err := writer.WriteField(parameter, value); err != nil {
				return nil, "", err
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return bytes.NewReader(output.Bytes()), writer.FormDataContentType(), nil
}

func replaceQueryValue(rawURL, parameter, value string) (string, error) {
	if strings.TrimSpace(parameter) == "" {
		return rawURL, errors.New("paramètre query absent")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}
	query := parsed.Query()
	query.Set(parameter, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func replacePathValue(rawURL, parameter, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	index := -1
	if strings.HasPrefix(parameter, "path[") && strings.HasSuffix(parameter, "]") {
		index, err = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(parameter, "path["), "]"))
	} else {
		for i, part := range parts {
			if part == parameter {
				index = i
				break
			}
		}
	}
	if err != nil || index < 0 || index >= len(parts) {
		return rawURL, fmt.Errorf("segment de chemin introuvable: %s", parameter)
	}
	parts[index] = value
	parsed.Path = "/" + strings.Join(parts, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func contentTypeForAsset(asset *models.Asset) string {
	for key, value := range asset.Headers {
		if strings.EqualFold(key, "Content-Type") {
			return value
		}
	}
	bodyType := strings.TrimSpace(asset.BodyType)
	if strings.Contains(strings.ToLower(bodyType), "/") {
		return bodyType
	}
	switch strings.ToLower(bodyType) {
	case "json", "graphql":
		return "application/json"
	case "xml":
		return "application/xml"
	case "multipart":
		return "multipart/form-data"
	case "form", "form-urlencoded":
		return "application/x-www-form-urlencoded"
	default:
		return ""
	}
}

func copyStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func AssetForPlan(asset *models.Asset, entry models.EntryPoint) *models.Asset {
	if asset == nil {
		return nil
	}
	copyAsset := *asset
	copyAsset.Params = nil
	if entry.Name != "" {
		copyAsset.Params = []string{entry.Name}
	}
	copyAsset.BodyTemplate = make(map[string]string, len(asset.BodyTemplate))
	for key, value := range asset.BodyTemplate {
		copyAsset.BodyTemplate[key] = value
	}
	copyAsset.Cookies = copyStringMap(asset.Cookies)
	return &copyAsset
}

func PlansForModule(module string, ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	if ctx == nil || ctx.Asset == nil {
		return nil
	}
	params := entryPointParameters(ctx.Asset)
	sort.Strings(params)
	var plans []models.ActiveTestPlan
	for _, rawParam := range unique(params) {
		location, param := entryPointSpec(rawParam, ctx.Asset)
		if !relevant(module, param) {
			continue
		}
		original := originalEntryValue(ctx.Asset, location, param)
		entry := models.EntryPoint{Endpoint: ctx.Asset.URL, Method: ctx.Asset.Method, Name: param, Location: location, OriginalValue: original, BodyType: ctx.Asset.BodyType}
		plans = append(plans, models.ActiveTestPlan{EntryPoint: entry, SourceFindingID: sourceFindingID(module, ctx.Asset.ID, param, findings), Reason: "point d'entrée pertinent pour " + module})
	}
	if module == "idor-simple" && len(plans) == 0 {
		if pathEntry, ok := pathIDEntry(ctx.Asset); ok {
			plans = append(plans, models.ActiveTestPlan{EntryPoint: pathEntry, SourceFindingID: sourceFindingID(module, ctx.Asset.ID, pathEntry.Name, findings), Reason: "identifiant dynamique détecté dans le chemin"})
		}
	}
	return plans
}

func relevant(module, param string) bool {
	p := strings.ToLower(entryPointLeafName(param))
	switch module {
	case "sqli-detection", "xss-reflected":
		return p != ""
	case "path-traversal":
		return containsAny(p, "file", "path", "dir", "folder", "include", "page", "template", "view", "load", "doc", "document", "img", "image")
	case "ssrf-basic":
		return containsAny(p, "url", "uri", "uri", "host", "hostname", "remote", "webhook", "callback", "image", "feed", "source", "proxy", "dest")
	case "open-redirect":
		return containsAny(p, "next", "url", "redirect", "return", "continue", "dest", "destination", "callback")
	case "idor-simple":
		return containsAny(p, "id", "user_id", "account_id", "order_id", "item_id", "product_id", "doc_id", "tenant")
	default:
		return false
	}
}

func entryPointParameters(asset *models.Asset) []string {
	params := append([]string(nil), asset.Params...)
	if len(params) > 0 {
		return params
	}
	if parsed, err := url.Parse(asset.URL); err == nil {
		for name := range parsed.Query() {
			params = append(params, name)
		}
	}
	if len(params) == 0 {
		for name := range asset.BodyTemplate {
			params = append(params, name)
		}
	}
	if len(params) == 0 && asset.BodyRaw != "" {
		bodyType := strings.ToLower(asset.BodyType)
		if strings.Contains(bodyType, "json") || strings.Contains(bodyType, "graphql") {
			params = append(params, jsonLeafPaths(asset.BodyRaw, strings.Contains(bodyType, "graphql"))...)
		} else if strings.Contains(bodyType, "xml") {
			params = append(params, xmlLeafPaths(asset.BodyRaw)...)
		}
	}
	return unique(params)
}

func entryPointSpec(raw string, asset *models.Asset) (models.EntryPointLocation, string) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)
	prefixes := []struct {
		prefix   string
		location models.EntryPointLocation
	}{
		{"header:", models.EntryPointHeader},
		{"cookie:", models.EntryPointCookie},
		{"query:", models.EntryPointQuery},
		{"form:", models.EntryPointForm},
		{"json:", models.EntryPointJSON},
		{"graphql:", models.EntryPointGraphQL},
		{"xml:", models.EntryPointXML},
		{"multipart:", models.EntryPointMultipart},
	}
	for _, candidate := range prefixes {
		if strings.HasPrefix(lower, candidate.prefix) {
			return candidate.location, trimmed[len(candidate.prefix):]
		}
	}
	if strings.HasPrefix(lower, "path[") {
		return models.EntryPointPath, trimmed
	}
	if asset != nil {
		return inferEntryPointLocation(asset, asset.Method), trimmed
	}
	return models.EntryPointQuery, trimmed
}

func entryPointLeafName(parameter string) string {
	parameter = strings.TrimSpace(parameter)
	if index := strings.LastIndexAny(parameter, "./"); index >= 0 {
		parameter = parameter[index+1:]
	}
	parameter = strings.Trim(parameter, "[]")
	return parameter
}

func originalEntryValue(asset *models.Asset, location models.EntryPointLocation, parameter string) string {
	switch location {
	case models.EntryPointHeader:
		for name, value := range asset.Headers {
			if strings.EqualFold(name, parameter) {
				return value
			}
		}
	case models.EntryPointCookie:
		return asset.Cookies[parameter]
	case models.EntryPointPath:
		if parsed, err := url.Parse(asset.URL); err == nil {
			parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
			if strings.HasPrefix(parameter, "path[") && strings.HasSuffix(parameter, "]") {
				if index, parseErr := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(parameter, "path["), "]")); parseErr == nil && index >= 0 && index < len(parts) {
					return parts[index]
				}
			}
		}
	case models.EntryPointJSON, models.EntryPointGraphQL:
		if asset.BodyRaw != "" {
			if document, err := decodeJSON(asset.BodyRaw); err == nil {
				if value, ok := getJSONPath(document, parameter); ok {
					return fmt.Sprint(value)
				}
			}
		}
	}
	if parsed, err := url.Parse(asset.URL); err == nil {
		return parsed.Query().Get(parameter)
	}
	return asset.BodyTemplate[parameter]
}

func decodeJSON(raw string) (any, error) {
	var document any
	err := json.Unmarshal([]byte(raw), &document)
	return document, err
}

func getJSONPath(document any, path string) (any, bool) {
	tokens := jsonPathTokens(path)
	current := document
	for _, token := range tokens {
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[token]
			if !ok {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) {
				return nil, false
			}
			current = node[index]
		default:
			return nil, false
		}
	}
	return current, len(tokens) > 0
}

func jsonLeafPaths(raw string, graphql bool) []string {
	document, err := decodeJSON(raw)
	if err != nil {
		return nil
	}
	var paths []string
	var walk func(any, string)
	walk = func(value any, prefix string) {
		switch node := value.(type) {
		case map[string]any:
			for key, child := range node {
				path := key
				if prefix != "" {
					path = prefix + "." + key
				}
				if graphql && prefix == "" && key != "variables" {
					continue
				}
				walk(child, path)
			}
		case []any:
			for index, child := range node {
				walk(child, fmt.Sprintf("%s[%d]", prefix, index))
			}
		default:
			if prefix != "" {
				paths = append(paths, prefix)
			}
		}
	}
	walk(document, "")
	return unique(paths)
}

func xmlLeafPaths(raw string) []string {
	decoder := xml.NewDecoder(strings.NewReader(raw))
	stack := []string{}
	paths := []string{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil
		}
		switch item := token.(type) {
		case xml.StartElement:
			stack = append(stack, item.Name.Local)
		case xml.CharData:
			if len(stack) > 0 && strings.TrimSpace(string(item)) != "" {
				paths = append(paths, strings.Join(stack, "."))
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return unique(paths)
}

func pathIDEntry(asset *models.Asset) (models.EntryPoint, bool) {
	parsed, err := url.Parse(asset.URL)
	if err != nil {
		return models.EntryPoint{}, false
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i, part := range parts {
		if _, err := strconv.Atoi(part); err == nil {
			parts[i] = part
			return models.EntryPoint{Endpoint: asset.URL, Method: asset.Method, Name: "path[" + strconv.Itoa(i) + "]", Location: models.EntryPointPath, OriginalValue: part}, true
		}
	}
	return models.EntryPoint{}, false
}

func sourceFindingID(module, assetID, param string, findings []*models.Finding) string {
	for _, finding := range findings {
		if finding == nil || finding.AssetID != assetID {
			continue
		}
		if finding.Parameter == param || strings.Contains(strings.ToLower(finding.Type), strings.TrimSuffix(module, "-detection")) {
			return finding.ID
		}
	}
	return ""
}

func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

var dynamicPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)?\b`),
	regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`),
	regexp.MustCompile(`(?i)(csrf|xsrf|request[_-]?id|trace[_-]?id|nonce|token)(["'\s:=]+)[^\s"'&<]+`),
	regexp.MustCompile(`(?i)\b(session|sid|phpsessid|connect\.sid)=([^;\s]+)`),
}

func NormalizeBody(body string) string {
	result := strings.TrimSpace(body)
	for _, pattern := range dynamicPatterns {
		result = pattern.ReplaceAllString(result, "$1=<dynamic>")
	}
	return result
}

func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func SanitizeHeaders(headers http.Header, options models.AuditOptions) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		value := strings.Join(values, ", ")
		if sensitiveKey(key, options) {
			value = "[REDACTED]"
		}
		result[key] = value
	}
	return result
}

func RedactURL(raw string, options models.AuditOptions) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return RedactText(raw)
	}
	query := parsed.Query()
	for key := range query {
		if sensitiveKey(key, options) {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}

func RedactText(value string) string {
	result := value
	result = regexp.MustCompile(`(?i)(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+`).ReplaceAllString(result, "$1[REDACTED]")
	result = regexp.MustCompile(`(?i)(authorization|proxy-authorization|password|passwd|secret|token|api[_-]?key|csrf[_-]?token|session[_-]?id)(\s*[=:]\s*)([^&\s,;"'}]+)`).ReplaceAllString(result, "$1$2[REDACTED]")
	result = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+`).ReplaceAllString(result, "$1[REDACTED]")
	result = regexp.MustCompile(`(?i)(Cookie\s*:\s*|Set-Cookie\s*:\s*)[^\r\n]+`).ReplaceAllString(result, "$1[REDACTED]")
	return result
}

func sensitiveKey(key string, options models.AuditOptions) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "authorization" || lower == "proxy-authorization" || strings.Contains(lower, "cookie") {
		return true
	}
	for _, configured := range options.SensitiveHeaders {
		if strings.EqualFold(strings.TrimSpace(configured), key) {
			return true
		}
	}
	return containsAny(lower, "token", "secret", "password", "passwd", "api-key", "apikey", "csrf")
}

func SanitizeFinding(finding *models.Finding, options models.AuditOptions) {
	if finding == nil {
		return
	}
	finding.Endpoint = RedactURL(finding.Endpoint, options)
	if finding.Evidence == nil {
		return
	}
	finding.Evidence.RequestRaw = RedactText(finding.Evidence.RequestRaw)
	finding.Evidence.ResponseRaw = RedactText(finding.Evidence.ResponseRaw)
	finding.Evidence.Payload = RedactText(finding.Evidence.Payload)
	finding.Evidence.MatcherResult = RedactText(finding.Evidence.MatcherResult)
}
