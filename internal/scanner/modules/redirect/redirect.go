package redirect

import (
	"context"
	"errors"
	"fmt"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/auditcore/auditcore/internal/scanner/matchers"
	"github.com/auditcore/auditcore/internal/scanner/modules/sqli"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var redirectParams = []string{"next", "url", "redirect", "redirect_url", "return", "return_to", "continue", "dest", "destination", "callback"}

const probeTarget = "https://auditcore-open-redirect.example.com/"

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "open-redirect" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.Name(), ctx, findings)
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestFailed, Reason: "validation open redirect non finalisée"}
	if moduleCtx == nil || moduleCtx.Asset == nil || !strings.EqualFold(moduleCtx.Asset.Method, http.MethodGet) || plan.EntryPoint.Name == "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = "le point d'entrée n'est pas un paramètre GET de redirection"
		return result
	}

	baselineRequest, err := active.BuildRequest(moduleCtx.Asset, plan.EntryPoint, plan.EntryPoint.OriginalValue)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête de référence impossible à construire: " + err.Error()
		return result
	}
	if _, err = executor.DoNoRedirect("baseline", "reference request", baselineRequest); err != nil {
		return finishRedirectError(result, executor, err)
	}

	probeRequest, err := active.BuildProbeRequest(moduleCtx.Asset, plan.EntryPoint, probeTarget)
	if err != nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "requête de probe impossible à construire: " + err.Error()
		return finishRedirectEvidence(result, executor, redirectObservation{}, false)
	}
	probeRequest = probeRequest.WithContext(ctx)
	probeURL := probeRequest.URL.String()
	probeRequest.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")

	baseOrigin := requestOrigin(moduleCtx.Asset.URL)
	targetOrigin := requestOrigin(probeTarget)
	trace, traceErr := followHTTPChain(ctx, executor, probeRequest, baseOrigin, targetOrigin, "probe", moduleCtx.Options.ActiveMaxRedirects)
	if traceErr != nil {
		return finishRedirectError(result, executor, traceErr)
	}
	if trace.TargetMatched && trace.StaticType == "" {
		// Rejouer exactement la chaîne permet d'écarter une redirection isolée.
		reproduceRequest, reproduceErr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if reproduceErr == nil {
			reproduced, reproducedErr := followHTTPChain(ctx, executor, reproduceRequest, baseOrigin, targetOrigin, "reproduction", moduleCtx.Options.ActiveMaxRedirects)
			if reproducedErr == nil && sameRedirectTrace(trace, reproduced) {
				executor.Step(models.ActiveTestReproducing, "chaîne HTTP externe reproduite")
				executor.Step(models.ActiveTestValidating, "destination finale externe validée")
				reason := fmt.Sprintf("la chaîne HTTP atteint l'origine externe %s après %d hop(s)", trace.FinalOrigin, len(trace.Chain)-1)
				result.Status = models.ActiveTestConfirmed
				result.Reason = reason
				result.Findings = []*models.Finding{buildRedirectFinding(moduleCtx, plan.EntryPoint.Name, probeURL, reason, trace)}
				result.MinimumConditionsMet = true
				executor.MarkMinimumProof()
				return finishRedirectEvidence(result, executor, trace, true)
			}
		}
		result.Status = models.ActiveTestInconclusive
		result.Reason = "une destination externe contrôlée a été observée mais la chaîne n'a pas pu être reproduite"
		return finishRedirectEvidence(result, executor, trace, false)
	}

	if trace.StaticType != "" {
		if trace.TargetMatched {
			result.Status = models.ActiveTestInconclusive
			result.Reason = fmt.Sprintf("une redirection %s vers %s est présente, mais elle n'a pas été exécutée par un navigateur", trace.StaticType, trace.FinalOrigin)
		} else {
			result.Status = models.ActiveTestNotConfirmed
			result.Reason = fmt.Sprintf("une redirection %s a été détectée mais sa destination finale n'est pas l'origine de contrôle", trace.StaticType)
		}
	} else if trace.Displayed {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "la destination contrôlée est seulement affichée dans la réponse"
	} else if trace.FinalOrigin == baseOrigin {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "la chaîne reste sur l'origine légitime après normalisation"
	} else {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "aucune redirection externe contrôlée n'a été observée"
	}
	return finishRedirectEvidence(result, executor, trace, false)
}

type redirectObservation struct {
	FinalURL      string
	FinalOrigin   string
	Chain         []string
	RedirectType  string
	TargetMatched bool
	StaticType    string
	Displayed     bool
	Body          string
}

func followHTTPChain(ctx context.Context, executor *active.Executor, initial *http.Request, baseOrigin, targetOrigin, label string, configuredMaxHops int) (redirectObservation, error) {
	observation := redirectObservation{Chain: []string{initial.URL.String()}, RedirectType: "http"}
	current := initial
	visited := map[string]bool{initial.URL.String(): true}
	maxHops := configuredMaxHops
	if maxHops <= 0 {
		maxHops = 5
	}
	for hop := 0; hop <= maxHops; hop++ {
		response, err := executor.DoNoRedirect("test", fmt.Sprintf("%s-hop-%d", label, hop), current)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return observation, err
			}
			return observation, fmt.Errorf("hop HTTP %d échoué: %w", hop, err)
		}
		if response == nil {
			return observation, errors.New("réponse de redirection absente")
		}
		body := ""
		if exchange := lastRedirectExchange(executor.Exchanges(), "test"); exchange != nil && exchange.Response != nil {
			body = exchange.Response.BodyPreview
		}
		observation.Body = body
		if response.StatusCode < 300 || response.StatusCode >= 400 {
			observation.FinalURL = current.URL.String()
			observation.FinalOrigin = requestOrigin(observation.FinalURL)
			if staticURL, kind := detectStaticRedirect(body); staticURL != "" {
				resolved, resolveErr := current.URL.Parse(staticURL)
				if resolveErr == nil {
					observation.FinalURL = resolved.String()
					observation.FinalOrigin = requestOrigin(observation.FinalURL)
					observation.StaticType = kind
					observation.TargetMatched = observation.FinalOrigin == targetOrigin
				}
			} else if strings.Contains(body, probeTarget) {
				observation.Displayed = true
			}
			return observation, nil
		}

		location := response.Header.Get("Location")
		if location == "" {
			observation.FinalURL = current.URL.String()
			observation.FinalOrigin = requestOrigin(observation.FinalURL)
			if strings.Contains(body, probeTarget) {
				observation.Displayed = true
			}
			return observation, nil
		}
		next, resolveErr := current.URL.Parse(location)
		if resolveErr != nil || next.Scheme == "" || next.Host == "" {
			return observation, fmt.Errorf("Location invalide: %q", location)
		}
		observation.Chain = append(observation.Chain, next.String())
		observation.FinalURL = next.String()
		observation.FinalOrigin = requestOrigin(next.String())
		if observation.FinalOrigin == targetOrigin {
			observation.TargetMatched = true
			return observation, nil
		}
		if observation.FinalOrigin != baseOrigin {
			return observation, nil
		}
		if visited[next.String()] {
			return observation, fmt.Errorf("boucle de redirection détectée vers %s", next.String())
		}
		if hop == maxHops {
			return observation, fmt.Errorf("limite de redirections atteinte")
		}
		visited[next.String()] = true
		current, err = http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
		if err != nil {
			return observation, err
		}
	}
	return observation, errors.New("chaîne de redirection incomplète")
}

func sameRedirectTrace(left, right redirectObservation) bool {
	if left.FinalOrigin != right.FinalOrigin || left.TargetMatched != right.TargetMatched || len(left.Chain) != len(right.Chain) {
		return false
	}
	for i := range left.Chain {
		if left.Chain[i] != right.Chain[i] {
			return false
		}
	}
	return true
}

func requestOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" || (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		return strings.ToLower(parsed.Scheme) + "://" + host
	}
	return strings.ToLower(parsed.Scheme) + "://" + host + ":" + port
}

var (
	jsRedirectPattern   = regexp.MustCompile(`(?is)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.replace\(\s*["']([^"']+)["']\s*\)`)
	metaRedirectPattern = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"';>]+)`)
)

func detectStaticRedirect(body string) (string, string) {
	if match := jsRedirectPattern.FindStringSubmatch(body); len(match) > 0 {
		for _, value := range match[1:] {
			if value != "" {
				return strings.TrimSpace(value), "javascript"
			}
		}
	}
	if match := metaRedirectPattern.FindStringSubmatch(body); len(match) == 2 {
		return strings.TrimSpace(match[1]), "html-meta-refresh"
	}
	return "", ""
}

func lastRedirectExchange(exchanges []models.HTTPExchange, kind string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if exchanges[i].Kind == kind {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func finishRedirectError(result *models.ActiveTestResult, executor *active.Executor, err error) *models.ActiveTestResult {
	if errors.Is(err, context.Canceled) {
		result.Status = models.ActiveTestCancelled
	} else if errors.Is(err, context.DeadlineExceeded) {
		result.Status = models.ActiveTestTimeout
	} else {
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "échange de redirection interrompu: " + err.Error()
	return finishRedirectEvidence(result, executor, redirectObservation{}, false)
}

func finishRedirectEvidence(result *models.ActiveTestResult, executor *active.Executor, observation redirectObservation, proof bool) *models.ActiveTestResult {
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
	result.Evidence = &models.ActiveEvidence{
		Expected:            "la destination finale doit atteindre l'origine externe de contrôle après résolution de la chaîne",
		Observed:            result.Reason,
		FinalURL:            observation.FinalURL,
		FinalOrigin:         observation.FinalOrigin,
		RedirectType:        observation.RedirectType,
		RedirectChain:       append([]string(nil), observation.Chain...),
		Baseline:            executor.Baseline(),
		TestExchanges:       tests,
		Differences:         differences,
		ValidationRule:      "résolution manuelle des hops HTTP internes et reproduction de l'origine finale",
		Confidence:          redirectConfidence(result.Status),
		Reproductions:       countRedirectReproductions(tests),
		MinimumProofReached: proof,
		Conclusion:          result.Reason,
	}
	if observation.StaticType != "" {
		result.Evidence.RedirectType = observation.StaticType
	}
	return result
}

func redirectConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func countRedirectReproductions(exchanges []models.HTTPExchange) int {
	count := 0
	for _, exchange := range exchanges {
		if strings.Contains(exchange.Label, "reproduction") {
			count++
		}
	}
	return count
}

func buildRedirectFinding(ctx *models.ModuleContext, param, probeURL, reason string, observation redirectObservation) *models.Finding {
	chain := strings.Join(observation.Chain, " -> ")
	return &models.Finding{
		ID: uuid.NewString(), AuditRunID: ctx.AuditRunID, TaxonomyID: "WEB-REDIR-001", Type: "open-redirect",
		Title: fmt.Sprintf("Open redirect via parameter %q", param), Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
		Status: models.FindingConfirmed, CWE: "CWE-601", OWASPCat: "A01:2021", ASVSMapping: "V5.5.1",
		Description: fmt.Sprintf("Le paramètre %q atteint l'origine externe %s après résolution de la chaîne. %s", param, observation.FinalOrigin, reason),
		Impact:      "Phishing, fuite de tokens OAuth et abus de chaînes de redirection.",
		Remediation: "Accepter uniquement les redirections relatives ou appliquer une liste blanche stricte des origines.",
		Replayable:  true, Endpoint: ctx.Asset.URL, Parameter: param, CreatedAt: time.Now(),
		Evidence: &models.Evidence{ID: uuid.NewString(), RequestRaw: fmt.Sprintf("GET %s HTTP/1.1", probeURL), ResponseRaw: fmt.Sprintf("Final-Origin: %s\nChain: %s", observation.FinalOrigin, chain), Payload: probeTarget, MatcherResult: reason},
	}
}

func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	result := &models.ModuleResult{}
	if ctx.Asset == nil || ctx.Asset.Method != "GET" {
		return result
	}
	params := ctx.Asset.Params
	if len(params) == 0 {
		params = sqli.ExtractURLParams(ctx.Asset.URL)
	}
	for _, param := range params {
		if !isRedirectParam(param) {
			continue
		}
		probeURL := setParam(ctx.Asset.URL, param, probeTarget)
		req, err := http.NewRequest("GET", probeURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AuditCore/3.0")
		redirectClient := *client
		redirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		resp, err := matchers.Fetch(&redirectClient, req)
		if err != nil {
			continue
		}
		if hit, evidence := matchers.OpenRedirect(resp, probeTarget); hit {
			result.Findings = append(result.Findings, &models.Finding{
				TaxonomyID:  "WEB-REDIR-001",
				Type:        "open-redirect",
				Title:       fmt.Sprintf("Open redirect via parameter %q", param),
				Severity:    models.SeverityMedium,
				Confidence:  models.ConfidenceHigh,
				Status:      models.FindingConfirmed,
				CWE:         "CWE-601",
				OWASPCat:    "A01:2021",
				ASVSMapping: "V5.5.1",
				Description: fmt.Sprintf("The endpoint redirects to an attacker-controlled external URL through parameter %q. %s", param, evidence),
				Impact:      "Useful for phishing, OAuth token leakage, redirect-chain abuse, and trust bypasses.",
				Remediation: "Accept only relative redirects or validate destinations against a strict allowlist.",
				Replayable:  true,
				Endpoint:    probeURL,
				Parameter:   param,
				Evidence: &models.Evidence{
					RequestRaw:    fmt.Sprintf("GET %s HTTP/1.1", probeURL),
					ResponseRaw:   fmt.Sprintf("HTTP/1.1 %d\nLocation: %s", resp.StatusCode, resp.Headers.Get("Location")),
					Payload:       probeTarget,
					MatcherResult: evidence,
				},
			})
			break
		}
	}
	return result
}

func setParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func isRedirectParam(param string) bool {
	p := strings.ToLower(param)
	for _, candidate := range redirectParams {
		if p == candidate || strings.Contains(p, candidate) {
			return true
		}
	}
	return false
}
