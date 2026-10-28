// Package idor valide defensivement les controles d'autorisation objet.
package idor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/httpx"
	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
	"github.com/google/uuid"
)

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "idor-simple" }

func (m *Module) Plan(ctx *models.ModuleContext, findings []*models.Finding) []models.ActiveTestPlan {
	return active.PlansForModule(m.Name(), ctx, findings)
}

type idorResponse struct {
	StatusCode  int
	Body        string
	Normalized  string
	BodySize    int64
	ContentType string
}

type idorMeta struct {
	Operation        string
	OwnerIdentity    string
	NonOwnerIdentity string
	OwnerResource    string
	NonOwnerResource string
	RedactionOptions models.AuditOptions
	OwnerControl     *idorResponse
	Reference        *idorResponse
	Observed         *idorResponse
	Cases            []models.IDORCaseEvidence
}

type idorCrossCase struct {
	Label       string
	Identity    models.ActiveIDORIdentity
	Resource    models.ActiveIDORResource
	Owner       models.ActiveIDORIdentity
	ResourceURL string
	Reference   idorResponse
	Direction   string
}

type idorConfig struct {
	Identities       []models.ActiveIDORIdentity
	Resources        []models.ActiveIDORResource
	OwnerIdentity    models.ActiveIDORIdentity
	NonOwnerIdentity models.ActiveIDORIdentity
}

func (m *Module) RunActive(ctx context.Context, moduleCtx *models.ModuleContext, plan models.ActiveTestPlan, executor *active.Executor) *models.ActiveTestResult {
	result := &models.ActiveTestResult{Status: models.ActiveTestInconclusive}
	if moduleCtx == nil || moduleCtx.Asset == nil || executor == nil {
		result.Status = models.ActiveTestUntestable
		result.Reason = "contexte IDOR incomplet"
		return finishIDOREvidence(result, executor, idorMeta{})
	}

	config, reason := validateIDORConfig(moduleCtx, plan)
	meta := idorMeta{
		Operation:        idorOperation(moduleCtx.Asset.Method),
		OwnerIdentity:    config.OwnerIdentity.Name,
		NonOwnerIdentity: config.NonOwnerIdentity.Name,
		RedactionOptions: moduleCtx.Options,
	}
	if len(config.Resources) > 0 {
		meta.OwnerResource = config.Resources[0].URL
	}
	if len(config.Resources) > 1 {
		meta.NonOwnerResource = config.Resources[1].URL
	}
	if reason != "" {
		result.Status = models.ActiveTestUntestable
		result.Reason = reason
		return finishIDOREvidence(result, executor, meta)
	}

	ownerResponses := make(map[string]idorResponse, len(config.Resources))
	ownerIdentities := make(map[string]models.ActiveIDORIdentity, len(config.Identities))
	for _, identity := range config.Identities {
		ownerIdentities[strings.ToLower(identity.Name)] = identity
	}
	for index, resource := range config.Resources {
		owner, ok := ownerIdentities[strings.ToLower(resource.OwnerIdentity)]
		if !ok {
			result.Status = models.ActiveTestUntestable
			result.Reason = "le proprietaire d'une ressource IDOR n'est pas configure"
			return finishIDOREvidence(result, executor, meta)
		}
		label := fmt.Sprintf("idor-owner-control:%s:%d", resource.Name, index)
		ownerResponse, requestErr := executeIDORRequest(ctx, moduleCtx.Asset, plan.EntryPoint, resource.URL, owner, label, executor)
		if requestErr != nil {
			return finishIDORError(result, executor, meta, requestErr)
		}
		if !isBusinessSuccess(ownerResponse, moduleCtx.Options.ActiveIDORSuccessMarker) {
			result.Status = models.ActiveTestInconclusive
			result.Reason = fmt.Sprintf("la ressource %s n'a pas fourni une reponse metier de succes identifiable avec son proprietaire", resource.Name)
			return finishIDOREvidence(result, executor, meta)
		}
		ownerResponses[strings.ToLower(resource.Name)] = ownerResponse
		if meta.OwnerControl == nil {
			responseCopy := ownerResponse
			meta.OwnerControl = &responseCopy
		}
	}

	var cases []idorCrossCase
	for _, resource := range config.Resources {
		owner, _ := ownerIdentities[strings.ToLower(resource.OwnerIdentity)]
		reference, ok := ownerResponses[strings.ToLower(resource.Name)]
		if !ok {
			continue
		}
		for _, identity := range config.Identities {
			if strings.EqualFold(identity.Name, resource.OwnerIdentity) {
				continue
			}
			direction := fmt.Sprintf("%s -> ressource de %s", identity.Name, owner.Name)
			if resource.Tenant != "" && identity.Tenant != "" && strings.EqualFold(resource.Tenant, identity.Tenant) {
				direction += " (meme tenant)"
			} else if resource.Tenant != "" || identity.Tenant != "" {
				direction += " (cross-tenant)"
			}
			cases = append(cases, idorCrossCase{
				Label: fmt.Sprintf("idor-cross:%s:%s", identity.Name, resource.Name), Identity: identity,
				Resource: resource, Owner: owner, ResourceURL: resource.URL, Reference: reference,
				Direction: direction,
			})
		}
	}

	allDenied := true
	for _, cross := range cases {
		observed, requestErr := executeIDORRequest(ctx, moduleCtx.Asset, plan.EntryPoint, cross.ResourceURL, cross.Identity, cross.Label, executor)
		if requestErr != nil {
			return finishIDORError(result, executor, meta, requestErr)
		}
		reference := cross.Reference
		meta.Reference = &reference
		meta.Observed = &observed
		equivalent := equivalentBusinessResponse(cross.Reference, observed, moduleCtx.Options.ActiveIDORSuccessMarker)
		denied := isDeniedResponse(observed, moduleCtx.Options.ActiveIDORDeniedMarker)
		meta.Cases = append(meta.Cases, models.IDORCaseEvidence{
			Label: cross.Label, Actor: cross.Identity.Name, ActorRole: cross.Identity.Role, ActorTenant: cross.Identity.Tenant, ActorOrganization: cross.Identity.Organization, ActorScopes: append([]string(nil), cross.Identity.Scopes...),
			Resource: active.RedactURL(cross.Resource.URL, moduleCtx.Options), Owner: cross.Owner.Name, ResourceTenant: cross.Resource.Tenant,
			Direction: cross.Direction, StatusCode: observed.StatusCode, Denied: denied, BusinessEquivalent: equivalent,
		})
		if equivalent {
			result.Status = models.ActiveTestConfirmed
			result.Reason = fmt.Sprintf("la session non autorisee %s (%s, tenant %s) a recu la reponse metier de la ressource %s (%s)", cross.Identity.Name, cross.Identity.Role, cross.Identity.Tenant, cross.Owner.Name, cross.Direction)
			result.Findings = []*models.Finding{buildIDORFinding(moduleCtx, plan.EntryPoint.Name, meta, cross, result.Reason, executor)}
			result.MinimumConditionsMet = true
			executor.MarkMinimumProof()
			return finishIDOREvidence(result, executor, meta)
		}
		if !denied {
			allDenied = false
		}
	}

	if allDenied {
		result.Status = models.ActiveTestNotConfirmed
		result.Reason = "les controles croises ont ete refuses par l'autorisation ou la ressource"
	} else {
		result.Status = models.ActiveTestInconclusive
		result.Reason = "la reponse croisee est differente, mais ne permet pas de distinguer un refus d'un comportement metier normal"
	}
	return finishIDOREvidence(result, executor, meta)
}

func validateIDORConfig(moduleCtx *models.ModuleContext, plan models.ActiveTestPlan) (idorConfig, string) {
	options := moduleCtx.Options
	if strings.TrimSpace(plan.EntryPoint.Name) == "" {
		return idorConfig{}, "aucun objet IDOR pertinent dans le point d'entree"
	}
	if idorOperation(moduleCtx.Asset.Method) == "write" && !options.ActiveIDORAllowWrite {
		return idorConfig{}, "operation de modification refusee : active_idor_allow_write est desactive"
	}
	identities := normalizeIdentities(options.ActiveIDORIdentities)
	if len(identities) < 2 {
		return idorConfig{}, "au moins deux identites distinctes sont requises"
	}
	if len(identities) > 8 {
		return idorConfig{}, "la matrice IDOR est limitee a huit identites"
	}
	resources := normalizeResources(options)
	if len(resources) < 2 {
		return idorConfig{}, "au moins deux ressources avec des proprietaires distincts sont requises"
	}
	if len(resources) > 8 {
		return idorConfig{}, "la matrice IDOR est limitee a huit ressources"
	}
	assetURL, err := url.Parse(moduleCtx.Asset.URL)
	if err != nil || assetURL.Scheme == "" || assetURL.Host == "" {
		return idorConfig{}, "URL de l'asset IDOR invalide"
	}
	knownOwners := make(map[string]bool, len(identities))
	for _, resource := range resources {
		parsed, parseErr := url.Parse(resource.URL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return idorConfig{}, "ressource IDOR invalide : URL HTTP(S) absolue attendue"
		}
		if !strings.EqualFold(parsed.Host, assetURL.Host) {
			return idorConfig{}, "ressource IDOR hors du meme scope que l'asset"
		}
		if len(options.AllowedHosts) > 0 && !hostAllowed(parsed.Hostname(), options.AllowedHosts) {
			return idorConfig{}, "ressource IDOR hors des hotes autorises"
		}
		owner, ok := findIdentity(identities, resource.OwnerIdentity)
		if !ok {
			return idorConfig{}, "chaque ressource IDOR doit avoir un proprietaire configure"
		}
		knownOwners[strings.ToLower(owner.Name)] = true
	}
	if len(knownOwners) < 2 {
		return idorConfig{}, "les ressources IDOR doivent appartenir a deux identites distinctes"
	}
	return idorConfig{Identities: identities, Resources: resources, OwnerIdentity: identities[0], NonOwnerIdentity: identities[1]}, ""
}

func normalizeIdentities(values []models.ActiveIDORIdentity) []models.ActiveIDORIdentity {
	result := make([]models.ActiveIDORIdentity, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, identity := range values {
		identity.Name = strings.TrimSpace(identity.Name)
		if identity.Name == "" || seen[strings.ToLower(identity.Name)] {
			continue
		}
		seen[strings.ToLower(identity.Name)] = true
		result = append(result, identity)
	}
	return result
}

func normalizeResources(options models.AuditOptions) []models.ActiveIDORResource {
	if len(options.ActiveIDORResources) > 0 {
		result := make([]models.ActiveIDORResource, 0, len(options.ActiveIDORResources))
		seen := make(map[string]bool, len(options.ActiveIDORResources))
		for index, resource := range options.ActiveIDORResources {
			resource.Name = strings.TrimSpace(resource.Name)
			if resource.Name == "" {
				resource.Name = fmt.Sprintf("resource-%d", index+1)
			}
			if resource.URL == "" || resource.OwnerIdentity == "" || seen[strings.ToLower(resource.Name)] {
				continue
			}
			seen[strings.ToLower(resource.Name)] = true
			result = append(result, resource)
		}
		return result
	}
	return []models.ActiveIDORResource{
		{Name: "owner-resource", URL: strings.TrimSpace(options.ActiveIDOROwnerResource), OwnerIdentity: strings.TrimSpace(options.ActiveIDOROwnerIdentity)},
		{Name: "non-owner-resource", URL: strings.TrimSpace(options.ActiveIDORNonOwnerResource), OwnerIdentity: strings.TrimSpace(options.ActiveIDORNonOwnerIdentity)},
	}
}

func findIdentity(identities []models.ActiveIDORIdentity, name string) (models.ActiveIDORIdentity, bool) {
	for _, identity := range identities {
		if strings.EqualFold(strings.TrimSpace(identity.Name), name) {
			identity.Name = strings.TrimSpace(identity.Name)
			return identity, true
		}
	}
	return models.ActiveIDORIdentity{}, false
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, candidate := range allowed {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if parsed, err := url.Parse(candidate); err == nil && parsed.Hostname() != "" {
			candidate = parsed.Hostname()
		}
		if host == candidate {
			return true
		}
	}
	return false
}

func idorOperation(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return "write"
	default:
		return "read"
	}
}

func buildIDORRequest(asset *models.Asset, entry models.EntryPoint, resourceURL string) (*http.Request, error) {
	assetCopy := *asset
	assetCopy.URL = resourceURL
	entry.Endpoint = resourceURL
	if entry.Method == "" {
		entry.Method = assetCopy.Method
	}
	return active.BuildRequest(&assetCopy, entry, entry.OriginalValue)
}

func applyIdentity(req *http.Request, identity models.ActiveIDORIdentity) *http.Request {
	req = httpx.WithAuthenticationOverride(req)
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Cookie")
	for key, value := range identity.Headers {
		if strings.TrimSpace(key) != "" {
			req.Header.Set(key, value)
		}
	}
	if identity.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+identity.BearerToken)
	} else if identity.BasicUsername != "" {
		req.SetBasicAuth(identity.BasicUsername, identity.BasicPassword)
	}
	for name, value := range identity.Cookies {
		if name != "" {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
	}
	return req
}

func executeIDORRequest(ctx context.Context, asset *models.Asset, entry models.EntryPoint, resourceURL string, identity models.ActiveIDORIdentity, label string, executor *active.Executor) (idorResponse, error) {
	request, err := buildIDORRequest(asset, entry, resourceURL)
	if err != nil {
		return idorResponse{}, err
	}
	request = request.WithContext(ctx)
	request = applyIdentity(request, identity)
	response, err := executor.DoNoRedirect("test", label, request)
	if err != nil {
		return idorResponse{}, err
	}
	return captureIDORResponse(response)
}

func captureIDORResponse(response *http.Response) (idorResponse, error) {
	if response == nil {
		return idorResponse{}, errors.New("reponse HTTP IDOR absente")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	_ = response.Body.Close()
	if err != nil {
		return idorResponse{}, err
	}
	text := string(body)
	return idorResponse{
		StatusCode: response.StatusCode, Body: text, Normalized: active.NormalizeBody(text),
		BodySize: int64(len(body)), ContentType: response.Header.Get("Content-Type"),
	}, nil
}

func isBusinessSuccess(response idorResponse, marker string) bool {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return false
	}
	if marker != "" {
		return strings.Contains(response.Body, marker)
	}
	return meaningfulBusinessBody(response.Body)
}

func equivalentBusinessResponse(reference, observed idorResponse, marker string) bool {
	if !isBusinessSuccess(reference, marker) || !isBusinessSuccess(observed, marker) {
		return false
	}
	if marker != "" {
		return reference.StatusCode == observed.StatusCode && strings.Contains(observed.Body, marker)
	}
	if reference.StatusCode != observed.StatusCode || reference.BodySize == 0 || observed.BodySize == 0 {
		return false
	}
	if referenceProjection, referenceOK := businessProjection(reference.Body); referenceOK {
		observedProjection, observedOK := businessProjection(observed.Body)
		return observedOK && referenceProjection == observedProjection
	}
	return reference.Normalized == observed.Normalized
}

func businessProjection(body string) (string, bool) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", false
	}
	knownFields := map[string]bool{
		"owner": true, "owner_id": true, "user_id": true, "tenant_id": true,
		"account_id": true, "organization": true, "organisation": true,
		"permissions": true, "role": true, "resource_id": true, "id": true,
	}
	values := make(map[string]string)
	for key, value := range payload {
		if knownFields[strings.ToLower(key)] {
			encoded, err := json.Marshal(value)
			if err == nil {
				values[strings.ToLower(key)] = string(encoded)
			}
		}
	}
	if len(values) == 0 {
		return "", false
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, "&"), true
}

func meaningfulBusinessBody(body string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(body))
	if len(trimmed) < 8 {
		return false
	}
	switch trimmed {
	case "ok", "success", "true", "false", "accepted", "authorized", "forbidden", "not found":
		return false
	default:
		return true
	}
}

func isDeniedResponse(response idorResponse, marker string) bool {
	if marker != "" && strings.Contains(response.Body, marker) {
		return true
	}
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed:
		return true
	default:
		return false
	}
}

func finishIDORError(result *models.ActiveTestResult, executor *active.Executor, meta idorMeta, err error) *models.ActiveTestResult {
	switch {
	case errors.Is(err, context.Canceled):
		result.Status = models.ActiveTestCancelled
	case errors.Is(err, context.DeadlineExceeded):
		result.Status = models.ActiveTestTimeout
	case errors.Is(err, active.ErrRequestBudget):
		result.Status = models.ActiveTestInconclusive
		result.LimitReached = executor.LimitReached()
	default:
		result.Status = models.ActiveTestFailed
	}
	result.Reason = "echange IDOR interrompu : " + err.Error()
	return finishIDOREvidence(result, executor, meta)
}

func finishIDOREvidence(result *models.ActiveTestResult, executor *active.Executor, meta idorMeta) *models.ActiveTestResult {
	if executor == nil {
		return result
	}
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
	var baseline *models.Baseline
	if exchange := exchangeByLabelPrefix(exchanges, "idor-owner-control:"); exchange != nil && exchange.Response != nil {
		baseline = &models.Baseline{Exchanges: []models.HTTPExchange{*exchange}, Stable: true, NormalizedHash: exchange.Response.NormalizedHash}
	}
	if meta.Reference != nil && meta.Observed != nil {
		differences = append(differences, idorResponseDifferences(*meta.Reference, *meta.Observed)...)
	}
	if meta.OwnerIdentity != "" && meta.NonOwnerIdentity != "" {
		differences = append(differences, models.ResponseDifference{
			Metric: "identity_context", Baseline: meta.OwnerIdentity, Observed: meta.NonOwnerIdentity,
			Significant: true, Explanation: "la meme ressource a ete demandee avec des identites distinctes",
		})
	}
	result.Evidence = &models.ActiveEvidence{
		Expected:            "la ressource du proprietaire doit etre accessible par son identite et refusee a l'autre identite",
		Observed:            result.Reason,
		Operation:           meta.Operation,
		OwnerIdentity:       meta.OwnerIdentity,
		NonOwnerIdentity:    meta.NonOwnerIdentity,
		OwnerResource:       active.RedactURL(meta.OwnerResource, meta.RedactionOptions),
		NonOwnerResource:    active.RedactURL(meta.NonOwnerResource, meta.RedactionOptions),
		IDORCases:           meta.Cases,
		Baseline:            baseline,
		TestExchanges:       tests,
		Differences:         differences,
		ValidationRule:      "un statut HTTP 200 seul ne suffit pas : identites, ressources et reponse metier doivent etre compares",
		Confidence:          idorConfidence(result.Status),
		MinimumProofReached: result.Status == models.ActiveTestConfirmed,
		Conclusion:          result.Reason,
	}
	return result
}

func idorResponseDifferences(reference, observed idorResponse) []models.ResponseDifference {
	var differences []models.ResponseDifference
	if reference.StatusCode != observed.StatusCode {
		differences = append(differences, models.ResponseDifference{Metric: "status_code", Baseline: fmt.Sprint(reference.StatusCode), Observed: fmt.Sprint(observed.StatusCode), Significant: true, Explanation: "codes HTTP proprietaire/non-proprietaire differents"})
	}
	if reference.Normalized != observed.Normalized {
		differences = append(differences, models.ResponseDifference{Metric: "normalized_business_body", Baseline: reference.Normalized, Observed: observed.Normalized, Significant: true, Explanation: "reponses metier proprietaire/non-proprietaire differentes"})
	}
	if reference.BodySize != observed.BodySize {
		differences = append(differences, models.ResponseDifference{Metric: "body_size", Baseline: fmt.Sprint(reference.BodySize), Observed: fmt.Sprint(observed.BodySize), Significant: false, Explanation: "taille de reponse differente"})
	}
	return differences
}

func idorConfidence(status models.ActiveTestStatus) models.Confidence {
	if status == models.ActiveTestConfirmed {
		return models.ConfidenceHigh
	}
	if status == models.ActiveTestInconclusive {
		return models.ConfidenceLow
	}
	return models.ConfidenceMedium
}

func buildIDORFinding(moduleCtx *models.ModuleContext, parameter string, meta idorMeta, cross idorCrossCase, reason string, executor *active.Executor) *models.Finding {
	requestLine := fmt.Sprintf("%s %s HTTP/1.1", moduleCtx.Asset.Method, cross.ResourceURL)
	if exchange := exchangeByLabel(executor.Exchanges(), cross.Label); exchange != nil {
		requestLine = fmt.Sprintf("%s %s HTTP/1.1", exchange.Request.Method, exchange.Request.URL)
	}
	return &models.Finding{
		ID: uuid.NewString(), AuditRunID: moduleCtx.AuditRunID, AssetID: moduleCtx.Asset.ID,
		TaxonomyID: "WEB-IDOR-001", Type: "idor-authorization-bypass",
		Title:    fmt.Sprintf("IDOR via %s identity on an owned resource", cross.Identity.Name),
		Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Status: models.FindingConfirmed,
		CWE: "CWE-639", OWASPCat: "A01:2021", ASVSMapping: "V4.2.1", Module: "idor-simple",
		Description: fmt.Sprintf("The %s identity received the business response for a resource owned by %s. %s", cross.Identity.Name, meta.OwnerIdentity, reason),
		Impact:      "Acces non autorise aux ressources d'un autre utilisateur.",
		Remediation: "Verifier l'autorisation cote serveur pour chaque objet et chaque operation, independamment de l'identifiant fourni par le client.",
		Replayable:  true, Endpoint: cross.ResourceURL, Parameter: parameter, CreatedAt: time.Now(),
		Evidence: &models.Evidence{
			ID: uuid.NewString(), RequestRaw: requestLine, Payload: cross.ResourceURL,
			MatcherResult: "owner=" + meta.OwnerIdentity + "; cross_identity=" + cross.Identity.Name + "; operation=" + meta.Operation,
		},
	}
}

func exchangeByLabel(exchanges []models.HTTPExchange, label string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if exchanges[i].Label == label {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

func exchangeByLabelPrefix(exchanges []models.HTTPExchange, prefix string) *models.HTTPExchange {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if strings.HasPrefix(exchanges[i].Label, prefix) {
			copyExchange := exchanges[i]
			return &copyExchange
		}
	}
	return nil
}

// Le chemin historique reste volontairement neutre : sans identites et
// ressources explicites, il ne doit pas emettre de probe IDOR heuristique.
func (m *Module) Run(ctx *models.ModuleContext, client *http.Client) *models.ModuleResult {
	return &models.ModuleResult{}
}
