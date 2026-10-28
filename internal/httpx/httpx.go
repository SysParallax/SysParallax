package httpx

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

const defaultUserAgent = "AuditCore/3.0"

var fullScanPhases = []models.Phase{
	models.PhasePreCheck,
	models.PhaseNetwork,
	models.PhaseRecon,
	models.PhaseCrawl,
	models.PhaseFingerprint,
	models.PhasePrioritize,
	models.PhasePassive,
	models.PhaseActive,
	models.PhaseScoring,
	models.PhaseReport,
}

var passiveOnlyPhases = []models.Phase{
	models.PhasePreCheck,
	models.PhaseNetwork,
	models.PhaseRecon,
	models.PhaseCrawl,
	models.PhaseFingerprint,
	models.PhasePrioritize,
	models.PhasePassive,
	models.PhaseScoring,
	models.PhaseReport,
}

var allPassiveModules = []string{"headers-security", "cors-misconfig", "cookies-security", "sensitive-exposure"}
var allActiveModules = []string{"sqli-detection", "xss-reflected", "path-traversal", "ssrf-basic", "idor-simple", "open-redirect"}

type transport struct {
	base      http.RoundTripper
	options   models.AuditOptions
	lastReqMu sync.Mutex
	lastReq   time.Time
}

func NewClient(timeout time.Duration, options models.AuditOptions) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	base := http.DefaultTransport
	return &http.Client{
		Timeout: timeout,
		Transport: &transport{
			base:    base,
			options: NormalizeOptions(options),
		},
	}
}

func NormalizeOptions(options models.AuditOptions) models.AuditOptions {
	if options.MaxDepth <= 0 {
		options.MaxDepth = 3
	}
	if options.MaxPages <= 0 {
		options.MaxPages = 150
	}
	if options.RateLimitRPS <= 0 {
		options.RateLimitRPS = 4
	}
	if options.UserAgent == "" {
		options.UserAgent = defaultUserAgent
	}
	if options.ActiveTestTimeoutSeconds <= 0 {
		options.ActiveTestTimeoutSeconds = 60
	}
	if options.ActiveMaxRequestsPerTest <= 0 {
		options.ActiveMaxRequestsPerTest = 32
	}
	if options.ActiveMaxRequestsPerEndpoint <= 0 {
		options.ActiveMaxRequestsPerEndpoint = 128
	}
	if options.ActiveMaxRequestsPerModule <= 0 {
		options.ActiveMaxRequestsPerModule = 512
	}
	if options.ActiveMaxRepetitions <= 0 {
		options.ActiveMaxRepetitions = 3
	}
	if options.ActiveMaxRedirects <= 0 {
		options.ActiveMaxRedirects = 5
	}
	if options.ActivePhaseTimeoutSeconds <= 0 {
		options.ActivePhaseTimeoutSeconds = 900
	}
	if options.ActiveMaxResponseBytes <= 0 {
		options.ActiveMaxResponseBytes = 256 * 1024
	}
	if options.ActiveBrowserTimeoutSeconds <= 0 {
		options.ActiveBrowserTimeoutSeconds = 10
	}
	if options.ActiveBrowserTimeoutSeconds > 30 {
		options.ActiveBrowserTimeoutSeconds = 30
	}
	if options.ActiveSSRFCallbackWindowMillis <= 0 {
		options.ActiveSSRFCallbackWindowMillis = 500
	}
	if options.ActiveSSRFCallbackWindowMillis > 30000 {
		options.ActiveSSRFCallbackWindowMillis = 30000
	}
	if options.ActiveSSRFCallbackPollIntervalMillis <= 0 {
		options.ActiveSSRFCallbackPollIntervalMillis = 100
	}
	if options.ActiveSSRFCallbackPollIntervalMillis > options.ActiveSSRFCallbackWindowMillis {
		options.ActiveSSRFCallbackPollIntervalMillis = options.ActiveSSRFCallbackWindowMillis
	}
	if options.ActiveSSRFCallbackMaxPolls <= 0 {
		options.ActiveSSRFCallbackMaxPolls = 6
	}
	if options.ActiveSSRFCallbackMaxPolls > 20 {
		options.ActiveSSRFCallbackMaxPolls = 20
	}
	if options.ActiveSQLiTimingDelayMillis <= 0 {
		options.ActiveSQLiTimingDelayMillis = 500
	}
	if options.ActiveSQLiTimingDelayMillis > 2000 {
		options.ActiveSQLiTimingDelayMillis = 2000
	}
	if options.ActiveSQLiTimingBaselineSamples <= 0 {
		options.ActiveSQLiTimingBaselineSamples = 2
	}
	if options.ActiveSQLiTimingControlSamples <= 0 {
		options.ActiveSQLiTimingControlSamples = 2
	}
	if options.ActiveSQLiTimingProbeSamples <= 0 {
		options.ActiveSQLiTimingProbeSamples = 2
	}
	if options.ActiveSQLiTimingReproductionSamples <= 0 {
		options.ActiveSQLiTimingReproductionSamples = 1
	}
	for _, samples := range []*int{
		&options.ActiveSQLiTimingBaselineSamples,
		&options.ActiveSQLiTimingControlSamples,
		&options.ActiveSQLiTimingProbeSamples,
		&options.ActiveSQLiTimingReproductionSamples,
	} {
		if *samples > 3 {
			*samples = 3
		}
	}
	if options.SensitiveHeaders == nil {
		options.SensitiveHeaders = []string{"X-API-Key", "X-CSRF-Token"}
	}
	return options
}

func DefaultOptionsForTarget(targetURL string) models.AuditOptions {
	options := NormalizeOptions(models.AuditOptions{})
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	u, err := url.Parse(targetURL)
	if err == nil && u.Hostname() != "" {
		options.AllowedHosts = []string{strings.ToLower(u.Hostname())}
	}
	return options
}

func MergeOptions(targetURL string, provided models.AuditOptions) models.AuditOptions {
	defaults := DefaultOptionsForTarget(targetURL)
	profileName := strings.TrimSpace(strings.ToLower(provided.ScanProfile))
	if profileName == "" {
		profileName = "full-scan"
	}
	profile := optionsForProfile(profileName)
	defaults.ScanProfile = profile.ScanProfile
	defaults.EnabledPhases = copyPhases(profile.EnabledPhases)
	defaults.PassiveModules = copyStrings(profile.PassiveModules)
	defaults.ActiveModules = copyStrings(profile.ActiveModules)
	defaults.MaxDepth = profile.MaxDepth
	defaults.MaxPages = profile.MaxPages
	defaults.RateLimitRPS = profile.RateLimitRPS

	if len(provided.AllowedHosts) > 0 {
		defaults.AllowedHosts = normalizeHosts(provided.AllowedHosts)
	}
	if len(provided.ExcludedPaths) > 0 {
		defaults.ExcludedPaths = provided.ExcludedPaths
	}
	if provided.ScanProfile != "" {
		defaults.ScanProfile = profileName
	}
	if provided.EnabledPhases != nil {
		defaults.EnabledPhases = copyPhases(provided.EnabledPhases)
	}
	if provided.PassiveModules != nil {
		defaults.PassiveModules = normalizeModuleNames(provided.PassiveModules)
	}
	if provided.ActiveModules != nil {
		defaults.ActiveModules = normalizeModuleNames(provided.ActiveModules)
	}
	if provided.MaxDepth > 0 {
		defaults.MaxDepth = provided.MaxDepth
	}
	if provided.MaxPages > 0 {
		defaults.MaxPages = provided.MaxPages
	}
	if provided.RateLimitRPS > 0 {
		defaults.RateLimitRPS = provided.RateLimitRPS
	}
	if provided.UserAgent != "" {
		defaults.UserAgent = provided.UserAgent
	}
	if len(provided.Headers) > 0 {
		defaults.Headers = provided.Headers
	}
	if len(provided.Cookies) > 0 {
		defaults.Cookies = provided.Cookies
	}
	defaults.BearerToken = provided.BearerToken
	defaults.BasicUsername = provided.BasicUsername
	defaults.BasicPassword = provided.BasicPassword
	if provided.ActiveTestTimeoutSeconds > 0 {
		defaults.ActiveTestTimeoutSeconds = provided.ActiveTestTimeoutSeconds
	}
	if provided.ActivePhaseTimeoutSeconds > 0 {
		defaults.ActivePhaseTimeoutSeconds = provided.ActivePhaseTimeoutSeconds
	}
	if provided.ActiveMaxRequestsPerTest > 0 {
		defaults.ActiveMaxRequestsPerTest = provided.ActiveMaxRequestsPerTest
	}
	if provided.ActiveMaxRequestsPerEndpoint > 0 {
		defaults.ActiveMaxRequestsPerEndpoint = provided.ActiveMaxRequestsPerEndpoint
	}
	if provided.ActiveMaxRequestsPerModule > 0 {
		defaults.ActiveMaxRequestsPerModule = provided.ActiveMaxRequestsPerModule
	}
	if provided.ActiveMaxRepetitions > 0 {
		defaults.ActiveMaxRepetitions = provided.ActiveMaxRepetitions
	}
	if provided.ActiveMaxRedirects > 0 {
		defaults.ActiveMaxRedirects = provided.ActiveMaxRedirects
	}
	if provided.ActiveMaxResponseBytes > 0 {
		defaults.ActiveMaxResponseBytes = provided.ActiveMaxResponseBytes
	}
	if provided.ActiveBrowserEnabled {
		defaults.ActiveBrowserEnabled = true
	}
	if provided.ActiveBrowserTimeoutSeconds > 0 {
		defaults.ActiveBrowserTimeoutSeconds = provided.ActiveBrowserTimeoutSeconds
	}
	if provided.ActiveSQLiTimingEnabled {
		defaults.ActiveSQLiTimingEnabled = true
	}
	if provided.ActiveSQLiTimingDelayMillis > 0 {
		defaults.ActiveSQLiTimingDelayMillis = provided.ActiveSQLiTimingDelayMillis
	}
	if provided.ActiveSQLiTimingBaselineSamples > 0 {
		defaults.ActiveSQLiTimingBaselineSamples = provided.ActiveSQLiTimingBaselineSamples
	}
	if provided.ActiveSQLiTimingControlSamples > 0 {
		defaults.ActiveSQLiTimingControlSamples = provided.ActiveSQLiTimingControlSamples
	}
	if provided.ActiveSQLiTimingProbeSamples > 0 {
		defaults.ActiveSQLiTimingProbeSamples = provided.ActiveSQLiTimingProbeSamples
	}
	if provided.ActiveSQLiTimingReproductionSamples > 0 {
		defaults.ActiveSQLiTimingReproductionSamples = provided.ActiveSQLiTimingReproductionSamples
	}
	if provided.SensitiveHeaders != nil {
		defaults.SensitiveHeaders = copyStrings(provided.SensitiveHeaders)
	}
	if provided.ActiveTraversalProofPath != "" {
		defaults.ActiveTraversalProofPath = provided.ActiveTraversalProofPath
	}
	if provided.ActiveTraversalProofMarker != "" {
		defaults.ActiveTraversalProofMarker = provided.ActiveTraversalProofMarker
	}
	if provided.ActiveTraversalProofPlatform != "" {
		defaults.ActiveTraversalProofPlatform = provided.ActiveTraversalProofPlatform
	}
	if provided.ActiveTraversalProofResourceType != "" {
		defaults.ActiveTraversalProofResourceType = provided.ActiveTraversalProofResourceType
	}
	if provided.ActiveSSRFCallbackURL != "" {
		defaults.ActiveSSRFCallbackURL = provided.ActiveSSRFCallbackURL
	}
	if provided.ActiveSSRFCallbackCheckURL != "" {
		defaults.ActiveSSRFCallbackCheckURL = provided.ActiveSSRFCallbackCheckURL
	}
	if provided.ActiveSSRFCallbackMarker != "" {
		defaults.ActiveSSRFCallbackMarker = provided.ActiveSSRFCallbackMarker
	}
	if provided.ActiveSSRFAllowPrivateCallback {
		defaults.ActiveSSRFAllowPrivateCallback = true
	}
	if provided.ActiveSSRFCallbackWindowMillis > 0 {
		defaults.ActiveSSRFCallbackWindowMillis = provided.ActiveSSRFCallbackWindowMillis
	}
	if provided.ActiveSSRFCallbackPollIntervalMillis > 0 {
		defaults.ActiveSSRFCallbackPollIntervalMillis = provided.ActiveSSRFCallbackPollIntervalMillis
	}
	if provided.ActiveSSRFCallbackMaxPolls > 0 {
		defaults.ActiveSSRFCallbackMaxPolls = provided.ActiveSSRFCallbackMaxPolls
	}
	if provided.ActiveIDORIdentities != nil {
		defaults.ActiveIDORIdentities = copyIDORIdentities(provided.ActiveIDORIdentities)
	}
	if provided.ActiveIDORResources != nil {
		defaults.ActiveIDORResources = copyIDORResources(provided.ActiveIDORResources)
	}
	if provided.ActiveIDOROwnerIdentity != "" {
		defaults.ActiveIDOROwnerIdentity = provided.ActiveIDOROwnerIdentity
	}
	if provided.ActiveIDORNonOwnerIdentity != "" {
		defaults.ActiveIDORNonOwnerIdentity = provided.ActiveIDORNonOwnerIdentity
	}
	if provided.ActiveIDOROwnerResource != "" {
		defaults.ActiveIDOROwnerResource = provided.ActiveIDOROwnerResource
	}
	if provided.ActiveIDORNonOwnerResource != "" {
		defaults.ActiveIDORNonOwnerResource = provided.ActiveIDORNonOwnerResource
	}
	if provided.ActiveIDORSuccessMarker != "" {
		defaults.ActiveIDORSuccessMarker = provided.ActiveIDORSuccessMarker
	}
	if provided.ActiveIDORDeniedMarker != "" {
		defaults.ActiveIDORDeniedMarker = provided.ActiveIDORDeniedMarker
	}
	if provided.ActiveIDORAllowWrite {
		defaults.ActiveIDORAllowWrite = true
	}
	return NormalizeOptions(defaults)
}

func optionsForProfile(profile string) models.AuditOptions {
	switch profile {
	case "passive-only":
		return models.AuditOptions{
			ScanProfile:    "passive-only",
			EnabledPhases:  passiveOnlyPhases,
			PassiveModules: allPassiveModules,
			ActiveModules:  []string{},
			MaxDepth:       2,
			MaxPages:       150,
			RateLimitRPS:   4,
		}
	case "api-deep":
		return models.AuditOptions{
			ScanProfile:    "api-deep",
			EnabledPhases:  fullScanPhases,
			PassiveModules: []string{"headers-security", "cors-misconfig", "cookies-security", "sensitive-exposure"},
			ActiveModules:  []string{"sqli-detection", "ssrf-basic", "idor-simple", "open-redirect"},
			MaxDepth:       4,
			MaxPages:       300,
			RateLimitRPS:   3,
		}
	case "quick-check":
		return models.AuditOptions{
			ScanProfile:    "quick-check",
			EnabledPhases:  fullScanPhases,
			PassiveModules: []string{"headers-security", "cookies-security"},
			ActiveModules:  []string{"sqli-detection", "xss-reflected", "path-traversal"},
			MaxDepth:       1,
			MaxPages:       50,
			RateLimitRPS:   6,
		}
	case "custom":
		return models.AuditOptions{
			ScanProfile:    "custom",
			EnabledPhases:  fullScanPhases,
			PassiveModules: allPassiveModules,
			ActiveModules:  allActiveModules,
			MaxDepth:       3,
			MaxPages:       150,
			RateLimitRPS:   4,
		}
	default:
		return models.AuditOptions{
			ScanProfile:    "full-scan",
			EnabledPhases:  fullScanPhases,
			PassiveModules: allPassiveModules,
			ActiveModules:  allActiveModules,
			MaxDepth:       3,
			MaxPages:       800,
			RateLimitRPS:   4,
		}
	}
}

type authenticationOverrideContextKey struct{}

// WithAuthenticationOverride indique qu'une requete porte explicitement
// l'identite a utiliser et ne doit pas recevoir l'authentification globale.
func WithAuthenticationOverride(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	return req.WithContext(context.WithValue(req.Context(), authenticationOverrideContextKey{}, true))
}

func authenticationOverride(req *http.Request) bool {
	if req == nil {
		return false
	}
	value, _ := req.Context().Value(authenticationOverrideContextKey{}).(bool)
	return value
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := CheckScope(req.URL, t.options); err != nil {
		return nil, err
	}
	t.rateLimit()
	if authenticationOverride(req) {
		applyNonAuthenticationHeaders(req, t.options)
	} else {
		applyHeaders(req, t.options)
	}
	return t.base.RoundTrip(req)
}

func CheckScope(u *url.URL, options models.AuditOptions) error {
	options = NormalizeOptions(options)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("scope blocked: missing host")
	}
	if len(options.AllowedHosts) > 0 {
		allowed := false
		for _, h := range normalizeHosts(options.AllowedHosts) {
			if host == h {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("scope blocked: host %s not allowed", host)
		}
	}
	for _, excluded := range options.ExcludedPaths {
		excluded = strings.TrimSpace(excluded)
		if excluded == "" {
			continue
		}
		if strings.HasPrefix(u.Path, excluded) {
			return fmt.Errorf("scope blocked: path %s excluded", u.Path)
		}
	}
	return nil
}

func (t *transport) rateLimit() {
	if t.options.RateLimitRPS <= 0 {
		return
	}
	delay := time.Duration(float64(time.Second) / t.options.RateLimitRPS)
	t.lastReqMu.Lock()
	defer t.lastReqMu.Unlock()
	wait := delay - time.Since(t.lastReq)
	if wait > 0 {
		time.Sleep(wait)
	}
	t.lastReq = time.Now()
}

func applyHeaders(req *http.Request, options models.AuditOptions) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", options.UserAgent)
	}
	for k, v := range options.Headers {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}
	if options.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+options.BearerToken)
	} else if options.BasicUsername != "" {
		req.SetBasicAuth(options.BasicUsername, options.BasicPassword)
	}
	for name, value := range options.Cookies {
		if name != "" {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
	}
}

func applyNonAuthenticationHeaders(req *http.Request, options models.AuditOptions) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", options.UserAgent)
	}
	for k, v := range options.Headers {
		if isAuthenticationHeader(k) || req.Header.Get(k) != "" {
			continue
		}
		req.Header.Set(k, v)
	}
}

func isAuthenticationHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" {
		return true
	}
	return strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey")
}

func normalizeHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	seen := make(map[string]bool)
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		if parsed, err := url.Parse(h); err == nil && parsed.Hostname() != "" {
			h = parsed.Hostname()
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func normalizeModuleNames(modules []string) []string {
	out := make([]string, 0, len(modules))
	seen := make(map[string]bool)
	for _, module := range modules {
		module = strings.TrimSpace(strings.ToLower(module))
		if module == "" || seen[module] {
			continue
		}
		seen[module] = true
		out = append(out, module)
	}
	return out
}

func copyStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func copyPhases(values []models.Phase) []models.Phase {
	if values == nil {
		return nil
	}
	out := make([]models.Phase, len(values))
	copy(out, values)
	return out
}

func copyIDORIdentities(values []models.ActiveIDORIdentity) []models.ActiveIDORIdentity {
	if values == nil {
		return nil
	}
	out := make([]models.ActiveIDORIdentity, len(values))
	for i, identity := range values {
		out[i] = identity
		if identity.Scopes != nil {
			out[i].Scopes = append([]string(nil), identity.Scopes...)
		}
		if identity.Headers != nil {
			out[i].Headers = make(map[string]string, len(identity.Headers))
			for key, value := range identity.Headers {
				out[i].Headers[key] = value
			}
		}
		if identity.Cookies != nil {
			out[i].Cookies = make(map[string]string, len(identity.Cookies))
			for key, value := range identity.Cookies {
				out[i].Cookies[key] = value
			}
		}
	}
	return out
}

func copyIDORResources(values []models.ActiveIDORResource) []models.ActiveIDORResource {
	if values == nil {
		return nil
	}
	out := make([]models.ActiveIDORResource, len(values))
	copy(out, values)
	return out
}
