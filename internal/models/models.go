package models

import "time"

// ─── Statuts audit ──────────────────────────────────────────────────────────

type AuditStatus string

const (
	StatusPending AuditStatus = "pending"
	StatusRunning AuditStatus = "running"
	StatusDone    AuditStatus = "done"
	StatusFailed  AuditStatus = "failed"
	StatusStopped AuditStatus = "stopped"
)

type Phase string

const (
	PhasePreCheck    Phase = "pre-check"
	PhaseNetwork     Phase = "network"
	PhaseRecon       Phase = "recon"
	PhaseCrawl       Phase = "crawl"
	PhaseFingerprint Phase = "fingerprint"
	PhasePrioritize  Phase = "prioritize"
	PhasePassive     Phase = "passive"
	PhaseActive      Phase = "active"
	PhaseValidation  Phase = "validation"
	PhaseScoring     Phase = "scoring"
	PhaseReport      Phase = "report"
	PhaseIdle        Phase = "idle"
)

type EventLevel string

const (
	LevelInfo  EventLevel = "info"
	LevelOK    EventLevel = "ok"
	LevelWarn  EventLevel = "warn"
	LevelError EventLevel = "error"
)

// ─── Sévérité / Confiance / Statut finding ──────────────────────────────────

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type FindingStatus string

const (
	FindingSuspected     FindingStatus = "suspected"
	FindingValidated     FindingStatus = "validated"
	FindingConfirmed     FindingStatus = "confirmed"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingAcceptedRisk  FindingStatus = "accepted_risk"
)

type FindingReplayState string

const (
	FindingReplayNotRun        FindingReplayState = "not_run"
	FindingReplayConfirmed     FindingReplayState = "confirmed"
	FindingReplayNotReproduced FindingReplayState = "not_reproduced"
	FindingReplayFailed        FindingReplayState = "failed"
	FindingReplayUnavailable   FindingReplayState = "unavailable"
)

// ─── Entités principales ────────────────────────────────────────────────────

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Environment string    `json:"environment"`
	CreatedAt   time.Time `json:"created_at"`
}

type Target struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	BaseURL   string    `json:"base_url"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditRun struct {
	ID         string       `json:"id"`
	TargetID   string       `json:"target_id"`
	TargetURL  string       `json:"target_url"`
	Options    AuditOptions `json:"options"`
	Status     AuditStatus  `json:"status"`
	Phase      Phase        `json:"phase"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt *time.Time   `json:"finished_at,omitempty"`
	Error      string       `json:"error,omitempty"`
}

type ScanEvent struct {
	ID         string     `json:"id"`
	AuditRunID string     `json:"audit_run_id"`
	Phase      Phase      `json:"phase"`
	Module     string     `json:"module,omitempty"`
	Level      EventLevel `json:"level"`
	Message    string     `json:"message"`
	Timestamp  time.Time  `json:"timestamp"`
}

// ─── Résultats de phases ────────────────────────────────────────────────────

type PreCheckResult struct {
	AuditRunID   string        `json:"audit_run_id"`
	Reachable    bool          `json:"reachable"`
	FinalURL     string        `json:"final_url"`
	StatusCode   int           `json:"status_code"`
	ResponseTime time.Duration `json:"response_time_ns"`
	Error        string        `json:"error,omitempty"`
	CheckedAt    time.Time     `json:"checked_at"`
}

type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	TXT   []string `json:"txt,omitempty"`
}

type PortProbe struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Open     bool   `json:"open"`
	Error    string `json:"error,omitempty"`
}

type TLSInfo struct {
	Checked      bool      `json:"checked"`
	Valid        bool      `json:"valid"`
	Version      string    `json:"version,omitempty"`
	CipherSuite  string    `json:"cipher_suite,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	DaysToExpiry int       `json:"days_to_expiry,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type NetworkResult struct {
	AuditRunID string      `json:"audit_run_id"`
	Host       string      `json:"host"`
	Scheme     string      `json:"scheme"`
	DNS        DNSRecords  `json:"dns"`
	Ports      []PortProbe `json:"ports"`
	TLS        *TLSInfo    `json:"tls,omitempty"`
	CheckedAt  time.Time   `json:"checked_at"`
}

type ReconResult struct {
	AuditRunID    string            `json:"audit_run_id"`
	FinalURL      string            `json:"final_url"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title,omitempty"`
	Server        string            `json:"server,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	Headers       map[string]string `json:"headers"`
	HasRobotsTxt  bool              `json:"has_robots_txt"`
	HasSitemapXML bool              `json:"has_sitemap_xml"`
	InternalLinks []string          `json:"internal_links,omitempty"`
	LooksLikeAPI  bool              `json:"looks_like_api"`
	CollectedAt   time.Time         `json:"collected_at"`
}

type CrawlResult struct {
	AuditRunID string    `json:"audit_run_id"`
	Assets     []*Asset  `json:"assets"`
	TotalFound int       `json:"total_found"`
	Skipped    []string  `json:"skipped,omitempty"`
	CrawledAt  time.Time `json:"crawled_at"`
}

type FingerprintResult struct {
	AuditRunID    string            `json:"audit_run_id"`
	Framework     string            `json:"framework,omitempty"`
	Language      string            `json:"language,omitempty"`
	Server        string            `json:"server,omitempty"`
	CMSOrPlatform string            `json:"cms_or_platform,omitempty"`
	AuthMechanism string            `json:"auth_mechanism,omitempty"`
	LooksLikeAPI  bool              `json:"looks_like_api"`
	Technologies  []string          `json:"technologies,omitempty"`
	HeaderClues   map[string]string `json:"header_clues,omitempty"`
	DetectedAt    time.Time         `json:"detected_at"`
}

// ─── Assets / Endpoints ─────────────────────────────────────────────────────

type AssetType string

const (
	AssetEndpoint AssetType = "endpoint"
	AssetAPIREST  AssetType = "api-rest"
	AssetForm     AssetType = "form"
	AssetFile     AssetType = "file"
)

type Asset struct {
	ID           string            `json:"id"`
	AuditRunID   string            `json:"audit_run_id"`
	Type         AssetType         `json:"type"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Params       []string          `json:"params,omitempty"`
	BodyType     string            `json:"body_type,omitempty"`
	BodyRaw      string            `json:"body_raw,omitempty"`
	BodyTemplate map[string]string `json:"body_template,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Cookies      map[string]string `json:"cookies,omitempty"`
	DiscoveredBy string            `json:"discovered_by"`
	TestedAt     *time.Time        `json:"tested_at,omitempty"`
}

// ─── Findings ───────────────────────────────────────────────────────────────

type Finding struct {
	ID                string             `json:"id"`
	AuditRunID        string             `json:"audit_run_id"`
	AssetID           string             `json:"asset_id,omitempty"`
	Method            string             `json:"method,omitempty"`
	TaxonomyID        string             `json:"taxonomy_id"`
	Type              string             `json:"type"`
	Title             string             `json:"title"`
	Severity          Severity           `json:"severity"`
	Confidence        Confidence         `json:"confidence"`
	Status            FindingStatus      `json:"status"`
	Score             int                `json:"score"`
	CWE               string             `json:"cwe,omitempty"`
	OWASPCat          string             `json:"owasp_category,omitempty"`
	WSTGMapping       string             `json:"wstg_mapping,omitempty"`
	ASVSMapping       string             `json:"asvs_mapping,omitempty"`
	Description       string             `json:"description"`
	Impact            string             `json:"impact,omitempty"`
	Remediation       string             `json:"remediation,omitempty"`
	Module            string             `json:"module,omitempty"`
	Category          string             `json:"category,omitempty"`
	CVSSScore         float64            `json:"cvss_score,omitempty"`
	References        []string           `json:"references,omitempty"`
	Tags              []string           `json:"tags,omitempty"`
	VerifiedBy        string             `json:"verified_by,omitempty"`
	Replayable        bool               `json:"replayable"`
	ReplayState       FindingReplayState `json:"replay_state,omitempty"`
	LastReplayAt      *time.Time         `json:"last_replay_at,omitempty"`
	Endpoint          string             `json:"endpoint,omitempty"`
	Parameter         string             `json:"parameter,omitempty"`
	Source            string             `json:"source,omitempty"`
	OccurrenceCount   int                `json:"occurrence_count,omitempty"`
	AffectedEndpoints []string           `json:"affected_endpoints,omitempty"`
	RelatedFindingIDs []string           `json:"related_finding_ids,omitempty"`
	Evidence          *Evidence          `json:"evidence,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         *time.Time         `json:"updated_at,omitempty"`
}

type Evidence struct {
	ID            string   `json:"id"`
	FindingID     string   `json:"finding_id"`
	RequestRaw    string   `json:"request_raw,omitempty"`
	ResponseRaw   string   `json:"response_raw,omitempty"`
	Payload       string   `json:"payload,omitempty"`
	MatcherResult string   `json:"matcher_result,omitempty"`
	Screenshots   []string `json:"screenshots,omitempty"`
}

// ─── Interface commune des modules scanner ───────────────────────────────────

// ModuleContext est le contexte enrichi passé à chaque module.
type ModuleContext struct {
	AuditRunID  string
	Asset       *Asset
	Fingerprint *FingerprintResult
	Options     AuditOptions
}

// ModuleResult est ce que retourne un module de test.
type ModuleResult struct {
	Findings []*Finding
	Error    error
}

// ─── Payloads API ────────────────────────────────────────────────────────────

type CreateAuditRequest struct {
	TargetURL string       `json:"target_url"`
	Options   AuditOptions `json:"options,omitempty"`
}

type AuditDetail struct {
	Audit         AuditRun            `json:"audit"`
	PreCheck      *PreCheckResult     `json:"pre_check,omitempty"`
	Network       *NetworkResult      `json:"network,omitempty"`
	Recon         *ReconResult        `json:"recon,omitempty"`
	Crawl         *CrawlResult        `json:"crawl,omitempty"`
	Fingerprint   *FingerprintResult  `json:"fingerprint,omitempty"`
	Report        *AuditReport        `json:"report,omitempty"`
	ActiveStats   *ActiveTestStats    `json:"active_stats,omitempty"`
	ActiveSummary *ActivePhaseSummary `json:"active_summary,omitempty"`
	EventCount    int                 `json:"event_count"`
	FindingCount  int                 `json:"finding_count"`
}

// ActiveIDORIdentity represente une session de test explicitement fournie
// par l'operateur. Les secrets ne doivent jamais etre exposes par l'API.
type ActiveIDORIdentity struct {
	Name          string            `json:"name"`
	Role          string            `json:"role,omitempty"`
	Tenant        string            `json:"tenant,omitempty"`
	Organization  string            `json:"organization,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       map[string]string `json:"cookies,omitempty"`
	BearerToken   string            `json:"bearer_token,omitempty"`
	BasicUsername string            `json:"basic_username,omitempty"`
	BasicPassword string            `json:"basic_password,omitempty"`
}

type ActiveIDORResource struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	OwnerIdentity string `json:"owner_identity"`
	Tenant        string `json:"tenant,omitempty"`
}

type IDORCaseEvidence struct {
	Label              string   `json:"label,omitempty"`
	Actor              string   `json:"actor,omitempty"`
	ActorRole          string   `json:"actor_role,omitempty"`
	ActorTenant        string   `json:"actor_tenant,omitempty"`
	ActorOrganization  string   `json:"actor_organization,omitempty"`
	ActorScopes        []string `json:"actor_scopes,omitempty"`
	Resource           string   `json:"resource,omitempty"`
	Owner              string   `json:"owner,omitempty"`
	ResourceTenant     string   `json:"resource_tenant,omitempty"`
	Direction          string   `json:"direction,omitempty"`
	StatusCode         int      `json:"status_code,omitempty"`
	Denied             bool     `json:"denied"`
	BusinessEquivalent bool     `json:"business_equivalent"`
}

type AuditOptions struct {
	AllowedHosts                         []string             `json:"allowed_hosts,omitempty"`
	ExcludedPaths                        []string             `json:"excluded_paths,omitempty"`
	ScanProfile                          string               `json:"scan_profile,omitempty"`
	EnabledPhases                        []Phase              `json:"enabled_phases,omitempty"`
	PassiveModules                       []string             `json:"passive_modules,omitempty"`
	ActiveModules                        []string             `json:"active_modules,omitempty"`
	MaxDepth                             int                  `json:"max_depth,omitempty"`
	MaxPages                             int                  `json:"max_pages,omitempty"`
	RateLimitRPS                         float64              `json:"rate_limit_rps,omitempty"`
	UserAgent                            string               `json:"user_agent,omitempty"`
	Headers                              map[string]string    `json:"headers,omitempty"`
	Cookies                              map[string]string    `json:"cookies,omitempty"`
	BearerToken                          string               `json:"bearer_token,omitempty"`
	BasicUsername                        string               `json:"basic_username,omitempty"`
	BasicPassword                        string               `json:"basic_password,omitempty"`
	ActiveTestTimeoutSeconds             int                  `json:"active_test_timeout_seconds,omitempty"`
	ActivePhaseTimeoutSeconds            int                  `json:"active_phase_timeout_seconds,omitempty"`
	ActiveMaxRequestsPerTest             int                  `json:"active_max_requests_per_test,omitempty"`
	ActiveMaxRequestsPerEndpoint         int                  `json:"active_max_requests_per_endpoint,omitempty"`
	ActiveMaxRequestsPerModule           int                  `json:"active_max_requests_per_module,omitempty"`
	ActiveMaxRepetitions                 int                  `json:"active_max_repetitions,omitempty"`
	ActiveMaxRedirects                   int                  `json:"active_max_redirects,omitempty"`
	ActiveMaxResponseBytes               int64                `json:"active_max_response_bytes,omitempty"`
	ActiveBrowserEnabled                 bool                 `json:"active_browser_enabled,omitempty"`
	ActiveBrowserTimeoutSeconds          int                  `json:"active_browser_timeout_seconds,omitempty"`
	ActiveSQLiTimingEnabled              bool                 `json:"active_sqli_timing_enabled,omitempty"`
	ActiveSQLiTimingDelayMillis          int                  `json:"active_sqli_timing_delay_ms,omitempty"`
	ActiveSQLiTimingBaselineSamples      int                  `json:"active_sqli_timing_baseline_samples,omitempty"`
	ActiveSQLiTimingControlSamples       int                  `json:"active_sqli_timing_control_samples,omitempty"`
	ActiveSQLiTimingProbeSamples         int                  `json:"active_sqli_timing_probe_samples,omitempty"`
	ActiveSQLiTimingReproductionSamples  int                  `json:"active_sqli_timing_reproduction_samples,omitempty"`
	SensitiveHeaders                     []string             `json:"sensitive_headers,omitempty"`
	ActiveTraversalProofPath             string               `json:"active_traversal_proof_path,omitempty"`
	ActiveTraversalProofMarker           string               `json:"active_traversal_proof_marker,omitempty"`
	ActiveTraversalProofPlatform         string               `json:"active_traversal_proof_platform,omitempty"`
	ActiveTraversalProofResourceType     string               `json:"active_traversal_proof_resource_type,omitempty"`
	ActiveSSRFCallbackURL                string               `json:"active_ssrf_callback_url,omitempty"`
	ActiveSSRFCallbackCheckURL           string               `json:"active_ssrf_callback_check_url,omitempty"`
	ActiveSSRFCallbackMarker             string               `json:"active_ssrf_callback_marker,omitempty"`
	ActiveSSRFAllowPrivateCallback       bool                 `json:"active_ssrf_allow_private_callback,omitempty"`
	ActiveSSRFCallbackWindowMillis       int                  `json:"active_ssrf_callback_window_ms,omitempty"`
	ActiveSSRFCallbackPollIntervalMillis int                  `json:"active_ssrf_callback_poll_interval_ms,omitempty"`
	ActiveSSRFCallbackMaxPolls           int                  `json:"active_ssrf_callback_max_polls,omitempty"`
	ActiveIDORIdentities                 []ActiveIDORIdentity `json:"active_idor_identities,omitempty"`
	ActiveIDORResources                  []ActiveIDORResource `json:"active_idor_resources,omitempty"`
	ActiveIDOROwnerIdentity              string               `json:"active_idor_owner_identity,omitempty"`
	ActiveIDORNonOwnerIdentity           string               `json:"active_idor_non_owner_identity,omitempty"`
	ActiveIDOROwnerResource              string               `json:"active_idor_owner_resource,omitempty"`
	ActiveIDORNonOwnerResource           string               `json:"active_idor_non_owner_resource,omitempty"`
	ActiveIDORSuccessMarker              string               `json:"active_idor_success_marker,omitempty"`
	ActiveIDORDeniedMarker               string               `json:"active_idor_denied_marker,omitempty"`
	ActiveIDORAllowWrite                 bool                 `json:"active_idor_allow_write,omitempty"`
}

type ActiveTestStatus string

const (
	ActiveTestQueued                   ActiveTestStatus = "QUEUED"
	ActiveTestStarted                  ActiveTestStatus = "STARTED"
	ActiveTestRequestSent              ActiveTestStatus = "REQUEST_SENT"
	ActiveTestResponseReceived         ActiveTestStatus = "RESPONSE_RECEIVED"
	ActiveTestAnalyzing                ActiveTestStatus = "ANALYZING"
	ActiveTestBaselineRequestSent      ActiveTestStatus = "BASELINE_REQUEST_SENT"
	ActiveTestBaselineResponseReceived ActiveTestStatus = "BASELINE_RESPONSE_RECEIVED"
	ActiveTestTestRequestSent          ActiveTestStatus = "TEST_REQUEST_SENT"
	ActiveTestTestResponseReceived     ActiveTestStatus = "TEST_RESPONSE_RECEIVED"
	ActiveTestComparing                ActiveTestStatus = "COMPARING"
	ActiveTestValidating               ActiveTestStatus = "VALIDATING"
	ActiveTestReproducing              ActiveTestStatus = "REPRODUCING"
	ActiveTestConfirmed                ActiveTestStatus = "CONFIRMED"
	ActiveTestNotConfirmed             ActiveTestStatus = "NOT_CONFIRMED"
	ActiveTestFalsePositive            ActiveTestStatus = "FALSE_POSITIVE"
	ActiveTestInconclusive             ActiveTestStatus = "INCONCLUSIVE"
	ActiveTestFailed                   ActiveTestStatus = "FAILED"
	ActiveTestTimeout                  ActiveTestStatus = "TIMEOUT"
	ActiveTestUntestable               ActiveTestStatus = "UNTESTABLE"
	ActiveTestSkipped                  ActiveTestStatus = "SKIPPED"
	ActiveTestCancelled                ActiveTestStatus = "CANCELLED"
)

type EntryPointLocation string

const (
	EntryPointQuery     EntryPointLocation = "query"
	EntryPointForm      EntryPointLocation = "form"
	EntryPointJSON      EntryPointLocation = "json"
	EntryPointXML       EntryPointLocation = "xml"
	EntryPointMultipart EntryPointLocation = "multipart"
	EntryPointGraphQL   EntryPointLocation = "graphql"
	EntryPointPath      EntryPointLocation = "path"
	EntryPointHeader    EntryPointLocation = "header"
	EntryPointCookie    EntryPointLocation = "cookie"
)

type EntryPoint struct {
	Endpoint      string             `json:"endpoint"`
	Method        string             `json:"method"`
	Name          string             `json:"name"`
	Location      EntryPointLocation `json:"location"`
	OriginalValue string             `json:"original_value,omitempty"`
	BodyType      string             `json:"body_type,omitempty"`
}

type HTTPRequestRecord struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type HTTPResponseRecord struct {
	StatusCode        int               `json:"status_code"`
	Headers           map[string]string `json:"headers,omitempty"`
	BodyPreview       string            `json:"body_preview,omitempty"`
	BodySize          int64             `json:"body_size"`
	DurationMillis    int64             `json:"duration_ms"`
	NormalizedHash    string            `json:"normalized_hash,omitempty"`
	NormalizedPreview string            `json:"normalized_preview,omitempty"`
	Redirects         []string          `json:"redirects,omitempty"`
}

type HTTPExchange struct {
	Kind       string              `json:"kind"`
	Label      string              `json:"label,omitempty"`
	Request    HTTPRequestRecord   `json:"request"`
	Response   *HTTPResponseRecord `json:"response,omitempty"`
	Error      string              `json:"error,omitempty"`
	StartedAt  time.Time           `json:"started_at"`
	FinishedAt time.Time           `json:"finished_at"`
}

type Baseline struct {
	Exchanges      []HTTPExchange `json:"exchanges"`
	Stable         bool           `json:"stable"`
	NormalizedHash string         `json:"normalized_hash,omitempty"`
}

type ResponseDifference struct {
	Metric      string `json:"metric"`
	Baseline    string `json:"baseline,omitempty"`
	Observed    string `json:"observed,omitempty"`
	Significant bool   `json:"significant"`
	Explanation string `json:"explanation,omitempty"`
}

// TimingEvidence records the samples and robust statistics used by a
// time-based active test. Durations are kept in milliseconds to make the
// decision reproducible without exposing raw request bodies or secrets.
type TimingEvidence struct {
	Strategy                   string  `json:"strategy,omitempty"`
	Context                    string  `json:"context,omitempty"`
	DelayMillis                int64   `json:"delay_ms,omitempty"`
	BaselineMillis             []int64 `json:"baseline_ms,omitempty"`
	ControlMillis              []int64 `json:"control_ms,omitempty"`
	ProbeMillis                []int64 `json:"probe_ms,omitempty"`
	ReproductionMillis         []int64 `json:"reproduction_ms,omitempty"`
	BaselineMedianMillis       float64 `json:"baseline_median_ms,omitempty"`
	ControlMedianMillis        float64 `json:"control_median_ms,omitempty"`
	ProbeMedianMillis          float64 `json:"probe_median_ms,omitempty"`
	ReproductionMedianMillis   float64 `json:"reproduction_median_ms,omitempty"`
	BaselineMADMillis          float64 `json:"baseline_mad_ms,omitempty"`
	ControlMADMillis           float64 `json:"control_mad_ms,omitempty"`
	ProbeMADMillis             float64 `json:"probe_mad_ms,omitempty"`
	ThresholdMillis            float64 `json:"threshold_ms,omitempty"`
	ProbeAboveThreshold        int     `json:"probe_above_threshold,omitempty"`
	ReproductionAboveThreshold int     `json:"reproduction_above_threshold,omitempty"`
	Significant                bool    `json:"significant,omitempty"`
	Rule                       string  `json:"rule,omitempty"`
}

type CallbackPollEvidence struct {
	Attempt    int    `json:"attempt"`
	StatusCode int    `json:"status_code,omitempty"`
	Status     string `json:"status,omitempty"`
	Body       string `json:"body,omitempty"`
}

type CallbackObservationEvidence struct {
	Role                string                 `json:"role,omitempty"`
	Token               string                 `json:"token,omitempty"`
	CallbackURL         string                 `json:"callback_url,omitempty"`
	CheckURL            string                 `json:"check_url,omitempty"`
	Status              string                 `json:"status,omitempty"`
	Observed            bool                   `json:"observed"`
	Polls               int                    `json:"polls"`
	Proof               string                 `json:"proof,omitempty"`
	Error               string                 `json:"error,omitempty"`
	ObservedDestination string                 `json:"observed_destination,omitempty"`
	ObservedHost        string                 `json:"observed_host,omitempty"`
	ObservedAddress     string                 `json:"observed_address,omitempty"`
	PollTrace           []CallbackPollEvidence `json:"poll_trace,omitempty"`
}

// BrowserEventEvidence conserve les événements utiles produits par un rendu
// navigateur sans coupler models au package d'exécution CDP.
type BrowserEventEvidence struct {
	Type   string    `json:"type"`
	URL    string    `json:"url,omitempty"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// BrowserEvidence prouve ce que le navigateur a réellement observé. Le DOM
// est déjà limité et masqué par le runner avant d'arriver ici.
type BrowserEvidence struct {
	FinalURL       string                 `json:"final_url,omitempty"`
	FinalOrigin    string                 `json:"final_origin,omitempty"`
	DOM            string                 `json:"dom,omitempty"`
	Marker         string                 `json:"marker,omitempty"`
	MarkerObserved bool                   `json:"marker_observed"`
	Navigations    []string               `json:"navigations,omitempty"`
	Events         []BrowserEventEvidence `json:"events,omitempty"`
	BlockedURLs    []string               `json:"blocked_urls,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Reproductions  int                    `json:"reproductions,omitempty"`
}

type ActiveEvidence struct {
	Expected                   string                        `json:"expected,omitempty"`
	Observed                   string                        `json:"observed,omitempty"`
	FinalURL                   string                        `json:"final_url,omitempty"`
	FinalOrigin                string                        `json:"final_origin,omitempty"`
	RedirectType               string                        `json:"redirect_type,omitempty"`
	RedirectChain              []string                      `json:"redirect_chain,omitempty"`
	CallbackToken              string                        `json:"callback_token,omitempty"`
	CallbackURL                string                        `json:"callback_url,omitempty"`
	CallbackCheckURL           string                        `json:"callback_check_url,omitempty"`
	CallbackObserved           bool                          `json:"callback_observed,omitempty"`
	CallbackProof              string                        `json:"callback_proof,omitempty"`
	CallbackError              string                        `json:"callback_error,omitempty"`
	CallbackObservations       []CallbackObservationEvidence `json:"callback_observations,omitempty"`
	CallbackPolls              int                           `json:"callback_polls,omitempty"`
	CallbackWindowMillis       int                           `json:"callback_window_ms,omitempty"`
	CallbackPollIntervalMillis int                           `json:"callback_poll_interval_ms,omitempty"`
	Operation                  string                        `json:"operation,omitempty"`
	Browser                    *BrowserEvidence              `json:"browser,omitempty"`
	IDORCases                  []IDORCaseEvidence            `json:"idor_cases,omitempty"`
	OwnerIdentity              string                        `json:"owner_identity,omitempty"`
	NonOwnerIdentity           string                        `json:"non_owner_identity,omitempty"`
	OwnerResource              string                        `json:"owner_resource,omitempty"`
	NonOwnerResource           string                        `json:"non_owner_resource,omitempty"`
	Baseline                   *Baseline                     `json:"baseline,omitempty"`
	TestExchanges              []HTTPExchange                `json:"test_exchanges,omitempty"`
	Differences                []ResponseDifference          `json:"differences,omitempty"`
	Timing                     *TimingEvidence               `json:"timing,omitempty"`
	ValidationRule             string                        `json:"validation_rule,omitempty"`
	Confidence                 Confidence                    `json:"confidence,omitempty"`
	Reproductions              int                           `json:"reproductions"`
	MinimumProofReached        bool                          `json:"minimum_proof_reached"`
	Conclusion                 string                        `json:"conclusion,omitempty"`
}

type ActiveTestPlan struct {
	EntryPoint      EntryPoint `json:"entry_point"`
	SourceFindingID string     `json:"source_finding_id,omitempty"`
	Reason          string     `json:"reason,omitempty"`
}

type ActiveTestResult struct {
	Status               ActiveTestStatus `json:"status"`
	Reason               string           `json:"reason"`
	Evidence             *ActiveEvidence  `json:"evidence,omitempty"`
	Findings             []*Finding       `json:"findings,omitempty"`
	RequestCount         int              `json:"request_count"`
	ResponseCount        int              `json:"response_count"`
	Executed             bool             `json:"executed"`
	Analyzed             bool             `json:"analyzed"`
	MinimumConditionsMet bool             `json:"minimum_conditions_met"`
	LimitReached         string           `json:"limit_reached,omitempty"`
}

type ActiveTestStep struct {
	Status    ActiveTestStatus `json:"status"`
	Message   string           `json:"message,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

type ActiveTest struct {
	ID                   string           `json:"id"`
	AuditRunID           string           `json:"audit_run_id"`
	AssetID              string           `json:"asset_id,omitempty"`
	Module               string           `json:"module"`
	Method               string           `json:"method,omitempty"`
	URL                  string           `json:"url,omitempty"`
	EntryPoint           *EntryPoint      `json:"entry_point,omitempty"`
	SourceFindingID      string           `json:"source_finding_id,omitempty"`
	FindingIDs           []string         `json:"finding_ids,omitempty"`
	AuthContext          string           `json:"auth_context,omitempty"`
	Status               ActiveTestStatus `json:"status"`
	Steps                []ActiveTestStep `json:"steps"`
	Error                string           `json:"error,omitempty"`
	RequestCount         int              `json:"request_count"`
	ResponseCount        int              `json:"response_count"`
	FindingCount         int              `json:"finding_count"`
	Executed             bool             `json:"executed"`
	Analyzed             bool             `json:"analyzed"`
	MinimumConditionsMet bool             `json:"minimum_conditions_met"`
	StatusReason         string           `json:"status_reason,omitempty"`
	LimitReached         string           `json:"limit_reached,omitempty"`
	Evidence             *ActiveEvidence  `json:"evidence,omitempty"`
	QueuedAt             time.Time        `json:"queued_at"`
	StartedAt            *time.Time       `json:"started_at,omitempty"`
	FinishedAt           *time.Time       `json:"finished_at,omitempty"`
	DurationMillis       int64            `json:"duration_ms,omitempty"`
}

type ActiveTestStats struct {
	Total           int                      `json:"total"`
	Queued          int                      `json:"queued"`
	Running         int                      `json:"running"`
	RequestsSent    int                      `json:"requests_sent"`
	Responses       int                      `json:"responses_received"`
	Finalized       int                      `json:"finalized"`
	Started         int                      `json:"started"`
	Analyzed        int                      `json:"analyzed"`
	WithoutRequest  int                      `json:"without_request"`
	WithoutResponse int                      `json:"without_response"`
	Progress        float64                  `json:"progress"`
	ByStatus        map[ActiveTestStatus]int `json:"by_status"`
	ByFinalStatus   map[ActiveTestStatus]int `json:"by_final_status"`
	ByModule        map[string]int           `json:"by_module"`
	NonFinal        int                      `json:"non_final"`
}

type ActivePhaseSummary struct {
	AuditRunID            string                   `json:"audit_run_id"`
	GeneratedTests        int                      `json:"generated_tests"`
	FinalizedTests        int                      `json:"finalized_tests"`
	StartedTests          int                      `json:"started_tests"`
	TestsWithRequests     int                      `json:"tests_with_requests"`
	TestsWithResponses    int                      `json:"tests_with_responses"`
	AnalyzedTests         int                      `json:"analyzed_tests"`
	TotalRequests         int                      `json:"total_requests"`
	TotalResponses        int                      `json:"total_responses"`
	StatusCounts          map[ActiveTestStatus]int `json:"status_counts"`
	ModuleCounts          map[string]int           `json:"module_counts"`
	DurationMillis        int64                    `json:"duration_ms"`
	AverageTestMillis     int64                    `json:"average_test_ms"`
	NonFinalTests         int                      `json:"non_final_tests"`
	TopErrors             []string                 `json:"top_errors,omitempty"`
	RecoveredBlockedTests int                      `json:"recovered_blocked_tests"`
	GeneratedAt           time.Time                `json:"generated_at"`
}

type AuditReport struct {
	AuditRunID         string                `json:"audit_run_id"`
	GeneratedAt        time.Time             `json:"generated_at"`
	TargetURL          string                `json:"target_url"`
	RiskScore          int                   `json:"risk_score"`
	RiskLevel          string                `json:"risk_level"`
	ExecutiveSummary   string                `json:"executive_summary"`
	FindingsBySeverity map[Severity]int      `json:"findings_by_severity"`
	FindingsByStatus   map[FindingStatus]int `json:"findings_by_status"`
	FindingsBySource   map[string]int        `json:"findings_by_source"`
	ConsolidatedCount  int                   `json:"consolidated_finding_count"`
	OccurrenceCount    int                   `json:"finding_occurrence_count"`
	TopFindings        []*Finding            `json:"top_findings"`
	Recommendations    []string              `json:"recommendations"`
	ActiveSummary      *ActivePhaseSummary   `json:"active_summary,omitempty"`
}

type AuditTrendRun struct {
	AuditID         string           `json:"audit_id"`
	TargetURL       string           `json:"target_url"`
	Status          AuditStatus      `json:"status"`
	StartedAt       time.Time        `json:"started_at"`
	FinishedAt      *time.Time       `json:"finished_at,omitempty"`
	RiskScore       int              `json:"risk_score"`
	RiskLevel       string           `json:"risk_level"`
	FindingCount    int              `json:"finding_count"`
	OccurrenceCount int              `json:"occurrence_count"`
	SeverityCounts  map[Severity]int `json:"severity_counts"`
}

type RecurringFindingTrend struct {
	Key          string   `json:"key"`
	Type         string   `json:"type"`
	Title        string   `json:"title"`
	Severity     Severity `json:"severity"`
	AuditCount   int      `json:"audit_count"`
	FindingCount int      `json:"finding_count"`
	Occurrences  int      `json:"occurrences"`
	Audits       []string `json:"audits"`
	Endpoints    []string `json:"endpoints"`
}

type AuditTrends struct {
	GeneratedAt       time.Time                `json:"generated_at"`
	Runs              []*AuditTrendRun         `json:"runs"`
	RecurringFindings []*RecurringFindingTrend `json:"recurring_findings"`
}
