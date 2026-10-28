package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

func TestCheckScopeAllowsConfiguredHost(t *testing.T) {
	u, _ := url.Parse("https://example.com/app")
	options := models.AuditOptions{AllowedHosts: []string{"example.com"}}
	if err := CheckScope(u, options); err != nil {
		t.Fatalf("expected host to be allowed: %v", err)
	}
}

func TestCheckScopeBlocksUnexpectedHost(t *testing.T) {
	u, _ := url.Parse("https://evil.example/app")
	options := models.AuditOptions{AllowedHosts: []string{"example.com"}}
	if err := CheckScope(u, options); err == nil {
		t.Fatal("expected host to be blocked")
	}
}

func TestCheckScopeBlocksExcludedPath(t *testing.T) {
	u, _ := url.Parse("https://example.com/admin/panel")
	options := models.AuditOptions{
		AllowedHosts:  []string{"example.com"},
		ExcludedPaths: []string{"/admin"},
	}
	if err := CheckScope(u, options); err == nil {
		t.Fatal("expected excluded path to be blocked")
	}
}

func TestMergeOptionsAppliesPassiveOnlyProfile(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{ScanProfile: "passive-only"})

	if options.ScanProfile != "passive-only" {
		t.Fatalf("expected passive-only profile, got %q", options.ScanProfile)
	}
	if containsPhase(options.EnabledPhases, models.PhaseActive) {
		t.Fatal("expected active phase to be disabled")
	}
	if options.ActiveModules == nil || len(options.ActiveModules) != 0 {
		t.Fatalf("expected active modules to be explicitly empty, got %#v", options.ActiveModules)
	}
	if len(options.PassiveModules) == 0 {
		t.Fatal("expected passive modules to be enabled")
	}
}

func TestMergeOptionsAllowsCustomModuleOverrides(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ScanProfile:    "custom",
		EnabledPhases:  []models.Phase{models.PhasePreCheck, models.PhasePassive, models.PhaseReport},
		PassiveModules: []string{"headers"},
		ActiveModules:  []string{},
	})

	if !containsPhase(options.EnabledPhases, models.PhasePassive) || containsPhase(options.EnabledPhases, models.PhaseActive) {
		t.Fatalf("unexpected phases: %#v", options.EnabledPhases)
	}
	if len(options.PassiveModules) != 1 || options.PassiveModules[0] != "headers" {
		t.Fatalf("expected custom passive modules to be preserved, got %#v", options.PassiveModules)
	}
	if options.ActiveModules == nil || len(options.ActiveModules) != 0 {
		t.Fatalf("expected custom active modules to be disabled, got %#v", options.ActiveModules)
	}
}

func TestMergeOptionsPreservesIDORConfiguration(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ActiveIDORIdentities:    []models.ActiveIDORIdentity{{Name: "alice", BearerToken: "secret", Role: "member", Tenant: "tenant-a", Organization: "org-a", Scopes: []string{"orders:read"}}},
		ActiveIDORResources:     []models.ActiveIDORResource{{Name: "order-1", URL: "https://example.com/orders/1", OwnerIdentity: "alice", Tenant: "tenant-a"}, {Name: "order-2", URL: "https://example.com/orders/2", OwnerIdentity: "bob", Tenant: "tenant-a"}},
		ActiveIDOROwnerIdentity: "alice", ActiveIDORNonOwnerIdentity: "bob",
		ActiveIDOROwnerResource: "https://example.com/orders/1", ActiveIDORNonOwnerResource: "https://example.com/orders/2",
		ActiveIDORSuccessMarker: "order_id", ActiveIDORDeniedMarker: "forbidden", ActiveIDORAllowWrite: true,
	})
	if len(options.ActiveIDORIdentities) != 1 || options.ActiveIDORIdentities[0].Name != "alice" || options.ActiveIDOROwnerIdentity != "alice" || options.ActiveIDORNonOwnerIdentity != "bob" {
		t.Fatalf("IDOR identities were not propagated: %+v", options)
	}
	if options.ActiveIDOROwnerResource == "" || options.ActiveIDORNonOwnerResource == "" || !options.ActiveIDORAllowWrite {
		t.Fatalf("IDOR resource/write configuration was not propagated: %+v", options)
	}
	if len(options.ActiveIDORResources) != 2 || options.ActiveIDORResources[0].Tenant != "tenant-a" || options.ActiveIDORIdentities[0].Role != "member" || len(options.ActiveIDORIdentities[0].Scopes) != 1 {
		t.Fatalf("IDOR matrix metadata was not propagated: %+v", options)
	}
}

func TestMergeOptionsPreservesSQLiTimingConfiguration(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ActiveSQLiTimingEnabled:             true,
		ActiveSQLiTimingDelayMillis:         1200,
		ActiveSQLiTimingBaselineSamples:     3,
		ActiveSQLiTimingControlSamples:      2,
		ActiveSQLiTimingProbeSamples:        3,
		ActiveSQLiTimingReproductionSamples: 1,
	})
	if !options.ActiveSQLiTimingEnabled || options.ActiveSQLiTimingDelayMillis != 1200 {
		t.Fatalf("SQLi timing enablement/delay was not preserved: %+v", options)
	}
	if options.ActiveSQLiTimingBaselineSamples != 3 || options.ActiveSQLiTimingControlSamples != 2 || options.ActiveSQLiTimingProbeSamples != 3 || options.ActiveSQLiTimingReproductionSamples != 1 {
		t.Fatalf("SQLi timing sample configuration was not preserved: %+v", options)
	}
}

func TestMergeOptionsPreservesSSRFCallbackPollingConfiguration(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ActiveSSRFCallbackWindowMillis:       1200,
		ActiveSSRFCallbackPollIntervalMillis: 150,
		ActiveSSRFCallbackMaxPolls:           8,
	})
	if options.ActiveSSRFCallbackWindowMillis != 1200 || options.ActiveSSRFCallbackPollIntervalMillis != 150 || options.ActiveSSRFCallbackMaxPolls != 8 {
		t.Fatalf("SSRF callback polling configuration was not preserved: %+v", options)
	}
}

func TestMergeOptionsPreservesTraversalProofConfiguration(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ActiveTraversalProofPath:         "/tmp/audit-proof.txt",
		ActiveTraversalProofMarker:       "AUDITCORE-PROOF",
		ActiveTraversalProofPlatform:     "unix",
		ActiveTraversalProofResourceType: "lfi",
	})
	if options.ActiveTraversalProofPath != "/tmp/audit-proof.txt" || options.ActiveTraversalProofMarker != "AUDITCORE-PROOF" || options.ActiveTraversalProofPlatform != "unix" || options.ActiveTraversalProofResourceType != "lfi" {
		t.Fatalf("traversal proof configuration was not preserved: %+v", options)
	}
}

func TestMergeOptionsPreservesBrowserValidationConfiguration(t *testing.T) {
	options := MergeOptions("https://example.com", models.AuditOptions{
		ActiveBrowserEnabled:        true,
		ActiveBrowserTimeoutSeconds: 17,
	})
	if !options.ActiveBrowserEnabled || options.ActiveBrowserTimeoutSeconds != 17 {
		t.Fatalf("browser validation configuration was not preserved: %+v", options)
	}
}

func TestAuthenticationOverrideDoesNotLeakGlobalCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer alice-token" {
			t.Errorf("expected IDOR identity authorization, got %q", got)
		}
		if got := r.Header.Get("Cookie"); got != "idor=session" {
			t.Errorf("expected IDOR identity cookie, got %q", got)
		}
		if got := r.Header.Get("X-API-Key"); got != "" {
			t.Errorf("global API key leaked into IDOR identity request: %q", got)
		}
		if got := r.Header.Get("X-Client"); got != "default" {
			t.Errorf("expected non-authentication default header, got %q", got)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	client := NewClient(time.Second, models.AuditOptions{
		BearerToken: "global-token", Cookies: map[string]string{"global": "cookie"},
		Headers: map[string]string{"X-API-Key": "global-api-key", "X-Client": "default"},
	})
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request = WithAuthenticationOverride(request)
	request.Header.Set("Authorization", "Bearer alice-token")
	request.AddCookie(&http.Cookie{Name: "idor", Value: "session"})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
}

func containsPhase(phases []models.Phase, phase models.Phase) bool {
	for _, item := range phases {
		if item == phase {
			return true
		}
	}
	return false
}
