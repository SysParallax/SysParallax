package idor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/scanner/active"
)

func runIDORActive(t *testing.T, method string, handler http.Handler, options models.AuditOptions, configure bool) *models.ActiveTestResult {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if configure {
		if options.ActiveIDORIdentities == nil {
			options.ActiveIDORIdentities = []models.ActiveIDORIdentity{
				{Name: "alice", Headers: map[string]string{"X-User": "alice"}},
				{Name: "bob", Headers: map[string]string{"X-User": "bob"}},
			}
		}
		if options.ActiveIDOROwnerIdentity == "" {
			options.ActiveIDOROwnerIdentity = "alice"
		}
		if options.ActiveIDORNonOwnerIdentity == "" {
			options.ActiveIDORNonOwnerIdentity = "bob"
		}
		if options.ActiveIDOROwnerResource == "" {
			options.ActiveIDOROwnerResource = server.URL + "/resource/1"
		}
		if options.ActiveIDORNonOwnerResource == "" {
			options.ActiveIDORNonOwnerResource = server.URL + "/resource/2"
		}
	}
	if options.ActiveMaxRequestsPerTest == 0 {
		options.ActiveMaxRequestsPerTest = 8
	}
	if options.ActiveMaxResponseBytes == 0 {
		options.ActiveMaxResponseBytes = 32 * 1024
	}
	asset := &models.Asset{
		ID: "asset-idor", AuditRunID: "audit-idor", Type: models.AssetEndpoint,
		Method: method, URL: server.URL + "/resource/1?id=1", Params: []string{"id"},
		BodyType: "form-urlencoded", BodyTemplate: map[string]string{"id": "1"},
	}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{
		Endpoint: asset.URL, Method: method, Name: "id", Location: models.EntryPointQuery, OriginalValue: "1",
	}}
	module := New()
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-idor", Asset: asset, Options: options}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "idor-test", module.Name(), plan.EntryPoint, active.NewBudget(options), nil)
	return module.RunActive(context.Background(), moduleCtx, plan, executor)
}

func TestIDORRequiresTwoIdentitiesAndTwoOwnedResources(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "should not be requested")
	}), models.AuditOptions{}, false)
	if result.Status != models.ActiveTestUntestable || result.RequestCount != 0 {
		t.Fatalf("missing IDOR configuration was probed: status=%s requests=%d reason=%s", result.Status, result.RequestCount, result.Reason)
	}
}

func TestIDORRejectsResourceOutsideTargetScope(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "should not be requested")
	}), models.AuditOptions{ActiveIDOROwnerResource: "https://outside.example/resource/1"}, true)
	if result.Status != models.ActiveTestUntestable || result.RequestCount != 0 {
		t.Fatalf("out-of-scope resource was probed: status=%s requests=%d reason=%s", result.Status, result.RequestCount, result.Reason)
	}
}

func TestIDORConfirmsCrossUserBusinessResponse(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resource/1" {
			_, _ = fmt.Fprint(w, `{"id":1,"owner":"alice","secret":"owner-record"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"id":2,"owner":"bob","secret":"bob-record"}`)
	}), models.AuditOptions{}, true)
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED for cross-user access, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || !result.Evidence.MinimumProofReached || result.Evidence.Operation != "read" || result.Evidence.OwnerIdentity != "alice" || len(result.Evidence.Differences) == 0 {
		t.Fatalf("missing owner/non-owner comparison evidence: %+v", result.Evidence)
	}
	if len(result.Findings) != 1 || result.Findings[0].Parameter != "id" || result.Findings[0].Status != models.FindingConfirmed {
		t.Fatalf("missing IDOR finding association: %+v", result.Findings)
	}
}

func TestIDORDoesNotConfirmDeniedCrossUserAccess(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		if r.URL.Path == "/resource/1" && user == "alice" {
			_, _ = fmt.Fprint(w, `{"id":1,"owner":"alice","secret":"owner-record"}`)
			return
		}
		if r.URL.Path == "/resource/2" && user == "bob" {
			_, _ = fmt.Fprint(w, `{"id":2,"owner":"bob","secret":"bob-record"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
	}), models.AuditOptions{}, true)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected NOT_CONFIRMED for denied cross-user access, got %s: %s", result.Status, result.Reason)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("denied cross-user access produced a finding: %+v", result.Findings)
	}
}

func TestIDORDoesNotTreatGeneric200AsBusinessAccess(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}), models.AuditOptions{}, true)
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for generic 200, got %s: %s", result.Status, result.Reason)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("generic 200 produced an IDOR finding: %+v", result.Findings)
	}
}

func TestIDORUsesConfiguredBusinessSuccessMarker(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK")
	}), models.AuditOptions{ActiveIDORSuccessMarker: "OK"}, true)
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected marker-based CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
}

func TestIDORDoesNotConfirmDifferentBusinessResponse(t *testing.T) {
	result := runIDORActive(t, http.MethodGet, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resource/1" && r.Header.Get("X-User") == "alice" {
			_, _ = fmt.Fprint(w, `{"id":1,"owner":"alice","secret":"owner-record"}`)
			return
		}
		if r.URL.Path == "/resource/2" && r.Header.Get("X-User") == "bob" {
			_, _ = fmt.Fprint(w, `{"id":2,"owner":"bob","secret":"bob-record"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"error":"not authorized for this resource"}`)
	}), models.AuditOptions{}, true)
	if result.Status != models.ActiveTestInconclusive {
		t.Fatalf("expected INCONCLUSIVE for ambiguous business response, got %s: %s", result.Status, result.Reason)
	}
}

func TestIDORDoesNotTestWriteOperationWithoutExplicitOptIn(t *testing.T) {
	result := runIDORActive(t, http.MethodPost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"updated","resource":"owner-record"}`)
	}), models.AuditOptions{}, true)
	if result.Status != models.ActiveTestUntestable {
		t.Fatalf("expected UNTESTABLE for write operation without opt-in, got %s: %s", result.Status, result.Reason)
	}
	if result.RequestCount != 0 {
		t.Fatalf("write operation was sent without opt-in: %d", result.RequestCount)
	}
}

func TestIDORDistinguishesExplicitlyAllowedWriteOperation(t *testing.T) {
	result := runIDORActive(t, http.MethodPost, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"updated","resource":"owner-record"}`)
	}), models.AuditOptions{ActiveIDORAllowWrite: true}, true)
	if result.Status != models.ActiveTestConfirmed {
		t.Fatalf("expected CONFIRMED for explicitly allowed write comparison, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || result.Evidence.Operation != "write" || !strings.Contains(result.Evidence.ValidationRule, "statut HTTP 200") {
		t.Fatalf("missing write operation evidence: %+v", result.Evidence)
	}
}

func TestIDORRecordsMultiTenantAuthorizationMatrix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ownerByPath := map[string]string{"/resource/1": "alice", "/resource/2": "bob", "/resource/3": "carol"}
		owner := ownerByPath[r.URL.Path]
		if owner == "" || owner != r.Header.Get("X-User") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"id":%q,"owner":%q,"tenant":%q,"resource_id":%q}`, r.URL.Path, owner, r.Header.Get("X-Tenant"), r.URL.Path)
	}))
	t.Cleanup(server.Close)
	options := models.AuditOptions{
		ActiveIDORIdentities: []models.ActiveIDORIdentity{
			{Name: "alice", Role: "member", Tenant: "tenant-a", Scopes: []string{"orders:read"}, Headers: map[string]string{"X-User": "alice", "X-Tenant": "tenant-a"}},
			{Name: "bob", Role: "member", Tenant: "tenant-a", Scopes: []string{"orders:read"}, Headers: map[string]string{"X-User": "bob", "X-Tenant": "tenant-a"}},
			{Name: "carol", Role: "admin", Tenant: "tenant-b", Scopes: []string{"orders:read"}, Headers: map[string]string{"X-User": "carol", "X-Tenant": "tenant-b"}},
		},
		ActiveIDORResources: []models.ActiveIDORResource{
			{Name: "alice-order", URL: server.URL + "/resource/1", OwnerIdentity: "alice", Tenant: "tenant-a"},
			{Name: "bob-order", URL: server.URL + "/resource/2", OwnerIdentity: "bob", Tenant: "tenant-a"},
			{Name: "carol-order", URL: server.URL + "/resource/3", OwnerIdentity: "carol", Tenant: "tenant-b"},
		},
		ActiveMaxRequestsPerTest: 16, ActiveMaxResponseBytes: 32 * 1024,
	}
	asset := &models.Asset{ID: "asset-idor-matrix", AuditRunID: "audit-idor-matrix", Type: models.AssetEndpoint, Method: http.MethodGet, URL: server.URL + "/resource/1?id=1", Params: []string{"id"}}
	plan := models.ActiveTestPlan{EntryPoint: models.EntryPoint{Endpoint: asset.URL, Method: http.MethodGet, Name: "id", Location: models.EntryPointQuery, OriginalValue: "1"}}
	moduleCtx := &models.ModuleContext{AuditRunID: "audit-idor-matrix", Asset: asset, Options: options}
	executor := active.NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "idor-matrix-test", New().Name(), plan.EntryPoint, active.NewBudget(options), nil)
	result := New().RunActive(context.Background(), moduleCtx, plan, executor)
	if result.Status != models.ActiveTestNotConfirmed {
		t.Fatalf("expected denied multi-tenant matrix to be NOT_CONFIRMED, got %s: %s", result.Status, result.Reason)
	}
	if result.Evidence == nil || len(result.Evidence.IDORCases) != 6 {
		t.Fatalf("expected six cross-identity cases, got evidence=%+v", result.Evidence)
	}
	for _, item := range result.Evidence.IDORCases {
		if !item.Denied || item.Actor == item.Owner || item.ActorRole == "" || item.ActorTenant == "" {
			t.Fatalf("invalid matrix case evidence: %+v", item)
		}
	}
}
