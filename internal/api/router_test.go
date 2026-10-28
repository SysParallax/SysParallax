package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
	"github.com/google/uuid"
)

func TestDashboardSPAFallback(t *testing.T) {
	dashboardDir := t.TempDir()
	writeDashboardFixture(t, dashboardDir, "index.html", "<html><body>AuditCore SPA</body></html>")
	writeDashboardFixture(t, dashboardDir, "router.js", "window.appRouter = {};")
	server := httptest.NewServer(NewRouter(&Handler{}, dashboardDir))
	t.Cleanup(server.Close)

	tests := []struct {
		path        string
		status      int
		body        string
		contentType string
	}{
		{path: "/findings", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/findings/finding-42", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/network", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/grc", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/trends", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/reports", status: http.StatusOK, body: "AuditCore SPA", contentType: "text/html"},
		{path: "/router.js", status: http.StatusOK, body: "window.appRouter", contentType: "javascript"},
		{path: "/missing.js", status: http.StatusNotFound},
		{path: "/api/missing", status: http.StatusNotFound},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response, err := http.Get(server.URL + test.path)
			if err != nil {
				t.Fatalf("GET %s: %v", test.path, err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read %s: %v", test.path, err)
			}
			if response.StatusCode != test.status {
				t.Fatalf("expected status %d, got %d", test.status, response.StatusCode)
			}
			if test.body != "" && !strings.Contains(string(body), test.body) {
				t.Fatalf("expected response to contain %q", test.body)
			}
			if test.contentType != "" && !strings.Contains(response.Header.Get("Content-Type"), test.contentType) {
				t.Fatalf("expected content type containing %q, got %q", test.contentType, response.Header.Get("Content-Type"))
			}
		})
	}
}

func TestGetAuditDoesNotExposeAuthenticationSecrets(t *testing.T) {
	store := storage.New()
	store.SaveAudit(&models.AuditRun{
		ID: "audit-safe", TargetURL: "https://example.test", Status: models.StatusDone,
		Phase: models.PhaseIdle, StartedAt: time.Now(),
		Options: models.AuditOptions{
			BearerToken: "bearer-secret", BasicUsername: "alice", BasicPassword: "basic-secret",
			Headers: map[string]string{"X-API-Key": "api-secret"}, Cookies: map[string]string{"session": "cookie-secret"},
			ActiveIDORIdentities: []models.ActiveIDORIdentity{{
				Name: "idor-alice", BearerToken: "idor-bearer-secret",
				BasicUsername: "idor-user", BasicPassword: "idor-password-secret",
				Headers: map[string]string{"X-Session-Token": "idor-header-secret"},
				Cookies: map[string]string{"idor": "idor-cookie-secret"},
			}},
		},
	})
	server := httptest.NewServer(NewRouter(New(store, nil), ""))
	defer server.Close()
	response, err := http.Get(server.URL + "/api/audits/audit-safe/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	serialized := string(body)
	for _, secret := range []string{"bearer-secret", "basic-secret", "api-secret", "cookie-secret", "idor-bearer-secret", "idor-password-secret", "idor-header-secret", "idor-cookie-secret"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret %q leaked in API response", secret)
		}
	}
	listResponse, err := http.Get(server.URL + "/api/audits")
	if err != nil {
		t.Fatal(err)
	}
	defer listResponse.Body.Close()
	listBody, err := io.ReadAll(listResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"bearer-secret", "basic-secret", "api-secret", "cookie-secret", "idor-bearer-secret", "idor-password-secret", "idor-header-secret", "idor-cookie-secret"} {
		if strings.Contains(string(listBody), secret) {
			t.Fatalf("secret %q leaked in audit list response", secret)
		}
	}
}

func TestDashboardDataEndpointsExposeNetworkAndTrends(t *testing.T) {
	store := storage.New()
	started := time.Now().Add(-time.Hour)
	store.SaveAudit(&models.AuditRun{ID: "audit-one", TargetURL: "https://one.example", Status: models.StatusDone, StartedAt: started})
	store.SaveAudit(&models.AuditRun{ID: "audit-two", TargetURL: "https://two.example", Status: models.StatusDone, StartedAt: started.Add(time.Minute)})
	store.SaveNetwork(&models.NetworkResult{
		AuditRunID: "audit-one", Host: "one.example", DNS: models.DNSRecords{A: []string{"192.0.2.10"}},
		Ports: []models.PortProbe{{Port: 443, Protocol: "tcp", Service: "https", Open: true}},
		TLS:   &models.TLSInfo{Checked: true, Valid: true, Version: "TLS 1.3"},
	})
	for _, auditID := range []string{"audit-one", "audit-two"} {
		store.AppendFinding(&models.Finding{
			ID: uuid.NewString(), AuditRunID: auditID, TaxonomyID: "WEB-XSS-002", Type: "xss-reflected",
			Title: "Reflected XSS", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh,
			Status: models.FindingConfirmed, Endpoint: map[string]string{"audit-one": "https://one.example/search", "audit-two": "https://two.example/search"}[auditID],
			Parameter: "q", OccurrenceCount: 1,
		})
	}
	server := httptest.NewServer(NewRouter(New(store, nil), ""))
	defer server.Close()

	networkResponse, err := http.Get(server.URL + "/api/audits/audit-one/network")
	if err != nil {
		t.Fatal(err)
	}
	defer networkResponse.Body.Close()
	if networkResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected network 200, got %d", networkResponse.StatusCode)
	}
	var network models.NetworkResult
	if err := json.NewDecoder(networkResponse.Body).Decode(&network); err != nil {
		t.Fatal(err)
	}
	if network.Host != "one.example" || len(network.DNS.A) != 1 || len(network.Ports) != 1 || network.TLS == nil {
		t.Fatalf("network data was not serialized completely: %+v", network)
	}

	trendsResponse, err := http.Get(server.URL + "/api/trends")
	if err != nil {
		t.Fatal(err)
	}
	defer trendsResponse.Body.Close()
	if trendsResponse.StatusCode != http.StatusOK {
		t.Fatalf("expected trends 200, got %d", trendsResponse.StatusCode)
	}
	var trends models.AuditTrends
	if err := json.NewDecoder(trendsResponse.Body).Decode(&trends); err != nil {
		t.Fatal(err)
	}
	if len(trends.Runs) != 2 || len(trends.RecurringFindings) != 1 || trends.RecurringFindings[0].AuditCount != 2 {
		t.Fatalf("trends data was not consolidated: %+v", trends)
	}
}

func writeDashboardFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write dashboard fixture %s: %v", name, err)
	}
}
