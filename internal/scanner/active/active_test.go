package active

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

func TestNormalizeBodyAndRedaction(t *testing.T) {
	body := `{"csrf_token":"abc123","created":"2026-07-11T10:20:30Z","value":"stable"}`
	normalized := NormalizeBody(body)
	if strings.Contains(normalized, "abc123") || strings.Contains(normalized, "2026-07-11") {
		t.Fatalf("dynamic values were not normalized: %s", normalized)
	}
	if RedactURL("https://example.test/?id=7&access_token=secret", models.AuditOptions{}) != "https://example.test/?access_token=%5BREDACTED%5D&id=7" {
		t.Fatalf("unexpected redacted URL")
	}
	if strings.Contains(RedactText("Authorization: Bearer abc Password=secret"), "abc") {
		t.Fatal("secret leaked from redacted text")
	}
}

func TestExecutorStoresBaselineAndEnforcesPerTestBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "dynamic-123")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"stable":true,"request_id":"dynamic-123"}`))
	}))
	defer server.Close()

	options := models.AuditOptions{ActiveMaxRequestsPerTest: 1, ActiveMaxResponseBytes: 2048}
	entry := models.EntryPoint{Endpoint: server.URL, Method: http.MethodGet, Name: "id", Location: models.EntryPointQuery, OriginalValue: "1"}
	executor := NewExecutor(context.Background(), &http.Client{Transport: http.DefaultTransport}, options, "test-1", "sqli-detection", entry, NewBudget(options), nil)
	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.DoBaseline(request); err != nil {
		t.Fatalf("baseline failed: %v", err)
	}
	if len(executor.Exchanges()) != 1 || executor.Baseline() == nil {
		t.Fatalf("baseline exchange was not stored")
	}
	second, err := http.NewRequest(http.MethodGet, server.URL+"?id=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Do("test", "probe", second); !errors.Is(err, ErrRequestBudget) {
		t.Fatalf("expected request budget error, got %v", err)
	}
	if executor.LimitReached() != "max_requests_per_test" {
		t.Fatalf("unexpected limit: %s", executor.LimitReached())
	}
}

func TestExecutorCancellationReachesHTTPRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := models.AuditOptions{ActiveMaxRequestsPerTest: 4}
	executor := NewExecutor(ctx, &http.Client{Transport: http.DefaultTransport}, options, "test-2", "xss-reflected", models.EntryPoint{Endpoint: server.URL, Method: http.MethodGet}, NewBudget(options), nil)
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	result := make(chan error, 1)
	go func() {
		_, err := executor.Do("test", "cancel", request)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach server")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP request was not cancelled")
	}
}
