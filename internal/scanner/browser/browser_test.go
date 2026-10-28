package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOriginAllowedUsesExactSchemeHostAndPort(t *testing.T) {
	allowed := []string{"https://example.com", "http://127.0.0.1:8080"}
	for _, target := range []string{"https://example.com/path", "http://127.0.0.1:8080/page"} {
		if !originAllowed(target, allowed) {
			t.Fatalf("expected origin to be allowed: %s", target)
		}
	}
	for _, target := range []string{"https://evil.example.com", "http://127.0.0.1:8081", "javascript:alert(1)", "file:///tmp/test"} {
		if originAllowed(target, allowed) {
			t.Fatalf("unexpected origin allowed: %s", target)
		}
	}
}

func TestRunRejectsBlockedOriginBeforeLaunchingBrowser(t *testing.T) {
	runner := New(Config{ExecutablePath: "C:\\does-not-exist\\browser.exe", AllowedOrigins: []string{"https://allowed.example"}})
	_, err := runner.Run(context.Background(), "https://evil.example/path", "marker")
	if !errors.Is(err, ErrOriginBlocked) {
		t.Fatalf("expected origin block before executable lookup, got %v", err)
	}
}

func TestNewAppliesBoundedDefaults(t *testing.T) {
	runner := New(Config{Timeout: -time.Second, MaxPages: 9, MaxNavigations: 0, MaxDOMBytes: 0})
	if runner.config.Timeout <= 0 || runner.config.MaxPages != 1 || runner.config.MaxNavigations != 5 || runner.config.MaxDOMBytes != 256*1024 {
		t.Fatalf("unexpected browser defaults: %+v", runner.config)
	}
}

func TestRedactURLMasksCallbackSecrets(t *testing.T) {
	redacted := redactURL("https://collector.example/hit?token=secret-value&item=42")
	if strings.Contains(redacted, "secret-value") || !strings.Contains(redacted, "item=42") {
		t.Fatalf("URL redaction is incorrect: %s", redacted)
	}
}

func TestRedactTextMasksRenderedSecrets(t *testing.T) {
	redacted := redactText(`<div data-token="secret-value" data-user="alice"></div>`)
	if strings.Contains(redacted, "secret-value") || !strings.Contains(redacted, "alice") {
		t.Fatalf("DOM secret redaction is incorrect: %s", redacted)
	}
}

func TestHeadlessBrowserIntegrationWhenExecutableIsAvailable(t *testing.T) {
	executable, err := discoverExecutable("")
	if err != nil {
		t.Skip("no Chromium-compatible executable available")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>console.log("AUDITCORE-MARKER")</script><p>AUDITCORE-MARKER</p></body></html>`))
	}))
	defer server.Close()
	runner := New(Config{ExecutablePath: executable, AllowedOrigins: []string{server.URL}, Timeout: 10 * time.Second})
	result, err := runner.Run(context.Background(), server.URL, "AUDITCORE-MARKER")
	if err != nil {
		if errors.Is(err, ErrBrowserUnavailable) || strings.Contains(err.Error(), "Page.enable") || strings.Contains(err.Error(), "connection was forcibly closed") {
			t.Skipf("browser executable cannot expose a usable CDP session in this environment: %v", err)
		}
		t.Fatalf("headless browser run failed: %v", err)
	}
	if !result.MarkerObserved || len(result.Navigations) == 0 || !strings.HasPrefix(result.FinalURL, server.URL) {
		t.Fatalf("incomplete browser observation: %+v", result)
	}
}
