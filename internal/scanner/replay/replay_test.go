package replay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/auditcore/auditcore/internal/models"
)

func TestRunReusesTheOriginalProofRequest(t *testing.T) {
	payload := "<script>alert(1)</script>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == payload {
			_, _ = fmt.Fprint(w, payload)
			return
		}
		_, _ = fmt.Fprint(w, "safe response")
	}))
	defer server.Close()

	proofURL := server.URL + "/search?q=" + url.QueryEscape(payload)
	finding := &models.Finding{
		ID:         "finding-xss-replay",
		Status:     models.FindingConfirmed,
		Type:       "xss-reflected",
		Replayable: true,
		Endpoint:   proofURL,
		Evidence: &models.Evidence{
			RequestRaw: fmt.Sprintf("GET %s HTTP/1.1", proofURL),
			Payload:    payload,
		},
	}

	result := Run(finding, models.AuditOptions{})
	if !result.Success || !result.MatcherHit || result.ReplayState != models.FindingReplayConfirmed {
		t.Fatalf("replay did not reuse the proof request: %+v", result)
	}
}

func TestRunMarksAConfirmedFindingAsNotReproduced(t *testing.T) {
	payload := "<script>alert(1)</script>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "sanitized response")
	}))
	defer server.Close()

	proofURL := server.URL + "/search?q=" + url.QueryEscape(payload)
	finding := &models.Finding{
		ID:         "finding-xss-fixed",
		Status:     models.FindingConfirmed,
		Type:       "xss-reflected",
		Replayable: true,
		Endpoint:   proofURL,
		Evidence: &models.Evidence{
			RequestRaw: fmt.Sprintf("GET %s HTTP/1.1", proofURL),
			Payload:    payload,
		},
	}

	result := Run(finding, models.AuditOptions{})
	if !result.Success || result.MatcherHit || result.ReplayState != models.FindingReplayNotReproduced {
		t.Fatalf("expected a successful request with a missing matcher: %+v", result)
	}
	if result.NewStatus != models.FindingConfirmed {
		t.Fatalf("replay should preserve the historical scan status, got %q", result.NewStatus)
	}
}
