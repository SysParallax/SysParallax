package storage

import (
	"testing"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

func TestMarkAssetTested(t *testing.T) {
	store := New()
	asset := &models.Asset{
		ID:         "asset-1",
		AuditRunID: "audit-1",
		Method:     "GET",
		URL:        "https://example.com",
	}
	store.AppendAsset(asset)
	beforeUpdate := store.GetAssets(asset.AuditRunID)

	testedAt := time.Date(2026, time.June, 10, 12, 30, 0, 0, time.UTC)
	if !store.MarkAssetTested(asset.AuditRunID, asset.ID, testedAt) {
		t.Fatal("expected existing asset to be marked as tested")
	}
	if beforeUpdate[0].TestedAt != nil {
		t.Fatal("expected previously read asset snapshot to remain unchanged")
	}

	assets := store.GetAssets(asset.AuditRunID)
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if assets[0].TestedAt == nil {
		t.Fatal("expected tested_at to be set")
	}
	if !assets[0].TestedAt.Equal(testedAt) {
		t.Fatalf("expected tested_at %s, got %s", testedAt, assets[0].TestedAt)
	}
	if store.MarkAssetTested(asset.AuditRunID, "missing-asset", testedAt) {
		t.Fatal("expected missing asset update to return false")
	}
}

func TestUpdateFindingStatusTracksModificationTime(t *testing.T) {
	store := New()
	finding := &models.Finding{
		ID:         "finding-1",
		AuditRunID: "audit-1",
		Status:     models.FindingSuspected,
	}
	store.AppendFinding(finding)

	if err := store.UpdateFindingStatus(finding.AuditRunID, finding.ID, models.FindingConfirmed); err != nil {
		t.Fatalf("update finding status: %v", err)
	}

	updated, err := store.GetFinding(finding.AuditRunID, finding.ID)
	if err != nil {
		t.Fatalf("get updated finding: %v", err)
	}
	if updated.Status != models.FindingConfirmed {
		t.Fatalf("expected confirmed status, got %s", updated.Status)
	}
	if updated.UpdatedAt == nil || updated.UpdatedAt.IsZero() {
		t.Fatal("expected updated_at to be recorded")
	}
}

func TestAppendFindingRestoresDefaultWSTGMapping(t *testing.T) {
	store := New()
	store.AppendFinding(&models.Finding{
		ID: "finding-wstg", AuditRunID: "audit-wstg", TaxonomyID: "WEB-XSS-002", Type: "xss-reflected",
	})
	findings := store.GetFindings("audit-wstg")
	if len(findings) != 1 || findings[0].WSTGMapping != "WSTG-INPV-01" {
		t.Fatalf("expected restored WSTG mapping, got %+v", findings)
	}
}

func TestUpdateFindingReplayPersistsCurrentValidationState(t *testing.T) {
	store := New()
	finding := &models.Finding{ID: "finding-replay", AuditRunID: "audit-replay", Status: models.FindingConfirmed}
	store.AppendFinding(finding)
	replayedAt := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)

	if err := store.UpdateFindingReplay(finding.AuditRunID, finding.ID, models.FindingReplayNotReproduced, replayedAt); err != nil {
		t.Fatalf("update replay state: %v", err)
	}

	updated, err := store.GetFinding(finding.AuditRunID, finding.ID)
	if err != nil {
		t.Fatalf("get replayed finding: %v", err)
	}
	if updated.Status != models.FindingConfirmed {
		t.Fatalf("historical scan status should remain confirmed, got %s", updated.Status)
	}
	if updated.ReplayState != models.FindingReplayNotReproduced || updated.LastReplayAt == nil || !updated.LastReplayAt.Equal(replayedAt) {
		t.Fatalf("replay state was not persisted: %+v", updated)
	}
}

func TestAppendFindingConsolidatesExactTechnicalDuplicates(t *testing.T) {
	store := New()
	first := &models.Finding{
		ID: "finding-first", AuditRunID: "audit-duplicates", Method: "GET",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-boolean-based", Status: models.FindingConfirmed,
		Confidence: models.ConfidenceHigh, Endpoint: "https://example.test/search?id=1", Parameter: "id",
		Evidence: &models.Evidence{Payload: "' AND '1'='1", MatcherResult: "boolean pair reproduced", RequestRaw: "GET /search?id=probe HTTP/1.1"},
	}
	second := &models.Finding{
		ID: "finding-second", AuditRunID: "audit-duplicates", Method: "GET",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-boolean-based", Status: models.FindingConfirmed,
		Confidence: models.ConfidenceHigh, Endpoint: "https://example.test/search?id=1", Parameter: "id",
		Evidence: &models.Evidence{Payload: "' AND '1'='1", MatcherResult: "boolean pair reproduced", RequestRaw: "GET /search?id=probe HTTP/1.1"},
	}
	canonical := store.AppendFinding(first)
	merged := store.AppendFinding(second)
	findings := store.GetFindings("audit-duplicates")
	if canonical == nil || merged == nil || canonical.ID != "finding-first" || merged.ID != "finding-first" {
		t.Fatalf("expected the first finding to remain canonical: canonical=%+v merged=%+v", canonical, merged)
	}
	if len(findings) != 1 || findings[0].OccurrenceCount != 2 || len(findings[0].RelatedFindingIDs) != 1 || findings[0].RelatedFindingIDs[0] != "finding-second" {
		t.Fatalf("unexpected consolidated duplicate: %+v", findings)
	}
}

func TestAppendFindingCorrelatesPassiveAndActiveValidation(t *testing.T) {
	store := New()
	store.AppendFinding(&models.Finding{
		ID: "passive-sqli", AuditRunID: "audit-correlation", Method: "GET", Source: "passive",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-suspected", Status: models.FindingSuspected,
		Confidence: models.ConfidenceLow, Endpoint: "https://example.test/search?id=1", Parameter: "id",
	})
	store.AppendFinding(&models.Finding{
		ID: "active-sqli", AuditRunID: "audit-correlation", Method: "GET", Source: "active",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-boolean-based", Status: models.FindingConfirmed,
		Confidence: models.ConfidenceHigh, Endpoint: "https://example.test/search?id=2", Parameter: "id",
		Evidence: &models.Evidence{Payload: "' AND '1'='1", MatcherResult: "reproduced"},
	})
	findings := store.GetFindings("audit-correlation")
	if len(findings) != 1 {
		t.Fatalf("expected passive and active result to correlate, got %d findings", len(findings))
	}
	if findings[0].Status != models.FindingConfirmed || findings[0].Confidence != models.ConfidenceHigh || findings[0].Source != "correlated" {
		t.Fatalf("active validation did not promote the canonical finding: %+v", findings[0])
	}
}

func TestAppendFindingAggregatesRepeatedMissingHeaders(t *testing.T) {
	store := New()
	for index, endpoint := range []string{"https://example.test/", "https://example.test/login", "https://example.test/account"} {
		store.AppendFinding(&models.Finding{
			ID: "header-" + string(rune('a'+index)), AuditRunID: "audit-headers", Method: "GET", Source: "passive",
			TaxonomyID: "WEB-HDRS-001", Type: "missing-header", Status: models.FindingSuspected,
			Confidence: models.ConfidenceMedium, Endpoint: endpoint, Title: "Missing Content-Security-Policy header",
		})
	}
	findings := store.GetFindings("audit-headers")
	if len(findings) != 1 || findings[0].OccurrenceCount != 3 || len(findings[0].AffectedEndpoints) != 3 {
		t.Fatalf("expected one aggregated header finding, got %+v", findings)
	}
}

func TestActiveTestStatsTrackLifecycleAndFinalStatuses(t *testing.T) {
	store := New()
	queuedAt := time.Date(2026, time.June, 10, 12, 0, 0, 0, time.UTC)
	startedAt := queuedAt.Add(time.Second)
	requestAt := startedAt.Add(time.Second)
	responseAt := requestAt.Add(time.Second)
	finishedAt := responseAt.Add(time.Second)

	store.SaveActiveTest(&models.ActiveTest{
		ID:         "active-1",
		AuditRunID: "audit-1",
		AssetID:    "asset-1",
		Module:     "xss-active",
		Method:     "GET",
		URL:        "https://example.test/",
		Status:     models.ActiveTestQueued,
		QueuedAt:   queuedAt,
	})
	store.TransitionActiveTest("active-1", models.ActiveTestStarted, "worker pickup", startedAt)
	store.IncrementActiveRequest("active-1")
	store.TransitionActiveTest("active-1", models.ActiveTestRequestSent, "GET /", requestAt)
	store.IncrementActiveResponse("active-1")
	store.TransitionActiveTest("active-1", models.ActiveTestResponseReceived, "HTTP 200", responseAt)
	store.FinishActiveTest("active-1", models.ActiveTestConfirmed, "confirmed", 1, finishedAt)

	stats := store.GetActiveTestStats("audit-1")
	if stats.Total != 1 || stats.Finalized != 1 || stats.NonFinal != 0 {
		t.Fatalf("unexpected totals: %+v", stats)
	}
	if stats.RequestsSent != 1 || stats.Responses != 1 {
		t.Fatalf("unexpected request counters: %+v", stats)
	}
	if stats.ByFinalStatus[models.ActiveTestConfirmed] != 1 {
		t.Fatalf("expected confirmed final status, got %+v", stats.ByFinalStatus)
	}
	if stats.Progress != 1 {
		t.Fatalf("expected full progress, got %f", stats.Progress)
	}

	tests := store.GetActiveTests("audit-1")
	if len(tests) != 1 {
		t.Fatalf("expected one active test, got %d", len(tests))
	}
	if tests[0].FinishedAt == nil || tests[0].DurationMillis <= 0 {
		t.Fatalf("expected finished active test with duration, got %+v", tests[0])
	}
	if len(tests[0].Steps) != 5 {
		t.Fatalf("expected lifecycle steps, got %d", len(tests[0].Steps))
	}
}
