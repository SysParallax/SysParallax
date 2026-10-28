package report

import (
	"testing"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

func TestScoreFindingBoundsAndWeights(t *testing.T) {
	score := ScoreFinding(&models.Finding{
		Severity:   models.SeverityCritical,
		Confidence: models.ConfidenceHigh,
		Status:     models.FindingConfirmed,
	})
	if score != 100 {
		t.Fatalf("expected capped critical score 100, got %d", score)
	}

	score = ScoreFinding(&models.Finding{
		Severity:   models.SeverityHigh,
		Confidence: models.ConfidenceMedium,
		Status:     models.FindingSuspected,
	})
	if score >= 75 {
		t.Fatalf("expected lower score for medium confidence suspected finding, got %d", score)
	}
}

func TestRiskLevel(t *testing.T) {
	cases := map[int]string{
		0:  "info",
		20: "low",
		45: "medium",
		70: "high",
		90: "critical",
	}
	for score, expected := range cases {
		if got := riskLevel(score); got != expected {
			t.Fatalf("riskLevel(%d) = %s, expected %s", score, got, expected)
		}
	}
}

func TestBuildUsesConsolidatedFindingsAndFinalStatuses(t *testing.T) {
	store := storage.New()
	store.SaveAudit(&models.AuditRun{ID: "audit-report", TargetURL: "https://example.test"})
	store.AppendFinding(&models.Finding{
		ID: "passive", AuditRunID: "audit-report", Method: "GET", Source: "passive",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-suspected", Status: models.FindingSuspected,
		Confidence: models.ConfidenceLow, Endpoint: "https://example.test/search?id=1", Parameter: "id",
	})
	store.AppendFinding(&models.Finding{
		ID: "active", AuditRunID: "audit-report", Method: "GET", Source: "active",
		TaxonomyID: "WEB-SQLI-001", Type: "sqli-boolean-based", Status: models.FindingConfirmed,
		Confidence: models.ConfidenceHigh, Endpoint: "https://example.test/search?id=1", Parameter: "id",
	})
	report, err := Build(store, "audit-report")
	if err != nil {
		t.Fatal(err)
	}
	if report.ConsolidatedCount != 1 || report.OccurrenceCount != 2 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if report.FindingsByStatus[models.FindingConfirmed] != 1 || report.FindingsByStatus[models.FindingSuspected] != 0 {
		t.Fatalf("report mixed passive and final active statuses: %+v", report.FindingsByStatus)
	}
	if report.FindingsBySource["correlated"] != 1 || len(report.TopFindings) != 1 {
		t.Fatalf("report did not use the consolidated canonical finding: %+v", report)
	}
}
