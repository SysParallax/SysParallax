package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/auditcore/auditcore/internal/models"
	"github.com/auditcore/auditcore/internal/storage"
)

func Build(store *storage.Store, auditID string) (*models.AuditReport, error) {
	audit, err := store.GetAudit(auditID)
	if err != nil {
		return nil, err
	}
	findings := store.GetFindings(auditID)
	for _, f := range findings {
		f.Score = ScoreFinding(f)
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Score > findings[j].Score
	})

	bySeverity := map[models.Severity]int{}
	byStatus := map[models.FindingStatus]int{}
	bySource := map[string]int{}
	occurrences := 0
	for _, f := range findings {
		bySeverity[f.Severity]++
		byStatus[f.Status]++
		source := f.Source
		if source == "" {
			source = "unknown"
		}
		bySource[source]++
		count := f.OccurrenceCount
		if count <= 0 {
			count = 1
		}
		occurrences += count
	}

	riskScore := auditRisk(findings)
	report := &models.AuditReport{
		AuditRunID:         auditID,
		GeneratedAt:        time.Now(),
		TargetURL:          audit.TargetURL,
		RiskScore:          riskScore,
		RiskLevel:          riskLevel(riskScore),
		ExecutiveSummary:   summary(audit.TargetURL, riskScore, findings),
		FindingsBySeverity: bySeverity,
		FindingsByStatus:   byStatus,
		FindingsBySource:   bySource,
		ConsolidatedCount:  len(findings),
		OccurrenceCount:    occurrences,
		TopFindings:        top(findings, 10),
		Recommendations:    recommendations(findings),
	}
	if activeSummary, ok := store.GetActiveSummary(auditID); ok {
		report.ActiveSummary = activeSummary
	}
	store.SaveReport(report)
	return report, nil
}

func ScoreFinding(f *models.Finding) int {
	severity := map[models.Severity]int{
		models.SeverityCritical: 95,
		models.SeverityHigh:     75,
		models.SeverityMedium:   50,
		models.SeverityLow:      25,
		models.SeverityInfo:     10,
	}[f.Severity]
	confidence := map[models.Confidence]int{
		models.ConfidenceHigh:   0,
		models.ConfidenceMedium: -10,
		models.ConfidenceLow:    -20,
	}[f.Confidence]
	status := map[models.FindingStatus]int{
		models.FindingConfirmed:     10,
		models.FindingValidated:     0,
		models.FindingSuspected:     -15,
		models.FindingAcceptedRisk:  -20,
		models.FindingFalsePositive: -80,
	}[f.Status]
	score := severity + confidence + status
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// RiskScore exposes the same consolidated score used by generated reports so
// dashboard trend data cannot drift from the report calculation.
func RiskScore(findings []*models.Finding) int {
	return auditRisk(findings)
}

func RiskLevel(score int) string {
	return riskLevel(score)
}

func auditRisk(findings []*models.Finding) int {
	if len(findings) == 0 {
		return 0
	}
	score := 0
	for i, f := range findings {
		if i >= 5 {
			break
		}
		weight := 5 - i
		score += ScoreFinding(f) * weight
	}
	return score / 15
}

func riskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func summary(target string, score int, findings []*models.Finding) string {
	if len(findings) == 0 {
		return fmt.Sprintf("Audit termine pour %s: aucune faiblesse notable detectee par les modules executes.", target)
	}
	return fmt.Sprintf("Audit termine pour %s: %d finding(s), niveau de risque %s (%d/100).", target, len(findings), riskLevel(score), score)
}

func top(findings []*models.Finding, n int) []*models.Finding {
	if len(findings) < n {
		n = len(findings)
	}
	return append([]*models.Finding(nil), findings[:n]...)
}

func recommendations(findings []*models.Finding) []string {
	seen := make(map[string]bool)
	var out []string
	for _, f := range findings {
		if f.Remediation == "" || seen[f.Remediation] {
			continue
		}
		seen[f.Remediation] = true
		out = append(out, f.Remediation)
		if len(out) == 8 {
			break
		}
	}
	return out
}
