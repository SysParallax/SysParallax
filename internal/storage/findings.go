package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/auditcore/auditcore/internal/models"
)

// findingCorrelationKey identifies one logical vulnerability, independently
// of the exact payload used to prove it.
func findingCorrelationKey(finding *models.Finding) string {
	if finding == nil {
		return ""
	}
	return strings.Join([]string{
		findingFamily(finding),
		findingMethod(finding),
		findingResourceKey(finding),
		strings.ToLower(strings.TrimSpace(finding.Parameter)),
	}, "|")
}

// findingExactKey keeps the technical proof in the identity. It is useful for
// exact duplicate detection before the broader logical correlation rule.
func findingExactKey(finding *models.Finding) string {
	if finding == nil {
		return ""
	}
	evidence := ""
	if finding.Evidence != nil {
		evidence = strings.Join([]string{
			finding.Evidence.Payload,
			finding.Evidence.MatcherResult,
			finding.Evidence.RequestRaw,
			finding.Evidence.ResponseRaw,
		}, "|")
	}
	return hashFindingKey(strings.Join([]string{
		findingCorrelationKey(finding),
		strings.ToLower(strings.TrimSpace(finding.Type)),
		evidence,
	}, "|"))
}

func findingFamily(finding *models.Finding) string {
	if taxonomy := strings.TrimSpace(finding.TaxonomyID); taxonomy != "" {
		return strings.ToLower(taxonomy)
	}
	if finding.Type != "" {
		return strings.ToLower(strings.TrimSpace(finding.Type))
	}
	return strings.ToLower(strings.TrimSpace(finding.Title))
}

func findingMethod(finding *models.Finding) string {
	if method := strings.ToUpper(strings.TrimSpace(finding.Method)); method != "" {
		return method
	}
	if finding.Evidence != nil {
		parts := strings.Fields(finding.Evidence.RequestRaw)
		if len(parts) > 0 {
			return strings.ToUpper(parts[0])
		}
	}
	return "UNKNOWN"
}

func findingResourceKey(finding *models.Finding) string {
	raw := strings.TrimSpace(finding.Endpoint)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return strings.ToLower(raw)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" {
		path = "/"
	}
	keys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		if strings.EqualFold(key, finding.Parameter) {
			continue
		}
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	queryShape := strings.Join(keys, ",")
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host) + path + "?" + queryShape
}

func aggregateFindingKey(finding *models.Finding) string {
	return strings.Join([]string{
		findingFamily(finding),
		strings.ToLower(strings.TrimSpace(finding.Parameter)),
	}, "|")
}

func isAggregateableFinding(finding *models.Finding) bool {
	if finding == nil {
		return false
	}
	typeName := strings.ToLower(strings.TrimSpace(finding.Type))
	taxonomy := strings.ToLower(strings.TrimSpace(finding.TaxonomyID))
	return typeName == "missing-header" || strings.HasPrefix(taxonomy, "web-hdrs-")
}

func hashFindingKey(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func normalizeFindingBeforeStore(finding *models.Finding) {
	if finding.OccurrenceCount <= 0 {
		finding.OccurrenceCount = 1
	}
	if finding.Method == "" {
		finding.Method = findingMethod(finding)
	}
	if finding.WSTGMapping == "" {
		finding.WSTGMapping = defaultWSTGMapping(finding.TaxonomyID)
	}
	if finding.Endpoint != "" {
		finding.AffectedEndpoints = uniqueFindingStrings(append(finding.AffectedEndpoints, finding.Endpoint))
	}
	finding.RelatedFindingIDs = uniqueFindingStrings(finding.RelatedFindingIDs)
}

func defaultWSTGMapping(taxonomy string) string {
	switch strings.ToUpper(strings.TrimSpace(taxonomy)) {
	case "WEB-XSS-002":
		return "WSTG-INPV-01"
	case "WEB-SQLI-001":
		return "WSTG-INPV-05"
	case "WEB-PATH-001":
		return "WSTG-ATHZ-01"
	case "WEB-IDOR-001":
		return "WSTG-ATHZ-04"
	case "WEB-SSRF-001":
		return "WSTG-INPV-19"
	case "WEB-REDIR-001":
		return "WSTG-CLNT-04"
	case "WEB-COOK-001", "WEB-COOK-002", "WEB-COOK-003":
		return "WSTG-SESS-02"
	case "WEB-HDRS-001", "WEB-HDRS-002", "WEB-HDRS-003", "WEB-HDRS-004", "WEB-HDRS-005", "WEB-HDRS-006":
		return "WSTG-CONF-07"
	default:
		return ""
	}
}

func mergeFinding(dst, incoming *models.Finding) {
	if dst == nil || incoming == nil {
		return
	}
	normalizeFindingBeforeStore(incoming)
	if dst.OccurrenceCount <= 0 {
		dst.OccurrenceCount = 1
	}
	dst.OccurrenceCount += incoming.OccurrenceCount
	dst.AffectedEndpoints = uniqueFindingStrings(append(dst.AffectedEndpoints, incoming.AffectedEndpoints...))
	relatedIDs := append(append([]string(nil), dst.RelatedFindingIDs...), incoming.ID)
	relatedIDs = append(relatedIDs, incoming.RelatedFindingIDs...)
	dst.RelatedFindingIDs = uniqueFindingStrings(relatedIDs)
	if dst.ID != "" {
		dst.RelatedFindingIDs = removeFindingString(dst.RelatedFindingIDs, dst.ID)
	}
	mergedSource := dst.Source
	if mergedSource == "" {
		mergedSource = incoming.Source
	} else if incoming.Source != "" && mergedSource != incoming.Source {
		mergedSource = "correlated"
	}
	dst.Source = mergedSource
	if dst.Method == "" {
		dst.Method = incoming.Method
	}
	if dst.AssetID == "" {
		dst.AssetID = incoming.AssetID
	}
	if dst.Endpoint == "" {
		dst.Endpoint = incoming.Endpoint
	}
	if dst.Parameter == "" {
		dst.Parameter = incoming.Parameter
	}
	if dst.CreatedAt.IsZero() || (!incoming.CreatedAt.IsZero() && incoming.CreatedAt.Before(dst.CreatedAt)) {
		dst.CreatedAt = incoming.CreatedAt
	}
	if shouldPreferFinding(incoming, dst) {
		canonicalID := dst.ID
		occurrences := dst.OccurrenceCount
		affected := append([]string(nil), dst.AffectedEndpoints...)
		related := append([]string(nil), dst.RelatedFindingIDs...)
		createdAt := dst.CreatedAt
		*dst = *cloneFinding(incoming)
		dst.ID = canonicalID
		dst.Source = mergedSource
		dst.OccurrenceCount = occurrences
		dst.AffectedEndpoints = uniqueFindingStrings(append(affected, dst.AffectedEndpoints...))
		dst.RelatedFindingIDs = uniqueFindingStrings(append(related, dst.RelatedFindingIDs...))
		if dst.CreatedAt.IsZero() || (!createdAt.IsZero() && createdAt.Before(dst.CreatedAt)) {
			dst.CreatedAt = createdAt
		}
	}
	if dst.UpdatedAt != nil || dst.OccurrenceCount > 1 {
		updated := time.Now().UTC()
		dst.UpdatedAt = &updated
	}
}

func shouldPreferFinding(candidate, current *models.Finding) bool {
	if current.Status == models.FindingFalsePositive || current.Status == models.FindingAcceptedRisk {
		return false
	}
	if findingStatusRank(candidate.Status) != findingStatusRank(current.Status) {
		return findingStatusRank(candidate.Status) > findingStatusRank(current.Status)
	}
	if findingConfidenceRank(candidate.Confidence) != findingConfidenceRank(current.Confidence) {
		return findingConfidenceRank(candidate.Confidence) > findingConfidenceRank(current.Confidence)
	}
	return evidenceSize(candidate) > evidenceSize(current)
}

func findingStatusRank(status models.FindingStatus) int {
	switch status {
	case models.FindingConfirmed:
		return 5
	case models.FindingValidated:
		return 4
	case models.FindingSuspected:
		return 3
	case models.FindingAcceptedRisk:
		return 2
	case models.FindingFalsePositive:
		return 1
	default:
		return 0
	}
}

func findingConfidenceRank(confidence models.Confidence) int {
	switch confidence {
	case models.ConfidenceHigh:
		return 3
	case models.ConfidenceMedium:
		return 2
	case models.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func evidenceSize(finding *models.Finding) int {
	if finding == nil || finding.Evidence == nil {
		return 0
	}
	return len(finding.Evidence.RequestRaw) + len(finding.Evidence.ResponseRaw) + len(finding.Evidence.Payload) + len(finding.Evidence.MatcherResult)
}

func uniqueFindingStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func removeFindingString(values []string, target string) []string {
	result := values[:0]
	for _, value := range values {
		if value != target {
			result = append(result, value)
		}
	}
	return result
}

func cloneFinding(finding *models.Finding) *models.Finding {
	if finding == nil {
		return nil
	}
	copyFinding := *finding
	copyFinding.References = append([]string(nil), finding.References...)
	copyFinding.Tags = append([]string(nil), finding.Tags...)
	copyFinding.AffectedEndpoints = append([]string(nil), finding.AffectedEndpoints...)
	copyFinding.RelatedFindingIDs = append([]string(nil), finding.RelatedFindingIDs...)
	if finding.Evidence != nil {
		evidence := *finding.Evidence
		evidence.Screenshots = append([]string(nil), finding.Evidence.Screenshots...)
		copyFinding.Evidence = &evidence
	}
	if finding.UpdatedAt != nil {
		updated := *finding.UpdatedAt
		copyFinding.UpdatedAt = &updated
	}
	if finding.LastReplayAt != nil {
		replayed := *finding.LastReplayAt
		copyFinding.LastReplayAt = &replayed
	}
	return &copyFinding
}
