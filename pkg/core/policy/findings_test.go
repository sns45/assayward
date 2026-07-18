package policy

import (
	"testing"

	core "github.com/sns45/assayward/pkg/core"
)

func hasReason(rs []core.Reason, code string, met bool) bool {
	for _, r := range rs {
		if r.Code == code && r.Met == met {
			return true
		}
	}
	return false
}

func TestFindingsForbiddenCodeDenies(t *testing.T) {
	rule := FindingsRule{ForbiddenCodes: []string{"UNDECLARED_NETWORK_EGRESS"}}
	rs := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_NETWORK_EGRESS", Severity: core.SeverityHigh}})
	if !hasReason(rs, "FINDINGS_FORBIDDEN_CODE_PRESENT", false) {
		t.Fatalf("forbidden code must deny: %+v", rs)
	}
	clean := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_ENV", Severity: core.SeverityLow}})
	if !hasReason(clean, "FINDINGS_WITHIN_POLICY", true) {
		t.Fatalf("no forbidden code must pass: %+v", clean)
	}
}

func TestFindingsMaxSeverityDenies(t *testing.T) {
	rule := FindingsRule{MaxSeverity: "medium"}
	rs := evaluateFindings(rule, []core.Finding{{Code: "UNDECLARED_EXEC", Severity: core.SeverityHigh}})
	if !hasReason(rs, "FINDINGS_SEVERITY_EXCEEDED", false) {
		t.Fatalf("high finding must exceed medium: %+v", rs)
	}
}

func TestNoFindingsRuleProducesNoReasons(t *testing.T) {
	rs := evaluateFindings(FindingsRule{}, []core.Finding{{Code: "UNDECLARED_ENV", Severity: core.SeverityCritical}})
	if len(rs) != 0 {
		t.Fatalf("no configured rule must not gate: %+v", rs)
	}
}
