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

// TestFindingsForbiddenCodeDeniesEndToEnd exercises the findings rule through the
// real EvaluatePolicy entry point (not the evaluateFindings helper directly) to
// prove the deny wiring actually reaches the top-level Result: a forbidden
// finding must flip an otherwise-passing policy to ResultDeny, and the same
// policy with no violating finding must still Allow.
func TestFindingsForbiddenCodeDeniesEndToEnd(t *testing.T) {
	pol := Policy{
		Name:    "test",
		Version: "v1",
		Mode:    ModeEnforce,
		Findings: FindingsRule{
			ForbiddenCodes: []string{"UNDECLARED_NETWORK_EGRESS"},
		},
	}

	result, reasons := EvaluatePolicy(
		pol,
		SignatureResultView{},
		SLSAView{},
		SBOMView{},
		VEXView{},
		IdentityView{},
		[]core.Finding{{Code: "UNDECLARED_NETWORK_EGRESS", Severity: core.SeverityHigh}},
	)

	if result != core.ResultDeny {
		t.Errorf("expected ResultDeny, got %q", result)
	}
	if !hasReason(reasons, "FINDINGS_FORBIDDEN_CODE_PRESENT", false) {
		t.Fatalf("expected FINDINGS_FORBIDDEN_CODE_PRESENT with Met=false: %+v", reasons)
	}

	// Same policy, no violating finding -> must Allow, proving the findings
	// rule (and not something else) drove the deny above.
	allowResult, allowReasons := EvaluatePolicy(
		pol,
		SignatureResultView{},
		SLSAView{},
		SBOMView{},
		VEXView{},
		IdentityView{},
		nil,
	)
	if allowResult != core.ResultAllow {
		t.Errorf("expected ResultAllow with no violating findings, got %q: %+v", allowResult, allowReasons)
	}
}
