//go:build !wasm

package policy_test

import (
	"errors"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
)

func TestDisabledCustomEvaluator_ReturnsErrAndDenies(t *testing.T) {
	ev := policy.NewCustomEvaluator()
	result, reasons, err := ev.Evaluate([]byte("{}"))

	if result != core.ResultDeny {
		t.Errorf("Evaluate: got result %q, want %q", result, core.ResultDeny)
	}
	if len(reasons) != 0 {
		t.Errorf("Evaluate: got %d reasons, want 0", len(reasons))
	}
	if !errors.Is(err, policy.ErrCustomPolicyNotEnabled) {
		t.Errorf("Evaluate: got err %v, want errors.Is(err, ErrCustomPolicyNotEnabled)", err)
	}
}
