//go:build !wasm

package policy

import (
	"errors"

	core "github.com/sns45/assayward/pkg/core"
)

// CustomEvaluator is the documented extension point for org-specific Rego policy (native-only).
// v0.1 ships the interface + a disabled stub. The Rego engine is intentionally NOT built (Decision 1).
type CustomEvaluator interface {
	Evaluate(input []byte) (core.Result, []core.Reason, error)
}

// ErrCustomPolicyNotEnabled is returned by the disabled stub.
var ErrCustomPolicyNotEnabled = errors.New("custom Rego policy is scaffolded but not enabled in v0.1")

// DisabledCustomEvaluator is the v0.1 stub: it implements CustomEvaluator and always returns ErrCustomPolicyNotEnabled.
type DisabledCustomEvaluator struct{}

func (DisabledCustomEvaluator) Evaluate(input []byte) (core.Result, []core.Reason, error) {
	return core.ResultDeny, nil, ErrCustomPolicyNotEnabled
}

// NewCustomEvaluator returns the v0.1 disabled stub. A future version wires a real Rego engine here.
func NewCustomEvaluator() CustomEvaluator { return DisabledCustomEvaluator{} }
