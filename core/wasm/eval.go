// Package main is the Wasm ABI shim for assayward.
// This file has NO build tag so it compiles on all targets (native + wasm).
// It only imports packages that are safe under wasm: core, policy, engine.
// The two main() entrypoints are in main_wasip1.go and main_js.go, each
// guarded by their respective build tags.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
)

// abiEnvelope is the JSON object the caller sends to runEvaluate.
// "policy" is a JSON string containing the YAML (or JSON) policy document.
// "now" is a JSON string containing an RFC3339 timestamp.
// "evidence" and "trustRoots" are the JSON-encoded core types.
type abiEnvelope struct {
	Evidence   json.RawMessage `json:"evidence"`
	PolicyDoc  string          `json:"policy"`
	TrustRoots json.RawMessage `json:"trustRoots"`
	Now        string          `json:"now"`
}

// runEvaluate is the shared entry point for both wasm ABIs. It:
//  1. Unmarshals the ABI envelope.
//  2. Decodes Evidence and TrustRoots.
//  3. Parses the policy document (strict YAML/JSON).
//  4. Parses the "now" timestamp.
//  5. Calls engine.Evaluate.
//  6. Returns the Decision as compact JSON.
//
// It never panics; all errors are returned to the caller.
func runEvaluate(envelope []byte) ([]byte, error) {
	// 1. Unmarshal the ABI envelope.
	var env abiEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("wasm: unmarshal envelope: %w", err)
	}

	// 2a. Decode Evidence.
	var ev core.Evidence
	if err := json.Unmarshal(env.Evidence, &ev); err != nil {
		return nil, fmt.Errorf("wasm: unmarshal evidence: %w", err)
	}

	// 2b. Decode TrustRoots.
	var roots core.TrustRoots
	if err := json.Unmarshal(env.TrustRoots, &roots); err != nil {
		return nil, fmt.Errorf("wasm: unmarshal trustRoots: %w", err)
	}

	// 3. Parse the policy document (strict YAML/JSON).
	pol, err := policy.Parse([]byte(env.PolicyDoc))
	if err != nil {
		return nil, fmt.Errorf("wasm: parse policy: %w", err)
	}

	// 4. Parse the "now" timestamp (RFC3339).
	now, err := time.Parse(time.RFC3339, env.Now)
	if err != nil {
		return nil, fmt.Errorf("wasm: parse now %q: %w", env.Now, err)
	}

	// 5. Evaluate.
	dec := engine.Evaluate(ev, pol, roots, core.FixedClock{T: now})

	// 6. Marshal as compact JSON.
	out, err := json.Marshal(dec)
	if err != nil {
		return nil, fmt.Errorf("wasm: marshal decision: %w", err)
	}
	return out, nil
}
