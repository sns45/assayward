package engine_test

// TestEvaluateDeterminism and TestEvaluateDeterminism_MultiCVE_VEX
// implement the M1 determinism gate: identical (Evidence, policy, clock)
// inputs must produce byte-identical JSON-marshaled Decisions on every call.
//
// The multi-CVE variant specifically guards the sort fix in engine.go that
// ensures AffectedCVEs is always sorted regardless of map iteration order.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// builtinPolicies returns the three built-in policies parsed and ready for use.
func builtinPolicies(t *testing.T) []policy.Policy {
	t.Helper()
	type entry struct {
		name string
		raw  []byte
	}
	entries := []entry{
		{"baseline", builtin.Baseline},
		{"slsa-l3", builtin.SLSAL3},
		{"serverless-edge", builtin.ServerlessEdge},
	}
	var policies []policy.Policy
	for _, e := range entries {
		pol, err := policy.Parse(e.raw)
		if err != nil {
			t.Fatalf("policy.Parse(%q): %v", e.name, err)
		}
		policies = append(policies, pol)
	}
	return policies
}

// TestEvaluateDeterminism verifies that engine.Evaluate produces byte-identical
// JSON-marshaled Decisions on 100 consecutive calls for every built-in policy
// when Evidence, TrustRoots, and Clock are identical.
func TestEvaluateDeterminism(t *testing.T) {
	ev := goldenEvidence(t)
	roots := goldenRoots(t)
	clk := goldenClock

	for _, pol := range builtinPolicies(t) {
		pol := pol
		t.Run(pol.Name, func(t *testing.T) {
			// Capture the first marshaled decision as the reference.
			first, err := json.Marshal(engine.Evaluate(ev, pol, roots, clk))
			if err != nil {
				t.Fatalf("json.Marshal(decision[0]): %v", err)
			}

			for i := 1; i < 100; i++ {
				got, err := json.Marshal(engine.Evaluate(ev, pol, roots, clk))
				if err != nil {
					t.Fatalf("json.Marshal(decision[%d]): %v", i, err)
				}
				if !bytes.Equal(first, got) {
					t.Errorf("decision[%d] differs from decision[0] for policy %q\nfirst: %s\ngot:   %s",
						i, pol.Name, first, got)
					return
				}
			}
		})
	}
}

// multiCVEVEXEnvelope constructs a DSSE envelope (in the same wire format as
// the testdata/gen/main.go generator) whose OpenVEX predicate lists three
// "affected" CVE statements in non-alphabetical order:
//
//	CVE-2024-0003, CVE-2024-0001, CVE-2024-0002
//
// Without the sort.Strings(affectedCVEs) call in engine.go the resulting
// Decision.Reasons field would vary across calls due to Go map iteration
// non-determinism, causing the determinism test to flake.
func multiCVEVEXEnvelope() []byte {
	type vulnEntry struct {
		ID          string `json:"@id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	type productEntry struct {
		ID string `json:"@id"`
	}
	type vexStatement struct {
		Vulnerability   vulnEntry      `json:"vulnerability"`
		Products        []productEntry `json:"products"`
		Status          string         `json:"status"`
		ActionStatement string         `json:"action_statement"`
	}
	type vexPredicate struct {
		Context    string         `json:"@context"`
		ID         string         `json:"@id"`
		Author     string         `json:"author"`
		Timestamp  string         `json:"timestamp"`
		Version    int            `json:"version"`
		Statements []vexStatement `json:"statements"`
	}

	// Non-sorted order is intentional; the engine must sort before marshaling.
	pred := vexPredicate{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        "https://example.com/vex/multi-affected-1",
		Author:    "sns45-ci",
		Timestamp: "2024-01-01T00:00:00Z",
		Version:   1,
		Statements: []vexStatement{
			{
				Vulnerability:   vulnEntry{ID: "https://osv.dev/CVE-2024-0003", Name: "CVE-2024-0003", Description: "Third synthetic CVE."},
				Products:        []productEntry{{ID: "pkg:oci/example@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
				Status:          "affected",
				ActionStatement: "No mitigation.",
			},
			{
				Vulnerability:   vulnEntry{ID: "https://osv.dev/CVE-2024-0001", Name: "CVE-2024-0001", Description: "First synthetic CVE."},
				Products:        []productEntry{{ID: "pkg:oci/example@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
				Status:          "affected",
				ActionStatement: "No mitigation.",
			},
			{
				Vulnerability:   vulnEntry{ID: "https://osv.dev/CVE-2024-0002", Name: "CVE-2024-0002", Description: "Second synthetic CVE."},
				Products:        []productEntry{{ID: "pkg:oci/example@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
				Status:          "affected",
				ActionStatement: "No mitigation.",
			},
		},
	}

	type subjectEntry struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	type inTotoStmt struct {
		Type          string         `json:"_type"`
		Subject       []subjectEntry `json:"subject"`
		PredicateType string         `json:"predicateType"`
		Predicate     interface{}    `json:"predicate"`
	}

	stmt := inTotoStmt{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []subjectEntry{
			{
				Name:   "ghcr.io/sns45/example:1.0.0",
				Digest: map[string]string{"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			},
		},
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate:     pred,
	}

	stmtJSON, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("multiCVEVEXEnvelope: marshal statement: %v", err))
	}

	type sigEntry struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	type dsseEnv struct {
		PayloadType string     `json:"payloadType"`
		Payload     string     `json:"payload"`
		Signatures  []sigEntry `json:"signatures"`
	}

	env := dsseEnv{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(stmtJSON),
		Signatures:  []sigEntry{{KeyID: "", Sig: ""}},
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("multiCVEVEXEnvelope: marshal envelope: %v", err))
	}
	return out
}

// TestEvaluateDeterminism_MultiCVE_VEX specifically guards the map-iteration
// sort fix. It builds Evidence with a synthetic VEX attestation that lists
// CVE-2024-0003, CVE-2024-0001, CVE-2024-0002 in non-sorted order, then
// evaluates 100 times against the slsa-l3 policy (which has
// maxUnmitigatedSeverity: high, so VEX is in scope), marshals each Decision,
// and asserts all 100 are byte-identical.
//
// Without sort.Strings(affectedCVEs) in engine.go this test would flake due to
// Go map iteration non-determinism.
func TestEvaluateDeterminism_MultiCVE_VEX(t *testing.T) {
	base := goldenEvidence(t)
	multiVEXEnv := multiCVEVEXEnvelope()

	// Substitute the single-CVE VEX fixture with our multi-CVE envelope.
	// All other attestations remain from goldenEvidence.
	ev := core.Evidence{
		Image: base.Image,
		Attestations: []core.Attestation{
			{Envelope: base.Attestations[0].Envelope, PredicateType: base.Attestations[0].PredicateType},
			{Envelope: base.Attestations[1].Envelope, PredicateType: base.Attestations[1].PredicateType},
			{Envelope: base.Attestations[2].Envelope, PredicateType: base.Attestations[2].PredicateType},
			{Envelope: multiVEXEnv, PredicateType: "https://openvex.dev/ns/v0.2.0"},
		},
		Identity: base.Identity,
	}

	roots := goldenRoots(t)
	clk := goldenClock

	pol, err := policy.Parse(builtin.SLSAL3)
	if err != nil {
		t.Fatalf("policy.Parse(SLSAL3): %v", err)
	}

	first, err := json.Marshal(engine.Evaluate(ev, pol, roots, clk))
	if err != nil {
		t.Fatalf("json.Marshal(decision[0]): %v", err)
	}

	for i := 1; i < 100; i++ {
		got, err := json.Marshal(engine.Evaluate(ev, pol, roots, clk))
		if err != nil {
			t.Fatalf("json.Marshal(decision[%d]): %v", i, err)
		}
		if !bytes.Equal(first, got) {
			t.Errorf("decision[%d] differs from decision[0] (multi-CVE VEX determinism)\nfirst: %s\ngot:   %s",
				i, first, got)
			return
		}
	}
}
