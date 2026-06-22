package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
)

// TestRunEvaluateServerlessEdge exercises runEvaluate natively using the
// serverless-edge built-in policy and the canonical golden evidence fixtures.
// It asserts:
//   - The result is valid (allow/deny/audit).
//   - DecidedAt equals the "now" timestamp from the envelope.
//   - The output is valid compact JSON (no trailing whitespace/indent).
func TestRunEvaluateServerlessEdge(t *testing.T) {
	// Use the canonical image and fixtures from testfix, mirroring golden_test.go.
	slsaEnv := testfix.Load(t, "slsa/valid-l3.dsse.json")
	sbomEnv := testfix.Load(t, "sbom/cyclonedx.dsse.json")
	vexEnv := testfix.Load(t, "vex/affected-critical.dsse.json")
	sigBundle := testfix.Load(t, "signature/bundle-provenance.json")
	jwtSVID := testfix.Load(t, "svid/jwt-valid.jwt")
	sigstoreTUF := testfix.Load(t, "signature/trusted-root-public-good.json")
	jwtBundle := testfix.Load(t, "svid/jwt-bundle.json")

	// serverless-edge policy inline (same content as builtin.ServerlessEdge).
	const policyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: serverless-edge
spec:
  mode: enforce
  signature:
    required: false
  slsa:
    minLevel: 0
  vex: {}
  sbom: {}
  identity:
    required: true
    trustDomain: "spiffe://sns45.dev"
    idPattern: "spiffe://sns45.dev/*"
`

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowStr := now.Format(time.RFC3339)

	// Build the Evidence JSON inline. The Attestation.Envelope fields are []byte,
	// which marshal to base64 in JSON. We need to marshal the evidence first, then
	// build the envelope JSON object.
	ev := core.Evidence{
		Image: core.ImageRef{
			Name:   testfix.TestImageName,
			Digest: testfix.TestImageDigest,
		},
		Attestations: []core.Attestation{
			{Envelope: sigBundle, PredicateType: "sigstore-bundle"},
			{Envelope: slsaEnv, PredicateType: "https://slsa.dev/provenance/v1"},
			{Envelope: sbomEnv, PredicateType: "https://cyclonedx.org/bom"},
			{Envelope: vexEnv, PredicateType: "https://openvex.dev/ns/v0.2.0"},
		},
		Identity: &core.WorkloadIdentity{
			SVIDType: core.SVIDTypeJWT,
			Raw:      jwtSVID,
		},
		FetchedAt: now,
	}

	evBytes, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}

	roots := core.TrustRoots{
		SigstoreTUF: sigstoreTUF,
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": jwtBundle,
		},
	}

	rootsBytes, err := json.Marshal(roots)
	if err != nil {
		t.Fatalf("marshal trust roots: %v", err)
	}

	// Build the ABI envelope. Policy is a JSON string containing the YAML.
	envelopeMap := map[string]json.RawMessage{
		"evidence":   evBytes,
		"policy":     mustMarshalString(t, policyYAML),
		"trustRoots": rootsBytes,
		"now":        mustMarshalString(t, nowStr),
	}
	envelopeBytes, err := json.Marshal(envelopeMap)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// RED: this call will fail until runEvaluate is implemented.
	result, err := runEvaluate(envelopeBytes)
	if err != nil {
		t.Fatalf("runEvaluate returned error: %v", err)
	}

	var dec core.Decision
	if err := json.Unmarshal(result, &dec); err != nil {
		t.Fatalf("unmarshal decision: %v", err)
	}

	// Assert Result is one of the valid values.
	switch dec.Result {
	case core.ResultAllow, core.ResultDeny, core.ResultAudit:
		// valid
	default:
		t.Errorf("unexpected Result %q; want allow/deny/audit", dec.Result)
	}

	// Assert DecidedAt equals the "now" we passed in.
	if !dec.DecidedAt.Equal(now) {
		t.Errorf("DecidedAt = %v; want %v", dec.DecidedAt, now)
	}

	// Assert output is compact JSON (no leading/trailing whitespace, no indentation).
	reMarshaled, err := json.Marshal(dec)
	if err != nil {
		t.Fatalf("re-marshal decision: %v", err)
	}
	if string(result) != string(reMarshaled) {
		t.Errorf("output is not compact JSON\ngot:  %s\nwant: %s", result, reMarshaled)
	}

	// Assert Reasons is non-nil (marshals as [] not null).
	if dec.Reasons == nil {
		t.Error("Reasons must be non-nil")
	}
}

// TestRunEvaluateBadEnvelope ensures runEvaluate returns an error (not panic)
// on malformed input.
func TestRunEvaluateBadEnvelope(t *testing.T) {
	_, err := runEvaluate([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON envelope, got nil")
	}
}

// TestRunEvaluateBadPolicy ensures runEvaluate returns an error on invalid policy.
func TestRunEvaluateBadPolicy(t *testing.T) {
	ev := core.Evidence{
		Image: core.ImageRef{Name: "example.com/img:1", Digest: "sha256:abc"},
	}
	evBytes, _ := json.Marshal(ev)
	rootsBytes, _ := json.Marshal(core.TrustRoots{})

	envelopeMap := map[string]json.RawMessage{
		"evidence":   evBytes,
		"policy":     mustMarshalString(t, "not: valid: yaml: [policy: missing mode"),
		"trustRoots": rootsBytes,
		"now":        mustMarshalString(t, "2026-01-01T00:00:00Z"),
	}
	envelopeBytes, _ := json.Marshal(envelopeMap)

	_, err := runEvaluate(envelopeBytes)
	if err == nil {
		t.Error("expected error for invalid policy, got nil")
	}
}

func mustMarshalString(t testing.TB, s string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal string: %v", err)
	}
	return b
}
