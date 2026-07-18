package forgeseal_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sns45/assayward/internal/forgeseal"
	"github.com/sns45/assayward/pkg/core/verify"
)

// TestEvidenceFromOutputRealFixture drives EvidenceFromOutput against the REAL
// forgeseal v0.5.1 pipeline output committed under testdata/pipeline-output.
// It asserts that the assembled Evidence carries the SLSA attestation as the
// FULL signed Sigstore bundle (the envelope is the keyed bundle whose content
// holds a dsseEnvelope, so the signature verifier can reach the certificate),
// alongside the SBOM (and VEX) attestations, and that the signing CA is
// discoverable in the same directory.
func TestEvidenceFromOutputRealFixture(t *testing.T) {
	const dir = "testdata/pipeline-output"

	// The artifact digest is orthogonal to fixture discovery here; any well-formed
	// sha256:<hex> is accepted. Use a deterministic 64-hex-char value.
	ev, err := forgeseal.EvidenceFromOutput(dir, "sha256:"+strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("EvidenceFromOutput on real pipeline output: %v", err)
	}

	var haveSLSA, haveSBOM, haveVEX bool
	for _, a := range ev.Attestations {
		switch a.PredicateType {
		case "https://slsa.dev/provenance/v1":
			haveSLSA = true
			// The SLSA attestation MUST carry the full signed bundle, not the raw
			// statement fallback: forgeseal's keyed bundle nests the DSSE envelope
			// under content.dsseEnvelope. Assert the signed shape is present.
			if !bytes.Contains(a.Envelope, []byte("dsseEnvelope")) {
				t.Errorf("SLSA envelope is not the signed bundle (no dsseEnvelope): %s", a.Envelope)
			}
			if !bytes.Contains(a.Envelope, []byte("verificationMaterial")) {
				t.Errorf("SLSA envelope is missing verificationMaterial (certificate) needed for keyed verification")
			}
			// The stored bundle must decode as DSSE so the engine can route the
			// SLSA predicate — proving the signed-bundle envelope is well-formed.
			if _, derr := verify.DecodeDSSE(a.Envelope); derr != nil {
				t.Errorf("DecodeDSSE on real SLSA bundle envelope: %v", derr)
			}
		case "https://cyclonedx.org/bom":
			haveSBOM = true
		case "https://openvex.dev/ns/v0.2.0":
			haveVEX = true
		}
	}
	if !haveSLSA || !haveSBOM {
		t.Fatalf("missing SLSA or SBOM attestation: %+v", ev.Attestations)
	}
	if !haveVEX {
		t.Errorf("expected VEX attestation from real vex.json fixture")
	}

	ca, err := forgeseal.DetectSigningCA(dir)
	if err != nil {
		t.Fatalf("DetectSigningCA errored: %v", err)
	}
	if ca == nil {
		t.Fatal("DetectSigningCA returned nil for a directory containing forgeseal-signing-ca.crt")
	}
	if !bytes.Contains(ca, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("detected CA is not a PEM certificate:\n%s", ca)
	}
}
