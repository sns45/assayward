package forgeseal_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sns45/assayward/internal/forgeseal"
	"github.com/sns45/assayward/pkg/core/verify"
)

// TestEvidenceFromOutput_CanonicalKeylessBundle verifies that EvidenceFromOutput
// correctly reads a canonical Sigstore v0.3 bundle (real keyless shape produced
// by sigstore-go / protojson.Marshal) from disk and that the extracted SLSA
// attestation decodes via DecodeDSSE, producing the expected SLSA statement.
//
// The canonical shape has dsseEnvelope at the TOP LEVEL of the bundle JSON,
// alongside mediaType and verificationMaterial (which carries certificate +
// tlogEntries for Fulcio + Rekor), NOT nested under a content wrapper.
func TestEvidenceFromOutput_CanonicalKeylessBundle(t *testing.T) {
	const payloadType = "application/vnd.in-toto+json"

	// Minimal SLSA provenance statement as the payload of the DSSE envelope.
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact","digest":{"sha256":"abc123deadbeef"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://example.com/build/v1","externalParameters":{}},"runDetails":{"builder":{"id":"https://keyless-builder.example.com/cli"},"metadata":{"startedOn":"2026-01-01T00:00:00Z","finishedOn":"2026-01-01T00:00:01Z"}}}}`)
	encodedPayload := base64.StdEncoding.EncodeToString(statement)

	// Canonical Sigstore v0.3 bundle shape: dsseEnvelope is a TOP-LEVEL field.
	// verificationMaterial carries certificate + tlogEntries (keyless indicators).
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{
				"rawBytes": base64.StdEncoding.EncodeToString([]byte("fake-fulcio-leaf-cert-der")),
			},
			"tlogEntries": []map[string]any{
				{
					"logIndex":       "42",
					"logId":          map[string]string{"keyId": "rekor-key-id"},
					"integratedTime": "1700000000",
					"kindVersion":    map[string]string{"kind": "dsse", "version": "0.0.1"},
				},
			},
		},
		// TOP-LEVEL dsseEnvelope: this is the canonical Sigstore v0.3 shape.
		"dsseEnvelope": map[string]any{
			"payloadType": payloadType,
			"payload":     encodedPayload,
			"signatures": []map[string]string{
				{"sig": base64.StdEncoding.EncodeToString([]byte("fake-keyless-sig"))},
			},
		},
	}

	bundleBytes, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal canonical keyless bundle: %v", err)
	}

	// Write a minimal temporary forgeseal output directory with the canonical bundle,
	// plus stub SBOM and VEX files (required by EvidenceFromOutput).
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "slsa.sigstore-bundle.json"), bundleBytes, 0o600); err != nil {
		t.Fatalf("write slsa.sigstore-bundle.json: %v", err)
	}

	// Minimal CycloneDX BOM stub.
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "sbom.cdx.json"), sbom, 0o600); err != nil {
		t.Fatalf("write sbom.cdx.json: %v", err)
	}

	// Minimal OpenVEX stub.
	vex := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","author":"test","timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "vex.openvex.json"), vex, 0o600); err != nil {
		t.Fatalf("write vex.openvex.json: %v", err)
	}

	const artifactDigest = "sha256:abc123deadbeef0000000000000000000000000000000000000000000000000"

	ev, err := forgeseal.EvidenceFromOutput(dir, artifactDigest)
	if err != nil {
		t.Fatalf("EvidenceFromOutput with canonical keyless bundle: %v", err)
	}

	if len(ev.Attestations) == 0 {
		t.Fatal("no attestations returned")
	}

	// The first attestation is the SLSA one; verify DecodeDSSE can extract the payload.
	slsaAtt := ev.Attestations[0]
	if slsaAtt.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("PredicateType = %q; want https://slsa.dev/provenance/v1", slsaAtt.PredicateType)
	}

	decoded, err := verify.DecodeDSSE(slsaAtt.Envelope)
	if err != nil {
		t.Fatalf("DecodeDSSE on canonical keyless bundle envelope: %v", err)
	}
	if decoded.PayloadType != payloadType {
		t.Errorf("decoded PayloadType = %q; want %q", decoded.PayloadType, payloadType)
	}
	if string(decoded.Payload) != string(statement) {
		t.Errorf("decoded Payload = %q; want %q", string(decoded.Payload), string(statement))
	}
}
