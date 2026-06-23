package verify_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sns45/assayward/pkg/core/verify"
)

// minimalDSSEEnvelope builds a raw DSSE envelope JSON for testing.
func minimalDSSEEnvelope(payloadType string, payload []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(payload)
	env := map[string]any{
		"payloadType": payloadType,
		"payload":     encoded,
		"signatures": []map[string]string{
			{"keyid": "", "sig": base64.StdEncoding.EncodeToString([]byte("fakesig"))},
		},
	}
	raw, _ := json.Marshal(env)
	return raw
}

func TestDecodeDSSE_ValidEnvelope(t *testing.T) {
	const payloadType = "application/vnd.in-toto+json"
	originalPayload := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)

	envelope := minimalDSSEEnvelope(payloadType, originalPayload)

	got, err := verify.DecodeDSSE(envelope)
	if err != nil {
		t.Fatalf("DecodeDSSE returned unexpected error: %v", err)
	}
	if got.PayloadType != payloadType {
		t.Errorf("PayloadType = %q; want %q", got.PayloadType, payloadType)
	}
	if string(got.Payload) != string(originalPayload) {
		t.Errorf("Payload = %q; want %q", string(got.Payload), string(originalPayload))
	}
}

func TestDecodeDSSE_MalformedInput(t *testing.T) {
	_, err := verify.DecodeDSSE([]byte("not valid json {{{"))
	if err == nil {
		t.Error("expected error for malformed input, got nil")
	}
}

func TestDecodeDSSE_InvalidBase64Payload(t *testing.T) {
	raw := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"!!!notbase64!!!","signatures":[]}`)
	_, err := verify.DecodeDSSE(raw)
	if err == nil {
		t.Error("expected error for invalid base64 payload, got nil")
	}
}

// TestDecodeDSSE_CanonicalKeylessBundle verifies that DecodeDSSE correctly
// extracts the DSSE envelope from a canonical Sigstore v0.3 bundle shape
// (real keyless bundles produced by sigstore-go / protojson.Marshal), where
// the dsseEnvelope field is at the TOP LEVEL alongside mediaType and
// verificationMaterial rather than nested under a content wrapper.
func TestDecodeDSSE_CanonicalKeylessBundle(t *testing.T) {
	const payloadType = "application/vnd.in-toto+json"
	// Minimal SLSA provenance statement as the inner payload.
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact","digest":{"sha256":"abc123"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)
	encodedPayload := base64.StdEncoding.EncodeToString(statement)

	// Build a canonical Sigstore v0.3 bundle: dsseEnvelope is a TOP-LEVEL field,
	// NOT nested under content. verificationMaterial carries certificate + tlogEntries
	// as found in real keyless (Fulcio + Rekor) bundles.
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{
				"rawBytes": base64.StdEncoding.EncodeToString([]byte("fake-der-cert")),
			},
			"tlogEntries": []map[string]any{
				{
					"logIndex":       "12345",
					"logId":          map[string]string{"keyId": "abc"},
					"integratedTime": "1700000000",
					"inclusionProof": map[string]any{},
				},
			},
		},
		// dsseEnvelope is at the TOP LEVEL (canonical v0.3 shape, not under content).
		"dsseEnvelope": map[string]any{
			"payloadType": payloadType,
			"payload":     encodedPayload,
			"signatures": []map[string]string{
				{"sig": base64.StdEncoding.EncodeToString([]byte("fakesig"))},
			},
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal canonical bundle: %v", err)
	}

	got, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE returned unexpected error for canonical keyless bundle: %v", err)
	}
	if got.PayloadType != payloadType {
		t.Errorf("PayloadType = %q; want %q", got.PayloadType, payloadType)
	}
	if string(got.Payload) != string(statement) {
		t.Errorf("Payload = %q; want %q", string(got.Payload), string(statement))
	}
}

// TestDecodeDSSE_ForgesealKeyedBundle verifies that DecodeDSSE correctly
// extracts the DSSE envelope from a forgeseal keyed bundle, where the
// dsseEnvelope is nested under the content field (not at the top level).
// This is the existing forgeseal-specific shape and must remain supported.
func TestDecodeDSSE_ForgesealKeyedBundle(t *testing.T) {
	const payloadType = "application/vnd.in-toto+json"
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`)
	encodedPayload := base64.StdEncoding.EncodeToString(statement)

	// Build a forgeseal keyed bundle: dsseEnvelope is nested under content.
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{
				"rawBytes": base64.StdEncoding.EncodeToString([]byte("fake-der-cert")),
			},
		},
		"content": map[string]any{
			"dsseEnvelope": map[string]any{
				"payloadType": payloadType,
				"payload":     encodedPayload,
				"signatures": []map[string]string{
					{"sig": base64.StdEncoding.EncodeToString([]byte("fakesig"))},
				},
			},
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal forgeseal keyed bundle: %v", err)
	}

	got, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE returned unexpected error for forgeseal keyed bundle: %v", err)
	}
	if got.PayloadType != payloadType {
		t.Errorf("PayloadType = %q; want %q", got.PayloadType, payloadType)
	}
	if string(got.Payload) != string(statement) {
		t.Errorf("Payload = %q; want %q", string(got.Payload), string(statement))
	}
}
