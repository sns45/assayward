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
