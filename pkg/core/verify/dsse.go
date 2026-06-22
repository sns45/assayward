// Package verify provides DSSE envelope decoding and the SignatureVerifier
// interface. It has no dependency on engine or policy.
package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// DecodedEnvelope is the result of decoding a DSSE envelope. It exposes the
// PayloadType and the raw (base64-decoded) Payload bytes so that policy stages
// can inspect attestation contents without needing signature logic.
type DecodedEnvelope struct {
	PayloadType string
	Payload     []byte
}

// dsseEnvelope is a minimal JSON representation of a DSSE envelope, matching
// the format produced by go-securesystemslib. The Payload field is a
// base64-standard-encoded string in the JSON wire format.
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  json.RawMessage `json:"signatures"`
}

// DecodeDSSE parses a raw DSSE envelope JSON, base64-decodes the payload, and
// returns a DecodedEnvelope. It returns a non-nil error for any malformed
// input and never panics.
func DecodeDSSE(envelope []byte) (DecodedEnvelope, error) {
	var env dsseEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return DecodedEnvelope{}, fmt.Errorf("verify: unmarshal DSSE envelope: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		// DSSE spec allows standard or URL-safe base64; try URL-safe as fallback.
		payload, err = base64.URLEncoding.DecodeString(env.Payload)
		if err != nil {
			return DecodedEnvelope{}, fmt.Errorf("verify: base64-decode DSSE payload: %w", err)
		}
	}

	return DecodedEnvelope{
		PayloadType: env.PayloadType,
		Payload:     payload,
	}, nil
}
