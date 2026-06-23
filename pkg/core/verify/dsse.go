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

// sigstoreBundleEnvelope is a minimal representation of a Sigstore bundle JSON
// used to extract the embedded DSSE envelope from content.dsseEnvelope.
// This allows DecodeDSSE to transparently handle both bare DSSE envelopes and
// Sigstore bundle JSON (mediaType: application/vnd.dev.sigstore.bundle.*).
type sigstoreBundleEnvelope struct {
	MediaType string `json:"mediaType"`
	Content   struct {
		DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"`
	} `json:"content"`
}

// DecodeDSSE parses a raw DSSE envelope JSON, base64-decodes the payload, and
// returns a DecodedEnvelope. It returns a non-nil error for any malformed
// input and never panics.
//
// DecodeDSSE transparently handles two input formats:
//  1. A bare DSSE envelope ({"payloadType":..., "payload":..., "signatures":[...]}).
//  2. A Sigstore bundle JSON (mediaType: application/vnd.dev.sigstore.bundle.*),
//     from which the embedded content.dsseEnvelope is extracted automatically.
//
// This allows the engine to route predicates from both bare DSSE and Sigstore
// bundle envelopes without requiring the adapter to strip the bundle wrapper.
func DecodeDSSE(envelope []byte) (DecodedEnvelope, error) {
	var env dsseEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return DecodedEnvelope{}, fmt.Errorf("verify: unmarshal DSSE envelope: %w", err)
	}

	// If payloadType is empty after unmarshal, check whether this is a Sigstore
	// bundle JSON with the DSSE envelope nested at content.dsseEnvelope.
	if env.PayloadType == "" {
		var bundle sigstoreBundleEnvelope
		if jsonErr := json.Unmarshal(envelope, &bundle); jsonErr == nil &&
			bundle.Content.DSSEEnvelope != nil &&
			bundle.Content.DSSEEnvelope.PayloadType != "" {
			env = *bundle.Content.DSSEEnvelope
		}
	}

	if env.PayloadType == "" {
		return DecodedEnvelope{}, fmt.Errorf("verify: DSSE envelope has no payloadType")
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
