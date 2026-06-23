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
// used to extract the embedded DSSE envelope. It handles two bundle shapes:
//  1. forgeseal keyed bundles: DSSE envelope nested at content.dsseEnvelope.
//  2. canonical Sigstore v0.3 bundles (protojson output): DSSE envelope at the
//     top-level dsseEnvelope field (sibling of mediaType, verificationMaterial).
//
// This allows DecodeDSSE to transparently handle both bare DSSE envelopes and
// Sigstore bundle JSON (mediaType: application/vnd.dev.sigstore.bundle.*).
type sigstoreBundleEnvelope struct {
	MediaType    string        `json:"mediaType"`
	DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"` // canonical top-level (keyless)
	Content      struct {
		DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"` // forgeseal keyed shape
	} `json:"content"`
}

// extractBundleDSSE extracts the DSSE envelope from a Sigstore bundle JSON,
// accepting both the forgeseal keyed shape (content.dsseEnvelope) and the
// canonical Sigstore v0.3 protojson shape (top-level dsseEnvelope). The
// canonical top-level field is checked first; content.dsseEnvelope is the
// fallback for forgeseal keyed bundles.
func extractBundleDSSE(envelope []byte) *dsseEnvelope {
	var bundle sigstoreBundleEnvelope
	if err := json.Unmarshal(envelope, &bundle); err != nil {
		return nil
	}
	// 1. Canonical Sigstore v0.3 shape: top-level dsseEnvelope (keyless bundles).
	if bundle.DSSEEnvelope != nil && bundle.DSSEEnvelope.PayloadType != "" {
		return bundle.DSSEEnvelope
	}
	// 2. forgeseal keyed shape: content.dsseEnvelope.
	if bundle.Content.DSSEEnvelope != nil && bundle.Content.DSSEEnvelope.PayloadType != "" {
		return bundle.Content.DSSEEnvelope
	}
	return nil
}

// DecodeDSSE parses a raw DSSE envelope JSON, base64-decodes the payload, and
// returns a DecodedEnvelope. It returns a non-nil error for any malformed
// input and never panics.
//
// DecodeDSSE transparently handles three input formats:
//  1. A bare DSSE envelope ({"payloadType":..., "payload":..., "signatures":[...]}).
//  2. A canonical Sigstore v0.3 bundle (top-level dsseEnvelope field, used by
//     real keyless bundles produced by sigstore-go / protojson.Marshal).
//  3. A forgeseal keyed Sigstore bundle (content.dsseEnvelope field).
//
// This allows the engine to route predicates from bare DSSE, keyless Sigstore
// bundles, and forgeseal keyed bundles without requiring the adapter to strip
// the bundle wrapper.
func DecodeDSSE(envelope []byte) (DecodedEnvelope, error) {
	var env dsseEnvelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return DecodedEnvelope{}, fmt.Errorf("verify: unmarshal DSSE envelope: %w", err)
	}

	// If payloadType is empty after unmarshal, this is a Sigstore bundle JSON.
	// Check both the canonical top-level dsseEnvelope and the forgeseal keyed
	// content.dsseEnvelope shapes via extractBundleDSSE.
	if env.PayloadType == "" {
		if extracted := extractBundleDSSE(envelope); extracted != nil {
			env = *extracted
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
