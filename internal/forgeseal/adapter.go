// Package forgeseal provides an adapter that reads forgeseal's native output
// directory and assembles a core.Evidence value for assayward policy evaluation.
//
// # Adapter design: raw-to-DSSE wrapping
//
// forgeseal emits three categories of artifact:
//
//  1. slsa.sigstore-bundle.json — a Sigstore bundle containing a dsseEnvelope
//     with the SLSA in-toto Statement inside. The dsseEnvelope is already a
//     valid bare DSSE envelope; EvidenceFromOutput extracts it from the bundle
//     wrapper and passes it directly to core.Attestation.Envelope.
//
//  2. sbom.cdx.json and vex.openvex.json — RAW documents with no in-toto or
//     DSSE wrapper. EvidenceFromOutput wraps each one into a synthetic in-toto
//     Statement v1 (using the artifact digest as the subject) and then into a
//     bare DSSE envelope (payloadType = application/vnd.in-toto+json, payload =
//     base64(statement), signatures = []). The signatures slice is deliberately
//     empty: these are raw artifacts and the dogfood policy does not require
//     cryptographic signatures (see gap note below).
//
// # Signature-stub gap (honest M6 state)
//
// forgeseal's Sigstore signing is STUBBED in the current release: the
// slsa.sigstore-bundle.json contains NO Fulcio certificate chain and NO Rekor
// transparency-log entry (verificationMaterial is absent). Consequently
// assayward's sigstore-go verifier CANNOT cryptographically verify the bundle.
//
// The dogfood policy (testdata/dogfood/policy-dogfood.yaml) therefore sets
// signature.required: false and relies instead on:
//   - SLSA provenance (level 3, builder https://forgeseal.dev/cli)
//   - SBOM presence
//   - VEX not_affected status
//   - svidmint publisher JWT-SVID for workload identity binding
//
// Full Sigstore-keyless + forgeseal-verified signing is a tracked gap to be
// resolved in a future milestone once forgeseal integrates a real Fulcio CA
// and Rekor instance.
package forgeseal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	core "github.com/sns45/assayward/pkg/core"
)

// EvidenceFromOutput reads forgeseal's native output directory (dir) and
// assembles a core.Evidence value. artifactDigest must be the sha256 digest of
// the attested artifact in the form "sha256:<hex>".
//
// The caller is responsible for attaching Identity to the returned Evidence
// before passing it to the engine; EvidenceFromOutput always returns
// Evidence.Identity == nil.
//
// Errors are returned for any missing or malformed file in dir.
func EvidenceFromOutput(dir string, artifactDigest string) (core.Evidence, error) {
	// Strip "sha256:" prefix to get the hex portion used in statement subjects.
	digestHex := strings.TrimPrefix(artifactDigest, "sha256:")

	ev := core.Evidence{
		Artifact: core.ArtifactRef{
			Kind:   "container",
			Name:   "forgeseal-artifact",
			Digest: core.DigestSet{"sha256": digestHex},
		},
		SchemaVersion: core.EvidenceSchemaVersion,
	}

	// -------------------------------------------------------------------------
	// 1. SLSA attestation: extract dsseEnvelope from the Sigstore bundle.
	// -------------------------------------------------------------------------
	slsaAtt, err := readSLSAAttestation(dir)
	if err != nil {
		return core.Evidence{}, fmt.Errorf("forgeseal: SLSA attestation: %w", err)
	}
	ev.Attestations = append(ev.Attestations, slsaAtt)

	// -------------------------------------------------------------------------
	// 2. SBOM attestation: wrap raw CycloneDX BOM into in-toto + DSSE.
	// -------------------------------------------------------------------------
	sbomAtt, err := readAndWrapRaw(
		filepath.Join(dir, "sbom.cdx.json"),
		"forgeseal-artifact",
		digestHex,
		"https://cyclonedx.org/bom",
	)
	if err != nil {
		return core.Evidence{}, fmt.Errorf("forgeseal: SBOM attestation: %w", err)
	}
	ev.Attestations = append(ev.Attestations, core.Attestation{
		PredicateType: "https://cyclonedx.org/bom",
		Envelope:      sbomAtt,
	})

	// -------------------------------------------------------------------------
	// 3. VEX attestation: wrap raw OpenVEX document into in-toto + DSSE.
	// -------------------------------------------------------------------------
	vexAtt, err := readAndWrapRaw(
		filepath.Join(dir, "vex.openvex.json"),
		"forgeseal-artifact",
		digestHex,
		"https://openvex.dev/ns/v0.2.0",
	)
	if err != nil {
		return core.Evidence{}, fmt.Errorf("forgeseal: VEX attestation: %w", err)
	}
	ev.Attestations = append(ev.Attestations, core.Attestation{
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Envelope:      vexAtt,
	})

	return ev, nil
}

// sigstoreBundle is a minimal JSON representation of a Sigstore bundle.
// Only the fields needed to validate that a dsseEnvelope is present are decoded.
//
// Two bundle shapes are supported:
//  1. forgeseal keyed bundles: dsseEnvelope is nested at content.dsseEnvelope.
//  2. canonical Sigstore v0.3 bundles (protojson output from sigstore-go): the
//     dsseEnvelope is a top-level field (sibling of mediaType and
//     verificationMaterial), not wrapped in a content object.
type sigstoreBundle struct {
	MediaType        string          `json:"mediaType"`
	DSSEEnvelope     json.RawMessage `json:"dsseEnvelope"`     // canonical top-level (keyless)
	MessageSignature json.RawMessage `json:"messageSignature"` // canonical top-level blob signature
	Content          struct {
		DSSEEnvelope     json.RawMessage `json:"dsseEnvelope"`     // forgeseal keyed shape
		MessageSignature json.RawMessage `json:"messageSignature"` // forgeseal keyed blob signature
	} `json:"content"`
}

// bundleDSSEEnvelope returns the raw DSSE envelope bytes from a sigstoreBundle,
// accepting both the canonical top-level shape and the forgeseal keyed shape.
// Returns nil when neither field is populated.
func bundleDSSEEnvelope(b sigstoreBundle) json.RawMessage {
	if len(b.DSSEEnvelope) > 0 {
		return b.DSSEEnvelope
	}
	if len(b.Content.DSSEEnvelope) > 0 {
		return b.Content.DSSEEnvelope
	}
	return nil
}

// bundleHasMessageSignature reports whether b carries a Sigstore
// messageSignature (used for detached "blob" signing rather than in-toto
// attestation), accepting both the canonical top-level shape and the
// forgeseal keyed shape.
func bundleHasMessageSignature(b sigstoreBundle) bool {
	return len(b.MessageSignature) > 0 || len(b.Content.MessageSignature) > 0
}

// dsseEnvelopeWire is the bare DSSE envelope wire format consumed by DecodeDSSE.
type dsseEnvelopeWire struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  json.RawMessage `json:"signatures"`
}

// readSLSAAttestation reads slsa.sigstore-bundle.json from dir and returns it
// as a core.Attestation whose Envelope contains the FULL Sigstore bundle JSON.
//
// Storing the full bundle (rather than only the extracted dsseEnvelope) allows
// the signature verifier to access verificationMaterial.certificate for keyed
// (self-signed-CA) verification. The engine's DSSE predicate routing handles
// Sigstore bundle JSON transparently via verify.DecodeDSSE's bundle-aware path.
//
// If the bundle file is absent but slsa.intoto.jsonl is present, the raw
// Statement is wrapped into a synthetic DSSE envelope instead (fallback path).
func readSLSAAttestation(dir string) (core.Attestation, error) {
	bundlePath := filepath.Join(dir, "slsa.sigstore-bundle.json")
	rawPath := filepath.Join(dir, "slsa.intoto.jsonl")

	bundleBytes, bundleErr := os.ReadFile(bundlePath)
	if bundleErr != nil {
		// Fallback: use the raw JSONL statement and wrap it.
		rawBytes, rawErr := os.ReadFile(rawPath)
		if rawErr != nil {
			return core.Attestation{}, fmt.Errorf("read slsa.sigstore-bundle.json: %w; read slsa.intoto.jsonl: %v", bundleErr, rawErr)
		}
		env, err := wrapStatementInDSSE(rawBytes, "application/vnd.in-toto+json")
		if err != nil {
			return core.Attestation{}, fmt.Errorf("wrap SLSA statement: %w", err)
		}
		return core.Attestation{
			PredicateType: "https://slsa.dev/provenance/v1",
			Envelope:      env,
		}, nil
	}

	// Validate the bundle is parseable JSON and contains a DSSE envelope in
	// one of the two supported locations before storing.
	var bundle sigstoreBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		return core.Attestation{}, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	if bundleDSSEEnvelope(bundle) == nil {
		return core.Attestation{}, fmt.Errorf("sigstore bundle has no dsseEnvelope (checked top-level and content.dsseEnvelope)")
	}

	// Store the FULL bundle JSON as the Attestation Envelope so that:
	//   - The signature verifier can access verificationMaterial.certificate
	//     for keyed (self-signed-CA) DSSE signature verification.
	//   - verify.DecodeDSSE transparently extracts content.dsseEnvelope for
	//     predicate routing in the engine.
	return core.Attestation{
		PredicateType: "https://slsa.dev/provenance/v1",
		Envelope:      bundleBytes,
	}, nil
}

// inTotoStatement is the minimal in-toto Statement v1 structure used for
// synthetic wrapping of raw SBOM and VEX documents. The JSON field names match
// the in-toto Statement v1 proto-JSON encoding expected by the verifier.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []inTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// readAndWrapRaw reads a raw artifact at path, wraps it in an in-toto
// Statement v1, and encodes the whole thing as a bare DSSE envelope.
//
// The subject uses subjectName (e.g. "forgeseal-artifact") and digestHex
// (the sha256 hex without the "sha256:" prefix). predicateType is embedded in
// the statement.
func readAndWrapRaw(path, subjectName, digestHex, predicateType string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	// Validate that the raw bytes are well-formed JSON before embedding.
	if !json.Valid(raw) {
		return nil, fmt.Errorf("%q is not valid JSON", path)
	}

	stmt := inTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []inTotoSubj{
			{
				Name:   subjectName,
				Digest: map[string]string{"sha256": digestHex},
			},
		},
		PredicateType: predicateType,
		Predicate:     json.RawMessage(raw),
	}

	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}

	return wrapStatementInDSSE(stmtBytes, "application/vnd.in-toto+json")
}

// wrapStatementInDSSE encodes stmtBytes as the payload of a bare DSSE envelope
// with an empty signatures slice. The payload is base64-standard-encoded as
// required by the DSSE spec and expected by verify.DecodeDSSE.
func wrapStatementInDSSE(stmtBytes []byte, payloadType string) ([]byte, error) {
	env := dsseEnvelopeWire{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(stmtBytes),
		Signatures:  json.RawMessage("[]"),
	}
	return json.Marshal(env)
}

// forgesealKind classifies a forgeseal output file by its JSON content
// (rather than its filename), so callers can discover forgeseal artifacts
// under arbitrary directory layouts.
type forgesealKind int

const (
	kindOther         forgesealKind = iota
	kindSBOM                        // CycloneDX SBOM document
	kindVEX                         // OpenVEX document
	kindSLSABundle                  // Sigstore bundle whose DSSE payload is a SLSA provenance
	kindSLSAStatement               // raw in-toto SLSA statement (unsigned fallback)
	kindBlobSig                     // Sigstore messageSignature bundle (not attached)
)

// classifyForgesealFile inspects the JSON content of b and returns the
// forgesealKind it represents. Unrecognized or non-JSON content is
// classified as kindOther.
func classifyForgesealFile(b []byte) forgesealKind {
	var probe struct {
		BomFormat     string          `json:"bomFormat"`
		Context       json.RawMessage `json:"@context"`
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
	}
	_ = json.Unmarshal(b, &probe)
	switch {
	case probe.BomFormat == "CycloneDX":
		return kindSBOM
	case len(probe.Context) > 0 && bytes.Contains(probe.Context, []byte("openvex.dev")):
		return kindVEX
	case strings.Contains(probe.Type, "in-toto.io/Statement") && strings.Contains(probe.PredicateType, "slsa.dev/provenance"):
		return kindSLSAStatement
	}

	// Structural Sigstore bundle detection: neither bomFormat, @context, nor
	// _type/predicateType matched, so probe for a DSSE envelope or a detached
	// message signature.
	var bundle sigstoreBundle
	if err := json.Unmarshal(b, &bundle); err == nil {
		if env := bundleDSSEEnvelope(bundle); env != nil {
			if predicateTypeOfDSSE(env) == "slsa" {
				return kindSLSABundle
			}
			return kindOther
		}
		if bundleHasMessageSignature(bundle) {
			return kindBlobSig
		}
	}
	return kindOther
}

// predicateTypeOfDSSE decodes the DSSE envelope env, base64-decodes its
// payload, and reads the predicateType of the embedded in-toto Statement,
// returning a coarse category label ("slsa" for SLSA provenance predicates,
// "" for anything else or on any decode failure).
func predicateTypeOfDSSE(env json.RawMessage) string {
	var wire dsseEnvelopeWire
	if err := json.Unmarshal(env, &wire); err != nil {
		return ""
	}
	payload, err := base64.StdEncoding.DecodeString(wire.Payload)
	if err != nil {
		return ""
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return ""
	}
	if strings.Contains(stmt.PredicateType, "slsa.dev/provenance") {
		return "slsa"
	}
	return ""
}

// DetectSigningCA scans dir for the first file whose contents contain a PEM
// CERTIFICATE block and returns its raw bytes. It returns (nil, nil) when no
// file in dir contains a certificate, and propagates any error from reading
// the directory itself. Errors reading individual files are skipped over
// (best-effort scan).
func DetectSigningCA(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte("-----BEGIN CERTIFICATE-----")) {
			return b, nil
		}
	}
	return nil, nil
}
