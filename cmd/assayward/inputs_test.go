package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
)

// A minimal CycloneDX SBOM document — enough for classifyForgesealFile to
// route it to the SBOM branch so forgeseal.EvidenceFromOutput succeeds
// without needing a full SLSA/SBOM/VEX fixture set.
const minimalSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`

// A syntactically-plausible PEM CA certificate. DetectSigningCA only checks
// for the "-----BEGIN CERTIFICATE-----" marker, so the body need not be a
// parseable certificate for these input-assembly tests.
const fakeCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBFAKECAAAAA==\n-----END CERTIFICATE-----\n"
const otherCAPEM = "-----BEGIN CERTIFICATE-----\nMIIBOTHERCAAAAA==\n-----END CERTIFICATE-----\n"

// TestBuildSignedBlobAlone verifies that --signed-blob alone (no --bundle,
// --from-oci, or --forgeseal-output) is accepted as a valid attestation
// source and sets ev.BlobSignature with ArtifactDigest matching the --image
// digest.
func TestBuildSignedBlobAlone(t *testing.T) {
	dir := t.TempDir()
	blobPath := filepath.Join(dir, "blob.sigstore.json")
	blobBytes := []byte(`{"mediaType":"x","messageSignature":{}}`)
	if err := os.WriteFile(blobPath, blobBytes, 0o644); err != nil {
		t.Fatalf("write blob fixture: %v", err)
	}

	o := &evalInputs{
		Policy:     "baseline",
		Image:      "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
		SignedBlob: blobPath,
	}

	ev, _, _, err := o.build("test")
	if err != nil {
		t.Fatalf("build with --signed-blob alone: unexpected error: %v", err)
	}
	if len(ev.Attestations) != 0 {
		t.Errorf("expected 0 attestations for a signature-only run, got %d", len(ev.Attestations))
	}
	if ev.BlobSignature == nil {
		t.Fatal("expected ev.BlobSignature to be set")
	}
	if string(ev.BlobSignature.Bundle) != string(blobBytes) {
		t.Errorf("BlobSignature.Bundle mismatch: got %q, want %q", ev.BlobSignature.Bundle, blobBytes)
	}
	if ev.BlobSignature.ArtifactDigest != testfix.TestImageDigest {
		t.Errorf("BlobSignature.ArtifactDigest = %q, want %q", ev.BlobSignature.ArtifactDigest, testfix.TestImageDigest)
	}
}

// TestBuildNoSourceStillRejectsWithoutSignedBlob verifies that the widened
// source guard still rejects a run with none of --bundle, --from-oci,
// --forgeseal-output, or --signed-blob.
func TestBuildNoSourceStillRejectsWithoutSignedBlob(t *testing.T) {
	o := &evalInputs{
		Policy: "baseline",
		Image:  "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
	}

	_, _, _, err := o.build("test")
	if err == nil {
		t.Fatal("expected an error when no attestation source is supplied")
	}
}

// newForgesealOutputDir builds a temp forgeseal-output directory containing a
// minimal SBOM (so forgeseal.EvidenceFromOutput succeeds) plus a signing-CA
// PEM file, so --forgeseal-output alone exercises the CA auto-merge path.
func newForgesealOutputDir(t *testing.T, caPEM string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sbom.cyclonedx.json"), []byte(minimalSBOM), 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "forgeseal-signing-ca.crt"), []byte(caPEM), 0o644); err != nil {
		t.Fatalf("write CA fixture: %v", err)
	}
	return dir
}

// TestBuildForgesealOutputAutoMergesCA verifies that when --signature-ca is
// not supplied, --forgeseal-output's signing CA is auto-detected and merged
// into roots.SignatureCAs.
func TestBuildForgesealOutputAutoMergesCA(t *testing.T) {
	dir := newForgesealOutputDir(t, fakeCAPEM)

	o := &evalInputs{
		Policy:          "baseline",
		Image:           "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
		ForgesealOutput: dir,
	}

	_, _, roots, err := o.build("test")
	if err != nil {
		t.Fatalf("build with --forgeseal-output: unexpected error: %v", err)
	}
	if string(roots.SignatureCAs) != fakeCAPEM {
		t.Errorf("roots.SignatureCAs = %q, want auto-detected %q", roots.SignatureCAs, fakeCAPEM)
	}
}

// TestBuildExplicitSignatureCAWinsOverAutoMerge verifies that an explicit
// --signature-ca always overrides the auto-detected forgeseal signing CA.
func TestBuildExplicitSignatureCAWinsOverAutoMerge(t *testing.T) {
	dir := newForgesealOutputDir(t, fakeCAPEM)

	explicitCAPath := filepath.Join(dir, "explicit-ca.crt")
	if err := os.WriteFile(explicitCAPath, []byte(otherCAPEM), 0o644); err != nil {
		t.Fatalf("write explicit CA fixture: %v", err)
	}

	o := &evalInputs{
		Policy:          "baseline",
		Image:           "ghcr.io/sns45/example:1.0.0@" + testfix.TestImageDigest,
		ForgesealOutput: dir,
		SignatureCA:     explicitCAPath,
	}

	_, _, roots, err := o.build("test")
	if err != nil {
		t.Fatalf("build with --forgeseal-output + --signature-ca: unexpected error: %v", err)
	}
	if string(roots.SignatureCAs) != otherCAPEM {
		t.Errorf("roots.SignatureCAs = %q, want explicit %q (must override auto-merge)", roots.SignatureCAs, otherCAPEM)
	}
}
