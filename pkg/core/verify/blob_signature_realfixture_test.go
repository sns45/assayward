//go:build !wasm

package verify_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

// forgesealTestdata returns the absolute path to internal/forgeseal/testdata,
// which holds the REAL forgeseal v0.5.1 fixtures generated in Task 11.
func forgesealTestdata(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// This file is at pkg/core/verify/blob_signature_realfixture_test.go.
	// internal/forgeseal/testdata is at ../../../internal/forgeseal/testdata.
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "internal", "forgeseal", "testdata")
}

// TestVerifyBlobBundleRealForgesealFixture is THE Task 11 key validation:
// VerifyBlobBundle must verify a GENUINE forgeseal keyed messageSignature bundle
// against the shared forgeseal signing CA, and must fail closed when the artifact
// digest is tampered by a single hex flip.
//
// forgeseal's keyed SignBlob signs sha256(content) with ecdsa.SignASN1 (DER),
// emitting messageDigest.digest = base64(sha256), signature = base64(DER), the
// ephemeral leaf cert in verificationMaterial.certificate, and no tlogEntries.
// This is exactly the shape VerifyBlobBundle's keyed path parses, so the happy
// path verifies with no code change.
func TestVerifyBlobBundleRealForgesealFixture(t *testing.T) {
	td := forgesealTestdata(t)

	bundle, err := os.ReadFile(filepath.Join(td, "blob", "artifact.bin.sigstore.json"))
	if err != nil {
		t.Fatalf("read real blob bundle: %v", err)
	}
	digestBytes, err := os.ReadFile(filepath.Join(td, "blob", "artifact.sha256"))
	if err != nil {
		t.Fatalf("read artifact.sha256: %v", err)
	}
	digestHex := strings.TrimSpace(string(digestBytes))

	// The blob was signed with the SAME shared CA as the pipeline output; read
	// the CA PEM from the pipeline-output directory (per the Task 11 brief).
	caPEM, err := os.ReadFile(filepath.Join(td, "pipeline-output", "forgeseal-signing-ca.crt"))
	if err != nil {
		t.Fatalf("read forgeseal-signing-ca.crt: %v", err)
	}

	roots := core.TrustRoots{SignatureCAs: caPEM}

	// Happy path: the real keyed blob signature MUST verify.
	res := verify.VerifyBlobBundle(bundle, "sha256:"+digestHex, roots)
	if !res.Verified {
		t.Fatalf("real forgeseal keyed blob did NOT verify: Verified=false Err=%q", res.Err)
	}
	if !res.Available {
		t.Errorf("Available=false on a native verify path; want true")
	}
	// The leaf SAN encodes the forgeseal CLI builder identity.
	if res.SubjectIdentity != "https://forgeseal.dev/cli" {
		t.Errorf("SubjectIdentity = %q; want https://forgeseal.dev/cli", res.SubjectIdentity)
	}

	// Fail-closed: flip the last hex nibble of the artifact digest. The bundle's
	// messageDigest no longer matches, so verification MUST fail (Verified=false).
	tampered := flipLastHexNibble(digestHex)
	if tampered == digestHex {
		t.Fatal("failed to construct a tampered digest")
	}
	bad := verify.VerifyBlobBundle(bundle, "sha256:"+tampered, roots)
	if bad.Verified {
		t.Fatalf("tampered digest unexpectedly verified (fail-open!): %q", tampered)
	}
	if bad.Err == "" {
		t.Errorf("tampered digest: expected a non-empty Err on the fail-closed path")
	}
}

// flipLastHexNibble returns hexStr with its final hex character changed to a
// different value, producing a digest that cannot match the signed one.
func flipLastHexNibble(hexStr string) string {
	if hexStr == "" {
		return hexStr
	}
	last := hexStr[len(hexStr)-1]
	var repl byte
	if last == '0' {
		repl = '1'
	} else {
		repl = '0'
	}
	return hexStr[:len(hexStr)-1] + string(repl)
}
