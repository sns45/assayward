package main

// parity_test.go: Wasm-PARITY test (M3 Definition of Done).
//
// Verifies that the same inputs yield BYTE-IDENTICAL decisions through:
//   - the native runEvaluate (compiled natively, same binary as the test)
//   - the wasm module running under wazero (GOOS=wasip1 GOARCH=wasm binary)
//
// ALL THREE PARITY CASES USE NO-SIGNATURE POLICIES. This is by design:
// the wasm signature stage is the fail-closed stub (Decision-5). When
// signature.required=true the wasm decision is always deny with reason
// SIGNATURE_VERIFICATION_UNAVAILABLE, diverging from the native verifier.
// Parity is tested over the stages that run fully in wasm: identity, SLSA,
// and VEX. Signature-required policies are native-only and out of parity scope.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
)

// wasmBytes holds the compiled wasip1 module bytes; built once in TestMain.
var wasmBytes []byte

// TestMain builds the wasip1 wasm module once and shares it across all parity tests.
func TestMain(m *testing.M) {
	// Resolve repo root via runtime.Caller: this file is at core/wasm/parity_test.go.
	// Two levels up from core/wasm gives us the repo root.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("parity_test: runtime.Caller(0) failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	// Build the wasip1 module into a temp file.
	tmpDir, err := os.MkdirTemp("", "assayward-wasm-parity-*")
	if err != nil {
		panic("parity_test: MkdirTemp: " + err.Error())
	}
	defer os.RemoveAll(tmpDir)

	wasmOut := filepath.Join(tmpDir, "assayward.wasm")
	cmd := exec.Command("go", "build", "-o", wasmOut, "./core/wasm")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
		panic("parity_test: wasm build failed:\n" + string(out))
	}

	wasmBytes, err = os.ReadFile(wasmOut)
	if err != nil {
		panic("parity_test: ReadFile wasm: " + err.Error())
	}

	os.Exit(m.Run())
}

// runWasm executes the wasip1 module with envelope as stdin and returns stdout.
// It fails the test (with stderr) if the module exits non-zero.
func runWasm(t *testing.T, envelope []byte) []byte {
	t.Helper()

	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	// Instantiate WASI host functions.
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	var outBuf, errBuf bytes.Buffer

	// The module's _start (main) runs on instantiation.
	// WithSysWalltime passes the real wall clock into the wasm module so that
	// go-spiffe's JWT validation (which calls time.Now() internally) sees the
	// real clock and does not reject a JWT based on a fake 1970-epoch timestamp.
	// The envelope "now" field governs only engine.Evaluate's FixedClock; the
	// SPIFFE JWT validator independently uses the host clock for exp/iat checks.
	mod, err := rt.InstantiateWithConfig(ctx, wasmBytes,
		wazero.NewModuleConfig().
			WithName("assayward").
			WithSysWalltime().
			WithSysNanotime().
			WithStdin(bytes.NewReader(envelope)).
			WithStdout(&outBuf).
			WithStderr(&errBuf),
	)
	if mod != nil {
		defer mod.Close(ctx)
	}

	// Exit code 0 is returned as *sys.ExitError with ExitCode()==0 by wazero.
	if err != nil {
		if exitErr, ok := err.(*sys.ExitError); ok {
			if exitErr.ExitCode() != 0 {
				t.Fatalf("wasm exited %d; stderr:\n%s", exitErr.ExitCode(), errBuf.String())
			}
			// exit 0: success — fall through
		} else {
			t.Fatalf("wasm instantiation error: %v; stderr:\n%s", err, errBuf.String())
		}
	}

	return outBuf.Bytes()
}

// goldenEvidence builds the canonical M1 golden-scenario Evidence used across
// all parity cases: sigstore bundle + SLSA/SBOM/VEX DSSE envelopes + JWT-SVID.
func goldenEvidence(t *testing.T) core.Evidence {
	t.Helper()
	slsaEnv := testfix.Load(t, "slsa/valid-l3.dsse.json")
	sbomEnv := testfix.Load(t, "sbom/cyclonedx.dsse.json")
	vexEnv := testfix.Load(t, "vex/affected-critical.dsse.json")
	sigBundle := testfix.Load(t, "signature/bundle-provenance.json")
	jwtSVID := testfix.Load(t, "svid/jwt-valid.jwt")

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return core.Evidence{
		Image: core.ImageRef{
			Name:   testfix.TestImageName,
			Digest: testfix.TestImageDigest,
		},
		Attestations: []core.Attestation{
			{Envelope: sigBundle, PredicateType: "sigstore-bundle"},
			{Envelope: slsaEnv, PredicateType: "https://slsa.dev/provenance/v1"},
			{Envelope: sbomEnv, PredicateType: "https://cyclonedx.org/bom"},
			{Envelope: vexEnv, PredicateType: "https://openvex.dev/ns/v0.2.0"},
		},
		Identity: &core.WorkloadIdentity{
			SVIDType: core.SVIDTypeJWT,
			Raw:      jwtSVID,
		},
		FetchedAt: now,
	}
}

// goldenTrustRoots builds the canonical TrustRoots for the golden evidence.
func goldenTrustRoots(t *testing.T) core.TrustRoots {
	t.Helper()
	sigstoreTUF := testfix.Load(t, "signature/trusted-root-public-good.json")
	jwtBundle := testfix.Load(t, "svid/jwt-bundle.json")
	return core.TrustRoots{
		SigstoreTUF: sigstoreTUF,
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": jwtBundle,
		},
	}
}

// buildEnvelope marshals ev, roots, policyYAML, and the fixed now into a
// compact ABI envelope JSON.
func buildEnvelope(t *testing.T, ev core.Evidence, roots core.TrustRoots, policyYAML string) []byte {
	t.Helper()
	const fixedNow = "2026-01-01T00:00:00Z"

	evBytes, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	rootsBytes, err := json.Marshal(roots)
	if err != nil {
		t.Fatalf("marshal trustRoots: %v", err)
	}
	polJSON, err := json.Marshal(policyYAML)
	if err != nil {
		t.Fatalf("marshal policy string: %v", err)
	}
	nowJSON, err := json.Marshal(fixedNow)
	if err != nil {
		t.Fatalf("marshal now string: %v", err)
	}

	env := map[string]json.RawMessage{
		"evidence":   evBytes,
		"policy":     polJSON,
		"trustRoots": rootsBytes,
		"now":        nowJSON,
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return out
}

// assertParity asserts that native and wasm outputs are byte-identical.
func assertParity(t *testing.T, caseName string, nativeOut, wasmOut []byte) {
	t.Helper()
	if bytes.Equal(nativeOut, wasmOut) {
		return
	}
	// Find first differing byte for debugging.
	diffOffset := -1
	for i := 0; i < len(nativeOut) && i < len(wasmOut); i++ {
		if nativeOut[i] != wasmOut[i] {
			diffOffset = i
			break
		}
	}
	if diffOffset == -1 {
		// One is a prefix of the other.
		diffOffset = min(len(nativeOut), len(wasmOut))
	}
	t.Errorf("PARITY MISMATCH in %s: outputs are NOT byte-identical\nnative (%d bytes): %s\nwasm   (%d bytes): %s\nfirst differing byte offset: %d",
		caseName, len(nativeOut), nativeOut, len(wasmOut), wasmOut, diffOffset)
}

// TestParityIdentityStage (case 1): serverless-edge policy — identity required,
// signature NOT required. go-spiffe JWT-SVID validation runs in wasm; both
// sides must validate the JWT-SVID and produce identical decisions.
// Uses jwt-valid.jwt (far-future-valid) so both agree on expiry.
func TestParityIdentityStage(t *testing.T) {
	// NO-SIGNATURE policy: signature.required=false; identity required.
	const policyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: serverless-edge
spec:
  mode: enforce
  signature:
    required: false
  slsa:
    minLevel: 0
  vex: {}
  sbom: {}
  identity:
    required: true
    trustDomain: "spiffe://sns45.dev"
    idPattern: "spiffe://sns45.dev/*"
`
	ev := goldenEvidence(t)
	roots := goldenTrustRoots(t)
	envelope := buildEnvelope(t, ev, roots, policyYAML)

	nativeOut, err := runEvaluate(envelope)
	if err != nil {
		t.Fatalf("native runEvaluate error: %v", err)
	}
	if len(nativeOut) == 0 || !json.Valid(nativeOut) {
		t.Fatal("native output empty or invalid JSON")
	}
	wasmOut := runWasm(t, envelope)
	if len(wasmOut) == 0 || !json.Valid(wasmOut) {
		t.Fatal("wasm output empty or invalid JSON")
	}

	assertParity(t, "IdentityStage", nativeOut, wasmOut)
}

// TestParitySLSAStage (case 2): custom inline policy — signature NOT required,
// SLSA minLevel=3, no identity. Both sides evaluate SLSA provenance and must
// produce identical decisions.
func TestParitySLSAStage(t *testing.T) {
	// NO-SIGNATURE policy: signature.required=false; SLSA level 3 required.
	const policyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: slsa-parity
spec:
  mode: enforce
  signature:
    required: false
  slsa:
    minLevel: 3
    allowedBuilders:
      - "https://github.com/sns45/*"
  vex: {}
  sbom: {}
  identity:
    required: false
`
	ev := goldenEvidence(t)
	roots := goldenTrustRoots(t)
	envelope := buildEnvelope(t, ev, roots, policyYAML)

	nativeOut, err := runEvaluate(envelope)
	if err != nil {
		t.Fatalf("native runEvaluate error: %v", err)
	}
	if len(nativeOut) == 0 || !json.Valid(nativeOut) {
		t.Fatal("native output empty or invalid JSON")
	}
	wasmOut := runWasm(t, envelope)
	if len(wasmOut) == 0 || !json.Valid(wasmOut) {
		t.Fatal("wasm output empty or invalid JSON")
	}

	assertParity(t, "SLSAStage", nativeOut, wasmOut)
}

// TestParityVEXStage (case 3): custom inline policy — signature NOT required,
// VEX maxUnmitigatedSeverity=high, no identity/SLSA. The golden evidence includes
// affected-critical.dsse.json (a critical-severity affected VEX statement), so
// both sides must produce a deny decision identically.
func TestParityVEXStage(t *testing.T) {
	// NO-SIGNATURE policy: signature.required=false; VEX max unmitigated = high.
	// The affected-critical VEX fixture should trigger a deny on both sides.
	const policyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: vex-parity
spec:
  mode: enforce
  signature:
    required: false
  slsa:
    minLevel: 0
  vex:
    maxUnmitigatedSeverity: high
  sbom: {}
  identity:
    required: false
`
	ev := goldenEvidence(t)
	roots := goldenTrustRoots(t)
	envelope := buildEnvelope(t, ev, roots, policyYAML)

	nativeOut, err := runEvaluate(envelope)
	if err != nil {
		t.Fatalf("native runEvaluate error: %v", err)
	}
	if len(nativeOut) == 0 || !json.Valid(nativeOut) {
		t.Fatal("native output empty or invalid JSON")
	}
	wasmOut := runWasm(t, envelope)
	if len(wasmOut) == 0 || !json.Valid(wasmOut) {
		t.Fatal("wasm output empty or invalid JSON")
	}

	assertParity(t, "VEXStage", nativeOut, wasmOut)
}

// TestParityWasmDeterminism verifies that running the wasm module 3 times with
// the same input yields byte-identical outputs (wasm output is stable).
// Uses the identity-stage envelope (case 1) as the reference input.
func TestParityWasmDeterminism(t *testing.T) {
	// Same setup as TestParityIdentityStage.
	const policyYAML = `apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: serverless-edge
spec:
  mode: enforce
  signature:
    required: false
  slsa:
    minLevel: 0
  vex: {}
  sbom: {}
  identity:
    required: true
    trustDomain: "spiffe://sns45.dev"
    idPattern: "spiffe://sns45.dev/*"
`
	ev := goldenEvidence(t)
	roots := goldenTrustRoots(t)
	envelope := buildEnvelope(t, ev, roots, policyYAML)

	var outputs [3][]byte
	for i := range outputs {
		outputs[i] = runWasm(t, envelope)
		if len(outputs[i]) == 0 || !json.Valid(outputs[i]) {
			t.Fatalf("wasm output empty or invalid JSON on run %d", i)
		}
	}

	for i := 1; i < 3; i++ {
		if !bytes.Equal(outputs[0], outputs[i]) {
			t.Errorf("wasm output run 0 != run %d (non-deterministic)\nrun 0: %s\nrun %d: %s",
				i, outputs[0], i, outputs[i])
		}
	}
}
