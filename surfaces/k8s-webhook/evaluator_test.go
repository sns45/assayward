package webhook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// goldenEvaluatorEvidence builds the attestation set used across evaluator
// golden tests, mirroring the engine golden test setup so we get the same
// deterministic ResultAllow for serverless-edge.
func goldenAttestation(t *testing.T) []core.Attestation {
	t.Helper()
	return []core.Attestation{
		{Envelope: testfix.Load(t, "signature/bundle-provenance.json"), PredicateType: "sigstore-bundle"},
		{Envelope: testfix.Load(t, "slsa/valid-l3.dsse.json"), PredicateType: "https://slsa.dev/provenance/v1"},
		{Envelope: testfix.Load(t, "sbom/cyclonedx.dsse.json"), PredicateType: "https://cyclonedx.org/bom"},
		{Envelope: testfix.Load(t, "vex/affected-critical.dsse.json"), PredicateType: "https://openvex.dev/ns/v0.2.0"},
	}
}

func goldenIdentity(t *testing.T) *core.WorkloadIdentity {
	t.Helper()
	return &core.WorkloadIdentity{
		SVIDType: core.SVIDTypeJWT,
		Raw:      testfix.Load(t, "svid/jwt-valid.jwt"),
	}
}

func goldenRoots(t *testing.T) core.TrustRoots {
	t.Helper()
	return core.TrustRoots{
		SigstoreTUF: testfix.Load(t, "signature/trusted-root-public-good.json"),
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": testfix.Load(t, "svid/jwt-bundle.json"),
		},
	}
}

// fixedTime is the same fixed clock used in engine golden tests.
var fixedTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// TestCoreEvaluator_ServerlessEdge_AllowWithInjectedFetch verifies that
// coreEvaluator.Evaluate returns ResultAllow for the serverless-edge policy
// when fed the M1 testdata attestations and JWT-SVID identity via injected
// fetch/identity functions (no network required).
func TestCoreEvaluator_ServerlessEdge_AllowWithInjectedFetch(t *testing.T) {
	pol, err := policy.Parse(builtin.ServerlessEdge)
	if err != nil {
		t.Fatalf("parse serverless-edge policy: %v", err)
	}
	roots := goldenRoots(t)

	atts := goldenAttestation(t)
	identity := goldenIdentity(t)

	img := core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: testfix.TestImageDigest,
	}

	eval := NewEvaluator(pol, roots)
	// Inject clock to keep test deterministic.
	eval.now = func() time.Time { return fixedTime }
	// Inject fetch returning pre-loaded attestations (no network).
	eval.fetch = func(_ context.Context, _ core.ImageRef) ([]core.Attestation, error) {
		return atts, nil
	}
	// Inject identity resolver returning the JWT-SVID.
	eval.identity = func(_ context.Context, _ core.ImageRef) (*core.WorkloadIdentity, error) {
		return identity, nil
	}

	dec, err := eval.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("Evaluate: unexpected error: %v", err)
	}

	if dec.Result != core.ResultAllow {
		t.Errorf("expected ResultAllow, got %q (reasons: %v)", dec.Result, dec.Reasons)
	}
}

// TestCoreEvaluator_FetchError_ReturnsError verifies that a fetch error is
// propagated and Evaluate returns an error (the handler fail-closes in enforce).
func TestCoreEvaluator_FetchError_ReturnsError(t *testing.T) {
	pol, err := policy.Parse(builtin.ServerlessEdge)
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	roots := core.TrustRoots{}

	fetchErr := errors.New("registry unavailable: connection refused")

	eval := NewEvaluator(pol, roots)
	eval.now = func() time.Time { return fixedTime }
	eval.fetch = func(_ context.Context, _ core.ImageRef) ([]core.Attestation, error) {
		return nil, fetchErr
	}

	img := core.ImageRef{Name: "myrepo/app:latest"}
	_, gotErr := eval.Evaluate(context.Background(), img)
	if gotErr == nil {
		t.Fatal("expected error from Evaluate when fetch fails, got nil")
	}
	if !errors.Is(gotErr, fetchErr) {
		t.Errorf("expected fetchErr in error chain, got: %v", gotErr)
	}
}

// TestCoreEvaluator_NilIdentity_ReducedMode verifies that when identity is nil
// (Decision 4: attestation-only reduced mode), Evaluate still returns a decision
// without error, using only attestations.
func TestCoreEvaluator_NilIdentity_ReducedMode(t *testing.T) {
	// Use a minimal permissive policy (no required checks) so we get ResultAllow
	// without a valid identity or attestations. This tests the reduced mode path
	// not the policy evaluation itself.
	pol := policy.Policy{
		Name:    "test-permissive",
		Version: "v0",
		Mode:    policy.ModeEnforce,
		// No required checks: Signature.Required=false, SBOM.Required=false,
		// Identity.Required=false, SLSA.MinLevel=0.
	}
	roots := core.TrustRoots{}

	eval := NewEvaluator(pol, roots)
	eval.now = func() time.Time { return fixedTime }
	// Fetch returns empty attestations.
	eval.fetch = func(_ context.Context, _ core.ImageRef) ([]core.Attestation, error) {
		return []core.Attestation{}, nil
	}
	// identity is nil by default (reduced mode, Decision 4).
	if eval.identity != nil {
		t.Fatal("NewEvaluator should default identity to nil for reduced mode")
	}

	img := core.ImageRef{Name: "myrepo/app:latest"}
	dec, err := eval.Evaluate(context.Background(), img)
	if err != nil {
		t.Fatalf("Evaluate with nil identity: unexpected error: %v", err)
	}
	// Permissive policy with no required checks and no attestations should allow.
	if dec.Result != core.ResultAllow {
		t.Errorf("reduced mode (nil identity) permissive policy: expected ResultAllow, got %q (reasons: %v)", dec.Result, dec.Reasons)
	}
}

// TestCoreEvaluator_DefaultFetch_IsNotNil verifies that NewEvaluator wires a
// non-nil default fetch function (discover.FromOCI). We cannot call it in tests
// (no network) but we can verify it is set so the real evaluator isn't silently
// a no-op.
func TestCoreEvaluator_DefaultFetch_IsNotNil(t *testing.T) {
	pol, err := policy.Parse(builtin.Baseline)
	if err != nil {
		t.Fatalf("parse baseline policy: %v", err)
	}
	eval := NewEvaluator(pol, core.TrustRoots{})
	if eval.fetch == nil {
		t.Fatal("NewEvaluator: default fetch must be non-nil")
	}
}
