package engine_test

import (
	"testing"
	"time"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
)

func TestEvaluateEmpty(t *testing.T) {
	clk := core.FixedClock{T: time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)}

	ev := core.Evidence{
		Artifact: core.ImageRef{
			Name:   "registry.example.com/myapp:latest",
			Digest: "sha256:abc123",
		}.AsArtifact(),
		Attestations: []core.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v1",
				Envelope:      []byte(`{}`),
			},
		},
		Identity: &core.WorkloadIdentity{
			SPIFFEID: "spiffe://example.org/workload/myapp",
		},
		FetchedAt: clk.Now(),
	}

	pol := policy.Policy{
		Name:    "p",
		Version: "v1",
		Mode:    policy.ModeEnforce,
	}

	roots := core.TrustRoots{}

	d := engine.Evaluate(ev, pol, roots, clk)

	if d.Result != core.ResultAllow {
		t.Errorf("expected ResultAllow, got %q", d.Result)
	}

	if d.Policy != "p@v1" {
		t.Errorf("expected policy %q, got %q", "p@v1", d.Policy)
	}

	if !d.DecidedAt.Equal(clk.Now()) {
		t.Errorf("expected DecidedAt %v, got %v", clk.Now(), d.DecidedAt)
	}

	// Reasons must be non-nil (marshals to [] not null).
	if d.Reasons == nil {
		t.Error("Reasons must be non-nil (should marshal as [] not null)")
	}
	if len(d.Reasons) != 0 {
		t.Errorf("expected 0 reasons, got %d", len(d.Reasons))
	}

	// EvidenceSummary must reflect the evidence.
	if d.Evidence.Artifact.Name != ev.Artifact.Name {
		t.Errorf("evidence artifact name: expected %q, got %q", ev.Artifact.Name, d.Evidence.Artifact.Name)
	}
	if d.Evidence.Artifact.Digest["sha256"] != ev.Artifact.Digest["sha256"] {
		t.Errorf("evidence artifact digest: expected %q, got %q", ev.Artifact.Digest["sha256"], d.Evidence.Artifact.Digest["sha256"])
	}
	if len(d.Evidence.AttestationTypes) != 1 {
		t.Errorf("expected 1 attestation type, got %d", len(d.Evidence.AttestationTypes))
	} else if d.Evidence.AttestationTypes[0] != "https://slsa.dev/provenance/v1" {
		t.Errorf("unexpected attestation type %q", d.Evidence.AttestationTypes[0])
	}
	if !d.Evidence.IdentityPresent {
		t.Error("expected IdentityPresent true")
	}
	if d.Evidence.SPIFFEID != "spiffe://example.org/workload/myapp" {
		t.Errorf("expected SPIFFEID %q, got %q", "spiffe://example.org/workload/myapp", d.Evidence.SPIFFEID)
	}
}
