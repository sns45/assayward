package engine_test

import (
	"encoding/base64"
	"strings"
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

// TestEngineFoldsBlobSignatureIntoSigView pins the Step-1 blob-signature fold:
// an Evidence with no verifiable attestations but a structurally-valid
// messageSignature bundle (keyed path, digest mismatch so it fails closed
// offline with no network access) must have its Available/Verified state
// folded into sigView. Under a policy with signature.required=true this
// yields SIGNATURE_REQUIRED_MISSING (verifier ran, no valid signature found)
// rather than SIGNATURE_VERIFICATION_UNAVAILABLE (verifier never ran) — the
// concrete, observable difference the fold must make — and denies either way.
func TestEngineFoldsBlobSignatureIntoSigView(t *testing.T) {
	clk := core.FixedClock{T: time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)}

	pol := policy.Policy{
		Name:    "p",
		Version: "v1",
		Mode:    policy.ModeEnforce,
		Signature: policy.SignatureRule{
			Required: true,
		},
	}

	// A keyed messageSignature bundle whose messageDigest deliberately does
	// NOT match the artifact digest below. roots.SignatureCAs is set so the
	// bundle routes to the offline keyed path (no network access); the digest
	// mismatch is rejected before any certificate/signature work, so the
	// result is deterministically Available:true, Verified:false.
	wrongDigest := base64.StdEncoding.EncodeToString(make([]byte, 32))
	bundle := []byte(`{"verificationMaterial":{"certificate":{"rawBytes":"AAAA"}},` +
		`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + wrongDigest + `"},"signature":"AAAA"}}`)
	roots := core.TrustRoots{SignatureCAs: []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")}

	artifactDigest := "sha256:" + strings.Repeat("ab", 32)
	baseEv := core.Evidence{
		SchemaVersion: core.EvidenceSchemaVersion,
		Artifact: core.ImageRef{
			Name:   "registry.example.com/blobapp:latest",
			Digest: artifactDigest,
		}.AsArtifact(),
		FetchedAt: clk.Now(),
	}

	// Case 1: no BlobSignature at all — sanity/no-regression check. The
	// verifier never ran (no attestations, no blob), so the decision must be
	// the pre-existing SIGNATURE_VERIFICATION_UNAVAILABLE deny.
	noBlobEv := baseEv
	noBlobEv.BlobSignature = nil
	dNoBlob := engine.Evaluate(noBlobEv, pol, roots, clk)
	if dNoBlob.Result != core.ResultDeny {
		t.Fatalf("no-blob baseline: expected ResultDeny, got %q", dNoBlob.Result)
	}
	if !hasReasonCode(dNoBlob.Reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE") {
		t.Fatalf("no-blob baseline: expected SIGNATURE_VERIFICATION_UNAVAILABLE, got %+v", dNoBlob.Reasons)
	}

	// Case 2: a BlobSignature present but unverified — the fold must surface
	// Available:true so the policy evaluates the individual sub-check and
	// emits SIGNATURE_REQUIRED_MISSING instead, still denying.
	withBlobEv := baseEv
	withBlobEv.BlobSignature = &core.BlobSignature{Bundle: bundle, ArtifactDigest: artifactDigest}
	dWithBlob := engine.Evaluate(withBlobEv, pol, roots, clk)
	if dWithBlob.Result != core.ResultDeny {
		t.Fatalf("with-blob: expected ResultDeny (unverified blob signature), got %q", dWithBlob.Result)
	}
	if !hasReasonCode(dWithBlob.Reasons, "SIGNATURE_REQUIRED_MISSING") {
		t.Fatalf("with-blob: expected SIGNATURE_REQUIRED_MISSING (fold surfaced Available:true), got %+v", dWithBlob.Reasons)
	}
	if hasReasonCode(dWithBlob.Reasons, "SIGNATURE_VERIFICATION_UNAVAILABLE") {
		t.Fatalf("with-blob: must not still report SIGNATURE_VERIFICATION_UNAVAILABLE once the blob fold ran: %+v", dWithBlob.Reasons)
	}
}

func hasReasonCode(reasons []core.Reason, code string) bool {
	for _, r := range reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}
