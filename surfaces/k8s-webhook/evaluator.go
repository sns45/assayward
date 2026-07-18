package webhook

// Decision 4: identity is OPTIONAL in the webhook evaluator. When identity is
// nil, the evaluator operates in "attestation-only reduced mode": workload
// identity is not resolved or verified, and only attestation-based policy rules
// are evaluated. This is a deliberate design choice: svidmint is not required
// for the webhook to function. Operators who want identity-aware enforcement can
// inject an identity resolver via the identity field or via a future CLI flag.

import (
	"context"
	"fmt"
	"time"

	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"

	"github.com/sns45/assayward/internal/discover"
)

// coreEvaluator implements Evaluator using the real engine.Evaluate and the
// discover package for attestation fetching. All fields are injectable for
// deterministic unit tests.
type coreEvaluator struct {
	pol   policy.Policy
	roots core.TrustRoots

	// now returns the current time. Defaults to time.Now in production; inject
	// a fixed clock in tests.
	now func() time.Time

	// fetch discovers attestations for an image. Defaults to discover.FromOCI.
	// Injectable in tests so no network is required.
	fetch func(ctx context.Context, img core.ImageRef) ([]core.Attestation, error)

	// identity resolves a workload identity for an image. May be nil (Decision 4:
	// attestation-only reduced mode). When nil, no identity is resolved and the
	// engine runs without identity evidence.
	identity func(ctx context.Context, img core.ImageRef) (*core.WorkloadIdentity, error)
}

// NewEvaluator returns a coreEvaluator with production defaults:
//   - now: time.Now
//   - fetch: discover.FromOCI (uses the OCI referrers API)
//   - identity: nil (attestation-only reduced mode, Decision 4)
func NewEvaluator(pol policy.Policy, roots core.TrustRoots) *coreEvaluator {
	return &coreEvaluator{
		pol:   pol,
		roots: roots,
		now:   time.Now,
		fetch: func(ctx context.Context, img core.ImageRef) ([]core.Attestation, error) {
			ref := img.Name
			if img.Digest != "" {
				ref = img.Name + "@" + img.Digest
			}
			return discover.FromOCI(ref)
		},
		identity: nil, // Decision 4: reduced mode by default; no svidmint required.
	}
}

// Evaluate fetches attestations for img, optionally resolves a workload
// identity, builds core.Evidence, and calls engine.Evaluate.
//
// A fetch error is returned directly so the webhook handler can fail-closed
// under enforce mode.
//
// When identity is nil (reduced mode) the Evidence.Identity field is left nil
// and the engine skips identity verification.
func (e *coreEvaluator) Evaluate(ctx context.Context, img core.ImageRef) (core.Decision, error) {
	atts, err := e.fetch(ctx, img)
	if err != nil {
		return core.Decision{}, fmt.Errorf("evaluator: fetch attestations for %q: %w", img.Name, err)
	}

	var id *core.WorkloadIdentity
	if e.identity != nil {
		resolved, idErr := e.identity(ctx, img)
		if idErr != nil {
			return core.Decision{}, fmt.Errorf("evaluator: resolve identity for %q: %w", img.Name, idErr)
		}
		id = resolved
	}

	t := e.now()
	ev := core.Evidence{
		Artifact:      img.AsArtifact(),
		Attestations:  atts,
		Identity:      id,
		SchemaVersion: core.EvidenceSchemaVersion,
		FetchedAt:     t,
	}

	dec := engine.Evaluate(ev, e.pol, e.roots, core.FixedClock{T: t})
	return dec, nil
}
