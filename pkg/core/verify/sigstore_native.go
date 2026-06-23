//go:build !wasm

package verify

import (
	"fmt"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"

	core "github.com/sns45/assayward/pkg/core"
)

// publicGoodTrustedRoot caches the public-good Sigstore trusted root fetched
// via TUF so that repeated verifications within a single process do not each
// incur a TUF round-trip. The cache is process-scoped and best-effort: if a
// concurrent fetch is in progress, callers will serialise on mu.
var (
	publicGoodOnce    sync.Once
	publicGoodRoot    *root.TrustedRoot
	publicGoodRootErr error
)

// fetchPublicGoodRoot returns the public-good Sigstore trusted root, fetching
// it from the public TUF repository on first call and caching the result for
// the lifetime of the process.
func fetchPublicGoodRoot() (*root.TrustedRoot, error) {
	publicGoodOnce.Do(func() {
		publicGoodRoot, publicGoodRootErr = root.FetchTrustedRootWithOptions(tuf.DefaultOptions())
	})
	return publicGoodRoot, publicGoodRootErr
}

// nativeVerifier is the production Sigstore verifier. It requires tlog
// inclusion (Rekor) and certificate chain to Fulcio but is policy-agnostic
// about which identity is allowed; identity extraction is left to the policy
// layer.
type nativeVerifier struct{}

// NewSignatureVerifier returns the native Sigstore-backed verifier. This
// constructor is only compiled into non-WASM builds.
func NewSignatureVerifier() SignatureVerifier {
	return &nativeVerifier{}
}

// Verify checks a Sigstore bundle for the given attestation. The
// implementation:
//  0. First attempts keyed (self-signed-CA) verification via VerifyKeyedBundle.
//     If the bundle carries a certificate WITHOUT tlogEntries and roots.SignatureCAs
//     is set, the keyed verifier handles it (stdlib crypto only) and the result is
//     returned immediately without touching sigstore-go.
//  1. Resolves the trusted root: uses roots.SigstoreTUF when provided; otherwise
//     fetches the Sigstore public-good trusted root via TUF (cached per-process).
//  2. Parses the Sigstore bundle from att.Envelope.
//  3. Verifies the bundle: tlog inclusion + cert chain (Fulcio).
//  4. Extracts OIDC issuer and SAN from the verified leaf certificate.
//
// It is deliberately policy-agnostic: it does NOT enforce which identity
// signed; that enforcement belongs to the policy layer.
func (v *nativeVerifier) Verify(att core.Attestation, img core.ImageRef, roots core.TrustRoots) SignatureResult {
	// Try keyed (self-signed-CA) verification first. If handled, return immediately.
	// VerifyKeyedBundle returns handled=false for keyless bundles (tlogEntries present).
	if result, handled := VerifyKeyedBundle(att, img, roots); handled {
		return result
	}

	// Resolve trusted root: prefer injected SigstoreTUF JSON; fall back to the
	// public-good TUF root fetched at runtime (cached per-process).
	var trustedRoot *root.TrustedRoot
	var err error
	if len(roots.SigstoreTUF) > 0 {
		trustedRoot, err = root.NewTrustedRootFromJSON(roots.SigstoreTUF)
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("parse trusted root: %v", err)}
		}
	} else {
		// No injected root: fetch the public-good trusted root via TUF.
		trustedRoot, err = fetchPublicGoodRoot()
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("fetch public-good TUF root: %v", err)}
		}
	}

	// Parse the Sigstore bundle from att.Envelope bytes.
	var b bundle.Bundle
	if unmarshalErr := b.UnmarshalJSON(att.Envelope); unmarshalErr != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("parse bundle: %v", unmarshalErr)}
	}

	// Build a verifier: require tlog inclusion (Rekor) + an observer
	// timestamp so that the short-lived Fulcio cert can be validated.
	// We do NOT require CTlog entries here because older bundles (v0.1)
	// may lack embedded SCTs.
	sev, err := sgverify.NewVerifier(
		root.TrustedMaterialCollection{trustedRoot},
		sgverify.WithTransparencyLog(1),
		sgverify.WithObserverTimestamps(1),
	)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("create verifier: %v", err)}
	}

	// Use WithoutIdentitiesUnsafe so the verifier only checks the
	// cryptographic chain + tlog inclusion without enforcing a specific SAN.
	// The policy layer (a later task) does the identity match.
	policy := sgverify.NewPolicy(
		sgverify.WithoutArtifactUnsafe(),
		sgverify.WithoutIdentitiesUnsafe(),
	)

	res, err := sev.Verify(&b, policy)
	if err != nil {
		return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("verify: %v", err)}
	}

	// Extract issuer and SAN from the verified certificate summary.
	// Fail closed: a keyless verification that produces no certificate identity
	// is a malformed or unexpected result and must not be treated as success.
	if res.Signature == nil || res.Signature.Certificate == nil {
		return SignatureResult{
			Available: true,
			Verified:  false,
			Err:       "verified bundle missing certificate identity",
		}
	}
	cert := res.Signature.Certificate
	issuer := cert.Extensions.Issuer
	san := cert.SubjectAlternativeName

	// RekorLogged is true when the verifier successfully verified a tlog entry.
	rekorLogged := len(res.VerifiedTimestamps) > 0

	return SignatureResult{
		Available:       true,
		Verified:        true,
		Issuer:          issuer,
		SubjectIdentity: san,
		RekorLogged:     rekorLogged,
	}
}
