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

// liveTrustedRootConstructor is the function used to create a new
// *root.LiveTrustedRoot. It is a package-level variable so tests can
// substitute a fake that simulates transient failures without hitting the
// network.
var liveTrustedRootConstructor = func(opts *tuf.Options) (*root.LiveTrustedRoot, error) {
	return root.NewLiveTrustedRoot(opts)
}

// publicGoodMu guards publicGoodLive. We use an explicit mutex (rather than
// sync.Once) so that a transient TUF error on the first call is NOT cached
// permanently. On every call where publicGoodLive is nil the constructor is
// retried; once it succeeds the *LiveTrustedRoot is cached for the lifetime
// of the process and self-refreshes every 24 h internally.
var (
	publicGoodMu   sync.Mutex
	publicGoodLive *root.LiveTrustedRoot
)

// fetchPublicGoodLiveRoot returns the process-scoped live trusted root,
// creating it on first call (or retrying if previous attempts failed).
// A *root.LiveTrustedRoot self-refreshes its trust material in the background
// on a 24-hour period so long-running processes (the webhook) always see
// current keys and intermediate CAs without a restart.
func fetchPublicGoodLiveRoot() (*root.LiveTrustedRoot, error) {
	publicGoodMu.Lock()
	defer publicGoodMu.Unlock()

	if publicGoodLive != nil {
		return publicGoodLive, nil
	}

	ltr, err := liveTrustedRootConstructor(tuf.DefaultOptions())
	if err != nil {
		// Do NOT cache the error: next call will retry.
		return nil, fmt.Errorf("init live trusted root: %w", err)
	}

	publicGoodLive = ltr
	return publicGoodLive, nil
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
//
//  0. First attempts keyed (self-signed-CA) verification via VerifyKeyedBundle.
//     If the bundle carries a certificate WITHOUT tlogEntries and roots.SignatureCAs
//     is set, the keyed verifier handles it (stdlib crypto only) and the result is
//     returned immediately without touching sigstore-go.
//  1. Resolves the trusted root: uses roots.SigstoreTUF when provided; otherwise
//     obtains the Sigstore public-good live trusted root (created once, retried on
//     transient error, self-refreshing every 24 h for long-running processes).
//  2. Parses the Sigstore bundle from att.Envelope.
//  3. Verifies the bundle: tlog inclusion + cert chain (Fulcio).
//  4. Extracts OIDC issuer and SAN from the verified leaf certificate.
//
// It is deliberately policy-agnostic: it does NOT enforce which identity
// signed; that enforcement belongs to the policy layer.
func (v *nativeVerifier) Verify(att core.Attestation, art core.ArtifactRef, roots core.TrustRoots) SignatureResult {
	// Try keyed (self-signed-CA) verification first. If handled, return immediately.
	// VerifyKeyedBundle returns handled=false for keyless bundles (tlogEntries present).
	if result, handled := VerifyKeyedBundle(att, art, roots); handled {
		return result
	}

	// Resolve trusted root: prefer injected SigstoreTUF JSON; fall back to the
	// public-good live trusted root (auto-refreshing, retry-on-failure).
	var trustedMaterial root.TrustedMaterial
	var err error
	if len(roots.SigstoreTUF) > 0 {
		var tr *root.TrustedRoot
		tr, err = root.NewTrustedRootFromJSON(roots.SigstoreTUF)
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("parse trusted root: %v", err)}
		}
		trustedMaterial = tr
	} else {
		// No injected root: obtain the public-good live trusted root.
		// A failed init is NOT cached; the next Verify call will retry.
		var ltr *root.LiveTrustedRoot
		ltr, err = fetchPublicGoodLiveRoot()
		if err != nil {
			return SignatureResult{Available: true, Verified: false, Err: fmt.Sprintf("fetch public-good TUF root: %v", err)}
		}
		trustedMaterial = ltr
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
		root.TrustedMaterialCollection{trustedMaterial},
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
