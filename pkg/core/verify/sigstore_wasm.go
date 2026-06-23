//go:build wasm

package verify

import (
	core "github.com/sns45/assayward/pkg/core"
)

// wasmVerifier is the fail-closed stub used when the package is compiled for
// WASM. It always returns an error so that callers that require a valid
// signature will deny-by-default.
type wasmVerifier struct{}

// NewSignatureVerifier returns the fail-closed WASM stub. It is only compiled
// into WASM builds matched by the `wasm` build tag (e.g. GOOS=wasip1 GOARCH=wasm).
// Note: the `wasm` tag matches any WASM target (wasip1/wasm, js/wasm, etc.);
// it does NOT exclusively match GOOS=js GOARCH=wasm.
func NewSignatureVerifier() SignatureVerifier {
	return &wasmVerifier{}
}

// Verify first attempts keyed (self-signed-CA) verification via VerifyKeyedBundle
// (stdlib crypto only, no sigstore-go, safe for WASM). If the bundle carries
// certificate material and roots.SignatureCAs is set, the keyed result is returned.
//
// If the bundle is not a keyed bundle (no cert, or no SignatureCAs configured),
// the call falls through to the fail-closed stub: sigstore-go cannot be compiled
// for WASM (it transitively imports unix-only syscalls via in-toto-golang), so
// callers that require keyless verification MUST treat this as a failure.
func (v *wasmVerifier) Verify(att core.Attestation, img core.ImageRef, roots core.TrustRoots) SignatureResult {
	// Try keyed (self-signed-CA) path first — this is WASM-safe stdlib crypto.
	if result, handled := VerifyKeyedBundle(att, img, roots); handled {
		return result
	}

	// Fall-closed stub: keyless sigstore-go is unavailable in WASM.
	return SignatureResult{
		Available: false, // verifier cannot run in WASM (fail-closed)
		Verified:  false,
		Err:       "signature verification unavailable in wasm runtime",
	}
}
