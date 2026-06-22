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

// Verify always returns Verified=false in the WASM runtime because
// sigstore-go cannot be compiled for WASM (it transitively imports
// unix-only syscalls via in-toto-golang). Callers that require a verified
// signature MUST treat this as a verification failure (fail-closed).
func (v *wasmVerifier) Verify(_ core.Attestation, _ core.ImageRef, _ core.TrustRoots) SignatureResult {
	return SignatureResult{
		Available: false, // verifier cannot run in WASM (fail-closed)
		Verified:  false,
		Err:       "signature verification unavailable in wasm runtime",
	}
}
