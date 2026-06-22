package verify

import (
	core "github.com/sns45/assayward/pkg/core"
)

// SignatureResult carries the outcome of a signature verification attempt.
type SignatureResult struct {
	Verified        bool
	Issuer          string
	SubjectIdentity string
	RekorLogged     bool
	Err             string
}

// SignatureVerifier checks a Sigstore bundle for one attestation against
// injected trust roots. Concrete implementations live in later tasks
// (sigstore_native.go, sigstore_wasm.go, etc.).
type SignatureVerifier interface {
	// Verify checks a Sigstore bundle for one attestation against injected roots.
	Verify(att core.Attestation, img core.ImageRef, roots core.TrustRoots) SignatureResult
}
