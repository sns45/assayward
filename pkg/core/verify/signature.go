package verify

import (
	core "github.com/sns45/assayward/pkg/core"
)

// SignatureResult carries the outcome of a signature verification attempt.
type SignatureResult struct {
	// Available is true when the verifier actually ran (i.e. the native Sigstore
	// verifier was active). It is false in WASM stub environments where the
	// verifier could not be compiled in. When Available is false, Verified is
	// always false.
	Available       bool
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
	Verify(att core.Attestation, art core.ArtifactRef, roots core.TrustRoots) SignatureResult
}
