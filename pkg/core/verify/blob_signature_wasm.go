//go:build wasm

package verify

import (
	core "github.com/sns45/assayward/pkg/core"
)

// VerifyBlobBundle is the fail-closed WASM stub for the blob (messageSignature)
// verify path. The keyless path requires sigstore-go, which cannot be compiled
// for WASM (it transitively imports unix-only syscalls), so this build cannot
// verify a blob bundle. It returns Available:false so callers that require a
// valid signature deny by default. The `wasm` tag matches any WASM target
// (wasip1/wasm, js/wasm, etc.), mirroring the NewSignatureVerifier split.
func VerifyBlobBundle(_ []byte, _ string, _ core.TrustRoots) SignatureResult {
	return SignatureResult{
		Available: false,
		Verified:  false,
		Err:       "blob signature verification unavailable in this build",
	}
}
