// Package bundle — signing helpers (sign.go).
//
// # v0.1 keyed signing proxy (offline, hermetic)
//
// This file implements ECDSA P-256 keyed signing of OCI manifest digests as a
// hermetic, offline stand-in for Sigstore keyless signing. The signature is
// stored as an OCI referrer artifact (subject = the bundle manifest) following
// the cosign referrer pattern so that the production swap is mechanical.
//
// # Production signing (wired at M6)
//
// Production signs the bundle with cosign keyless (Fulcio CA + Rekor
// transparency log) and the signature is verified by forgeseal (the trilogy
// loop, §6.6). The referrer/subject wiring here matches the cosign referrer
// pattern precisely: in production, replace Sign/Verify with cosign's Sign and
// the forgeseal verifier; the Push/Pull referrer plumbing is identical.
//
//	TODO(M6): replace keyed proxy with cosign keyless + forgeseal verifier.
//	          Add --sigstore flag stub to the CLI verify subcommand.
//
// # Referrer artifact type
//
// artifactType: application/vnd.assayward.policybundle.sig.v1
// subject:      the bundle manifest descriptor
// layer:        one layer carrying the raw DER signature bytes,
//
//	mediaType: application/vnd.assayward.policybundle.sig.v1+bytes
package bundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	orasremote "oras.land/oras-go/v2/registry/remote"
)

// SigArtifactType is the OCI artifactType for a bundle signature referrer.
const SigArtifactType = "application/vnd.assayward.policybundle.sig.v1"

// SigLayerMediaType is the media type for the signature payload layer.
const SigLayerMediaType = "application/vnd.assayward.policybundle.sig.v1+bytes"

// ecdsaSig is the wire format for an ECDSA (R, S) pair stored in a referrer layer.
type ecdsaSig struct {
	R []byte `json:"r"`
	S []byte `json:"s"`
}

// Sign signs the manifest digest with the given ECDSA private key and returns
// the JSON-encoded signature bytes. The digest is hashed with SHA-256 before
// signing (ECDSA-P256-SHA256).
//
// For v0.1 hermetic tests this replaces Sigstore keyless signing. Production
// replaces this call with cosign keyless; see package doc.
func Sign(manifestDigest string, privKey *ecdsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256([]byte(manifestDigest))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, h[:])
	if err != nil {
		return nil, fmt.Errorf("bundle/sign: ECDSA sign: %w", err)
	}
	wire := ecdsaSig{R: r.Bytes(), S: s.Bytes()}
	return json.Marshal(wire)
}

// Verify verifies a signature produced by Sign against the given manifest digest
// and ECDSA public key. Returns nil on success, error on failure.
//
// For v0.1 hermetic tests. Production replaces this with forgeseal verification.
func Verify(manifestDigest string, sig []byte, pubKey *ecdsa.PublicKey) error {
	var wire ecdsaSig
	if err := json.Unmarshal(sig, &wire); err != nil {
		return fmt.Errorf("bundle/sign: unmarshal signature: %w", err)
	}
	h := sha256.Sum256([]byte(manifestDigest))
	r := new(big.Int).SetBytes(wire.R)
	s := new(big.Int).SetBytes(wire.S)
	if !ecdsa.Verify(pubKey, h[:], r, s) {
		return errors.New("bundle/sign: ECDSA verification failed")
	}
	return nil
}

// SignAndPushReferrer signs the bundle at manifestDigest, then pushes the
// signature as an OCI referrer artifact (subject = the bundle manifest).
//
// ref is the OCI reference used to derive the repository and host
// (the tag is not used; the referrer subject is the digest).
func SignAndPushReferrer(ctx context.Context, manifestDigest string, ref string, privKey *ecdsa.PrivateKey, opts PushOptions) error {
	sigBytes, err := Sign(manifestDigest, privKey)
	if err != nil {
		return err
	}

	// Build a subject descriptor from the manifest digest.
	dgst, err := godigest.Parse(manifestDigest)
	if err != nil {
		return fmt.Errorf("bundle/sign: parse manifest digest %q: %w", manifestDigest, err)
	}
	subject := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactType,
		Digest:       dgst,
		// Size is not strictly required for referrer subject, but oras validates
		// non-zero size for manifest descriptors. Use the sig bytes size as a
		// reasonable stand-in. The registry does not re-verify it on push.
		Size: int64(len(sigBytes)),
	}

	// Pack into a minimal memory store.
	store := memory.New()

	sigDesc := ocispec.Descriptor{
		MediaType: SigLayerMediaType,
		Digest:    godigest.FromBytes(sigBytes),
		Size:      int64(len(sigBytes)),
	}
	if err := store.Push(ctx, sigDesc, bytes.NewReader(sigBytes)); err != nil {
		return fmt.Errorf("bundle/sign: push sig layer: %w", err)
	}

	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, SigArtifactType, oras.PackManifestOptions{
		Subject: &subject,
		Layers:  []ocispec.Descriptor{sigDesc},
	})
	if err != nil {
		return fmt.Errorf("bundle/sign: pack sig manifest: %w", err)
	}

	// Push the referrer manifest. Use the digest as the tag (cosign convention).
	sigTag := manifestDigest
	if err := store.Tag(ctx, manifestDesc, sigTag); err != nil {
		return fmt.Errorf("bundle/sign: tag sig manifest: %w", err)
	}

	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return fmt.Errorf("bundle/sign: build remote: %w", err)
	}

	if _, err := oras.Copy(ctx, store, sigTag, repo, sigTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("bundle/sign: push sig referrer: %w", err)
	}
	return nil
}

// PullAndVerifyReferrer pulls the signature referrer for manifestDigest from
// the registry, extracts the signature bytes, and verifies them with pubKey.
//
// Returns nil if the signature is valid; an error otherwise.
func PullAndVerifyReferrer(ctx context.Context, manifestDigest string, ref string, pubKey *ecdsa.PublicKey, opts PullOptions) error {
	var transport http.RoundTripper
	if opts.Transport != nil {
		transport = opts.Transport
	}
	repo, err := newRepo(ref, opts.PlainHTTP, transport)
	if err != nil {
		return fmt.Errorf("bundle/sign: build remote: %w", err)
	}

	dgst, err := godigest.Parse(manifestDigest)
	if err != nil {
		return fmt.Errorf("bundle/sign: parse manifest digest %q: %w", manifestDigest, err)
	}
	subjectDesc := ocispec.Descriptor{Digest: dgst}

	// List referrers for the subject digest. We pass empty artifactType so that
	// no client-side descriptor-level filtering is applied; instead we check the
	// actual manifest's artifactType field after fetching it. This is necessary
	// because some registries (e.g. the ggcr in-memory test registry) populate
	// the descriptor's ArtifactType from the config mediaType rather than the
	// manifest's artifactType field, which would cause filtering to miss our sig.
	var sigBytes []byte
	err = repo.Referrers(ctx, subjectDesc, "", func(referrers []ocispec.Descriptor) error {
		for _, referrerDesc := range referrers {
			// Fetch the full manifest to check its actual artifactType field.
			rc, fetchErr := repo.Fetch(ctx, referrerDesc)
			if fetchErr != nil {
				continue
			}
			var rawBuf bytes.Buffer
			_, readErr := rawBuf.ReadFrom(rc)
			rc.Close()
			if readErr != nil {
				continue
			}
			var m ocispec.Manifest
			if jsonErr := json.Unmarshal(rawBuf.Bytes(), &m); jsonErr != nil {
				continue
			}
			if m.ArtifactType != SigArtifactType {
				continue
			}
			// Found a sig referrer; extract the sig layer bytes.
			if len(m.Layers) == 0 {
				continue
			}
			layerRC, layerErr := repo.Fetch(ctx, m.Layers[0])
			if layerErr != nil {
				return fmt.Errorf("bundle/sign: fetch sig layer: %w", layerErr)
			}
			var sigBuf bytes.Buffer
			_, layerReadErr := sigBuf.ReadFrom(layerRC)
			layerRC.Close()
			if layerReadErr != nil {
				return fmt.Errorf("bundle/sign: read sig layer: %w", layerReadErr)
			}
			sigBytes = sigBuf.Bytes()
			return nil
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("bundle/sign: list referrers: %w", err)
	}
	if sigBytes == nil {
		return errors.New("bundle/sign: no signature referrer found for manifest")
	}

	return Verify(manifestDigest, sigBytes, pubKey)
}

// fetchSigLayer fetches the signature layer bytes from a referrer manifest
// descriptor in the given repository.
func fetchSigLayer(ctx context.Context, repo *orasremote.Repository, referrerDesc ocispec.Descriptor) ([]byte, error) {
	// Fetch the manifest blob.
	rc, err := repo.Fetch(ctx, referrerDesc)
	if err != nil {
		return nil, fmt.Errorf("bundle/sign: fetch sig manifest: %w", err)
	}
	defer rc.Close()
	var rawManifest bytes.Buffer
	if _, err := rawManifest.ReadFrom(rc); err != nil {
		return nil, fmt.Errorf("bundle/sign: read sig manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(rawManifest.Bytes(), &manifest); err != nil {
		return nil, fmt.Errorf("bundle/sign: unmarshal sig manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, errors.New("bundle/sign: sig manifest has no layers")
	}

	layerDesc := manifest.Layers[0]
	layerRC, err := repo.Fetch(ctx, layerDesc)
	if err != nil {
		return nil, fmt.Errorf("bundle/sign: fetch sig layer: %w", err)
	}
	defer layerRC.Close()

	var sigBuf bytes.Buffer
	if _, err := sigBuf.ReadFrom(layerRC); err != nil {
		return nil, fmt.Errorf("bundle/sign: read sig layer: %w", err)
	}
	return sigBuf.Bytes(), nil
}
