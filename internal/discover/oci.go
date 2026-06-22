// Package discover provides attestation discovery adapters for the assayward CLI.
// This file implements OCI referrers-based discovery (Decision 2, --from-oci path).
// It is a pure adapter: no verification or policy logic lives here.
//
// v0.1 scope and simplifications:
//
//   - A referrer manifest is treated as an attestation source when its
//     ArtifactType (set on the manifest descriptor in the referrers index) is one
//     of the recognised attestation artifact types, OR when a layer inside the
//     manifest has one of the recognised attestation layer media types.
//
//   - Recognised artifactTypes (manifest level):
//     "application/vnd.dev.cosign.attestation.v1"  (cosign DSSE attestation)
//     "application/vnd.sigstore.bundle+json;version=0.3"
//
//   - Recognised layer mediaTypes (blob level):
//     "application/vnd.dsse.envelope.v1+json"       (DSSE envelope)
//     "application/vnd.sigstore.bundle+json;version=0.3"
//
//   - Auto-discovery of referrers from a plain image tag (without @sha256:...)
//     is a future refinement; v0.1 requires an explicit digest in the image ref.
//
//   - The function calls remote.Referrers which supports both the OCI 1.1
//     Referrers API endpoint (/v2/.../referrers/<digest>) and the OCI 1.0
//     fallback tag scheme (sha256-<hex>) transparently.
package discover

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	core "github.com/sns45/assayward/pkg/core"
)

// attestationArtifactTypes is the set of referrer manifest artifactTypes that
// FromOCI recognises as attestation containers (v0.1 list).
var attestationArtifactTypes = map[string]bool{
	"application/vnd.dev.cosign.attestation.v1":        true,
	"application/vnd.sigstore.bundle+json;version=0.3": true,
}

// attestationLayerMediaTypes is the set of layer media types that FromOCI
// extracts as attestation blobs from a referrer manifest (v0.1 list).
var attestationLayerMediaTypes = map[string]bool{
	"application/vnd.dsse.envelope.v1+json":            true,
	"application/vnd.sigstore.bundle+json;version=0.3": true,
}

// options carries the injectable configuration for FromOCI.
type options struct {
	remoteOpts []remote.Option
}

// Option is a functional option for FromOCI.
type Option func(*options)

// WithRemoteOptions injects ggcr remote.Option values into FromOCI. Use this
// in tests to supply a custom transport pointing at an in-memory registry, and
// to override authentication. If not provided, FromOCI uses the default
// keychain (remote.WithAuthFromKeychain(authn.DefaultKeychain)).
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(o *options) {
		o.remoteOpts = append(o.remoteOpts, opts...)
	}
}

// defaultRemoteOpts returns the default remote options used when the caller has
// not provided any via WithRemoteOptions.
func defaultRemoteOpts() []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
}

// FromOCI discovers attestations for imageRef via the OCI referrers API.
//
// imageRef must be a content-addressed reference in the form
// "<registry>/<repository>@sha256:<hex>". Tag-only refs are rejected because
// the OCI referrers API is keyed on the subject digest.
//
// The function lists all referrer manifests for the image's digest, fetches
// each manifest, and extracts layers whose media type matches one of the
// recognised attestation media types (see package doc for the v0.1 list).
// Each such layer blob is returned as a core.Attestation with Envelope set to
// the raw blob bytes. PredicateType is set to the referrer's ArtifactType if
// non-empty, otherwise to the layer's media type string.
//
// No verification is performed; the assayward engine does that.
func FromOCI(imageRef string, opts ...Option) ([]core.Attestation, error) {
	o := &options{}
	for _, fn := range opts {
		fn(o)
	}
	if len(o.remoteOpts) == 0 {
		o.remoteOpts = defaultRemoteOpts()
	}

	// Parse the ref. We require a digest ref for the referrers API.
	ref, err := name.ParseReference(imageRef, name.Insecure)
	if err != nil {
		return nil, fmt.Errorf("discover/oci: parse image ref %q: %w", imageRef, err)
	}

	digestRef, ok := ref.(name.Digest)
	if !ok {
		return nil, fmt.Errorf("discover/oci: image ref %q must include a digest (e.g. @sha256:...) for OCI referrers discovery", imageRef)
	}

	// List referrers for the subject digest.
	idx, err := remote.Referrers(digestRef, o.remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("discover/oci: referrers(%q): %w", imageRef, err)
	}

	idxManifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("discover/oci: read referrers index manifest: %w", err)
	}

	var atts []core.Attestation

	for _, desc := range idxManifest.Manifests {
		artifactType := desc.ArtifactType

		// Fetch the referrer manifest as a v1.Image to access its layers.
		refDigestStr := digestRef.Context().Digest(desc.Digest.String())
		img, err := remote.Image(refDigestStr, o.remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("discover/oci: fetch referrer manifest %s: %w", desc.Digest, err)
		}

		layers, err := img.Layers()
		if err != nil {
			return nil, fmt.Errorf("discover/oci: list layers of referrer %s: %w", desc.Digest, err)
		}

		for _, layer := range layers {
			mt, err := layer.MediaType()
			if err != nil {
				continue
			}
			mtStr := string(mt)

			// Determine if this layer is an attestation blob.
			isAttLayer := attestationLayerMediaTypes[mtStr]
			isAttManifest := attestationArtifactTypes[artifactType]

			if !isAttLayer && !isAttManifest {
				continue
			}

			// Fetch the raw blob bytes. Compressed() returns the as-stored bytes,
			// which for DSSE/Sigstore blobs are raw JSON (not actually gzip-compressed
			// despite the method name -- ggcr uses Compressed() as "what the registry
			// stores / what the content-digest covers").
			rc, err := layer.Compressed()
			if err != nil {
				return nil, fmt.Errorf("discover/oci: read blob for layer in %s: %w", desc.Digest, err)
			}
			blobBytes, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("discover/oci: read blob bytes for layer in %s: %w", desc.Digest, err)
			}

			// Choose the most informative predicate type.
			predicateType := artifactType
			if predicateType == "" {
				predicateType = strings.TrimSuffix(mtStr, ";version=0.3")
				if predicateType == "" {
					predicateType = mtStr
				}
			}

			atts = append(atts, core.Attestation{
				Envelope:      blobBytes,
				PredicateType: predicateType,
			})
		}
	}

	return atts, nil
}
