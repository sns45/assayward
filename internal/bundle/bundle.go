// Package bundle provides OCI artifact packaging, push, and pull for
// assayward policy bundles. It is a pure CLI/adapter layer: no policy
// evaluation or trust logic lives here.
//
// # Artifact format
//
// A policy bundle is an OCI image manifest (OCI image-spec v1.1) with:
//   - artifactType: application/vnd.assayward.policybundle.v1+json
//   - config blob: JSON-encoded Meta (bundle name, version, policy file list)
//   - one layer per policy file:
//     mediaType: application/vnd.assayward.policy.v1+yaml
//     annotation org.opencontainers.image.title = <policy filename>
//
// This layout follows OCI artifact guidance and is compatible with the cosign
// referrer pattern so that the production signing swap (see sign.go) is
// mechanical.
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	orasremote "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/sns45/assayward/pkg/core/policy"
)

// ArtifactType is the OCI artifactType for an assayward policy bundle manifest.
// Exported so tests and the CLI can reference it without duplication.
const ArtifactType = "application/vnd.assayward.policybundle.v1+json"

// PolicyMediaType is the OCI layer media type for a single policy YAML file.
const PolicyMediaType = "application/vnd.assayward.policy.v1+yaml"

// ConfigMediaType is the OCI config blob media type carrying bundle metadata.
const ConfigMediaType = "application/vnd.assayward.policybundle.config.v1+json"

// Meta is the bundle-level metadata stored in the OCI config blob.
type Meta struct {
	BundleName  string   `json:"bundleName"`
	Version     string   `json:"version"`
	PolicyFiles []string `json:"policyFiles"`
}

// PushOptions carries transport configuration for Push and SignAndPushReferrer.
type PushOptions struct {
	// PlainHTTP signals the remote repository should use HTTP (not HTTPS).
	PlainHTTP bool
	// Transport is the http.RoundTripper to use. When nil, the default oras
	// auth.DefaultClient is used. In tests, inject the httptest.Server transport.
	Transport http.RoundTripper
	// RemoteOpts is retained for compatibility with test helpers but is NOT
	// used internally; use Transport instead.
	RemoteOpts interface{}
}

// PullOptions carries transport configuration for Pull and PullAndVerifyReferrer.
type PullOptions struct {
	PlainHTTP bool
	Transport http.RoundTripper
	// RemoteOpts is retained for compatibility with test helpers but is NOT
	// used internally; use Transport instead.
	RemoteOpts interface{}
}

// Pack builds an in-memory ORAS content store containing all layers, the config
// blob, and the manifest for the given policy files.
//
// Returns the populated store and the manifest descriptor (which carries the
// digest and artifactType). The store is ready to pass to Push.
func Pack(ctx context.Context, policies map[string][]byte, meta Meta) (*memory.Store, ocispec.Descriptor, error) {
	store := memory.New()

	// Build layers: one per policy file, in sorted order so that identical
	// policy content always yields an identical manifest digest (deterministic).
	sortedNames := make([]string, 0, len(policies))
	for name := range policies {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	layers := make([]ocispec.Descriptor, 0, len(policies))
	fileNames := make([]string, 0, len(policies))

	for _, name := range sortedNames {
		rawYAML := policies[name]
		desc := ocispec.Descriptor{
			MediaType: PolicyMediaType,
			Digest:    godigest.FromBytes(rawYAML),
			Size:      int64(len(rawYAML)),
			Annotations: map[string]string{
				ocispec.AnnotationTitle: name,
			},
		}
		if err := store.Push(ctx, desc, bytes.NewReader(rawYAML)); err != nil {
			return nil, ocispec.Descriptor{}, fmt.Errorf("bundle: push policy layer %q: %w", name, err)
		}
		layers = append(layers, desc)
		fileNames = append(fileNames, name)
	}

	// Build config blob with bundle metadata.
	meta.PolicyFiles = fileNames
	configBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("bundle: marshal config: %w", err)
	}
	configDesc := ocispec.Descriptor{
		MediaType: ConfigMediaType,
		Digest:    godigest.FromBytes(configBytes),
		Size:      int64(len(configBytes)),
	}
	if err := store.Push(ctx, configDesc, bytes.NewReader(configBytes)); err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("bundle: push config blob: %w", err)
	}

	// Pack the manifest using OCI image-spec v1.1.
	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
		Layers:           layers,
		ConfigDescriptor: &configDesc,
	})
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("bundle: pack manifest: %w", err)
	}

	return store, manifestDesc, nil
}

// ResolveDigest resolves the manifest digest for the given OCI reference
// directly from the registry (without downloading layers). This binds
// signatures to the actual stored manifest rather than a local repack.
func ResolveDigest(ctx context.Context, ref string, opts PullOptions) (ocispec.Descriptor, error) {
	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: resolve: build remote: %w", err)
	}
	desc, err := repo.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("bundle: resolve %q: %w", ref, err)
	}
	return desc, nil
}

// Push copies the packed bundle from store to the OCI registry at ref.
// Returns the manifest digest string (e.g. "sha256:abc...").
func Push(ctx context.Context, store *memory.Store, manifestDesc ocispec.Descriptor, ref string, opts PushOptions) (string, error) {
	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return "", fmt.Errorf("bundle: push: build remote: %w", err)
	}

	tag := tagFromRef(ref)

	// Tag the manifest in the local store so oras.Copy can resolve it by tag.
	if err := store.Tag(ctx, manifestDesc, tag); err != nil {
		return "", fmt.Errorf("bundle: push: tag local store: %w", err)
	}

	if _, err := oras.Copy(ctx, store, tag, repo, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("bundle: push to %q: %w", ref, err)
	}

	return manifestDesc.Digest.String(), nil
}

// Pull downloads the bundle from ref, validates each policy layer with
// policy.Parse, and returns the policy map (filename -> YAML bytes) and
// the bundle metadata.
func Pull(ctx context.Context, ref string, opts PullOptions) (map[string][]byte, Meta, error) {
	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull: build remote: %w", err)
	}

	// Copy into an in-memory store.
	dst := memory.New()
	tag := tagFromRef(ref)

	manifestDesc, err := oras.Copy(ctx, repo, tag, dst, tag, oras.DefaultCopyOptions)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull from %q: %w", ref, err)
	}

	// Fetch and parse the manifest.
	manifestBytes, err := fetchBlob(ctx, dst, manifestDesc)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull: fetch manifest blob: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull: unmarshal manifest: %w", err)
	}

	// Decode the config blob.
	configBytes, err := fetchBlob(ctx, dst, manifest.Config)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull: fetch config blob: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(configBytes, &meta); err != nil {
		return nil, Meta{}, fmt.Errorf("bundle: pull: unmarshal config: %w", err)
	}

	// Extract each policy layer.
	policies := make(map[string][]byte, len(manifest.Layers))
	for _, layerDesc := range manifest.Layers {
		name := layerDesc.Annotations[ocispec.AnnotationTitle]
		if name == "" {
			continue
		}
		raw, err := fetchBlob(ctx, dst, layerDesc)
		if err != nil {
			return nil, Meta{}, fmt.Errorf("bundle: pull: fetch layer %q: %w", name, err)
		}
		// Validate on pull: every policy must parse successfully.
		if _, err := policy.Parse(raw); err != nil {
			return nil, Meta{}, fmt.Errorf("bundle: pull: policy.Parse(%q): %w", name, err)
		}
		policies[name] = raw
	}

	return policies, meta, nil
}

// ---------------------------------------------------------------------------
// internal helpers
// ---------------------------------------------------------------------------

// newRepo creates an oras remote.Repository for the given ref.
// transport may be nil to use the oras default.
func newRepo(ref string, plainHTTP bool, transport http.RoundTripper) (*orasremote.Repository, error) {
	repo, err := orasremote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parse ref %q: %w", ref, err)
	}
	repo.PlainHTTP = plainHTTP
	if transport != nil {
		repo.Client = &auth.Client{
			Client: &http.Client{Transport: transport},
		}
	}
	return repo, nil
}

// fetchBlob fetches and returns the raw bytes for a descriptor from a
// memory.Store.
func fetchBlob(ctx context.Context, store *memory.Store, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := store.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(rc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// tagFromRef extracts the tag portion of an OCI reference string.
// For "host:port/repo:tag" it returns "tag". Falls back to "latest".
func tagFromRef(ref string) string {
	// Scan backwards for the last colon that has a slash before it.
	for i := len(ref) - 1; i >= 0; i-- {
		if ref[i] == ':' {
			hasSlash := false
			for j := 0; j < i; j++ {
				if ref[j] == '/' {
					hasSlash = true
					break
				}
			}
			if hasSlash {
				return ref[i+1:]
			}
		}
	}
	return "latest"
}
