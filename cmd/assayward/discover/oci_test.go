package discover_test

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/sns45/assayward/cmd/assayward/discover"
)

// attestationArtifactType is the cosign/sigstore artifact type used on referrer
// manifests to tag them as attestations. FromOCI recognises this value.
const attestationArtifactType = "application/vnd.dev.cosign.attestation.v1"

// attestationLayerMediaType is the layer media type for DSSE envelope blobs.
// FromOCI treats layers with this media type as attestation payloads.
const attestationLayerMediaType = "application/vnd.dsse.envelope.v1+json"

// newTestRegistry starts an in-memory OCI registry with OCI referrers API
// support and returns the httptest.Server. The caller must call srv.Close().
func newTestRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	return srv
}

// pushBaseImage pushes a minimal scratch-based image to host/repo:base and
// returns a name.Digest pointing at its content-addressed ref.
func pushBaseImage(t *testing.T, host string, opts ...remote.Option) name.Digest {
	t.Helper()

	ref, err := name.ParseReference(fmt.Sprintf("%s/repo:base", host), name.Insecure)
	if err != nil {
		t.Fatalf("pushBaseImage: parse ref: %v", err)
	}

	layer := static.NewLayer([]byte("base-layer-content"), types.OCIUncompressedLayer)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("pushBaseImage: build image: %v", err)
	}

	if err := remote.Write(ref, img, opts...); err != nil {
		t.Fatalf("pushBaseImage: push: %v", err)
	}

	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("pushBaseImage: digest: %v", err)
	}
	return ref.Context().Digest(digest.String())
}

// pushAttestationReferrer pushes an OCI manifest with subjectDigest as its
// subject. The manifest carries one layer (envelopeBytes) with the DSSE
// envelope media type and uses attestationArtifactType as the manifest
// artifactType, mimicking a cosign attestation referrer.
func pushAttestationReferrer(t *testing.T, host string, subjectDigest name.Digest, envelopeBytes []byte, opts ...remote.Option) v1.Hash {
	t.Helper()

	layer := static.NewLayer(envelopeBytes, types.MediaType(attestationLayerMediaType))

	subjectHash, err := v1.NewHash(subjectDigest.DigestStr())
	if err != nil {
		t.Fatalf("pushAttestationReferrer: parse subject hash: %v", err)
	}
	subjectDesc := v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    subjectHash,
		Size:      0,
	}

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("pushAttestationReferrer: build image: %v", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(attestationArtifactType))
	img = mutate.Subject(img, subjectDesc).(v1.Image)

	referrerRef, err := name.ParseReference(fmt.Sprintf("%s/repo:att", host), name.Insecure)
	if err != nil {
		t.Fatalf("pushAttestationReferrer: parse ref: %v", err)
	}
	if err := remote.Write(referrerRef, img, opts...); err != nil {
		t.Fatalf("pushAttestationReferrer: push: %v", err)
	}

	d, err := img.Digest()
	if err != nil {
		t.Fatalf("pushAttestationReferrer: digest: %v", err)
	}
	return d
}

// TestFromOCI_FullRoundTrip exercises the complete OCI referrers path:
//  1. Push a base image to an in-memory registry.
//  2. Push an attestation referrer manifest pointing at the base image.
//  3. Call FromOCI with the base image digest ref.
//  4. Assert that the returned Attestation contains the expected envelope bytes.
//
// No network I/O occurs: the httptest.Server handles all registry traffic.
func TestFromOCI_FullRoundTrip(t *testing.T) {
	srv := newTestRegistry(t)
	host := srv.Listener.Addr().String()

	remoteOpts := []remote.Option{
		remote.WithAuth(authn.Anonymous),
	}

	// Push a base image.
	baseDigestRef := pushBaseImage(t, host, remoteOpts...)

	// Our synthetic DSSE envelope.
	wantEnvelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"dGVzdA==","signatures":[]}`)

	// Push an attestation referrer manifest that points at the base image.
	pushAttestationReferrer(t, host, baseDigestRef, wantEnvelope, remoteOpts...)

	// imageRef as expected by FromOCI: "<host>/repo@<digest>" with insecure scheme.
	imageRef := fmt.Sprintf("%s/repo@%s", host, baseDigestRef.DigestStr())

	atts, err := discover.FromOCI(imageRef, discover.WithRemoteOptions(remoteOpts...))
	if err != nil {
		t.Fatalf("FromOCI(%q) error: %v", imageRef, err)
	}

	if len(atts) == 0 {
		t.Fatalf("FromOCI returned 0 attestations, want at least 1")
	}

	// Assert the envelope is present in the returned attestations.
	var found bool
	for _, att := range atts {
		if bytes.Equal(att.Envelope, wantEnvelope) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("FromOCI did not return the expected envelope bytes")
		for i, att := range atts {
			t.Logf("  atts[%d].Envelope = %s", i, att.Envelope)
		}
	}
}

// TestFromOCI_UnparseableRef verifies that a syntactically invalid image
// reference returns an error immediately (no panic).
func TestFromOCI_UnparseableRef(t *testing.T) {
	_, err := discover.FromOCI("::not-valid:://@@")
	if err == nil {
		t.Error("FromOCI with unparseable ref returned nil, want an error")
	}
}

// TestFromOCI_NonDigestRef verifies that a tag-only ref returns an error
// explaining that a digest is required. The OCI referrers API is keyed on
// the subject digest and cannot operate on mutable tags.
func TestFromOCI_NonDigestRef(t *testing.T) {
	_, err := discover.FromOCI("registry.example.com/repo:latest-but-no-digest")
	if err == nil {
		t.Error("FromOCI with tag-only ref returned nil, want an error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "digest") {
		t.Errorf("expected 'digest' in error message, got: %v", err)
	}
}
