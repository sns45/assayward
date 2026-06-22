package bundle_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/sns45/assayward/internal/bundle"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

// newTestRegistry starts an in-memory OCI registry with referrers support.
// Returns the server and the default transport (tests use plain HTTP).
func newTestRegistry(t *testing.T) (*httptest.Server, http.RoundTripper) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	return srv, http.DefaultTransport
}

// TestPackAndPull_BuiltinPoliciesRoundTrip packs the 3 built-in policies,
// pushes them to an in-memory registry, pulls them back, and asserts:
//  1. The byte content round-trips exactly.
//  2. Each pulled policy file can be parsed by policy.Parse without error.
func TestPackAndPull_BuiltinPoliciesRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv, transport := newTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := builtin.All()
	meta := bundle.Meta{
		BundleName: "test-bundle",
		Version:    "v0.1.0",
	}

	store, manifestDesc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	ref := fmt.Sprintf("%s/testbundle:v0.1.0", host)
	digest, err := bundle.Push(ctx, store, manifestDesc, ref, bundle.PushOptions{
		PlainHTTP: true,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if digest == "" {
		t.Fatal("Push() returned empty digest")
	}

	pulledPolicies, pulledMeta, err := bundle.Pull(ctx, ref, bundle.PullOptions{
		PlainHTTP: true,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Pull() error: %v", err)
	}

	// Assert metadata round-trips.
	if pulledMeta.BundleName != meta.BundleName {
		t.Errorf("Meta.BundleName: got %q, want %q", pulledMeta.BundleName, meta.BundleName)
	}
	if pulledMeta.Version != meta.Version {
		t.Errorf("Meta.Version: got %q, want %q", pulledMeta.Version, meta.Version)
	}

	// Assert all 3 policies are present and byte-identical.
	if len(pulledPolicies) != 3 {
		t.Fatalf("Pull() returned %d policies, want 3", len(pulledPolicies))
	}
	for name, wantBytes := range policies {
		gotBytes, ok := pulledPolicies[name]
		if !ok {
			t.Errorf("policy %q missing from pulled bundle", name)
			continue
		}
		if string(gotBytes) != string(wantBytes) {
			t.Errorf("policy %q bytes differ:\ngot:\n%s\nwant:\n%s", name, gotBytes, wantBytes)
		}
		// Each pulled policy must parse successfully.
		if _, err := policy.Parse(gotBytes); err != nil {
			t.Errorf("policy.Parse(%q) on pulled bytes: %v", name, err)
		}
	}
}

// TestPack_ArtifactType verifies that the manifest descriptor returned by Pack
// carries the correct artifact type.
func TestPack_ArtifactType(t *testing.T) {
	ctx := context.Background()
	policies := map[string][]byte{
		"baseline": builtin.Baseline,
	}
	meta := bundle.Meta{
		BundleName: "mytest",
		Version:    "v1.2.3",
	}

	_, desc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	if desc.ArtifactType != bundle.ArtifactType {
		t.Errorf("manifest ArtifactType: got %q, want %q", desc.ArtifactType, bundle.ArtifactType)
	}
}

// TestPack_Deterministic verifies that packing the same policies twice yields
// identical manifest digests. This ensures that Go map non-determinism does not
// cause divergent digests between pack calls (and therefore between sign and
// verify when both repack locally).
func TestPack_Deterministic(t *testing.T) {
	ctx := context.Background()
	policies := builtin.All()
	meta := bundle.Meta{BundleName: "det-test", Version: "v1.0.0"}

	_, desc1, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() first call error: %v", err)
	}
	_, desc2, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() second call error: %v", err)
	}

	if desc1.Digest != desc2.Digest {
		t.Errorf("Pack() is non-deterministic: first=%s second=%s", desc1.Digest, desc2.Digest)
	}
}

// TestPush_DigestPrefix verifies the returned digest starts with sha256:.
func TestPush_DigestPrefix(t *testing.T) {
	ctx := context.Background()
	srv, transport := newTestRegistry(t)
	host := srv.Listener.Addr().String()

	policies := map[string][]byte{"baseline": builtin.Baseline}
	meta := bundle.Meta{BundleName: "digest-test", Version: "v0.1.0"}

	store, desc, err := bundle.Pack(ctx, policies, meta)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	ref := fmt.Sprintf("%s/digesttest:v0.1.0", host)
	got, err := bundle.Push(ctx, store, desc, ref, bundle.PushOptions{
		PlainHTTP: true,
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if len(got) < 7 || got[:7] != "sha256:" {
		t.Errorf("Push() digest = %q, want sha256:...", got)
	}
}
