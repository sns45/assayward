//go:build !wasm

package verify

// sigstore_live_root_test.go tests the retry-on-failure semantics of
// fetchPublicGoodLiveRoot using an injectable constructor. No network access
// is performed: the fake constructor simulates transient TUF failures.

import (
	"errors"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// resetPublicGoodState clears the process-level cache so each test sub-case
// starts from scratch. Must only be called from tests.
func resetPublicGoodState() {
	publicGoodMu.Lock()
	defer publicGoodMu.Unlock()
	publicGoodLive = nil
}

// TestFetchPublicGoodLiveRoot_RetryOnFailure verifies that a transient TUF
// error on the first call does NOT permanently poison the cache: a subsequent
// call with a working constructor must succeed and return a non-nil root.
//
// The test does NOT hit the network. It injects a fake constructor that fails
// on the first invocation then succeeds on subsequent ones.
func TestFetchPublicGoodLiveRoot_RetryOnFailure(t *testing.T) {
	// Save and restore the real constructor and cache so this test is isolated.
	origConstructor := liveTrustedRootConstructor
	t.Cleanup(func() {
		liveTrustedRootConstructor = origConstructor
		resetPublicGoodState()
	})
	resetPublicGoodState()

	callCount := 0
	transientErr := errors.New("simulated transient TUF network error")

	// Fake constructor: fails on call 1, returns a stub on call 2+.
	liveTrustedRootConstructor = func(_ *tuf.Options) (*root.LiveTrustedRoot, error) {
		callCount++
		if callCount == 1 {
			return nil, transientErr
		}
		// Return a zero-value LiveTrustedRoot. For the purpose of this test we
		// only need a non-nil pointer: the retry semantics do not depend on the
		// root's contents.
		return &root.LiveTrustedRoot{}, nil
	}

	// First call: constructor fails; error must be returned, cache must remain nil.
	ltr, err := fetchPublicGoodLiveRoot()
	if err == nil {
		t.Fatal("expected error on first call (transient failure), got nil")
	}
	if ltr != nil {
		t.Fatal("expected nil LiveTrustedRoot on failure, got non-nil")
	}
	if callCount != 1 {
		t.Fatalf("expected constructor to be called once, got %d", callCount)
	}

	// Confirm the cache is still nil after the failure.
	publicGoodMu.Lock()
	stillNil := publicGoodLive == nil
	publicGoodMu.Unlock()
	if !stillNil {
		t.Fatal("publicGoodLive must remain nil after a failed init (failure must not be cached)")
	}

	// Second call: constructor succeeds; must return a non-nil root and cache it.
	ltr, err = fetchPublicGoodLiveRoot()
	if err != nil {
		t.Fatalf("expected success on second call (constructor now healthy), got: %v", err)
	}
	if ltr == nil {
		t.Fatal("expected non-nil LiveTrustedRoot on second call, got nil")
	}
	if callCount != 2 {
		t.Fatalf("expected constructor to be called twice total, got %d", callCount)
	}

	// Third call: constructor must NOT be called again; cached value is returned.
	ltr2, err := fetchPublicGoodLiveRoot()
	if err != nil {
		t.Fatalf("unexpected error on third call (should use cache): %v", err)
	}
	if ltr2 == nil {
		t.Fatal("expected non-nil LiveTrustedRoot from cache on third call")
	}
	if callCount != 2 {
		t.Fatalf("expected constructor NOT to be called on third call (use cache), but callCount=%d", callCount)
	}
}

// TestFetchPublicGoodLiveRoot_SuccessIsCached verifies that a single
// successful init is reused on subsequent calls without re-invoking the
// constructor.
func TestFetchPublicGoodLiveRoot_SuccessIsCached(t *testing.T) {
	origConstructor := liveTrustedRootConstructor
	t.Cleanup(func() {
		liveTrustedRootConstructor = origConstructor
		resetPublicGoodState()
	})
	resetPublicGoodState()

	callCount := 0
	liveTrustedRootConstructor = func(_ *tuf.Options) (*root.LiveTrustedRoot, error) {
		callCount++
		return &root.LiveTrustedRoot{}, nil
	}

	for i := 0; i < 5; i++ {
		ltr, err := fetchPublicGoodLiveRoot()
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if ltr == nil {
			t.Fatalf("call %d: expected non-nil LiveTrustedRoot", i+1)
		}
	}

	if callCount != 1 {
		t.Fatalf("constructor should be called exactly once for repeated successful calls; got %d", callCount)
	}
}
