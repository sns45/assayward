// Package testfix provides shared test fixtures and helpers for the assayward
// test suite. It is a test-only package and MUST NOT be imported from any
// non-test file in pkg/core or production code paths.
//
// SYNTHETIC PLACEHOLDERS: All fixtures loaded by this package are generated,
// representative data. They will be replaced with real forgeseal/svidmint
// artifacts before v0.1 ships. See testdata/README.md for details.
package testfix

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestImageName is the canonical image reference used in all fixture subjects.
const TestImageName = "ghcr.io/sns45/example:1.0.0"

// TestImageDigest is the sha256 digest of TestImageName used in fixture subjects.
// This is the digest of the empty string (sha256 of zero bytes) used as a stable
// placeholder until real image digests are available.
const TestImageDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// root returns the absolute path to the repo-root testdata/ directory.
// It is resolved relative to this source file via runtime.Caller so that tests
// work regardless of which package directory they are run from.
func root() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("testfix: runtime.Caller(0) failed — cannot resolve testdata root")
	}
	// testfix.go lives at internal/testfix/testfix.go.
	// testdata/ is at ../../testdata relative to this file.
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

// Root returns the absolute path to the repo-root testdata/ directory.
func Root() string {
	return root()
}

// Load reads testdata/<rel> and returns its contents. It calls t.Fatal if the
// file cannot be read, so callers do not need to check errors.
func Load(t testing.TB, rel string) []byte {
	t.Helper()
	path := filepath.Join(root(), rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("testfix.Load(%q): %v", rel, err)
	}
	return data
}
