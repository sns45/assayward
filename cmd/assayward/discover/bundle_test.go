package discover_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sns45/assayward/cmd/assayward/discover"
)

// testdataRoot returns the absolute path to repo-root testdata/.
func testdataRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("discover_test: runtime.Caller(0) failed")
	}
	// bundle_test.go is at cmd/assayward/discover/bundle_test.go
	// repo root is ../../../
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "testdata")
}

// TestFromBundles_ReadsNFilesAsNAttestations verifies that FromBundles returns
// one Attestation per path with a non-empty Envelope.
func TestFromBundles_ReadsNFilesAsNAttestations(t *testing.T) {
	root := testdataRoot()
	paths := []string{
		filepath.Join(root, "signature", "bundle-provenance.json"),
		filepath.Join(root, "slsa", "valid-l3.dsse.json"),
		filepath.Join(root, "sbom", "cyclonedx.dsse.json"),
		filepath.Join(root, "vex", "affected-critical.dsse.json"),
	}

	atts, err := discover.FromBundles(paths)
	if err != nil {
		t.Fatalf("FromBundles returned unexpected error: %v", err)
	}
	if len(atts) != len(paths) {
		t.Fatalf("FromBundles returned %d attestations, want %d", len(atts), len(paths))
	}
	for i, a := range atts {
		if len(a.Envelope) == 0 {
			t.Errorf("attestation[%d] has empty Envelope (path %s)", i, paths[i])
		}
	}
}

// TestFromBundles_UnreadablePath verifies that an unreadable path returns an error.
func TestFromBundles_UnreadablePath(t *testing.T) {
	// Create a temp file, then remove it so the path is unreadable.
	f, err := os.CreateTemp(t.TempDir(), "bundle-*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path)

	_, err = discover.FromBundles([]string{path})
	if err == nil {
		t.Error("FromBundles with unreadable path returned nil error, want an error")
	}
}
