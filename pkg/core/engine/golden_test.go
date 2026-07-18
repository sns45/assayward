package engine_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sns45/assayward/internal/testfix"
	core "github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/engine"
	"github.com/sns45/assayward/pkg/core/policy"
	"github.com/sns45/assayward/pkg/core/policy/builtin"
)

var update = flag.Bool("update", false, "regenerate golden decision files")

// goldenDir returns the absolute path to this file's testdata/golden directory.
func goldenDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("golden_test.go: runtime.Caller(0) failed")
	}
	return filepath.Join(filepath.Dir(filename), "testdata", "golden")
}

// goldenEvidence builds the canonical Evidence used in all golden tests.
func goldenEvidence(t *testing.T) core.Evidence {
	t.Helper()
	return core.Evidence{
		Artifact: core.ImageRef{
			Name:   testfix.TestImageName,
			Digest: testfix.TestImageDigest,
		}.AsArtifact(),
		Attestations: []core.Attestation{
			{Envelope: testfix.Load(t, "signature/bundle-provenance.json"), PredicateType: "sigstore-bundle"},
			{Envelope: testfix.Load(t, "slsa/valid-l3.dsse.json"), PredicateType: "https://slsa.dev/provenance/v1"},
			{Envelope: testfix.Load(t, "sbom/cyclonedx.dsse.json"), PredicateType: "https://cyclonedx.org/bom"},
			{Envelope: testfix.Load(t, "vex/affected-critical.dsse.json"), PredicateType: "https://openvex.dev/ns/v0.2.0"},
		},
		Identity: &core.WorkloadIdentity{
			SVIDType: core.SVIDTypeJWT,
			Raw:      testfix.Load(t, "svid/jwt-valid.jwt"),
		},
	}
}

// goldenRoots builds the canonical TrustRoots used in all golden tests.
func goldenRoots(t *testing.T) core.TrustRoots {
	t.Helper()
	return core.TrustRoots{
		SigstoreTUF: testfix.Load(t, "signature/trusted-root-public-good.json"),
		SPIFFEBundles: map[string][]byte{
			"sns45.dev": testfix.Load(t, "svid/jwt-bundle.json"),
		},
	}
}

// goldenClock is the fixed clock for all golden tests.
var goldenClock = core.FixedClock{T: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

// TestGoldenDecisions evaluates the canonical evidence against each built-in
// policy and compares the result byte-for-byte to committed golden JSON files.
// Run with -update to regenerate the golden files.
func TestGoldenDecisions(t *testing.T) {
	ev := goldenEvidence(t)
	roots := goldenRoots(t)

	type policyCase struct {
		name string
		raw  []byte
	}

	cases := []policyCase{
		{name: "baseline", raw: builtin.Baseline},
		{name: "slsa-l3", raw: builtin.SLSAL3},
		{name: "serverless-edge", raw: builtin.ServerlessEdge},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pol, err := policy.Parse(tc.raw)
			if err != nil {
				t.Fatalf("policy.Parse(%q): %v", tc.name, err)
			}

			decision := engine.Evaluate(ev, pol, roots, goldenClock)

			got, err := json.MarshalIndent(decision, "", "  ")
			if err != nil {
				t.Fatalf("marshal decision: %v", err)
			}
			// Append a trailing newline for clean diffs.
			got = append(got, '\n')

			goldenPath := filepath.Join(goldenDir(), tc.name+".decision.json")

			if *update {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0755); err != nil {
					t.Fatalf("mkdir golden dir: %v", err)
				}
				if err := os.WriteFile(goldenPath, got, 0644); err != nil {
					t.Fatalf("write golden %q: %v", goldenPath, err)
				}
				t.Logf("updated golden: %s", goldenPath)
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %q: %v (run with -update to generate)", goldenPath, err)
			}

			if string(got) != string(want) {
				t.Errorf("golden mismatch for %q\ngot:\n%s\nwant:\n%s", tc.name, got, want)
			}
		})
	}
}
