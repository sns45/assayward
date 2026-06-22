//go:build ignore

// Generator for synthetic DSSE fixture files used in assayward tests.
//
// SYNTHETIC PLACEHOLDERS: All generated fixtures are representative data for
// development and CI testing. They will be replaced with real forgeseal/svidmint
// artifacts before v0.1 ships. See testdata/README.md for details.
//
// Usage:
//
//	go run testdata/gen/main.go
//
// Run from the repository root. Writes fixture files into testdata/.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Constants matching internal/testfix/testfix.go.
const (
	testImageName   = "ghcr.io/sns45/example:1.0.0"
	testImageDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// A clearly different digest used for the digest-mismatch fixture.
	// All-'a' hex string of the same length.
	mismatchDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	payloadType = "application/vnd.in-toto+json"
	statementV1 = "https://in-toto.io/Statement/v1"
)

// dsseEnvelope is the DSSE wire format.
type dsseEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

// signature is a placeholder signature entry (no real crypto for synthetic fixtures).
type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// statement is a minimal in-toto Statement v1.
type statement struct {
	Type          string      `json:"_type"`
	Subject       []subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// buildDSSE encodes a statement as a DSSE envelope JSON.
func buildDSSE(stmt statement) ([]byte, error) {
	stmtJSON, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	env := dsseEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(stmtJSON),
		Signatures: []signature{
			{KeyID: "", Sig: ""},
		},
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

// digestHex strips the "sha256:" prefix from a digest string.
func digestHex(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}

// subjectFor builds a subject list for the given image and digest.
func subjectFor(name, digest string) []subject {
	return []subject{
		{
			Name:   name,
			Digest: map[string]string{"sha256": digestHex(digest)},
		},
	}
}

func writeDSSE(path string, stmt statement) {
	data, err := buildDSSE(stmt)
	if err != nil {
		log.Fatalf("build DSSE for %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	// Resolve output directory relative to this file (repo root / testdata).
	// When invoked as "go run testdata/gen/main.go" from the repo root, the
	// working directory is the repo root.
	root := "testdata"

	// 1. testdata/slsa/valid-l3.dsse.json
	//
	// SLSA Provenance v1 with builder.id present and hosted — this meets the
	// minimum bar for SLSA Build L3 under the SLSA v1.0 specification:
	//   - predicateType: https://slsa.dev/provenance/v1
	//   - buildDefinition.buildType identifies the build system
	//   - runDetails.builder.id is a fully-qualified HTTPS URI (hosted builder)
	//   - runDetails.builder.builderDependencies is empty (trusted builder, no
	//     external deps injected at build time — a L3 requirement)
	//
	// NOTE: actual L3 verification requires a Sigstore-signed bundle attesting
	// to a SLSA-conformant builder. This fixture has a placeholder signature and
	// is for non-crypto predicate parsing tests only.
	writeDSSE(filepath.Join(root, "slsa", "valid-l3.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]interface{}{
			"buildDefinition": map[string]interface{}{
				"buildType": "https://github.com/sns45/ci/build-system@v1",
				"externalParameters": map[string]interface{}{
					"ref": "refs/heads/main",
				},
				"internalParameters":   map[string]interface{}{},
				"resolvedDependencies": []interface{}{},
			},
			"runDetails": map[string]interface{}{
				"builder": map[string]interface{}{
					"id":                  "https://github.com/sns45/ci",
					"builderDependencies": []interface{}{},
					"version":             map[string]string{},
				},
				"metadata": map[string]interface{}{
					"invocationId": "https://github.com/sns45/example/actions/runs/1",
					"startedOn":    "2024-01-01T00:00:00Z",
					"finishedOn":   "2024-01-01T00:05:00Z",
				},
				"byproducts": []interface{}{},
			},
		},
	})

	// 2. testdata/slsa/digest-mismatch.dsse.json
	//
	// Same structure as valid-l3 but the subject digest does NOT match
	// TestImageDigest. Used for the subject-digest-mismatch negative test.
	writeDSSE(filepath.Join(root, "slsa", "digest-mismatch.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, mismatchDigest),
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]interface{}{
			"buildDefinition": map[string]interface{}{
				"buildType": "https://github.com/sns45/ci/build-system@v1",
			},
			"runDetails": map[string]interface{}{
				"builder": map[string]interface{}{
					"id": "https://github.com/sns45/ci",
				},
			},
		},
	})

	// 3. testdata/sbom/cyclonedx.dsse.json
	//
	// CycloneDX 1.5 SBOM with two representative components.
	writeDSSE(filepath.Join(root, "sbom", "cyclonedx.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://cyclonedx.org/bom",
		Predicate: map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"version":     1,
			"metadata": map[string]interface{}{
				"timestamp": "2024-01-01T00:00:00Z",
				"component": map[string]interface{}{
					"type":    "container",
					"name":    testImageName,
					"version": "1.0.0",
				},
			},
			"components": []interface{}{
				map[string]interface{}{
					"type":     "library",
					"name":     "left-pad",
					"version":  "1.3.0",
					"purl":     "pkg:npm/left-pad@1.3.0",
					"licenses": []interface{}{map[string]interface{}{"license": map[string]string{"id": "MIT"}}},
					"supplier": "Organization: npm",
					"bom-ref":  "pkg:npm/left-pad@1.3.0",
				},
				map[string]interface{}{
					"type":     "library",
					"name":     "example.com/x",
					"version":  "1.0.0",
					"purl":     "pkg:golang/example.com/x@1.0.0",
					"licenses": []interface{}{map[string]interface{}{"license": map[string]string{"id": "Apache-2.0"}}},
					"supplier": "Organization: example.com",
					"bom-ref":  "pkg:golang/example.com/x@1.0.0",
				},
			},
		},
	})

	// 4. testdata/vex/affected-critical.dsse.json
	//
	// OpenVEX document with one statement: CVE-2024-0001 is "affected" with no
	// justification (used for negative/critical-finding tests).
	writeDSSE(filepath.Join(root, "vex", "affected-critical.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate: map[string]interface{}{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.com/vex/affected-critical-1",
			"author":    "sns45-ci",
			"timestamp": "2024-01-01T00:00:00Z",
			"version":   "1",
			"statements": []interface{}{
				map[string]interface{}{
					"vulnerability": map[string]interface{}{
						"@id":         "https://osv.dev/CVE-2024-0001",
						"name":        "CVE-2024-0001",
						"description": "Critical synthetic vulnerability for fixture testing.",
					},
					"products": []interface{}{
						map[string]interface{}{
							"@id": "pkg:oci/example@sha256:" + digestHex(testImageDigest),
							"subcomponents": []interface{}{
								map[string]interface{}{"@id": "pkg:npm/left-pad@1.3.0"},
							},
						},
					},
					"status": "affected",
					// No justification field — status is "affected", justification not applicable.
					"impact_statement": "Component is directly vulnerable; no mitigations in place.",
				},
			},
		},
	})

	// 5. testdata/vex/not-affected.dsse.json
	//
	// OpenVEX document with same vuln (CVE-2024-0001) but status "not_affected"
	// with a justification. Used for the positive/mitigated-vuln tests.
	writeDSSE(filepath.Join(root, "vex", "not-affected.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate: map[string]interface{}{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.com/vex/not-affected-1",
			"author":    "sns45-ci",
			"timestamp": "2024-01-01T00:00:00Z",
			"version":   "1",
			"statements": []interface{}{
				map[string]interface{}{
					"vulnerability": map[string]interface{}{
						"@id":         "https://osv.dev/CVE-2024-0001",
						"name":        "CVE-2024-0001",
						"description": "Critical synthetic vulnerability for fixture testing.",
					},
					"products": []interface{}{
						map[string]interface{}{
							"@id": "pkg:oci/example@sha256:" + digestHex(testImageDigest),
						},
					},
					"status":           "not_affected",
					"justification":    "vulnerable_code_not_in_execute_path",
					"impact_statement": "The vulnerable code path in left-pad is never called by this image.",
				},
			},
		},
	})

	fmt.Println("done — all fixtures written to testdata/")
}
