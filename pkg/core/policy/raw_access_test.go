package policy_test

// TestPolicyDoesNotReadRawEnvelope enforces §4 of the architecture specification:
//
//	The policy layer MUST consume only projected View types (scalars/bools).
//	It MUST NOT read Attestation.Envelope, WorkloadIdentity.Raw, or access
//	the verify package directly. Those fields and that package carry unverified
//	or raw cryptographic material; the Verified flag on each attestation is set
//	exclusively by a verify stage. Any policy code that bypasses the View
//	projection and reads raw data could make trust decisions on unverified
//	material, constituting a security regression.
//
// Adding .Envelope access, .Raw access, or a verify package import to the
// policy package MUST be treated as a breaking security change requiring a
// deliberate architectural review — not a routine code change.
//
// Self-check: a sub-test verifies the detector is not vacuously passing by
// running the same AST scan against a synthetic in-memory source that contains
// a forbidden selector, and asserting the detector does flag it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// forbiddenSelectors is the set of field selector names that the policy
// package must never access.
var forbiddenSelectors = []string{
	"Envelope", // Attestation.Envelope — raw DSSE bytes
	"Raw",      // WorkloadIdentity.Raw — raw SVID credential
}

// forbiddenImports is the set of import paths the policy package must never use.
var forbiddenImports = []string{
	"github.com/sns45/assayward/pkg/core/verify",
}

// violation records a single lint finding.
type violation struct {
	file       string
	identifier string
	line       int
}

// scanFile parses a single Go source file (or in-memory source when src != nil)
// and returns any violations of the raw-access rules.
//
// name is used as the display filename in violation records.
// src may be a string, []byte, or io.Reader; when nil the file at name is read.
func scanFile(fset *token.FileSet, name string, src any) []violation {
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		// A parse error is reported as a violation so the caller can t.Errorf it.
		return []violation{{file: name, identifier: "PARSE_ERROR: " + err.Error()}}
	}

	var violations []violation

	// Check imports.
	for _, imp := range f.Imports {
		if imp.Path == nil {
			continue
		}
		// Strip surrounding quotes from the import path literal.
		path := strings.Trim(imp.Path.Value, `"`)
		for _, forbidden := range forbiddenImports {
			if path == forbidden {
				pos := fset.Position(imp.Path.Pos())
				violations = append(violations, violation{
					file:       name,
					identifier: "import " + path,
					line:       pos.Line,
				})
			}
		}
	}

	// Walk the AST for forbidden selector expressions.
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, forbidden := range forbiddenSelectors {
			if sel.Sel.Name == forbidden {
				pos := fset.Position(sel.Sel.Pos())
				violations = append(violations, violation{
					file:       name,
					identifier: "." + sel.Sel.Name,
					line:       pos.Line,
				})
			}
		}
		return true
	})

	return violations
}

// TestPolicyDoesNotReadRawEnvelope statically asserts that no non-test source
// file in the policy package accesses raw attestation envelopes, raw SVID
// credentials, or imports the verify package.
func TestPolicyDoesNotReadRawEnvelope(t *testing.T) {
	t.Run("real_policy_package_scan", func(t *testing.T) {
		// Resolve the directory containing this test file at runtime so the test
		// is relocatable and does not rely on a hardcoded GOPATH.
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller(0) failed: cannot determine source directory")
		}
		dir := filepath.Dir(thisFile)

		// Collect non-test .go files in the policy package directory.
		entries, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("glob failed: %v", err)
		}

		fset := token.NewFileSet()
		var allViolations []violation

		for _, path := range entries {
			base := filepath.Base(path)
			// Skip test files — we only lint the production sources.
			if strings.HasSuffix(base, "_test.go") {
				continue
			}
			// Skip files with a build tag that excludes them on the current
			// platform (e.g. custom.go with //go:build !wasm); the AST scanner
			// still parses them because we want the lint to apply regardless of
			// build tag — a forbidden pattern hidden behind a build tag is still
			// a violation.
			violations := scanFile(fset, path, nil)
			allViolations = append(allViolations, violations...)
		}

		for _, v := range allViolations {
			t.Errorf("policy package raw-access violation in %s:%d — identifier %q is forbidden (§4 critical rule: policy must consume only View projections)",
				v.file, v.line, v.identifier)
		}
	})

	// self_check proves the detector is not vacuously passing by feeding it a
	// synthetic source string that contains a forbidden selector and asserting
	// that at least one violation is reported.
	t.Run("self_check_detector_fires_on_synthetic_source", func(t *testing.T) {
		const syntheticSrc = `package policy

import "fmt"

func badPolicyCode(a interface{ GetEnvelope() []byte }) {
	// The following selector access mimics what a policy file MUST NOT do:
	// reading the raw Envelope field directly off an attestation struct.
	type attestation struct{ Envelope []byte }
	att := attestation{Envelope: []byte("raw")}
	_ = att.Envelope // FORBIDDEN: raw envelope access in policy
	fmt.Println("bad policy accessing raw data")
}
`
		fset := token.NewFileSet()
		// "synthetic.go" is purely in-memory; it is never written to disk and
		// is not part of the policy package directory.
		violations := scanFile(fset, "synthetic.go", syntheticSrc)

		found := false
		for _, v := range violations {
			if v.identifier == ".Envelope" {
				found = true
				break
			}
		}
		if !found {
			t.Error("self-check FAILED: the AST detector did not flag .Envelope in the synthetic source — the lint may be vacuously passing")
		}
	})

	// self_check_raw proves the detector catches .Raw accesses too.
	t.Run("self_check_detector_fires_on_raw_field", func(t *testing.T) {
		const syntheticSrc = `package policy

func badRawAccess() {
	type identity struct{ Raw []byte }
	id := identity{Raw: []byte("jwt-token")}
	_ = id.Raw // FORBIDDEN: raw SVID credential access in policy
}
`
		fset := token.NewFileSet()
		violations := scanFile(fset, "synthetic.go", syntheticSrc)

		found := false
		for _, v := range violations {
			if v.identifier == ".Raw" {
				found = true
				break
			}
		}
		if !found {
			t.Error("self-check FAILED: the AST detector did not flag .Raw in the synthetic source — the lint may be vacuously passing")
		}
	})

	// self_check_import proves the detector catches forbidden import paths.
	t.Run("self_check_detector_fires_on_forbidden_import", func(t *testing.T) {
		const syntheticSrc = `package policy

import "github.com/sns45/assayward/pkg/core/verify"

func badImport() {
	_ = verify.DecodeDSSE // FORBIDDEN: direct verify package import in policy
}
`
		fset := token.NewFileSet()
		violations := scanFile(fset, "synthetic.go", syntheticSrc)

		found := false
		for _, v := range violations {
			if strings.Contains(v.identifier, "verify") {
				found = true
				break
			}
		}
		if !found {
			t.Error("self-check FAILED: the AST detector did not flag the verify import in the synthetic source — the lint may be vacuously passing")
		}
	})
}
