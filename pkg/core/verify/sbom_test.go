package verify_test

import (
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core/verify"
)

func TestVerifySBOM_ValidFixture(t *testing.T) {
	raw := testfix.Load(t, "sbom/cyclonedx.dsse.json")
	env, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE: %v", err)
	}

	result := verify.VerifySBOM(env)

	if !result.Present {
		t.Fatalf("expected Present=true, got false; Err=%q", result.Err)
	}
	if result.Err != "" {
		t.Fatalf("expected Err empty, got %q", result.Err)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}

	// Build a map by PURL for order-independent assertions.
	byPURL := make(map[string]verify.Component, len(result.Components))
	for _, c := range result.Components {
		byPURL[c.PURL] = c
	}

	leftPad, ok := byPURL["pkg:npm/left-pad@1.3.0"]
	if !ok {
		t.Fatalf("component pkg:npm/left-pad@1.3.0 not found; got %v", result.Components)
	}
	if leftPad.Name != "left-pad" {
		t.Errorf("left-pad Name: got %q, want %q", leftPad.Name, "left-pad")
	}
	if leftPad.Version != "1.3.0" {
		t.Errorf("left-pad Version: got %q, want %q", leftPad.Version, "1.3.0")
	}
	if leftPad.License != "MIT" {
		t.Errorf("left-pad License: got %q, want %q", leftPad.License, "MIT")
	}

	goLib, ok := byPURL["pkg:golang/example.com/x@1.0.0"]
	if !ok {
		t.Fatalf("component pkg:golang/example.com/x@1.0.0 not found; got %v", result.Components)
	}
	if goLib.Name != "example.com/x" {
		t.Errorf("go lib Name: got %q, want %q", goLib.Name, "example.com/x")
	}
	if goLib.Version != "1.0.0" {
		t.Errorf("go lib Version: got %q, want %q", goLib.Version, "1.0.0")
	}
	if goLib.License != "Apache-2.0" {
		t.Errorf("go lib License: got %q, want %q", goLib.License, "Apache-2.0")
	}
}

func TestVerifySBOM_Garbage(t *testing.T) {
	env := verify.DecodedEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     []byte(`{"_type":"garbage"}`),
	}

	result := verify.VerifySBOM(env)

	if result.Present {
		t.Error("expected Present=false for garbage input")
	}
	if result.Err == "" {
		t.Error("expected non-empty Err for garbage input")
	}
}
