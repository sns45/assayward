package verify_test

import (
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core/verify"
)

func TestVerifyVEX_AffectedCritical(t *testing.T) {
	raw := testfix.Load(t, "vex/affected-critical.dsse.json")
	env, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE: %v", err)
	}

	result := verify.VerifyVEX(env)

	if !result.Present {
		t.Fatalf("expected Present=true, got false; Err=%q", result.Err)
	}
	if result.Err != "" {
		t.Fatalf("expected Err empty, got %q", result.Err)
	}

	status, ok := result.Statuses["CVE-2024-0001"]
	if !ok {
		t.Fatalf("CVE-2024-0001 not found in Statuses; got %v", result.Statuses)
	}
	if status != "affected" {
		t.Errorf("CVE-2024-0001 status: got %q, want %q", status, "affected")
	}
}

func TestVerifyVEX_NotAffected(t *testing.T) {
	raw := testfix.Load(t, "vex/not-affected.dsse.json")
	env, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE: %v", err)
	}

	result := verify.VerifyVEX(env)

	if !result.Present {
		t.Fatalf("expected Present=true, got false; Err=%q", result.Err)
	}

	status, ok := result.Statuses["CVE-2024-0001"]
	if !ok {
		t.Fatalf("CVE-2024-0001 not found in Statuses; got %v", result.Statuses)
	}
	if status != "not_affected" {
		t.Errorf("CVE-2024-0001 status: got %q, want %q", status, "not_affected")
	}
}

func TestVerifyVEX_Garbage(t *testing.T) {
	env := verify.DecodedEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     []byte(`{"_type":"garbage"}`),
	}

	result := verify.VerifyVEX(env)

	if result.Present {
		t.Error("expected Present=false for garbage input")
	}
	if result.Err == "" {
		t.Error("expected non-empty Err for garbage input")
	}
}
