package verify_test

import (
	"encoding/base64"
	"encoding/json"
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

// TestVerifyVEX_AffectedCritical_IDOnly verifies the fallback path where the
// OpenVEX statement carries the CVE only in the "@id" field (Vulnerability.ID)
// with no "name" field present. This is the format emitted by forgeseal.
// Without the ID fallback, the CVE would be silently dropped from Statuses,
// causing an affected critical to be missed (false-allow security bug).
func TestVerifyVEX_AffectedCritical_IDOnly(t *testing.T) {
	// Build a forgeseal-style OpenVEX document: vulnerability identified only
	// via "@id", no "name" field, status "affected".
	openvexDoc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      "https://example.com/vex/id-only-test",
		"author":   "test",
		"version":  1,
		"statements": []map[string]any{
			{
				"vulnerability": map[string]any{
					"@id": "CVE-2024-9999",
				},
				"products": []map[string]any{
					{"@id": "pkg:golang/example@v1.0.0"},
				},
				"status": "affected",
			},
		},
	}
	predicate, err := json.Marshal(openvexDoc)
	if err != nil {
		t.Fatalf("marshal openvex doc: %v", err)
	}

	// Wrap the predicate in an in-toto Statement v1.
	stmt := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{
				"name":   "test-artifact",
				"digest": map[string]string{"sha256": "deadbeef"},
			},
		},
		"predicateType": "https://openvex.dev/ns/v0.2.0",
		"predicate":     json.RawMessage(predicate),
	}
	stmtBytes, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal in-toto statement: %v", err)
	}

	// Wrap the statement in a bare DSSE envelope (empty signatures).
	dsseEnv := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmtBytes),
		"signatures":  []any{},
	}
	dsseBytes, err := json.Marshal(dsseEnv)
	if err != nil {
		t.Fatalf("marshal dsse envelope: %v", err)
	}

	env, err := verify.DecodeDSSE(dsseBytes)
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

	// The CVE must be captured via the "@id" fallback path.
	status, ok := result.Statuses["CVE-2024-9999"]
	if !ok {
		t.Fatalf("CVE-2024-9999 not found in Statuses; got %v — @id fallback is broken", result.Statuses)
	}
	if status != "affected" {
		t.Errorf("CVE-2024-9999 status: got %q, want %q", status, "affected")
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
