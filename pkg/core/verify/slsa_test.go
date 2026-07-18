package verify_test

import (
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

func TestVerifySLSA_ValidL3(t *testing.T) {
	raw := testfix.Load(t, "slsa/valid-l3.dsse.json")
	env, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE: %v", err)
	}

	art := core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: testfix.TestImageDigest,
	}.AsArtifact()

	result := verify.VerifySLSA(env, art)

	if !result.Verified {
		t.Errorf("Verified = false; want true (Err=%q)", result.Err)
	}
	if result.BuildLevel != 3 {
		t.Errorf("BuildLevel = %d; want 3", result.BuildLevel)
	}
	if !result.SubjectDigestMatch {
		t.Error("SubjectDigestMatch = false; want true")
	}
	if result.BuilderID != "https://github.com/sns45/ci" {
		t.Errorf("BuilderID = %q; want %q", result.BuilderID, "https://github.com/sns45/ci")
	}
	if result.Err != "" {
		t.Errorf("Err = %q; want empty", result.Err)
	}
}

func TestVerifySLSA_DigestMismatch(t *testing.T) {
	raw := testfix.Load(t, "slsa/digest-mismatch.dsse.json")
	env, err := verify.DecodeDSSE(raw)
	if err != nil {
		t.Fatalf("DecodeDSSE: %v", err)
	}

	art := core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: testfix.TestImageDigest,
	}.AsArtifact()

	result := verify.VerifySLSA(env, art)

	if result.SubjectDigestMatch {
		t.Error("SubjectDigestMatch = true; want false (digest should not match)")
	}
	if result.Verified {
		t.Error("Verified = true; want false when digest does not match")
	}
}

func TestVerifySLSA_GarbagePayload(t *testing.T) {
	env := verify.DecodedEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     []byte("not valid json {{{"),
	}

	art := core.ImageRef{
		Name:   testfix.TestImageName,
		Digest: testfix.TestImageDigest,
	}.AsArtifact()

	result := verify.VerifySLSA(env, art)

	if result.Verified {
		t.Error("Verified = true; want false for garbage payload")
	}
	if result.Err == "" {
		t.Error("Err is empty; want non-empty error for garbage payload")
	}
}
