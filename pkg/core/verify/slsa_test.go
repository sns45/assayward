package verify_test

import (
	"encoding/json"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core"
	"github.com/sns45/assayward/pkg/core/verify"
)

// slsaEnvelopeWithSubjectDigest builds a DecodedEnvelope wrapping a minimal
// in-toto v1 Statement whose sole subject carries the given name and digest
// map. It exists because the file's other helpers only load fixed fixture
// files (whose subject digest is always sha256); tests that need an
// arbitrary {algorithm: hex} subject digest map construct the statement
// JSON directly here.
func slsaEnvelopeWithSubjectDigest(t *testing.T, subjectName string, digest map[string]string) verify.DecodedEnvelope {
	t.Helper()
	stmt := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]any{
			{"name": subjectName, "digest": digest},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType":            "https://example.com/build-system@v1",
				"externalParameters":   map[string]any{},
				"internalParameters":   map[string]any{},
				"resolvedDependencies": []any{},
			},
			"runDetails": map[string]any{
				"builder": map[string]any{
					"id": "https://example.com/ci",
				},
			},
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("slsaEnvelopeWithSubjectDigest: marshal statement: %v", err)
	}
	return verify.DecodedEnvelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payload,
	}
}

// TestSLSASubjectMatchIsAlgorithmAware asserts that subject digest matching
// considers whichever algorithm(s) the artifact and the statement subject
// actually share, rather than assuming sha256. A smithmark-bundle-v1 skill
// subject must match its own algorithm, and a sha256-only artifact must not
// silently cross-match a smithmark-bundle-v1-only subject.
func TestSLSASubjectMatchIsAlgorithmAware(t *testing.T) {
	env := slsaEnvelopeWithSubjectDigest(t, "hello", map[string]string{"smithmark-bundle-v1": "cd34"})

	// A skill subject carries smithmark-bundle-v1, not sha256.
	art := core.ArtifactRef{Kind: "skill", Name: "hello",
		Digest: core.DigestSet{"smithmark-bundle-v1": "cd34"}}
	if got := verify.VerifySLSA(env, art); !got.SubjectDigestMatch {
		t.Fatalf("smithmark-bundle-v1 subject must match its own algorithm")
	}

	// A sha256-only artifact must NOT silently match a smithmark subject.
	sha := core.ArtifactRef{Kind: "container", Name: "hello",
		Digest: core.DigestSet{"sha256": "cd34"}}
	if got := verify.VerifySLSA(env, sha); got.SubjectDigestMatch {
		t.Fatalf("sha256 artifact must not match a smithmark-bundle-v1 subject")
	}
}

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
