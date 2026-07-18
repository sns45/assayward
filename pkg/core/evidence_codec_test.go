package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceRoundTripArtifact(t *testing.T) {
	in := Evidence{
		SchemaVersion: EvidenceSchemaVersion,
		Artifact:      ArtifactRef{Kind: "skill", Name: "hello", Digest: DigestSet{"smithmark-bundle-v1": "cd34"}},
		FetchedAt:     time.Unix(0, 0).UTC(),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEvidence(b)
	if err != nil {
		t.Fatalf("DecodeEvidence: %v", err)
	}
	if got.Artifact.Kind != "skill" || got.Artifact.Digest["smithmark-bundle-v1"] != "cd34" {
		t.Fatalf("round trip lost artifact: %+v", got.Artifact)
	}
}

func TestEvidenceDecodesLegacyImage(t *testing.T) {
	legacy := `{"schemaVersion":"0.2.0","image":{"name":"reg/repo:tag","digest":"sha256:ab12"},"attestations":[],"fetchedAt":"1970-01-01T00:00:00Z"}`
	got, err := DecodeEvidence([]byte(legacy))
	if err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if got.Artifact.Kind != "container" || got.Artifact.Digest["sha256"] != "ab12" {
		t.Fatalf("legacy image not mapped: %+v", got.Artifact)
	}
}

func TestDecodeEvidenceRejectsBadSchemaAndUnknownFields(t *testing.T) {
	cases := map[string]string{
		"missing version": `{"artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"wrong version":   `{"schemaVersion":"9.9.9","artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"unknown field":   `{"schemaVersion":"0.2.0","artifact":{"kind":"container","name":"x","digest":{"sha256":"ab"}},"bogus":1,"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"bare hex image":  `{"schemaVersion":"0.2.0","image":{"name":"x","digest":"deadbeef"},"fetchedAt":"1970-01-01T00:00:00Z"}`,
		"neither":         `{"schemaVersion":"0.2.0","fetchedAt":"1970-01-01T00:00:00Z"}`,
	}
	for name, doc := range cases {
		if _, err := DecodeEvidence([]byte(doc)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
