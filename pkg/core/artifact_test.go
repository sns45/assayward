package core

import "testing"

func TestParseDigestAlgorithmKeyed(t *testing.T) {
	ds, err := parseDigest("sha256:ab12")
	if err != nil {
		t.Fatalf("parseDigest: %v", err)
	}
	if ds["sha256"] != "ab12" {
		t.Fatalf("got %v", ds)
	}
	if _, err := parseDigest("deadbeef"); err == nil {
		t.Fatal("bare hex without alg prefix must error")
	}
	if _, err := parseDigest("smithmark-bundle-v1:cd34"); err != nil {
		t.Fatalf("non-sha256 algorithm must parse: %v", err)
	}
}

func TestImageRefAsArtifactAndPrimaryDigest(t *testing.T) {
	a := ImageRef{Name: "reg/repo:tag", Digest: "sha256:ab12"}.AsArtifact()
	if a.Kind != "container" || a.Name != "reg/repo:tag" || a.Digest["sha256"] != "ab12" {
		t.Fatalf("AsArtifact wrong: %+v", a)
	}
	alg, hex, ok := a.PrimaryDigest()
	if !ok || alg != "sha256" || hex != "ab12" {
		t.Fatalf("PrimaryDigest wrong: %q %q %v", alg, hex, ok)
	}
	if _, _, ok := (ArtifactRef{}).PrimaryDigest(); ok {
		t.Fatal("empty digest set must report ok=false")
	}
}
