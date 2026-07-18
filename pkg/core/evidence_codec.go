package core

import (
	"fmt"
	"strings"
)

// EvidenceSchemaVersion is the semver of the Evidence wire schema. Producers
// set Evidence.SchemaVersion to this; DecodeEvidence validates it.
const EvidenceSchemaVersion = "0.2.0"

// parseDigest converts "alg:hex" into a single-entry DigestSet. A value with
// no "alg:" prefix is rejected rather than assumed to be sha256.
func parseDigest(s string) (DigestSet, error) {
	alg, hex, ok := strings.Cut(s, ":")
	if !ok || alg == "" || hex == "" {
		return nil, fmt.Errorf("digest %q must be in alg:hex form", s)
	}
	return DigestSet{alg: hex}, nil
}

// AsArtifact maps a container ImageRef onto an ArtifactRef.
func (i ImageRef) AsArtifact() ArtifactRef {
	ds, _ := parseDigest(i.Digest) // best effort; empty on malformed
	return ArtifactRef{Kind: "container", Name: i.Name, Digest: ds}
}

// PrimaryDigest returns a stable canonical entry from the DigestSet for display
// and blob binding. sha256 is preferred; otherwise the lexicographically
// smallest algorithm is chosen so the result is deterministic.
func (a ArtifactRef) PrimaryDigest() (alg, hex string, ok bool) {
	if len(a.Digest) == 0 {
		return "", "", false
	}
	if h, present := a.Digest["sha256"]; present {
		return "sha256", h, true
	}
	best := ""
	for k := range a.Digest {
		if best == "" || k < best {
			best = k
		}
	}
	return best, a.Digest[best], true
}
