package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

// evidenceWire is the strict decode target: it accepts both the canonical
// "artifact" and the legacy "image" object, and rejects unknown fields.
type evidenceWire struct {
	Artifact      *ArtifactRef      `json:"artifact"`
	Image         *ImageRef         `json:"image"`
	Attestations  []Attestation     `json:"attestations"`
	Identity      *WorkloadIdentity `json:"identity"`
	Findings      []Finding         `json:"findings"`
	BlobSignature *BlobSignature    `json:"blobSignature"`
	SchemaVersion string            `json:"schemaVersion"`
	FetchedAt     time.Time         `json:"fetchedAt"`
}

func (e *Evidence) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w evidenceWire
	if err := dec.Decode(&w); err != nil {
		return err
	}
	switch {
	case w.Artifact != nil:
		e.Artifact = *w.Artifact
	case w.Image != nil:
		ds, err := parseDigest(w.Image.Digest)
		if err != nil {
			return fmt.Errorf("legacy image digest: %w", err)
		}
		e.Artifact = ArtifactRef{Kind: "container", Name: w.Image.Name, Digest: ds}
	default:
		return fmt.Errorf("evidence has neither artifact nor image")
	}
	e.Attestations, e.Identity = w.Attestations, w.Identity
	e.Findings, e.BlobSignature = w.Findings, w.BlobSignature
	e.SchemaVersion, e.FetchedAt = w.SchemaVersion, w.FetchedAt
	return nil
}

// evidenceAlias avoids infinite recursion in MarshalJSON.
type evidenceAlias Evidence

func (e Evidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(evidenceAlias(e))
}

// DecodeEvidence strictly decodes Evidence JSON and validates schemaVersion.
func DecodeEvidence(b []byte) (Evidence, error) {
	var ev Evidence
	if err := ev.UnmarshalJSON(b); err != nil {
		return Evidence{}, err
	}
	if ev.SchemaVersion != EvidenceSchemaVersion {
		return Evidence{}, fmt.Errorf("unsupported evidence schemaVersion %q (want %q)", ev.SchemaVersion, EvidenceSchemaVersion)
	}
	return ev, nil
}
