// Package verify provides DSSE envelope decoding and the SignatureVerifier
// interface. It has no dependency on engine or policy.
package verify

import (
	"encoding/json"
	"fmt"
	"strings"

	attestv1 "github.com/in-toto/attestation/go/v1"
	slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/assayward/pkg/core"
)

// SLSAResult is the outcome of verifying a SLSA provenance attestation.
type SLSAResult struct {
	// Verified is true when the statement and predicate parsed successfully AND
	// SubjectDigestMatch is true.
	Verified bool

	// BuilderID is the builder.id URI extracted from runDetails.builder.id.
	BuilderID string

	// BuildLevel is a structural heuristic for the SLSA build level derived
	// from the predicate fields.
	//
	// v0.1 heuristic (structural placeholder):
	//   3 - builder.id is a non-empty "https://" URI AND buildType is non-empty.
	//   2 - builder.id is non-empty (any value) but buildType is empty.
	//   1 - statement parses but no builder.id is present.
	//   0 - payload cannot be parsed as an in-toto Statement.
	//
	// Real SLSA level is determined by the build platform's trust configuration
	// and forgeseal provenance; this heuristic will be refined in a future release.
	BuildLevel int

	// SubjectDigestMatch is true when ANY subject in the statement shares AT
	// LEAST ONE digest algorithm with art.Digest and the hex values are equal
	// (case-insensitive comparison). Matching is algorithm-aware: an artifact
	// digest under one algorithm (e.g. "smithmark-bundle-v1") is never
	// compared against a subject digest under a different algorithm, so a
	// coincidentally-equal hex value across algorithms cannot produce a false
	// match.
	SubjectDigestMatch bool

	// Err is a non-empty human-readable error string when the statement or
	// predicate could not be parsed. Empty on success.
	Err string
}

// VerifySLSA parses the in-toto Statement carried in env.Payload, extracts
// SLSA provenance fields, and checks whether the statement's subject digest
// matches the artifact digest in art.
//
// Matching is algorithm-aware: every entry of art.Digest is compared against
// the corresponding algorithm entry (if any) of each subject's digest map, so
// container images (sha256), skills, and other artifact kinds using
// non-sha256 digest algorithms are all supported without assuming sha256.
func VerifySLSA(env DecodedEnvelope, art core.ArtifactRef) SLSAResult {
	// Parse the Statement using protojson (required for the proto-based Statement type).
	stmt := &attestv1.Statement{}
	if err := protojson.Unmarshal(env.Payload, stmt); err != nil {
		return SLSAResult{
			Verified: false,
			Err:      fmt.Sprintf("slsa: parse in-toto statement: %v", err),
		}
	}

	// Check whether any subject shares a digest algorithm with art.Digest and
	// has an equal (case-insensitive) hex value under that algorithm.
	subjectDigestMatch := false
	for _, subj := range stmt.GetSubject() {
		if subjectMatches(subj.GetDigest(), art) {
			subjectDigestMatch = true
			break
		}
	}

	// Extract the predicate by re-marshaling the structpb.Struct predicate into
	// the slsa_provenance/v1 ProvenancePredicate type. This avoids any direct
	// dependency on the parent in_toto package while preserving type safety.
	var pred slsav1.ProvenancePredicate
	if stmt.GetPredicate() != nil {
		predJSON, err := stmt.GetPredicate().MarshalJSON()
		if err != nil {
			return SLSAResult{
				Verified: false,
				Err:      fmt.Sprintf("slsa: marshal predicate structpb: %v", err),
			}
		}
		if err := json.Unmarshal(predJSON, &pred); err != nil {
			return SLSAResult{
				Verified: false,
				Err:      fmt.Sprintf("slsa: unmarshal SLSA predicate: %v", err),
			}
		}
	}

	builderID := pred.RunDetails.Builder.ID
	buildType := pred.BuildDefinition.BuildType

	// Derive build level using the v0.1 structural heuristic (see BuildLevel doc).
	buildLevel := deriveBuildLevel(builderID, buildType)

	verified := subjectDigestMatch

	return SLSAResult{
		Verified:           verified,
		BuilderID:          builderID,
		BuildLevel:         buildLevel,
		SubjectDigestMatch: subjectDigestMatch,
	}
}

// subjectMatches reports whether any digest algorithm present in art.Digest
// is also present in subjectDigest with a case-insensitively equal,
// non-empty hex value. Comparison never crosses algorithms: a hex value that
// happens to match under a different algorithm key is not a match.
func subjectMatches(subjectDigest map[string]string, art core.ArtifactRef) bool {
	for alg, hex := range art.Digest {
		if hex == "" {
			continue
		}
		if subjHex, ok := subjectDigest[alg]; ok && strings.EqualFold(subjHex, hex) {
			return true
		}
	}
	return false
}

// deriveBuildLevel applies the v0.1 structural heuristic to determine the
// inferred SLSA build level from the builder ID and build type fields.
func deriveBuildLevel(builderID, buildType string) int {
	if builderID == "" {
		return 1
	}
	if strings.HasPrefix(builderID, "https://") && buildType != "" {
		return 3
	}
	return 2
}
