package verify

import (
	"encoding/json"
	"fmt"

	govex "github.com/openvex/go-vex/pkg/vex"
)

// VEXResult is the outcome of verifying an OpenVEX attestation.
type VEXResult struct {
	// Present is true when the predicate parsed as a valid OpenVEX document.
	Present bool

	// Statuses maps each vulnerability ID (e.g. "CVE-2024-0001") to its status
	// string (e.g. "affected", "not_affected"). Empty when Present is false.
	Statuses map[string]string

	// Err is a non-empty human-readable error string when parsing failed.
	Err string
}

// VerifyVEX parses the in-toto Statement carried in env.Payload, extracts the
// predicate as an OpenVEX document, and returns the CVE-to-status map. It
// never panics and performs no I/O.
func VerifyVEX(env DecodedEnvelope) VEXResult {
	// Extract the predicate JSON from the in-toto Statement wrapper.
	var stmt inTotoStatement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return VEXResult{
			Err: fmt.Sprintf("vex: parse in-toto statement: %v", err),
		}
	}
	if stmt.Predicate == nil {
		return VEXResult{
			Err: "vex: in-toto statement has no predicate field",
		}
	}

	// Unmarshal the predicate as an OpenVEX document.
	var doc govex.VEX
	if err := json.Unmarshal(stmt.Predicate, &doc); err != nil {
		return VEXResult{
			Err: fmt.Sprintf("vex: decode OpenVEX document: %v", err),
		}
	}

	// Require at least one statement to consider the document present.
	if len(doc.Statements) == 0 {
		return VEXResult{
			Err: "vex: OpenVEX document contains no statements",
		}
	}

	// Build CVE-to-status map from each statement's vulnerability identifier.
	// Prefer Vulnerability.Name (the canonical VulnerabilityID field); if empty,
	// fall back to Vulnerability.ID (the "@id" IRI field). OpenVEX documents
	// produced by tools such as forgeseal carry the CVE only in "@id" with Name
	// left empty. Without the fallback, affected CVEs would be silently missed.
	statuses := make(map[string]string, len(doc.Statements))
	for _, s := range doc.Statements {
		id := string(s.Vulnerability.Name)
		if id == "" {
			id = s.Vulnerability.ID
		}
		if id != "" {
			statuses[id] = string(s.Status)
		}
	}

	return VEXResult{
		Present:  true,
		Statuses: statuses,
	}
}
