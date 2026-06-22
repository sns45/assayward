package verify

import (
	"bytes"
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// SBOMResult is the outcome of verifying a CycloneDX SBOM attestation.
type SBOMResult struct {
	// Present is true when the predicate parsed as a valid CycloneDX BOM.
	Present bool

	// Components is the list of software components extracted from the BOM.
	// Empty when Present is false.
	Components []Component

	// Err is a non-empty human-readable error string when parsing failed.
	Err string
}

// Component is a single software component extracted from a CycloneDX BOM.
type Component struct {
	Name    string
	Version string
	PURL    string
	// License is the first license name or SPDX id found for this component,
	// or the empty string if no license information is present.
	License string
}

// inTotoStatement is a minimal in-toto Statement v1 used to extract the predicate.
type inTotoStatement struct {
	Predicate json.RawMessage `json:"predicate"`
}

// VerifySBOM parses the in-toto Statement carried in env.Payload, extracts the
// predicate as a CycloneDX BOM, and returns the components. It never panics and
// performs no I/O.
func VerifySBOM(env DecodedEnvelope) SBOMResult {
	// Extract the predicate JSON from the in-toto Statement wrapper.
	var stmt inTotoStatement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return SBOMResult{
			Err: fmt.Sprintf("sbom: parse in-toto statement: %v", err),
		}
	}
	if stmt.Predicate == nil {
		return SBOMResult{
			Err: "sbom: in-toto statement has no predicate field",
		}
	}

	// Decode the predicate as a CycloneDX BOM using the JSON decoder.
	var bom cdx.BOM
	decoder := cdx.NewBOMDecoder(bytes.NewReader(stmt.Predicate), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		return SBOMResult{
			Err: fmt.Sprintf("sbom: decode CycloneDX BOM: %v", err),
		}
	}

	// Require the bomFormat field to confirm this is actually a CycloneDX BOM.
	if bom.BOMFormat != cdx.BOMFormat {
		return SBOMResult{
			Err: fmt.Sprintf("sbom: unexpected bomFormat %q (want %q)", bom.BOMFormat, cdx.BOMFormat),
		}
	}

	// Map each CycloneDX component to our Component type.
	var components []Component
	if bom.Components != nil {
		for _, c := range *bom.Components {
			components = append(components, Component{
				Name:    c.Name,
				Version: c.Version,
				PURL:    c.PackageURL,
				License: firstLicense(c.Licenses),
			})
		}
	}

	return SBOMResult{
		Present:    true,
		Components: components,
	}
}

// firstLicense extracts the first license name or SPDX ID from a CycloneDX
// Licenses slice. Returns empty string when no license is present.
func firstLicense(ls *cdx.Licenses) string {
	if ls == nil {
		return ""
	}
	for _, lc := range *ls {
		if lc.License != nil {
			if lc.License.ID != "" {
				return lc.License.ID
			}
			if lc.License.Name != "" {
				return lc.License.Name
			}
		}
		if lc.Expression != "" {
			return lc.Expression
		}
	}
	return ""
}
