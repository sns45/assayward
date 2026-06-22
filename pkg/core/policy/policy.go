// Package policy defines typed TrustPolicy definitions, strict YAML parsing,
// and version resolution for the assayward policy-decision core.
package policy

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode controls how policy violations are handled.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
	ModeWarn    Mode = "warn"
)

// Policy is the internal flat representation of a TrustPolicy document.
// It is the canonical type used by the engine; no alias exists elsewhere.
type Policy struct {
	APIVersion string
	Kind       string
	Name       string
	Version    string // surfaced in every Decision as Name+"@"+Version
	Mode       Mode
	Signature  SignatureRule
	SLSA       SLSARule
	VEX        VEXRule
	SBOM       SBOMRule
	Identity   IdentityRule
}

// SignatureRule controls image signature requirements.
type SignatureRule struct {
	Required bool
	Keyless  *KeylessRule
	Rekor    RekorRule
}

// KeylessRule configures keyless (Sigstore) signature verification.
type KeylessRule struct {
	Issuer          string
	IdentityPattern string
}

// RekorRule controls Rekor transparency-log requirements.
type RekorRule struct {
	Required bool
}

// SLSARule controls SLSA provenance requirements.
type SLSARule struct {
	MinLevel        int
	AllowedBuilders []string
}

// VEXRule controls vulnerability-exploitability requirements.
type VEXRule struct {
	MaxUnmitigatedSeverity string
}

// SBOMRule controls software bill-of-materials requirements.
type SBOMRule struct {
	Required           bool
	DisallowedLicenses []string
}

// IdentityRule controls workload-identity requirements.
type IdentityRule struct {
	Required    bool
	TrustDomain string
	IDPattern   string
}

// ---------------------------------------------------------------------------
// Wire types — the nested YAML structure on disk.
// These are private; only Parse exposes a Policy to callers.
// ---------------------------------------------------------------------------

type wireDoc struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   wireMetadata `yaml:"metadata"`
	Spec       wireSpec     `yaml:"spec"`
}

type wireMetadata struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

type wireSpec struct {
	Mode      Mode              `yaml:"mode"`
	Signature wireSignatureRule `yaml:"signature"`
	SLSA      wireSLSARule      `yaml:"slsa"`
	VEX       wireVEXRule       `yaml:"vex"`
	SBOM      wireSBOMRule      `yaml:"sbom"`
	Identity  wireIdentityRule  `yaml:"identity"`
}

type wireSignatureRule struct {
	Required bool             `yaml:"required"`
	Keyless  *wireKeylessRule `yaml:"keyless"`
	Rekor    wireRekorRule    `yaml:"rekor"`
}

type wireKeylessRule struct {
	Issuer          string `yaml:"issuer"`
	IdentityPattern string `yaml:"identityPattern"`
}

type wireRekorRule struct {
	Required bool `yaml:"required"`
}

type wireSLSARule struct {
	MinLevel        int      `yaml:"minLevel"`
	AllowedBuilders []string `yaml:"allowedBuilders"`
}

type wireVEXRule struct {
	MaxUnmitigatedSeverity string `yaml:"maxUnmitigatedSeverity"`
}

type wireSBOMRule struct {
	Required           bool     `yaml:"required"`
	DisallowedLicenses []string `yaml:"disallowedLicenses"`
}

type wireIdentityRule struct {
	Required    bool   `yaml:"required"`
	TrustDomain string `yaml:"trustDomain"`
	IDPattern   string `yaml:"idPattern"`
}

// Parse decodes a TrustPolicy YAML document into a Policy.
//
// Strict mode is enforced: any unknown field at any nesting level returns an
// error. This prevents silent misconfiguration, which is a security risk.
//
// Version resolution:
//   - If metadata.version is present, it is used as Policy.Version.
//   - Otherwise the version token of apiVersion is extracted (e.g. "v1alpha1"
//     from "assayward.dev/v1alpha1").
func Parse(b []byte) (Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)

	var w wireDoc
	if err := dec.Decode(&w); err != nil {
		return Policy{}, fmt.Errorf("policy: YAML decode error: %w", err)
	}

	version := w.Metadata.Version
	if version == "" {
		version = versionFromAPIVersion(w.APIVersion)
	}

	var keyless *KeylessRule
	if w.Spec.Signature.Keyless != nil {
		keyless = &KeylessRule{
			Issuer:          w.Spec.Signature.Keyless.Issuer,
			IdentityPattern: w.Spec.Signature.Keyless.IdentityPattern,
		}
	}

	p := Policy{
		APIVersion: w.APIVersion,
		Kind:       w.Kind,
		Name:       w.Metadata.Name,
		Version:    version,
		Mode:       w.Spec.Mode,
		Signature: SignatureRule{
			Required: w.Spec.Signature.Required,
			Keyless:  keyless,
			Rekor: RekorRule{
				Required: w.Spec.Signature.Rekor.Required,
			},
		},
		SLSA: SLSARule{
			MinLevel:        w.Spec.SLSA.MinLevel,
			AllowedBuilders: w.Spec.SLSA.AllowedBuilders,
		},
		VEX: VEXRule{
			MaxUnmitigatedSeverity: w.Spec.VEX.MaxUnmitigatedSeverity,
		},
		SBOM: SBOMRule{
			Required:           w.Spec.SBOM.Required,
			DisallowedLicenses: w.Spec.SBOM.DisallowedLicenses,
		},
		Identity: IdentityRule{
			Required:    w.Spec.Identity.Required,
			TrustDomain: w.Spec.Identity.TrustDomain,
			IDPattern:   w.Spec.Identity.IDPattern,
		},
	}

	return p, nil
}

// versionFromAPIVersion extracts the version token from an apiVersion string
// of the form "group/version" (e.g. "assayward.dev/v1alpha1" -> "v1alpha1").
// If no slash is present, the entire string is returned.
func versionFromAPIVersion(apiVersion string) string {
	if idx := strings.LastIndex(apiVersion, "/"); idx >= 0 {
		return apiVersion[idx+1:]
	}
	return apiVersion
}
