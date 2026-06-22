// Package policy defines typed TrustPolicy definitions, strict YAML parsing,
// version resolution, and the native typed policy evaluator for the assayward
// policy-decision core.
package policy

import (
	"regexp"
	"sort"
	"strings"

	core "github.com/sns45/assayward/pkg/core"
)

// ---------------------------------------------------------------------------
// View types — policy-visible projections of verify-stage results.
// These are scalars and booleans only; the policy layer never sees envelopes
// or raw cryptographic material (§4 of the architecture spec).
// ---------------------------------------------------------------------------

// SignatureResultView is the policy-visible projection of a signature
// verification run. Available is false when the verifier could not run at all
// (e.g. wasm stub environment), in which case Verified is always false.
type SignatureResultView struct {
	Available       bool // false when signature verification could not run (e.g. wasm stub)
	Verified        bool
	Issuer          string
	SubjectIdentity string
	RekorLogged     bool
}

// SLSAView is the policy-visible projection of a SLSA provenance verification.
type SLSAView struct {
	Verified           bool
	BuilderID          string
	BuildLevel         int
	SubjectDigestMatch bool
}

// SBOMView is the policy-visible projection of an SBOM scan.
// Licenses contains all license identifiers found across all components.
type SBOMView struct {
	Present  bool
	Licenses []string // license identifiers across all components
}

// VEXView is the policy-visible projection of a VEX document scan.
// AffectedCVEs contains CVE IDs where the VEX status is "affected".
type VEXView struct {
	Present      bool
	AffectedCVEs []string // CVE IDs with status "affected"
}

// IdentityView is the policy-visible projection of a workload identity
// verification.
type IdentityView struct {
	Present      bool
	Verified     bool
	SPIFFEID     string
	TrustDomain  string
	BindingMatch bool
}

// ---------------------------------------------------------------------------
// EvaluatePolicy is the security decision core.
//
// It evaluates the verified stage results (expressed as *View projections)
// against pol and returns a Result and a sorted slice of Reasons.
//
// Reason emission rules:
//   - A Reason is emitted only for a check that the policy actually requests.
//   - Both passing (Met=true) and failing (Met=false) checks emit a Reason so
//     the decision is fully explainable.
//   - Reasons are sorted by Code (deterministic).
//
// Mode semantics:
//   - ModeEnforce: ResultDeny if any Met=false, else ResultAllow.
//   - ModeAudit:   ResultAudit always (decision logged, never blocked).
//   - ModeWarn:    ResultAllow always; unmet checks remain in Reasons as warnings.
//
// ---------------------------------------------------------------------------
func EvaluatePolicy(
	pol Policy,
	sig SignatureResultView,
	slsa SLSAView,
	sbom SBOMView,
	vex VEXView,
	id IdentityView,
) (core.Result, []core.Reason) {

	var reasons []core.Reason
	emit := func(r core.Reason) { reasons = append(reasons, r) }

	// -----------------------------------------------------------------------
	// Signature checks
	// -----------------------------------------------------------------------

	// sigChecksRequested is true when any signature-dependent check is configured.
	// When the verifier could not run (sig.Available==false) we collapse all
	// signature checks into a single SIGNATURE_VERIFICATION_UNAVAILABLE to avoid
	// both misleading dual-codes and a fail-open hole (e.g. Rekor.Required==true
	// but Available==false would otherwise silently allow).
	sigChecksRequested := pol.Signature.Required || pol.Signature.Rekor.Required || pol.Signature.Keyless != nil

	if sigChecksRequested && !sig.Available {
		// SIGNATURE_VERIFICATION_UNAVAILABLE (Critical): the verifier could not
		// run; any signature-dependent check cannot be meaningfully evaluated.
		// Emit ONLY this code and skip the individual sub-checks below.
		emit(core.Reason{
			Code:     "SIGNATURE_VERIFICATION_UNAVAILABLE",
			Severity: core.SeverityCritical,
			Detail:   "signature verification is required but the verifier was unavailable",
			Met:      false,
		})
	} else if sig.Available {
		// Verifier ran — evaluate individual signature sub-checks.

		// SIGNATURE_REQUIRED_MISSING (High): verifier ran but found no valid signature.
		if pol.Signature.Required {
			if !sig.Verified {
				emit(core.Reason{
					Code:     "SIGNATURE_REQUIRED_MISSING",
					Severity: core.SeverityHigh,
					Detail:   "signature is required but no valid signature was found",
					Met:      false,
				})
			} else {
				emit(core.Reason{
					Code:     "SIGNATURE_REQUIRED_MISSING",
					Severity: core.SeverityHigh,
					Detail:   "signature verified",
					Met:      true,
				})
			}
		}

		// SIGNATURE_IDENTITY_MISMATCH (High): keyless rule set, sig verified, but
		// issuer or subject identity does not match.
		if pol.Signature.Keyless != nil {
			if sig.Verified {
				issuerOK := sig.Issuer == pol.Signature.Keyless.Issuer
				patternOK := globMatch(pol.Signature.Keyless.IdentityPattern, sig.SubjectIdentity)
				if !issuerOK || !patternOK {
					emit(core.Reason{
						Code:     "SIGNATURE_IDENTITY_MISMATCH",
						Severity: core.SeverityHigh,
						Detail:   "signature issuer or subject identity does not match the keyless policy",
						Met:      false,
					})
				} else {
					emit(core.Reason{
						Code:     "SIGNATURE_IDENTITY_MISMATCH",
						Severity: core.SeverityHigh,
						Detail:   "signature issuer and subject identity match the keyless policy",
						Met:      true,
					})
				}
			}
			// When sig.Verified is false and Keyless is set, the SIGNATURE_REQUIRED_MISSING
			// check has already fired; we do not emit SIGNATURE_IDENTITY_MISMATCH on top of it.
		}

		// REKOR_REQUIRED_MISSING (High): Rekor transparency log entry required but
		// the signature was not logged.
		if pol.Signature.Rekor.Required {
			if !sig.RekorLogged {
				emit(core.Reason{
					Code:     "REKOR_REQUIRED_MISSING",
					Severity: core.SeverityHigh,
					Detail:   "Rekor transparency log entry is required but was not found",
					Met:      false,
				})
			} else {
				emit(core.Reason{
					Code:     "REKOR_REQUIRED_MISSING",
					Severity: core.SeverityHigh,
					Detail:   "Rekor transparency log entry present",
					Met:      true,
				})
			}
		}
	}

	// -----------------------------------------------------------------------
	// SLSA provenance checks
	// -----------------------------------------------------------------------

	slsaInScope := pol.SLSA.MinLevel > 0 || len(pol.SLSA.AllowedBuilders) > 0

	// SLSA_LEVEL_BELOW_THRESHOLD (High): build level does not meet minimum.
	if pol.SLSA.MinLevel > 0 {
		if slsa.BuildLevel < pol.SLSA.MinLevel {
			emit(core.Reason{
				Code:     "SLSA_LEVEL_BELOW_THRESHOLD",
				Severity: core.SeverityHigh,
				Detail:   "SLSA build level is below the required minimum",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "SLSA_LEVEL_BELOW_THRESHOLD",
				Severity: core.SeverityHigh,
				Detail:   "SLSA build level meets the required minimum",
				Met:      true,
			})
		}
	}

	// SLSA_BUILDER_NOT_ALLOWED (High): builder not in the allowed list.
	if len(pol.SLSA.AllowedBuilders) > 0 {
		if !anyGlobMatch(pol.SLSA.AllowedBuilders, slsa.BuilderID) {
			emit(core.Reason{
				Code:     "SLSA_BUILDER_NOT_ALLOWED",
				Severity: core.SeverityHigh,
				Detail:   "SLSA builder is not in the allowed builders list",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "SLSA_BUILDER_NOT_ALLOWED",
				Severity: core.SeverityHigh,
				Detail:   "SLSA builder is in the allowed builders list",
				Met:      true,
			})
		}
	}

	// SUBJECT_DIGEST_MISMATCH (Critical): only checked when SLSA is in scope.
	// A mismatch means the provenance does not describe the artifact being evaluated,
	// which is a critical integrity failure.
	if slsaInScope {
		if !slsa.SubjectDigestMatch {
			emit(core.Reason{
				Code:     "SUBJECT_DIGEST_MISMATCH",
				Severity: core.SeverityCritical,
				Detail:   "the SLSA provenance subject digest does not match the artifact digest",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "SUBJECT_DIGEST_MISMATCH",
				Severity: core.SeverityCritical,
				Detail:   "SLSA provenance subject digest matches the artifact digest",
				Met:      true,
			})
		}
	}

	// -----------------------------------------------------------------------
	// VEX checks
	// -----------------------------------------------------------------------

	// VEX_UNMITIGATED_CRITICAL (Critical): any CVE with status "affected" is
	// treated as unmitigated in v0.1 semantics. Severity-aware gating (joining
	// SBOM CVE severity data) is deferred to a future minor version — at that
	// point MaxUnmitigatedSeverity will be compared against the actual CVSS
	// severity of each affected CVE rather than acting as a binary gate.
	if pol.VEX.MaxUnmitigatedSeverity != "" {
		if len(vex.AffectedCVEs) > 0 {
			emit(core.Reason{
				Code:     "VEX_UNMITIGATED_CRITICAL",
				Severity: core.SeverityCritical,
				Detail:   "one or more CVEs have VEX status 'affected' (unmitigated)",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "VEX_UNMITIGATED_CRITICAL",
				Severity: core.SeverityCritical,
				Detail:   "no unmitigated CVEs found",
				Met:      true,
			})
		}
	}

	// -----------------------------------------------------------------------
	// SBOM checks
	// -----------------------------------------------------------------------

	// SBOM_REQUIRED_MISSING (High): SBOM is required but not present.
	if pol.SBOM.Required {
		if !sbom.Present {
			emit(core.Reason{
				Code:     "SBOM_REQUIRED_MISSING",
				Severity: core.SeverityHigh,
				Detail:   "SBOM is required but was not found",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "SBOM_REQUIRED_MISSING",
				Severity: core.SeverityHigh,
				Detail:   "SBOM is present",
				Met:      true,
			})
		}
	}

	// SBOM_DISALLOWED_LICENSE (Medium): a license in the SBOM matches the
	// disallowed list.
	if len(pol.SBOM.DisallowedLicenses) > 0 {
		if len(intersect(sbom.Licenses, pol.SBOM.DisallowedLicenses)) > 0 {
			emit(core.Reason{
				Code:     "SBOM_DISALLOWED_LICENSE",
				Severity: core.SeverityMedium,
				Detail:   "one or more disallowed licenses found in the SBOM",
				Met:      false,
			})
		} else {
			emit(core.Reason{
				Code:     "SBOM_DISALLOWED_LICENSE",
				Severity: core.SeverityMedium,
				Detail:   "no disallowed licenses found in the SBOM",
				Met:      true,
			})
		}
	}

	// -----------------------------------------------------------------------
	// Identity checks
	// -----------------------------------------------------------------------

	// IDENTITY_REQUIRED_MISSING (High): identity required but not present or
	// verification failed.
	if pol.Identity.Required {
		identityOK := id.Present && id.Verified
		emit(core.Reason{
			Code:     "IDENTITY_REQUIRED_MISSING",
			Severity: core.SeverityHigh,
			Detail: func() string {
				if !identityOK {
					return "workload identity is required but was not present or could not be verified"
				}
				return "workload identity is present and verified"
			}(),
			Met: identityOK,
		})

		if identityOK {
			// IDENTITY_TRUST_DOMAIN_MISMATCH (High): identity is not within the
			// allowed trust domain or does not match the ID pattern. Emitted only
			// when a trust domain or ID pattern constraint is configured.
			if pol.Identity.TrustDomain != "" || pol.Identity.IDPattern != "" {
				trustOK := pol.Identity.TrustDomain == "" || id.TrustDomain == pol.Identity.TrustDomain
				patternOK := pol.Identity.IDPattern == "" || globMatch(pol.Identity.IDPattern, id.SPIFFEID)
				domainMatch := trustOK && patternOK
				emit(core.Reason{
					Code:     "IDENTITY_TRUST_DOMAIN_MISMATCH",
					Severity: core.SeverityHigh,
					Detail: func() string {
						if !domainMatch {
							return "identity is not within the allowed trust domain or does not match the ID pattern"
						}
						return "identity trust domain and ID pattern match"
					}(),
					Met: domainMatch,
				})
			}

			// IDENTITY_BINDING_MISMATCH (High): identity is verified but the binding
			// to the artifact does not match.
			// v0.1: binding is implicitly required whenever identity is required (fail-closed); an opt-out knob is deferred.
			emit(core.Reason{
				Code:     "IDENTITY_BINDING_MISMATCH",
				Severity: core.SeverityHigh,
				Detail: func() string {
					if !id.BindingMatch {
						return "workload identity binding does not match the artifact"
					}
					return "workload identity binding matches the artifact"
				}(),
				Met: id.BindingMatch,
			})
		}
	}

	// -----------------------------------------------------------------------
	// Sort reasons by Code for deterministic output.
	// -----------------------------------------------------------------------
	sort.SliceStable(reasons, func(i, j int) bool {
		return reasons[i].Code < reasons[j].Code
	})

	// -----------------------------------------------------------------------
	// Determine result based on mode.
	// -----------------------------------------------------------------------
	failed := false
	for _, r := range reasons {
		if !r.Met {
			failed = true
			break
		}
	}

	switch pol.Mode {
	case ModeEnforce:
		if failed {
			return core.ResultDeny, reasons
		}
		return core.ResultAllow, reasons
	case ModeAudit:
		// Audit: always allow, decision is logged; reasons (including failures) recorded.
		return core.ResultAudit, reasons
	case ModeWarn:
		// Warn: always allow; unmet checks remain in Reasons as warnings (Met=false).
		return core.ResultAllow, reasons
	default:
		// Treat unknown modes as enforce (fail-closed).
		if failed {
			return core.ResultDeny, reasons
		}
		return core.ResultAllow, reasons
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// globMatch reports whether pattern matches s. The only special character is
// '*' which matches any sequence of characters including '/'. Literal parts of
// the pattern are regexp-quoted. The match is anchored (full-string).
//
// An empty pattern matches any string.
//
// On a regexp compilation error (malformed pattern) the function returns false
// rather than panicking, so a bad policy pattern is a safe no-match.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return true
	}
	// Split on '*', quote literal parts, join with '.*'.
	parts := strings.Split(pattern, "*")
	regexParts := make([]string, len(parts))
	for i, p := range parts {
		regexParts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(regexParts, ".*") + "$")
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// anyGlobMatch reports whether s matches any of the patterns.
func anyGlobMatch(patterns []string, s string) bool {
	for _, p := range patterns {
		if globMatch(p, s) {
			return true
		}
	}
	return false
}

// intersect returns elements that appear in both a and b.
func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	var result []string
	for _, v := range a {
		if _, ok := set[v]; ok {
			result = append(result, v)
		}
	}
	return result
}
