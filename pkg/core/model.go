package core

import "time"

type Result string

const (
	ResultAllow Result = "allow"
	ResultDeny  Result = "deny"
	ResultAudit Result = "audit"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type SVIDType string

const (
	SVIDTypeJWT  SVIDType = "jwt"
	SVIDTypeX509 SVIDType = "x509"
)

type ImageRef struct {
	Name   string `json:"name"`   // registry/repo:tag
	Digest string `json:"digest"` // sha256:...
}

type Evidence struct {
	Image        ImageRef          `json:"image"`
	Attestations []Attestation     `json:"attestations"`
	Identity     *WorkloadIdentity `json:"identity,omitempty"`
	FetchedAt    time.Time         `json:"fetchedAt"` // injected, not read from a clock
}

type Attestation struct {
	PredicateType string `json:"predicateType"`
	Envelope      []byte `json:"envelope"` // DSSE
	Verified      bool   `json:"verified"` // set ONLY by a verify stage
	SignatureNote string `json:"signatureNote,omitempty"`
}

type WorkloadIdentity struct {
	SPIFFEID string         `json:"spiffeID"`
	SVIDType SVIDType       `json:"svidType"`
	Claims   map[string]any `json:"claims"`
	Verified bool           `json:"verified"`
}

type Reason struct {
	Code     string   `json:"code"` // stable machine-readable, e.g. SLSA_LEVEL_BELOW_THRESHOLD
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
	Met      bool     `json:"met"`
}

type EvidenceSummary struct {
	Image            ImageRef `json:"image"`
	AttestationTypes []string `json:"attestationTypes"`
	IdentityPresent  bool     `json:"identityPresent"`
	SPIFFEID         string   `json:"spiffeID,omitempty"`
}

type Decision struct {
	Result    Result          `json:"result"`
	Policy    string          `json:"policy"`  // name@version that decided
	Reasons   []Reason        `json:"reasons"` // sorted by Code for determinism
	Evidence  EvidenceSummary `json:"evidence"`
	DecidedAt time.Time       `json:"decidedAt"` // from injected Clock
}

// TrustRoots carries injected trust material (Fulcio/Rekor roots, SPIFFE bundles).
// Opaque to the policy layer; consumed only by verify stages.
type TrustRoots struct {
	SigstoreTUF   []byte            `json:"sigstoreTUF,omitempty"`
	SPIFFEBundles map[string][]byte `json:"spiffeBundles,omitempty"` // trustDomain -> JWKS/PEM
}
