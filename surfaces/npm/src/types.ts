/**
 * TypeScript types mirroring core.Decision and the ABI envelope.
 * Field names follow the Go JSON tags in pkg/core/model.go.
 * []byte fields (envelope, raw, sigstoreTUF, spiffeBundles values) are
 * base64 strings in JSON.
 */

export type Result = "allow" | "deny" | "audit";
export type Severity = "low" | "medium" | "high" | "critical";
export type SVIDType = "jwt" | "x509";

export interface ImageRef {
  /** registry/repo:tag */
  name: string;
  /** sha256:... */
  digest: string;
}

export interface Attestation {
  predicateType: string;
  /** DSSE envelope bytes, base64-encoded */
  envelope: string;
  /** Set only by a verify stage outside wasm */
  verified?: boolean;
  signatureNote?: string;
}

export interface WorkloadIdentity {
  spiffeID: string;
  svidType: SVIDType;
  claims?: Record<string, unknown>;
  verified?: boolean;
  /**
   * Raw SVID credential: compact JWT token bytes (JWT) or PEM cert chain (X509).
   * Base64-encoded in JSON.
   */
  raw?: string;
}

/**
 * TrustRoots carries injected trust material.
 * SigstoreTUF and spiffeBundles values are base64-encoded bytes.
 */
export interface TrustRoots {
  /** Base64-encoded Sigstore TUF root JSON */
  sigstoreTUF?: string;
  /** trustDomain -> base64-encoded JWKS/PEM bundle */
  spiffeBundles?: Record<string, string>;
}

export interface Evidence {
  image: ImageRef;
  attestations: Attestation[];
  identity?: WorkloadIdentity;
  /** RFC3339; injected, not read from a clock */
  fetchedAt?: string;
}

export interface Reason {
  /** Stable machine-readable code, e.g. IDENTITY_REQUIRED_MISSING */
  code: string;
  severity: Severity;
  detail: string;
  met: boolean;
}

export interface EvidenceSummary {
  image: ImageRef;
  attestationTypes: string[];
  identityPresent: boolean;
  spiffeID?: string;
}

export interface Decision {
  result: Result;
  /** "name@version" of the policy that decided */
  policy: string;
  /** Sorted by Code for determinism */
  reasons: Reason[];
  evidence: EvidenceSummary;
  /** RFC3339 */
  decidedAt: string;
}

/** Returned by assayEvaluate on error (instead of throwing) */
export interface WasmError {
  error: string;
}
