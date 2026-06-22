/**
 * TypeScript types for the assayward gate Worker.
 * These mirror surfaces/npm/src/types.ts and pkg/core/model.go.
 * Kept local to avoid a runtime dependency on the npm package.
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
  /** Set only by a pre-verify stage outside wasm */
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
  /** RFC3339 */
  fetchedAt?: string;
}

export interface Reason {
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
  policy: string;
  reasons: Reason[];
  evidence: EvidenceSummary;
  decidedAt: string;
}

export interface WasmError {
  error: string;
}
