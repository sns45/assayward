/**
 * Tests for the assayward npm wrapper.
 *
 * Prerequisites: `make wasm` must have been run from repo root so that
 * dist/assayward_js.wasm and dist/wasm_exec.js exist.
 * If either file is missing, tests skip with a descriptive message rather
 * than producing a false pass.
 */

import { test, expect, beforeAll, describe } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve paths relative to repo root (two levels up from surfaces/npm/).
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..", "..", "..");

const wasmPath = resolve(repoRoot, "dist", "assayward_js.wasm");
const wasmExecPath = resolve(repoRoot, "dist", "wasm_exec.js");
const testdataRoot = resolve(repoRoot, "testdata");
const policyPath = resolve(
  repoRoot,
  "pkg",
  "core",
  "policy",
  "builtin",
  "serverless-edge.yaml",
);

const wasmAvailable =
  existsSync(wasmPath) && existsSync(wasmExecPath) && existsSync(policyPath);

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

function b64(filePath: string): string {
  return readFileSync(filePath).toString("base64");
}

// -------------------------------------------------------------------
// Fixture constants (match testfix.go and golden_test.go)
// -------------------------------------------------------------------
const TEST_IMAGE_NAME = "ghcr.io/sns45/example:1.0.0";
const TEST_IMAGE_DIGEST =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const GOLDEN_NOW = "2026-01-01T00:00:00Z";

// -------------------------------------------------------------------
// Import the module under test (after TDD: types exist, impl to follow)
// -------------------------------------------------------------------
import { assay } from "./index.ts";
import type { Evidence, TrustRoots, Decision } from "./types.ts";

// -------------------------------------------------------------------
// RED: failing test written before implementation exists
// -------------------------------------------------------------------

describe("assayward npm wrapper", () => {
  beforeAll(() => {
    if (!wasmAvailable) {
      console.warn(
        "SKIP: wasm artifacts not found. Run `make wasm` from repo root first.",
      );
    }
  });

  test("assay() returns allow for serverless-edge with valid JWT identity", async () => {
    if (!wasmAvailable) {
      console.warn("SKIPPED: wasm not built");
      return;
    }

    const policyYaml = readFileSync(policyPath, "utf8");

    const evidence: Evidence = {
      image: { name: TEST_IMAGE_NAME, digest: TEST_IMAGE_DIGEST },
      attestations: [
        {
          predicateType: "sigstore-bundle",
          envelope: b64(resolve(testdataRoot, "signature", "bundle-provenance.json")),
        },
        {
          predicateType: "https://slsa.dev/provenance/v1",
          envelope: b64(resolve(testdataRoot, "slsa", "valid-l3.dsse.json")),
        },
        {
          predicateType: "https://cyclonedx.org/bom",
          envelope: b64(resolve(testdataRoot, "sbom", "cyclonedx.dsse.json")),
        },
        {
          predicateType: "https://openvex.dev/ns/v0.2.0",
          envelope: b64(resolve(testdataRoot, "vex", "affected-critical.dsse.json")),
        },
      ],
      identity: {
        spiffeID: "spiffe://sns45.dev/ci/release",
        svidType: "jwt",
        raw: b64(resolve(testdataRoot, "svid", "jwt-valid.jwt")),
        claims: {},
        verified: false,
      },
      fetchedAt: GOLDEN_NOW,
    };

    const trustRoots: TrustRoots = {
      sigstoreTUF: b64(
        resolve(testdataRoot, "signature", "trusted-root-public-good.json"),
      ),
      spiffeBundles: {
        "sns45.dev": b64(resolve(testdataRoot, "svid", "jwt-bundle.json")),
      },
    };

    const decision: Decision = await assay(
      evidence,
      policyYaml,
      trustRoots,
      GOLDEN_NOW,
    );

    expect(decision.result).toBe("allow");
    expect(decision.policy).toBe("serverless-edge@v1alpha1");

    // At least one identity reason should be met
    const identityReasons = decision.reasons.filter(
      (r) => r.code.startsWith("IDENTITY_") && r.met === true,
    );
    expect(identityReasons.length).toBeGreaterThan(0);

    // Evidence summary should match golden
    expect(decision.evidence.image.name).toBe(TEST_IMAGE_NAME);
    expect(decision.evidence.image.digest).toBe(TEST_IMAGE_DIGEST);
    expect(decision.evidence.identityPresent).toBe(true);
    expect(decision.decidedAt).toBe(GOLDEN_NOW);
  });

  test("assay() with signature-required policy yields SIGNATURE_VERIFICATION_UNAVAILABLE deny", async () => {
    if (!wasmAvailable) {
      console.warn("SKIPPED: wasm not built");
      return;
    }

    // Policy that requires signature verification (fail-closed caveat in wasm)
    const signaturePolicyYaml = `
apiVersion: assayward.dev/v1alpha1
kind: TrustPolicy
metadata:
  name: signature-required
spec:
  mode: enforce
  signature:
    required: true
`;

    const evidence: Evidence = {
      image: { name: TEST_IMAGE_NAME, digest: TEST_IMAGE_DIGEST },
      attestations: [
        {
          predicateType: "sigstore-bundle",
          envelope: b64(resolve(testdataRoot, "signature", "bundle-provenance.json")),
        },
      ],
      fetchedAt: GOLDEN_NOW,
    };

    const decision: Decision = await assay(
      evidence,
      signaturePolicyYaml,
      {},
      GOLDEN_NOW,
    );

    // Wasm fail-closed: signature verification unavailable -> deny
    expect(decision.result).toBe("deny");

    const sigReason = decision.reasons.find(
      (r) => r.code === "SIGNATURE_VERIFICATION_UNAVAILABLE",
    );
    expect(sigReason).toBeDefined();
    expect(sigReason?.met).toBe(false);
  });

  test("assay() called twice reuses the cached wasm instance", async () => {
    if (!wasmAvailable) {
      console.warn("SKIPPED: wasm not built");
      return;
    }

    const policyYaml = readFileSync(policyPath, "utf8");

    const evidence: Evidence = {
      image: { name: TEST_IMAGE_NAME, digest: TEST_IMAGE_DIGEST },
      attestations: [],
      identity: {
        spiffeID: "spiffe://sns45.dev/ci/release",
        svidType: "jwt",
        raw: b64(resolve(testdataRoot, "svid", "jwt-valid.jwt")),
        claims: {},
        verified: false,
      },
      fetchedAt: GOLDEN_NOW,
    };

    const trustRoots: TrustRoots = {
      spiffeBundles: {
        "sns45.dev": b64(resolve(testdataRoot, "svid", "jwt-bundle.json")),
      },
    };

    // Both calls should complete without error (second uses cached instance)
    const d1 = await assay(evidence, policyYaml, trustRoots, GOLDEN_NOW);
    const d2 = await assay(evidence, policyYaml, trustRoots, GOLDEN_NOW);

    expect(d1.result).toBe(d2.result);
    expect(d1.decidedAt).toBe(d2.decidedAt);
  });
});
