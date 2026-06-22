/**
 * Logic tests for the gate handler — runs in Node.js/Bun (NOT in workerd).
 *
 * These tests exercise the gate's routing logic and wasm integration by
 * calling the handler function directly, bypassing the vitest-pool-workers
 * sandbox. This allows full filesystem access to testdata and wasm assets.
 *
 * To run these tests:
 *   bun test:logic
 *
 * Note: These tests import the Worker handler which in turn imports wasm-loader.ts.
 * The wasm-loader.ts uses `ASSAYWARD_WASM` and `WASM_EXEC_JS` bindings which are
 * declared as globals (declare const). In the Bun runtime, these don't exist,
 * so we stub them via globalThis before importing the handler.
 *
 * ## Design
 *
 * The gate handler has exactly two moving parts:
 *   1. Routing / input validation (no wasm needed)
 *   2. The wasm assayEvaluate call
 *
 * For (1) we test directly using a fake `assayEvaluate`.
 * For (2) we test using the real wasm via the npm surface (`surfaces/npm`).
 *
 * The `assay()` function from surfaces/npm/src/index.ts is the authoritative
 * wasm integration test. The vitest-pool-workers tests (gate.test.ts) verify
 * the routing contract in a real workerd environment.
 */

import { test, expect, describe, beforeAll } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ESM __dirname shim
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const templateDir = resolve(__dirname, "..");
const repoRoot = resolve(templateDir, "..", "..");

const testdataRoot = resolve(repoRoot, "testdata");
const policyPath = resolve(
  repoRoot,
  "pkg",
  "core",
  "policy",
  "builtin",
  "serverless-edge.yaml",
);

// ---------------------------------------------------------------------------
// Inject fake bindings so wasm-loader.ts globals are defined
// (wrangler injects these as module-scope globals in workerd)
// ---------------------------------------------------------------------------

const wasmBytes = readFileSync(
  resolve(repoRoot, "dist", "assayward_js.wasm"),
).buffer;
const wasmExecSrc = readFileSync(
  resolve(repoRoot, "dist", "wasm_exec.js"),
  "utf8",
);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).ASSAYWARD_WASM = wasmBytes;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).WASM_EXEC_JS = wasmExecSrc;

// ---------------------------------------------------------------------------
// Import the Worker handler AFTER setting globals
// ---------------------------------------------------------------------------

// Dynamic import so globals are set first
const { default: worker } = await import("../src/index.js");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function b64(filePath: string): string {
  return readFileSync(filePath).toString("base64");
}

const TEST_IMAGE_NAME = "ghcr.io/sns45/example:1.0.0";
const TEST_IMAGE_DIGEST =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const GOLDEN_NOW = "2026-01-01T00:00:00Z";

function makeRequest(body: unknown): Request {
  return new Request("http://localhost/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Minimal stub env/ctx for the ExportedHandler signature
const fakeEnv = {};
const fakeCtx = {
  waitUntil: (_p: Promise<unknown>) => {},
  passThroughOnException: () => {},
} as unknown as ExecutionContext;

// ---------------------------------------------------------------------------
// Routing tests
// ---------------------------------------------------------------------------

describe("gate routing (Bun runtime)", () => {
  test("404 for unknown path", async () => {
    const res = await worker.fetch(
      new Request("http://localhost/health"),
      fakeEnv,
      fakeCtx,
    );
    expect(res.status).toBe(404);
  });

  test("405 for GET /verify", async () => {
    const res = await worker.fetch(
      new Request("http://localhost/verify", { method: "GET" }),
      fakeEnv,
      fakeCtx,
    );
    expect(res.status).toBe(405);
  });

  test("400 for non-JSON body", async () => {
    const res = await worker.fetch(
      new Request("http://localhost/verify", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "bad",
      }),
      fakeEnv,
      fakeCtx,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("JSON");
  });

  test("400 when evidence missing", async () => {
    const res = await worker.fetch(
      makeRequest({ policy: "some-policy" }),
      fakeEnv,
      fakeCtx,
    );
    expect(res.status).toBe(400);
  });

  test("400 when policy missing", async () => {
    const res = await worker.fetch(
      makeRequest({
        evidence: {
          image: { name: "img", digest: "sha256:abc" },
          attestations: [],
        },
      }),
      fakeEnv,
      fakeCtx,
    );
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Wasm integration tests (uses real wasm via globalThis.ASSAYWARD_WASM)
// ---------------------------------------------------------------------------

describe("gate wasm integration (Bun runtime)", () => {
  let policyYaml: string;

  beforeAll(() => {
    policyYaml = readFileSync(policyPath, "utf8");
  });

  test("200 (allow) for serverless-edge policy with valid JWT identity", async () => {
    const body = {
      evidence: {
        image: { name: TEST_IMAGE_NAME, digest: TEST_IMAGE_DIGEST },
        attestations: [
          {
            predicateType: "sigstore-bundle",
            envelope: b64(
              resolve(testdataRoot, "signature", "bundle-provenance.json"),
            ),
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
            envelope: b64(
              resolve(testdataRoot, "vex", "affected-critical.dsse.json"),
            ),
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
      },
      policy: policyYaml,
      trustRoots: {
        sigstoreTUF: b64(
          resolve(
            testdataRoot,
            "signature",
            "trusted-root-public-good.json",
          ),
        ),
        spiffeBundles: {
          "sns45.dev": b64(resolve(testdataRoot, "svid", "jwt-bundle.json")),
        },
      },
      now: GOLDEN_NOW,
    };

    const res = await worker.fetch(makeRequest(body), fakeEnv, fakeCtx);
    expect(res.status).toBe(200);

    const decision = (await res.json()) as {
      result: string;
      policy: string;
      evidence: { image: { name: string }; identityPresent: boolean };
      decidedAt: string;
    };
    expect(decision.result).toBe("allow");
    expect(decision.policy).toBe("serverless-edge@v1alpha1");
    expect(decision.evidence.image.name).toBe(TEST_IMAGE_NAME);
    expect(decision.evidence.identityPresent).toBe(true);
    expect(decision.decidedAt).toBe(GOLDEN_NOW);
  });

  test("403 (deny) for signature-required policy (Decision-5 caveat)", async () => {
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

    const body = {
      evidence: {
        image: { name: TEST_IMAGE_NAME, digest: TEST_IMAGE_DIGEST },
        attestations: [
          {
            predicateType: "sigstore-bundle",
            envelope: b64(
              resolve(testdataRoot, "signature", "bundle-provenance.json"),
            ),
          },
        ],
        fetchedAt: GOLDEN_NOW,
      },
      policy: signaturePolicyYaml,
      trustRoots: {},
      now: GOLDEN_NOW,
    };

    const res = await worker.fetch(makeRequest(body), fakeEnv, fakeCtx);
    expect(res.status).toBe(403);

    const decision = (await res.json()) as {
      result: string;
      reasons: Array<{ code: string; met: boolean }>;
    };
    expect(decision.result).toBe("deny");
    const sigReason = decision.reasons.find(
      (r) => r.code === "SIGNATURE_VERIFICATION_UNAVAILABLE",
    );
    expect(sigReason).toBeDefined();
    expect(sigReason?.met).toBe(false);
  });
});
