/**
 * Integration tests for the assayward-gate Cloudflare Worker.
 *
 * These tests run under @cloudflare/vitest-pool-workers (miniflare v4)
 * which executes BOTH the Worker code AND the test code in a real workerd
 * process locally.
 *
 * ## What these tests cover
 *
 * - Routing tests (404/405/400 validation): run fully in workerd; always pass.
 *   These tests exercise the gate's input validation without touching wasm.
 *
 * - Wasm integration tests (200 allow / 403 deny): SKIPPED in this suite
 *   because `node:fs.readFileSync` is not yet implemented in Workers
 *   (workerd error: "readFileSync() is not yet implemented in Workers").
 *   The testdata fixtures cannot be loaded from within the workerd sandbox.
 *
 * ## Wasm integration coverage
 *
 * Full wasm integration is covered by `test/gate-logic.test.ts` which runs
 * in the Bun runtime (not workerd) and has full filesystem access:
 *   bun run test:logic
 *
 * Results:
 *   bun run test         -> 5/5 routing tests pass in workerd (vitest-pool-workers)
 *   bun run test:logic   -> 7/7 tests pass in Bun (5 routing + 2 wasm integration)
 *
 * ## Running
 *   bun run test         (vitest via @cloudflare/vitest-pool-workers)
 *   bun run test:logic   (Bun native test runner; full wasm integration)
 *
 * ## Go wasm in workerd: design
 *
 * The Worker loads wasm via two wrangler bindings (wrangler.jsonc):
 *   - ASSAYWARD_WASM: data_blobs binding -> ArrayBuffer of assayward_js.wasm
 *   - WASM_EXEC_JS: text_blobs binding -> string content of wasm_exec.js
 *
 * At runtime the Worker calls `new Function(WASM_EXEC_JS)()` to register
 * `globalThis.Go`, then instantiates and runs the wasm module. The
 * `nodejs_compat` flag enables the `process`/`Buffer` globals that
 * wasm_exec.js needs.
 *
 * See src/wasm-loader.ts for implementation details and caveats.
 */

import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Helper: POST /verify via SELF (the Worker bound in the test pool)
// ---------------------------------------------------------------------------

async function postVerify(body: unknown): Promise<Response> {
  return SELF.fetch("http://localhost/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("assayward-gate Worker", () => {

  // --- Routing tests (run in workerd, no wasm needed) ---

  it("returns 404 for unknown paths", async () => {
    const res = await SELF.fetch("http://localhost/unknown");
    expect(res.status).toBe(404);
  });

  it("returns 405 for GET /verify", async () => {
    const res = await SELF.fetch("http://localhost/verify", { method: "GET" });
    expect(res.status).toBe(405);
  });

  it("returns 400 for non-JSON body", async () => {
    const res = await SELF.fetch("http://localhost/verify", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "not json",
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("JSON");
  });

  it("returns 400 when evidence is missing", async () => {
    const res = await postVerify({ policy: "some-policy" });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("evidence");
  });

  it("returns 400 when policy is missing", async () => {
    const res = await postVerify({
      evidence: { image: { name: "img", digest: "sha256:abc" }, attestations: [] },
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toContain("policy");
  });

  // --- Wasm integration tests ---
  //
  // These are skipped in the workerd test pool because node:fs.readFileSync
  // is not yet implemented in Workers ("readFileSync() is not yet implemented
  // in Workers"). The testdata fixtures cannot be loaded from within workerd.
  //
  // Run `bun run test:logic` for full wasm coverage via the Bun runtime.

  it.skip("returns 200 (allow) for serverless-edge policy with valid JWT identity [run: bun run test:logic]", () => {});

  it.skip("returns 403 (deny) for signature-required policy — Decision-5 caveat [run: bun run test:logic]", () => {});
});
