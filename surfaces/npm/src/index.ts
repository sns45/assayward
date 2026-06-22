/**
 * assayward — TypeScript wrapper around the assayward js/wasm core.
 *
 * The module loads dist/wasm_exec.js (Go's runtime glue) and
 * dist/assayward_js.wasm once, caches the instance, then exposes a single
 * async function `assay()` that marshals Evidence + policy into the ABI
 * envelope, calls the synchronous `globalThis.assayEvaluate`, and
 * JSON-parses the Decision.
 *
 * No business logic lives here — this is a thin ABI shim.
 */

import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import type { Decision, Evidence, TrustRoots, WasmError } from "./types.ts";
export type { Decision, Evidence, TrustRoots, Reason, EvidenceSummary, ImageRef, Attestation, WorkloadIdentity } from "./types.ts";

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Resolve wasm artifacts relative to this file.
 *
 * During development / testing:   surfaces/npm/src/ -> ../../dist/
 * After publishing (npm pack):    dist/ -> bundled wasm alongside dist/index.js
 *
 * Publishing note: run `npm pack` (or `bun pack`) after copying or symlinking
 * the two wasm artifacts into surfaces/npm/dist/ so they travel with the
 * package.  The `files` field in package.json includes dist/ for exactly this
 * purpose.
 */
function resolveWasmPath(filename: string): string {
  // Try adjacent to this compiled file first (published package layout).
  const adjacent = resolve(__dirname, filename);
  try {
    // existsSync is not imported; use Bun.file().size instead (works in bun/node)
    const { statSync } = require("node:fs") as typeof import("node:fs");
    statSync(adjacent);
    return adjacent;
  } catch {
    // Fall back to repo dist/ (development / test layout).
    return resolve(__dirname, "..", "..", "..", "dist", filename);
  }
}

// ---------------------------------------------------------------------------
// Go wasm_exec loader
// ---------------------------------------------------------------------------

// wasm_exec.js is a self-contained IIFE that sets globalThis.Go.
// We load it once at module init time by reading the file and evaluating it.
let wasmExecLoaded = false;

function ensureWasmExecLoaded(): void {
  if (wasmExecLoaded) return;
  const wasmExecPath = resolveWasmPath("wasm_exec.js");
  const src = readFileSync(wasmExecPath, "utf8");
  // eslint-disable-next-line no-new-func
  new Function(src)();
  wasmExecLoaded = true;
}

// ---------------------------------------------------------------------------
// Module-level cache: we only want one Go runtime + wasm instance alive.
// ---------------------------------------------------------------------------

interface GoRuntime {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  importObject: Record<string, any>;
  run(instance: WebAssembly.Instance): Promise<void>;
}

let cachedAssayEvaluate: ((json: string) => string) | null = null;
let initPromise: Promise<void> | null = null;

async function initWasm(): Promise<void> {
  if (cachedAssayEvaluate) return;

  ensureWasmExecLoaded();

  // globalThis.Go is set by wasm_exec.js
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const GoClass = (globalThis as any).Go as new () => GoRuntime;
  if (!GoClass) {
    throw new Error(
      "assayward: globalThis.Go not found after loading wasm_exec.js",
    );
  }

  const go = new GoClass();

  const wasmPath = resolveWasmPath("assayward_js.wasm");
  const wasmBytes = readFileSync(wasmPath);

  const result = await WebAssembly.instantiate(wasmBytes, go.importObject);

  // go.run() is async and only resolves when the Go program exits.
  // Go's main() calls select{} so it never exits — the promise never resolves.
  // We fire-and-forget it; the function is registered synchronously during run().
  // We use a small race: call run() and then poll for assayEvaluate.
  go.run(result.instance).catch(() => {
    // The Go runtime exiting is an error state; reset cache so next call retries.
    cachedAssayEvaluate = null;
    initPromise = null;
  });

  // go.run() calls this._inst.exports.run() synchronously before awaiting
  // _exitPromise, which means assayEvaluate is registered on globalThis
  // synchronously as part of the first tick of Go's goroutine scheduler.
  // We yield once to let the Go goroutine register the function.
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = (globalThis as any).assayEvaluate as
    | ((json: string) => string)
    | undefined;
  if (typeof fn !== "function") {
    throw new Error(
      "assayward: globalThis.assayEvaluate not registered after wasm init. " +
        "The Go wasm module may have exited early.",
    );
  }

  cachedAssayEvaluate = fn;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Evaluate a trust policy against evidence using the assayward wasm engine.
 *
 * @param evidence   The supply-chain evidence for an image.
 * @param policy     The full TrustPolicy document as a YAML (or JSON) string.
 * @param trustRoots Optional trust material (Sigstore TUF root, SPIFFE bundles).
 * @param now        Optional RFC3339 timestamp used as the evaluation clock.
 *                   Defaults to the current time.
 * @returns          The Decision from the policy engine.
 *
 * @throws           If the wasm module fails to initialize or returns an error object.
 *
 * Decision-5 caveat: when a policy sets `signature.required: true` the wasm
 * engine returns `deny` with reason code `SIGNATURE_VERIFICATION_UNAVAILABLE`
 * because `sigstore-go` cannot be compiled to wasm. Use the native CLI for
 * full signature verification.
 */
export async function assay(
  evidence: Evidence,
  policy: string,
  trustRoots?: TrustRoots,
  now?: string,
): Promise<Decision> {
  // Serialize init so concurrent calls don't instantiate twice.
  if (!initPromise) {
    initPromise = initWasm();
  }
  await initPromise;

  const evaluate = cachedAssayEvaluate!;

  const envelope = {
    evidence,
    policy,
    trustRoots: trustRoots ?? {},
    now: now ?? new Date().toISOString(),
  };

  const resultJSON = evaluate(JSON.stringify(envelope));

  const parsed = JSON.parse(resultJSON) as Decision | WasmError;

  if ("error" in parsed && typeof (parsed as WasmError).error === "string") {
    throw new Error(`assayward wasm error: ${(parsed as WasmError).error}`);
  }

  return parsed as Decision;
}
