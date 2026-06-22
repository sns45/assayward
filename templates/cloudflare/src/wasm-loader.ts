/**
 * wasm-loader.ts — Go js/wasm loader for the Cloudflare Workers runtime.
 *
 * ## Background: why this is complex
 *
 * Go's js/wasm ABI (GOOS=js GOARCH=wasm) is designed for browser and Node.js
 * environments. It requires a runtime glue script (wasm_exec.js) that:
 *   - Registers a `Go` class on `globalThis`
 *   - Provides the `go.importObject` (WASM imports) that implement the Go
 *     scheduler, syscall shims, and JS interop
 *   - Calls `go.run(instance)` which keeps the Go runtime alive
 *
 * Cloudflare Workers (workerd) is NOT a browser or Node.js environment.
 * It runs a V8 isolate with a subset of Web APIs and (optionally) a subset
 * of Node.js APIs via the `nodejs_compat` compatibility flag.
 *
 * ## What works
 *
 * With `compatibility_flags: ["nodejs_compat"]`:
 *   - `globalThis.process` is available (Go runtime checks it)
 *   - `globalThis.Buffer` is available
 *   - `TextEncoder` / `TextDecoder` are available
 *   - `WebAssembly` is available
 *   - `setTimeout` is available
 *
 * wasm_exec.js can be loaded via `eval()` since Workers allows it (unlike
 * some CSP-restricted environments). The `Go` class is then on `globalThis`.
 *
 * ## Known limitations / blockers
 *
 * 1. **`fs` module**: wasm_exec.js v1.21+ conditionally imports Node's `fs`
 *    module for file I/O. In Workers, `nodejs_compat` provides `fs` stubs but
 *    they may not be complete. The Go runtime only uses `fs` for stdin/stdout
 *    which are not used by the js/wasm ABI (it uses globalThis.assayEvaluate).
 *    This is a non-issue for our use case.
 *
 * 2. **`crypto.getRandomValues`**: Go's runtime.getRandomValues calls this.
 *    Workers provides `crypto.getRandomValues` natively. OK.
 *
 * 3. **`performance.now`**: Used by Go's scheduler. Workers provides it. OK.
 *
 * 4. **`setTimeout` with 0ms**: go.run() uses setTimeout(resolve, 0) style
 *    patterns. Workers supports this. OK.
 *
 * 5. **Global state across requests**: Workers isolates are reused across
 *    requests within the same instance (same `env` lifetime). The Go runtime
 *    singleton is initialized once per isolate lifetime (via module-scope
 *    singleton pattern). This is the correct behavior.
 *
 * 6. **Cold start latency**: First request initializes the Go runtime (~50-200ms).
 *    Subsequent requests in the same isolate reuse the cached assayEvaluate fn.
 */

// ---------------------------------------------------------------------------
// Type declarations for Worker bindings (populated by wrangler at runtime)
// ---------------------------------------------------------------------------

declare const ASSAYWARD_WASM: ArrayBuffer;
declare const WASM_EXEC_JS: string;

// ---------------------------------------------------------------------------
// Go runtime types (set on globalThis by wasm_exec.js)
// ---------------------------------------------------------------------------

interface GoRuntime {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  importObject: Record<string, any>;
  run(instance: WebAssembly.Instance): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module-level singleton: one Go runtime + wasm instance per isolate lifetime
// ---------------------------------------------------------------------------

let cachedAssayEvaluate: ((json: string) => string) | null = null;
let initPromise: Promise<void> | null = null;

async function initWasm(): Promise<void> {
  if (cachedAssayEvaluate) return;

  // Step 1: Load wasm_exec.js to register globalThis.Go
  // WASM_EXEC_JS is a text blob bound by wrangler from assets/wasm_exec.js.
  // We eval() it to execute the IIFE that sets globalThis.Go.
  // eslint-disable-next-line no-new-func
  new Function(WASM_EXEC_JS)();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const GoClass = (globalThis as any).Go as (new () => GoRuntime) | undefined;
  if (!GoClass) {
    throw new Error(
      "assayward: globalThis.Go not found after evaluating wasm_exec.js. " +
        "Ensure WASM_EXEC_JS binding is populated with the Go wasm_exec.js glue.",
    );
  }

  // Step 2: Instantiate the Go wasm module
  const go = new GoClass();

  // ASSAYWARD_WASM is an ArrayBuffer bound by wrangler from assets/assayward_js.wasm.
  // Workers' WebAssembly.instantiate(Module, imports) -> Promise<Instance>.
  // We compile first (WebAssembly.compile exists in workerd but is missing from
  // @cloudflare/workers-types; cast to any to avoid the type error).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wasmModule = await (WebAssembly as any).compile(ASSAYWARD_WASM) as WebAssembly.Module;
  const instance = await WebAssembly.instantiate(wasmModule, go.importObject);

  // Step 3: Start the Go runtime (fire-and-forget: Go's main() calls select{}
  // and never returns; the promise resolves only if Go exits, which is an error).
  go.run(instance).catch(() => {
    // Go runtime exited — reset cache so next request retries init.
    cachedAssayEvaluate = null;
    initPromise = null;
  });

  // Step 4: Yield one microtask tick so the Go goroutine scheduler runs and
  // registers globalThis.assayEvaluate during Go's main().
  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  // Step 5: Grab and cache the registered function.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = (globalThis as any).assayEvaluate as
    | ((json: string) => string)
    | undefined;
  if (typeof fn !== "function") {
    throw new Error(
      "assayward: globalThis.assayEvaluate not registered after wasm init. " +
        "The Go wasm module may have exited early or the wrong wasm build was used. " +
        "Ensure the wasm binary was compiled with GOOS=js GOARCH=wasm (not wasip1).",
    );
  }

  cachedAssayEvaluate = fn;
}

/**
 * Returns the assayEvaluate function, initializing the Go wasm runtime on
 * first call. Serializes concurrent callers behind a single init promise.
 */
export async function getAssayEvaluate(): Promise<(json: string) => string> {
  if (!initPromise) {
    initPromise = initWasm();
  }
  await initPromise;
  return cachedAssayEvaluate!;
}
