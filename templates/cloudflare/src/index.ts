/**
 * assayward-gate — Cloudflare Workers trust gate
 *
 * This Worker evaluates supply-chain trust policies using the assayward wasm
 * core. It is a thin edge gate: NO business logic lives here. The wasm engine
 * (globalThis.assayEvaluate) makes all decisions.
 *
 * ## Endpoint
 *
 *   POST /verify
 *     Body:  { evidence, policy, trustRoots?, now? }
 *     200    Decision JSON  (result: "allow" | "audit")
 *     403    Decision JSON  (result: "deny")
 *     400    { error: string }  bad/missing input
 *     405    { error: string }  wrong method
 *     404    { error: string }  unknown path
 *     503    { error: string }  wasm init failure (see body for details)
 *
 * ## Decision-5 Caveat
 *
 * When a policy sets `signature.required: true`, the wasm engine returns
 * `deny` with reason code `SIGNATURE_VERIFICATION_UNAVAILABLE` because
 * sigstore-go cannot be compiled to wasm. This Worker correctly returns
 * HTTP 403 in that case — the deny is accurate, not an error.
 *
 * For full signature verification use the native assayward CLI or the webhook
 * integration (which runs the native binary).
 */

import { getAssayEvaluate } from "./wasm-loader.js";
import type { Decision, Evidence, TrustRoots } from "./types.js";

// ---------------------------------------------------------------------------
// ABI envelope type (mirrors core/wasm/abi.md)
// ---------------------------------------------------------------------------

interface VerifyRequest {
  evidence: Evidence;
  policy: string;
  trustRoots?: TrustRoots;
  now?: string;
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function jsonResponse(
  body: unknown,
  status: number,
  headers?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function errorResponse(status: number, message: string): Response {
  return jsonResponse({ error: message }, status);
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

function validateRequest(raw: unknown): VerifyRequest | string {
  if (typeof raw !== "object" || raw === null) {
    return "request body must be a JSON object";
  }

  const r = raw as Record<string, unknown>;

  // evidence
  if (typeof r.evidence !== "object" || r.evidence === null) {
    return "evidence is required and must be an object";
  }
  const ev = r.evidence as Record<string, unknown>;
  if (typeof ev.image !== "object" || ev.image === null) {
    return "evidence.image is required";
  }
  const img = ev.image as Record<string, unknown>;
  if (typeof img.name !== "string" || img.name === "") {
    return "evidence.image.name is required";
  }
  if (typeof img.digest !== "string" || img.digest === "") {
    return "evidence.image.digest is required";
  }
  if (!Array.isArray(ev.attestations)) {
    return "evidence.attestations is required and must be an array";
  }

  // policy
  if (typeof r.policy !== "string" || r.policy.trim() === "") {
    return "policy is required and must be a non-empty string (YAML or JSON)";
  }

  // trustRoots (optional)
  if (r.trustRoots !== undefined && (typeof r.trustRoots !== "object" || r.trustRoots === null)) {
    return "trustRoots must be an object if provided";
  }

  // now (optional)
  if (r.now !== undefined && typeof r.now !== "string") {
    return "now must be an RFC3339 string if provided";
  }

  return {
    evidence: r.evidence as Evidence,
    policy: r.policy,
    trustRoots: r.trustRoots as TrustRoots | undefined,
    now: r.now as string | undefined,
  };
}

// ---------------------------------------------------------------------------
// Main fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Route: only POST /verify is handled
    if (url.pathname !== "/verify") {
      return errorResponse(404, `not found: ${url.pathname}`);
    }
    if (request.method !== "POST") {
      return errorResponse(405, `method not allowed: ${request.method} (use POST)`);
    }

    // Parse JSON body
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      return errorResponse(400, "request body must be valid JSON");
    }

    // Validate
    const validated = validateRequest(rawBody);
    if (typeof validated === "string") {
      return errorResponse(400, validated);
    }

    // Build ABI envelope (mirrors core/wasm/abi.md)
    const envelope = {
      evidence: validated.evidence,
      policy: validated.policy,
      trustRoots: validated.trustRoots ?? {},
      now: validated.now ?? new Date().toISOString(),
    };

    // Initialize wasm and call assayEvaluate
    let assayEvaluate: (json: string) => string;
    try {
      assayEvaluate = await getAssayEvaluate();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return errorResponse(
        503,
        `wasm initialization failed: ${msg}. ` +
          "Ensure assets/assayward_js.wasm and assets/wasm_exec.js are present " +
          "and the Worker was deployed with nodejs_compat flag.",
      );
    }

    // Call the wasm engine (synchronous, never throws — returns {error} on failure)
    let resultJSON: string;
    try {
      resultJSON = assayEvaluate(JSON.stringify(envelope));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return errorResponse(500, `assayEvaluate threw unexpectedly: ${msg}`);
    }

    // Parse the Decision (or WasmError)
    let parsed: Decision | { error: string };
    try {
      parsed = JSON.parse(resultJSON);
    } catch {
      return errorResponse(500, `assayEvaluate returned non-JSON: ${resultJSON}`);
    }

    // Handle wasm-level error (e.g. policy parse error)
    if ("error" in parsed && typeof (parsed as { error: string }).error === "string") {
      return errorResponse(400, `assayward wasm error: ${(parsed as { error: string }).error}`);
    }

    const decision = parsed as Decision;

    // Gate: allow/audit -> 200, deny -> 403
    const status = decision.result === "deny" ? 403 : 200;
    return jsonResponse(decision, status);
  },
} satisfies ExportedHandler;
