// Package webhook implements the Kubernetes validating-admission-webhook adapter.
// It is a pure translator: AdmissionReview -> images -> Evaluator -> AdmissionResponse.
// All trust decisions come from the injected Evaluator (which wraps engine.Evaluate).
// No network, no TLS — those belong to the HTTP server layer.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	core "github.com/sns45/assayward/pkg/core"
)

// Mode controls the admission behavior of the webhook, decoupled from policy.mode
// so operators can roll out audit-first without changing policy configuration.
type Mode string

const (
	// ModeAudit always admits; deny-signals are surfaced as Warnings for observability.
	ModeAudit Mode = "audit"
	// ModeEnforce denies admission when any image produces a deny-signal or eval error.
	ModeEnforce Mode = "enforce"
	// ModeWarn always admits; deny-signals are surfaced as Warnings.
	ModeWarn Mode = "warn"
)

// Evaluator evaluates the trust decision for a single image.
// It is injected so tests can stub it without network or policy dependencies.
// In production this wraps engine.Evaluate plus any discovery/resolution logic.
type Evaluator interface {
	Evaluate(ctx context.Context, img core.ImageRef) (core.Decision, error)
}

// denySignal records a deny-signal from a single image evaluation.
type denySignal struct {
	img     core.ImageRef
	dec     core.Decision
	evalErr error
}

// Review processes an AdmissionReview request and returns a complete response review.
// It is the single entry point for the webhook adapter.
//
// Semantics by mode:
//   - ModeAudit:   always Allowed=true; deny-signals and eval errors -> Warnings.
//   - ModeEnforce: Allowed=false when any deny-signal or eval error (fail-closed); else true.
//   - ModeWarn:    always Allowed=true; deny-signals -> Warnings.
//
// TypeMeta of the returned review is always set to admission.k8s.io/v1 / AdmissionReview.
// response.UID always echoes request.UID.
// If ar or ar.Request is nil the call returns a well-formed deny (fail-closed) without panicking.
func Review(ctx context.Context, ar *admissionv1.AdmissionReview, eval Evaluator, mode Mode) *admissionv1.AdmissionReview {
	out := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
	}

	// Nil-guard: fail-closed on a nil or request-less review.
	if ar == nil || ar.Request == nil {
		out.Response = &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: "assayward: nil admission request",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    400,
			},
		}
		return out
	}

	req := ar.Request
	out.Response = &admissionv1.AdmissionResponse{
		UID: req.UID,
	}

	// Decode Pod from the AdmissionRequest object.
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return applyDecodeError(out, mode, fmt.Sprintf("failed to decode Pod: %v", err))
	}

	imgs := podImages(&pod)

	// Evaluate each image; collect deny-signals (ResultDeny or eval error).
	var denies []denySignal
	for _, img := range imgs {
		dec, err := eval.Evaluate(ctx, img)
		if err != nil {
			denies = append(denies, denySignal{img: img, evalErr: err})
			continue
		}
		if dec.Result == core.ResultDeny {
			denies = append(denies, denySignal{img: img, dec: dec})
		}
		// ResultAllow and ResultAudit are not deny-signals.
	}

	hasDenySignal := len(denies) > 0

	switch mode {
	case ModeEnforce:
		if hasDenySignal {
			out.Response.Allowed = false
			out.Response.Result = &metav1.Status{
				Message: "assayward: " + buildDenyMessage(denies),
				Reason:  metav1.StatusReasonForbidden,
				Code:    403,
			}
		} else {
			out.Response.Allowed = true
		}

	case ModeAudit, ModeWarn:
		out.Response.Allowed = true
		if hasDenySignal {
			out.Response.Warnings = buildWarnings(denies)
		}

	default:
		// Unknown mode: fail-closed (treat like enforce) so misconfiguration is never silently permissive.
		out.Response.Allowed = false
		out.Response.Result = &metav1.Status{
			Message: fmt.Sprintf("assayward: unknown webhook mode %q", mode),
			Reason:  metav1.StatusReasonForbidden,
			Code:    403,
		}
	}

	return out
}

// applyDecodeError returns an admission response for a Pod decode failure.
// In enforce mode (and for any unknown mode) this is fail-closed (denied).
// In audit/warn modes it allows with a warning.
func applyDecodeError(out *admissionv1.AdmissionReview, mode Mode, msg string) *admissionv1.AdmissionReview {
	switch mode {
	case ModeAudit, ModeWarn:
		out.Response.Allowed = true
		out.Response.Warnings = []string{"assayward: " + msg}
	default:
		// ModeEnforce and any unknown mode: fail-closed.
		out.Response.Allowed = false
		out.Response.Result = &metav1.Status{
			Message: msg,
			Reason:  metav1.StatusReasonForbidden,
			Code:    403,
		}
	}
	return out
}

// buildDenyMessage constructs a concise human-readable message listing all deny reasons.
func buildDenyMessage(denies []denySignal) string {
	parts := make([]string, 0, len(denies))
	for _, d := range denies {
		if d.evalErr != nil {
			parts = append(parts, fmt.Sprintf("[%s] eval error: %v", d.img.Name, d.evalErr))
			continue
		}
		codes := reasonCodes(d.dec.Reasons)
		parts = append(parts, fmt.Sprintf("[%s] denied: %s", d.img.Name, codes))
	}
	return strings.Join(parts, "; ")
}

// buildWarnings constructs per-image warning strings for audit/warn modes.
func buildWarnings(denies []denySignal) []string {
	warnings := make([]string, 0, len(denies))
	for _, d := range denies {
		if d.evalErr != nil {
			warnings = append(warnings, fmt.Sprintf("assayward: [%s] eval error: %v", d.img.Name, d.evalErr))
			continue
		}
		codes := reasonCodes(d.dec.Reasons)
		warnings = append(warnings, fmt.Sprintf("assayward: [%s] would deny: %s", d.img.Name, codes))
	}
	return warnings
}

// reasonCodes extracts and joins the Code fields from a reasons slice.
func reasonCodes(reasons []core.Reason) string {
	codes := make([]string, 0, len(reasons))
	for _, r := range reasons {
		codes = append(codes, r.Code)
	}
	if len(codes) == 0 {
		return "(no reason codes)"
	}
	return strings.Join(codes, ", ")
}
