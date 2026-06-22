package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	core "github.com/sns45/assayward/pkg/core"
)

// stubEvaluator is an injected test double for the Evaluator interface.
type stubEvaluator struct {
	// decisions maps image Name to the Decision to return. If the name is not
	// found, the zero Decision (ResultAllow) is returned.
	decisions map[string]core.Decision
	// errors maps image Name to an error to return from Evaluate.
	errors map[string]error
}

func (s *stubEvaluator) Evaluate(_ context.Context, img core.ImageRef) (core.Decision, error) {
	if s.errors != nil {
		if err, ok := s.errors[img.Name]; ok {
			return core.Decision{}, err
		}
	}
	if s.decisions != nil {
		if d, ok := s.decisions[img.Name]; ok {
			return d, nil
		}
	}
	return core.Decision{Result: core.ResultAllow}, nil
}

// buildReview constructs a minimal AdmissionReview wrapping a Pod with the given images.
func buildReview(uid types.UID, images ...string) *admissionv1.AdmissionReview {
	containers := make([]corev1.Container, len(images))
	for i, img := range images {
		containers[i] = corev1.Container{Name: "c", Image: img}
	}
	pod := corev1.Pod{
		Spec: corev1.PodSpec{Containers: containers},
	}
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:    uid,
			Object: runtime.RawExtension{Raw: raw},
		},
	}
}

func TestReview_AuditMode_DenySignal_AllowedWithWarnings(t *testing.T) {
	ar := buildReview("test-uid-1", "myrepo/app:latest")

	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:latest": {
				Result: core.ResultDeny,
				Reasons: []core.Reason{
					{Code: "SLSA_LEVEL_BELOW_THRESHOLD", Severity: core.SeverityHigh, Detail: "level 0 < 2"},
					{Code: "SIGNATURE_MISSING", Severity: core.SeverityCritical, Detail: "no sig"},
				},
			},
		},
	}

	resp := Review(context.Background(), ar, eval, ModeAudit)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("audit mode: expected Allowed=true, got false")
	}
	if len(resp.Response.Warnings) == 0 {
		t.Errorf("audit mode deny-signal: expected warnings, got none")
	}
	// Warnings should mention the reason codes
	combinedWarnings := strings.Join(resp.Response.Warnings, " ")
	if !strings.Contains(combinedWarnings, "SLSA_LEVEL_BELOW_THRESHOLD") {
		t.Errorf("warnings should mention SLSA_LEVEL_BELOW_THRESHOLD, got: %v", resp.Response.Warnings)
	}
}

func TestReview_EnforceMode_DenySignal_Denied(t *testing.T) {
	ar := buildReview("test-uid-2", "myrepo/app:latest")

	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:latest": {
				Result: core.ResultDeny,
				Reasons: []core.Reason{
					{Code: "SIGNATURE_MISSING", Severity: core.SeverityCritical, Detail: "no sig"},
				},
			},
		},
	}

	resp := Review(context.Background(), ar, eval, ModeEnforce)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if resp.Response.Allowed {
		t.Errorf("enforce mode: expected Allowed=false, got true")
	}
	if resp.Response.Result == nil {
		t.Fatal("enforce deny: Result should be non-nil")
	}
	if resp.Response.Result.Code != 403 {
		t.Errorf("enforce deny: expected Code=403, got %d", resp.Response.Result.Code)
	}
	if resp.Response.Result.Reason != metav1.StatusReasonForbidden {
		t.Errorf("enforce deny: expected Reason=Forbidden, got %v", resp.Response.Result.Reason)
	}
	if !strings.Contains(resp.Response.Result.Message, "assayward:") {
		t.Errorf("enforce deny: message should have assayward: prefix, got: %q", resp.Response.Result.Message)
	}
	if !strings.Contains(resp.Response.Result.Message, "SIGNATURE_MISSING") {
		t.Errorf("enforce deny: message should list reason codes, got: %q", resp.Response.Result.Message)
	}
}

func TestReview_EnforceMode_AllAllow_Admitted(t *testing.T) {
	ar := buildReview("test-uid-3", "myrepo/app@sha256:abc123")

	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app": {
				Result: core.ResultAllow,
			},
		},
	}

	resp := Review(context.Background(), ar, eval, ModeEnforce)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("enforce mode all-allow: expected Allowed=true, got false")
	}
}

func TestReview_WarnMode_DenySignal_AllowedWithWarnings(t *testing.T) {
	ar := buildReview("test-uid-4", "myrepo/app:v2")

	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:v2": {
				Result: core.ResultDeny,
				Reasons: []core.Reason{
					{Code: "SBOM_MISSING", Severity: core.SeverityMedium, Detail: "no sbom"},
				},
			},
		},
	}

	resp := Review(context.Background(), ar, eval, ModeWarn)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("warn mode: expected Allowed=true, got false")
	}
	if len(resp.Response.Warnings) == 0 {
		t.Errorf("warn mode deny-signal: expected warnings, got none")
	}
}

func TestReview_EnforceMode_EvalError_FailClosed(t *testing.T) {
	ar := buildReview("test-uid-5", "myrepo/app:latest")

	eval := &stubEvaluator{
		errors: map[string]error{
			"myrepo/app:latest": errors.New("registry unavailable"),
		},
	}

	resp := Review(context.Background(), ar, eval, ModeEnforce)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if resp.Response.Allowed {
		t.Errorf("enforce + eval error: expected Allowed=false (fail-closed), got true")
	}
	if resp.Response.Result == nil {
		t.Fatal("enforce fail-closed: Result should be non-nil")
	}
	if resp.Response.Result.Code != 403 {
		t.Errorf("enforce fail-closed: expected Code=403, got %d", resp.Response.Result.Code)
	}
}

func TestReview_AuditMode_EvalError_AllowWithWarning(t *testing.T) {
	ar := buildReview("test-uid-6", "myrepo/app:latest")

	eval := &stubEvaluator{
		errors: map[string]error{
			"myrepo/app:latest": errors.New("eval failed: timeout"),
		},
	}

	resp := Review(context.Background(), ar, eval, ModeAudit)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("audit + eval error: expected Allowed=true, got false")
	}
	if len(resp.Response.Warnings) == 0 {
		t.Errorf("audit + eval error: expected warning about error, got none")
	}
	combined := strings.Join(resp.Response.Warnings, " ")
	if !strings.Contains(combined, "timeout") {
		t.Errorf("audit eval error warning should mention error detail, got: %v", resp.Response.Warnings)
	}
}

func TestReview_ResponseUID_EchoesRequestUID(t *testing.T) {
	const requestUID = "uid-echo-test-789"
	ar := buildReview(requestUID, "myrepo/app:latest")

	eval := &stubEvaluator{}

	for _, mode := range []Mode{ModeAudit, ModeEnforce, ModeWarn} {
		t.Run(string(mode), func(t *testing.T) {
			resp := Review(context.Background(), ar, eval, mode)
			if resp.Response == nil {
				t.Fatal("response is nil")
			}
			if string(resp.Response.UID) != requestUID {
				t.Errorf("mode %s: UID mismatch: got %q want %q", mode, resp.Response.UID, requestUID)
			}
		})
	}
}

func TestReview_ResultAudit_TreatedAsNonDeny(t *testing.T) {
	// ResultAudit from policy should NOT trigger a deny-signal
	ar := buildReview("test-uid-7", "myrepo/app:latest")

	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:latest": {
				Result: core.ResultAudit, // policy says audit — not a deny
			},
		},
	}

	// In enforce mode: ResultAudit => should still be admitted (no deny-signal)
	resp := Review(context.Background(), ar, eval, ModeEnforce)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("enforce + ResultAudit: expected Allowed=true (audit is not deny), got false")
	}
}

func TestReview_TypeMeta_IsSet(t *testing.T) {
	ar := buildReview("test-uid-8", "myrepo/app:latest")
	eval := &stubEvaluator{}

	resp := Review(context.Background(), ar, eval, ModeAudit)

	if resp.TypeMeta.APIVersion != "admission.k8s.io/v1" {
		t.Errorf("APIVersion: got %q want %q", resp.TypeMeta.APIVersion, "admission.k8s.io/v1")
	}
	if resp.TypeMeta.Kind != "AdmissionReview" {
		t.Errorf("Kind: got %q want %q", resp.TypeMeta.Kind, "AdmissionReview")
	}
}

func TestReview_DecodeFailure_EnforceMode_Denied(t *testing.T) {
	// Send invalid JSON as the pod object
	ar := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:    "test-uid-bad",
			Object: runtime.RawExtension{Raw: []byte(`not-valid-json`)},
		},
	}
	eval := &stubEvaluator{}

	resp := Review(context.Background(), ar, eval, ModeEnforce)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if resp.Response.Allowed {
		t.Errorf("enforce + decode failure: expected Allowed=false (fail-closed), got true")
	}
}

func TestReview_DecodeFailure_AuditMode_AllowedWithWarning(t *testing.T) {
	ar := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:    "test-uid-bad-audit",
			Object: runtime.RawExtension{Raw: []byte(`not-valid-json`)},
		},
	}
	eval := &stubEvaluator{}

	resp := Review(context.Background(), ar, eval, ModeAudit)

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("audit + decode failure: expected Allowed=true, got false")
	}
	if len(resp.Response.Warnings) == 0 {
		t.Errorf("audit + decode failure: expected warning, got none")
	}
}

// --- Nil-request guard tests (fix: issue 1) ---

func TestReview_NilAdmissionReview_DoesNotPanic_ReturnsDeny(t *testing.T) {
	eval := &stubEvaluator{}
	resp := Review(context.Background(), nil, eval, ModeEnforce)
	if resp == nil {
		t.Fatal("expected non-nil response for nil ar")
	}
	if resp.Response == nil {
		t.Fatal("expected non-nil Response for nil ar")
	}
	if resp.Response.Allowed {
		t.Errorf("nil ar: expected Allowed=false (fail-closed), got true")
	}
	if resp.Response.Result == nil {
		t.Fatal("nil ar: expected non-nil Result")
	}
	if resp.Response.Result.Reason != metav1.StatusReasonBadRequest {
		t.Errorf("nil ar: expected Reason=BadRequest, got %v", resp.Response.Result.Reason)
	}
	if !strings.Contains(resp.Response.Result.Message, "nil admission request") {
		t.Errorf("nil ar: expected message about nil admission request, got: %q", resp.Response.Result.Message)
	}
}

func TestReview_NilRequest_DoesNotPanic_ReturnsDeny(t *testing.T) {
	ar := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: nil,
	}
	eval := &stubEvaluator{}
	resp := Review(context.Background(), ar, eval, ModeEnforce)
	if resp == nil {
		t.Fatal("expected non-nil response for nil Request")
	}
	if resp.Response == nil {
		t.Fatal("expected non-nil Response for nil Request")
	}
	if resp.Response.Allowed {
		t.Errorf("nil Request: expected Allowed=false (fail-closed), got true")
	}
	if resp.Response.Result == nil {
		t.Fatal("nil Request: expected non-nil Result")
	}
	if resp.Response.Result.Reason != metav1.StatusReasonBadRequest {
		t.Errorf("nil Request: expected Reason=BadRequest, got %v", resp.Response.Result.Reason)
	}
}

// --- Unknown mode fail-closed tests (fix: issue 2) ---

func TestReview_UnknownMode_DenySignal_FailClosed(t *testing.T) {
	ar := buildReview("test-uid-unknown-mode", "myrepo/app:latest")
	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:latest": {
				Result:  core.ResultDeny,
				Reasons: []core.Reason{{Code: "SIGNATURE_MISSING", Severity: core.SeverityCritical}},
			},
		},
	}

	resp := Review(context.Background(), ar, eval, Mode("bogus"))

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if resp.Response.Allowed {
		t.Errorf("unknown mode + deny signal: expected Allowed=false (fail-closed), got true")
	}
	if resp.Response.Result == nil {
		t.Fatal("unknown mode: expected non-nil Result")
	}
	if !strings.Contains(resp.Response.Result.Message, "unknown webhook mode") {
		t.Errorf("unknown mode: expected message about unknown mode, got: %q", resp.Response.Result.Message)
	}
}

func TestReview_UnknownMode_DecodeError_FailClosed(t *testing.T) {
	ar := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:    "test-uid-unknown-decode",
			Object: runtime.RawExtension{Raw: []byte(`not-valid-json`)},
		},
	}
	eval := &stubEvaluator{}

	resp := Review(context.Background(), ar, eval, Mode("bogus"))

	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if resp.Response.Allowed {
		t.Errorf("unknown mode + decode error: expected Allowed=false (fail-closed), got true")
	}
}
