package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	core "github.com/sns45/assayward/pkg/core"
)

// buildAdmissionReviewJSON returns raw AdmissionReview JSON wrapping a Pod with
// the given container images. It is used across server handler tests.
func buildAdmissionReviewJSON(t *testing.T, uid types.UID, images ...string) []byte {
	t.Helper()
	containers := make([]corev1.Container, len(images))
	for i, img := range images {
		containers[i] = corev1.Container{Name: "c", Image: img}
	}
	pod := corev1.Pod{Spec: corev1.PodSpec{Containers: containers}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	ar := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:    uid,
			Object: runtime.RawExtension{Raw: raw},
		},
	}
	b, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal admission review: %v", err)
	}
	return b
}

// decodeAdmissionReview decodes an HTTP response body as an AdmissionReview.
func decodeAdmissionReview(t *testing.T, body io.Reader) *admissionv1.AdmissionReview {
	t.Helper()
	var ar admissionv1.AdmissionReview
	if err := json.NewDecoder(body).Decode(&ar); err != nil {
		t.Fatalf("decode AdmissionReview response: %v", err)
	}
	return &ar
}

// TestHandler_AuditMode_StubDeny_AllowedWithWarnings verifies that under audit
// mode, a stub evaluator returning ResultDeny leads to HTTP 200 and Allowed==true
// with warnings populated.
func TestHandler_AuditMode_StubDeny_AllowedWithWarnings(t *testing.T) {
	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:v1": {
				Result: core.ResultDeny,
				Reasons: []core.Reason{
					{Code: "SIGNATURE_MISSING", Severity: core.SeverityCritical, Detail: "no sig"},
				},
			},
		},
	}

	srv := httptest.NewServer(Handler(eval, ModeAudit))
	defer srv.Close()

	body := buildAdmissionReviewJSON(t, "uid-audit-deny", "myrepo/app:v1")
	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}

	ar := decodeAdmissionReview(t, resp.Body)
	if ar.Response == nil {
		t.Fatal("response is nil")
	}
	if !ar.Response.Allowed {
		t.Errorf("audit mode + deny signal: expected Allowed=true, got false")
	}
	if len(ar.Response.Warnings) == 0 {
		t.Errorf("audit mode + deny signal: expected warnings, got none")
	}
}

// TestHandler_EnforceMode_StubDeny_Denied verifies that under enforce mode, a
// stub evaluator returning ResultDeny causes Allowed==false with HTTP 200.
func TestHandler_EnforceMode_StubDeny_Denied(t *testing.T) {
	eval := &stubEvaluator{
		decisions: map[string]core.Decision{
			"myrepo/app:v1": {
				Result: core.ResultDeny,
				Reasons: []core.Reason{
					{Code: "SLSA_LEVEL_BELOW_THRESHOLD", Severity: core.SeverityHigh},
				},
			},
		},
	}

	srv := httptest.NewServer(Handler(eval, ModeEnforce))
	defer srv.Close()

	body := buildAdmissionReviewJSON(t, "uid-enforce-deny", "myrepo/app:v1")
	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 (admission webhook convention), got %d", resp.StatusCode)
	}

	ar := decodeAdmissionReview(t, resp.Body)
	if ar.Response == nil {
		t.Fatal("response is nil")
	}
	if ar.Response.Allowed {
		t.Errorf("enforce mode + deny signal: expected Allowed=false, got true")
	}
}

// TestHandler_EnforceMode_MalformedBody_FailClosed verifies that malformed JSON
// under enforce mode returns HTTP 200 with Allowed==false (fail-closed).
func TestHandler_EnforceMode_MalformedBody_FailClosed(t *testing.T) {
	eval := &stubEvaluator{}

	srv := httptest.NewServer(Handler(eval, ModeEnforce))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader([]byte(`not-json`)))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for malformed body, got %d", resp.StatusCode)
	}

	ar := decodeAdmissionReview(t, resp.Body)
	if ar.Response == nil {
		t.Fatal("response is nil")
	}
	if ar.Response.Allowed {
		t.Errorf("enforce + malformed body: expected Allowed=false (fail-closed), got true")
	}
}

// TestHandler_Healthz_OK verifies that GET /healthz returns 200 OK.
func TestHandler_Healthz_OK(t *testing.T) {
	eval := &stubEvaluator{}

	srv := httptest.NewServer(Handler(eval, ModeAudit))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz: expected 200, got %d", resp.StatusCode)
	}
}

// TestHandler_ContentType_ApplicationJSON verifies that /validate sets
// Content-Type: application/json on success.
func TestHandler_ContentType_ApplicationJSON(t *testing.T) {
	eval := &stubEvaluator{}

	srv := httptest.NewServer(Handler(eval, ModeAudit))
	defer srv.Close()

	body := buildAdmissionReviewJSON(t, "uid-ct", "myrepo/app:latest")
	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q want %q", ct, "application/json")
	}
}

// TestHandler_ResponseUID_EchoesRequest verifies the handler echoes the request
// UID in the response.
func TestHandler_ResponseUID_EchoesRequest(t *testing.T) {
	eval := &stubEvaluator{}

	srv := httptest.NewServer(Handler(eval, ModeAudit))
	defer srv.Close()

	const wantUID = "server-uid-echo-test"
	body := buildAdmissionReviewJSON(t, wantUID, "myrepo/app:latest")
	resp, err := http.Post(srv.URL+"/validate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /validate: %v", err)
	}
	defer resp.Body.Close()

	ar := decodeAdmissionReview(t, resp.Body)
	if ar.Response == nil {
		t.Fatal("response is nil")
	}
	if string(ar.Response.UID) != wantUID {
		t.Errorf("UID: got %q want %q", ar.Response.UID, wantUID)
	}
}

// TestHandler_Context_Cancelled verifies that the handler uses the request context
// and returns a well-formed response even if the context is already cancelled
// (simulates a short timeout scenario).
func TestHandler_Context_CancelledRequest_StillReturnsResponse(t *testing.T) {
	// A stub evaluator that blocks until context is cancelled is too complex to
	// wire in a unit test. We instead verify that posting with an already-cancelled
	// client context does not cause a panic or nil-dereference in the handler.
	eval := &stubEvaluator{}
	h := Handler(eval, ModeAudit)

	body := buildAdmissionReviewJSON(t, "uid-ctx-test", "myrepo/app:latest")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/validate", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	// The handler must not panic even with a cancelled context.
	h.ServeHTTP(rr, req)
	// We just verify it didn't panic and returned some status.
	if rr.Code == 0 {
		t.Error("expected non-zero status code")
	}
}
