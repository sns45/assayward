package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Config holds the configuration for the webhook HTTP server.
type Config struct {
	// Mode controls admission behavior (audit, enforce, warn).
	Mode Mode
	// Addr is the TCP address to listen on (e.g. ":8443").
	Addr string
	// CertFile is the path to the TLS certificate PEM file.
	CertFile string
	// KeyFile is the path to the TLS private key PEM file.
	KeyFile string
	// Eval is the Evaluator to use for trust decisions.
	Eval Evaluator
}

// Handler returns an http.Handler with two routes:
//
//	POST /validate  — the validating-admission-webhook endpoint.
//	GET  /healthz   — a liveness probe returning 200 OK.
//
// The handler never panics. Malformed bodies and nil-admission-request cases
// are fail-closed under ModeEnforce (Allowed=false, HTTP 200) per the
// Kubernetes admission webhook convention: transport errors are HTTP 4xx/5xx;
// logical denials are HTTP 200 with Allowed=false.
func Handler(eval Evaluator, mode Mode) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		handleValidate(w, r, eval, mode)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// handleValidate is the core handler for POST /validate. It reads and decodes
// an AdmissionReview, calls Review, and writes back the response review as JSON.
//
// On any body-read or JSON-unmarshal error the handler returns a fail-closed
// AdmissionReview (Allowed=false under enforce) with HTTP 200 — admission
// webhooks must not return non-200 for logical denials, only for transport
// errors (which would cause the apiserver to fail-open or fail-closed depending
// on configuration). Returning HTTP 200 with Allowed=false is the correct
// protocol response.
func handleValidate(w http.ResponseWriter, r *http.Request, eval Evaluator, mode Mode) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeFailClosed(w, mode, "assayward: failed to read request body")
		return
	}

	var ar admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &ar); err != nil {
		writeFailClosed(w, mode, "assayward: failed to decode AdmissionReview")
		return
	}

	resp := Review(r.Context(), &ar, eval, mode)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Encoding to the response writer failed. There is nothing useful we can
		// do at this point — the partial write has already been sent. Log-only.
		log.Printf("assayward-webhook: encode response: %v", err)
	}
}

// writeFailClosed writes a fail-closed AdmissionReview response (Allowed=false
// under enforce, Allowed=true with warning under audit/warn) with HTTP 200.
// This is used when the request body cannot be read or decoded.
func writeFailClosed(w http.ResponseWriter, mode Mode, msg string) {
	out := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
	}

	switch mode {
	case ModeAudit, ModeWarn:
		out.Response = &admissionv1.AdmissionResponse{
			Allowed:  true,
			Warnings: []string{msg},
		}
	default:
		// ModeEnforce and any unknown mode: fail-closed.
		out.Response = &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: msg,
				Reason:  metav1.StatusReasonForbidden,
				Code:    403,
			},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("assayward-webhook: encode response: %v", err)
	}
}

// ListenAndServeTLS starts the webhook HTTPS server using the Config's CertFile
// and KeyFile. Admission webhooks MUST be HTTPS; plain HTTP is only for tests.
//
// The server shuts down gracefully when ctx is cancelled.
func (c Config) ListenAndServeTLS(ctx context.Context) error {
	srv := &http.Server{
		Addr:    c.Addr,
		Handler: Handler(c.Eval, c.Mode),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS(c.CertFile, c.KeyFile)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
