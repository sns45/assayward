package forgeseal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyByContent(t *testing.T) {
	cases := map[string]forgesealKind{
		`{"bomFormat":"CycloneDX","specVersion":"1.5"}`:                                                kindSBOM,
		`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`:                                 kindVEX,
		`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}`: kindSLSAStatement,
	}
	for body, want := range cases {
		if got := classifyForgesealFile([]byte(body)); got != want {
			t.Errorf("classify %q = %v, want %v", body, got, want)
		}
	}
}

// Fixtures below are built as raw JSON literals (rather than json.Marshal of
// the sigstoreBundle struct) so that absent fields are simply omitted from
// the document, matching real Sigstore bundle output. Marshaling the struct
// directly would emit explicit "dsseEnvelope":null / "messageSignature":null
// keys for zero-value fields, which json.RawMessage round-trips as the
// non-empty literal "null" and so is indistinguishable from "present".

func TestClassifySigstoreBundle(t *testing.T) {
	stmt := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"x","digest":{"sha256":"aa"}}]}`)
	env := dsseEnvelopeWire{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(stmt),
		Signatures:  json.RawMessage("[]"),
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON := fmt.Sprintf(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":%s}`, envBytes)
	if got := classifyForgesealFile([]byte(bundleJSON)); got != kindSLSABundle {
		t.Errorf("classify sigstore bundle = %v, want kindSLSABundle", got)
	}
}

func TestClassifyBlobSignatureBundle(t *testing.T) {
	bundleJSON := `{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"aaaa"},"signature":"c2ln"}}`
	if got := classifyForgesealFile([]byte(bundleJSON)); got != kindBlobSig {
		t.Errorf("classify blob-signature bundle = %v, want kindBlobSig", got)
	}
}

// TestClassifyExplicitNullFields guards against a real misclassification
// path: json.RawMessage of an explicit JSON null unmarshals to the non-empty
// bytes "null" (length 4), so a naive len(v) > 0 presence check treats an
// explicit null the same as a populated field. Go structs marshaled without
// omitempty (including forgeseal's own output in some code paths) can emit
// exactly these explicit-null shapes.
func TestClassifyExplicitNullFields(t *testing.T) {
	// A null messageSignature (and no dsseEnvelope) must NOT be classified as
	// a blob signature: there is no signature here, only an explicit null.
	nullMessageSig := `{"mediaType":"x","messageSignature":null}`
	if got := classifyForgesealFile([]byte(nullMessageSig)); got != kindOther {
		t.Errorf("classify null messageSignature = %v, want kindOther", got)
	}

	// A null dsseEnvelope alongside a real messageSignature must fall through
	// to the blob-signature branch: the DSSE null must be ignored rather than
	// short-circuiting classification (and, critically, must not cause the
	// DSSE branch to always return before the real messageSignature is ever
	// inspected).
	nullDSSEWithRealSig := `{"dsseEnvelope":null,"messageSignature":{"signature":"abc"}}`
	if got := classifyForgesealFile([]byte(nullDSSEWithRealSig)); got != kindBlobSig {
		t.Errorf("classify null dsseEnvelope + real messageSignature = %v, want kindBlobSig", got)
	}
}

// TestClassifyNonJSONGarbage confirms non-JSON input classifies as kindOther
// without panicking.
func TestClassifyNonJSONGarbage(t *testing.T) {
	if got := classifyForgesealFile([]byte("not json")); got != kindOther {
		t.Errorf("classify non-JSON garbage = %v, want kindOther", got)
	}
}

func TestDetectSigningCA(t *testing.T) {
	dir := t.TempDir()
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "forgeseal-signing-ca.crt"), []byte(pem), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := DetectSigningCA(dir)
	if err != nil || string(got) != pem {
		t.Fatalf("DetectSigningCA = %q, %v", got, err)
	}
	empty, err := DetectSigningCA(t.TempDir())
	if err != nil || empty != nil {
		t.Fatalf("absent CA must be (nil,nil): %q %v", empty, err)
	}
}
