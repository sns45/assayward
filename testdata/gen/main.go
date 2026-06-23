//go:build ignore

// Generator for synthetic DSSE and SVID fixture files used in assayward tests.
//
// DETERMINISM CONTRACT — this file MUST remain deterministic:
//
//   - All ECDSA keys are derived directly from a SHA-256 scalar (see deriveKey).
//     No crypto/rand and no ecdsa.GenerateKey. The Go P-256 implementation has
//     sync.Once state that causes a variable number of bytes to be consumed from
//     a reader depending on whether the P-256 curve is already initialised —
//     making ecdsa.GenerateKey non-reproducible across calls within a process.
//     We avoid it entirely by computing the private scalar directly from a hash.
//
//   - All ECDSA signing (JWTs and X.509 certificates) uses RFC 6979 deterministic
//     mode. For JWTs, rfc6979Signer implements jose.OpaqueSigner and calls
//     ecdsa.PrivateKey.Sign(nil, ...) which triggers RFC 6979 in Go 1.20+.
//     For X.509 certs, x509.CreateCertificate is called with nil rand (Go 1.20+
//     interprets nil rand as "use RFC 6979 for ECDSA").
//
//   - All timestamps are hard-coded constants; time.Now() is NEVER called.
//
//   - All serial numbers are hard-coded constants.
//
// Prove determinism:
//
//	go run testdata/gen/main.go
//	go run testdata/gen/main.go
//	git diff --stat testdata/svid/   # must show no changes
//
// SYNTHETIC PLACEHOLDERS: All generated fixtures are representative data for
// development and CI testing. They will be replaced with real forgeseal/svidmint
// artifacts before v0.1 ships. See testdata/README.md for details.
//
// Usage:
//
//	go run testdata/gen/main.go
//
// Run from the repository root. Writes fixture files into testdata/.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// Fixed timestamps used for all generated fixtures.
// Using constants ensures the output is byte-identical across runs.
var (
	// fixedNotBefore is a fixed point in the past, well before any test run.
	fixedNotBefore = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// fixedNotAfter is far in the future so fixtures never expire during tests.
	fixedNotAfter = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	// fixedExpiredBefore / fixedExpiredAfter bracket a window entirely in the past.
	fixedExpiredBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedExpiredAfter  = time.Date(2020, 6, 1, 0, 0, 0, 0, time.UTC)

	// fixedIssuedAt is used as the iat claim in JWT-SVIDs.
	fixedIssuedAt = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
)

// deriveKey deterministically derives an ECDSA P-256 private key from label.
//
// We do NOT use ecdsa.GenerateKey because it uses rejection sampling with a
// reader, and elliptic.P256() has internal sync.Once state that causes a
// different number of bytes to be consumed on the first vs subsequent calls
// within the same process. Deriving the key scalar directly from a hash avoids
// that variability entirely.
func deriveKey(label string) *ecdsa.PrivateKey {
	curve := elliptic.P256()
	order := curve.Params().N

	for counter := uint64(0); ; counter++ {
		h := sha256.New()
		h.Write([]byte("assayward-fixture-gen-v1:" + label + ":key"))
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], counter)
		h.Write(ctr[:])
		scalar := new(big.Int).SetBytes(h.Sum(nil))

		// The private scalar must be in [1, N-1].
		if scalar.Sign() == 0 || scalar.Cmp(order) >= 0 {
			continue
		}

		x, y := curve.ScalarBaseMult(scalar.Bytes())
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         scalar,
		}
	}
}

// rfc6979Signer implements jose.OpaqueSigner using RFC 6979 deterministic ECDSA.
//
// Go 1.20+ triggers RFC 6979 when ecdsa.PrivateKey.Sign is called with a nil
// rand reader. Implementing jose.OpaqueSigner lets us intercept the signing
// call and supply nil, bypassing jose.RandReader entirely.
type rfc6979Signer struct {
	key *ecdsa.PrivateKey
	kid string
}

// Public returns the JWK for the public key.
func (s *rfc6979Signer) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       &s.key.PublicKey,
		KeyID:     s.kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
}

// Algs returns the supported signing algorithms.
func (s *rfc6979Signer) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// SignPayload signs the payload using RFC 6979 deterministic ECDSA (nil rand).
//
// go-jose passes the raw JWS signing input and expects the signature in the
// compact r || s encoding (32 + 32 bytes for P-256), not ASN.1 DER.
// ecdsa.PrivateKey.Sign returns ASN.1 DER, so we parse and re-encode.
func (s *rfc6979Signer) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("rfc6979Signer: unsupported algorithm %s", alg)
	}
	// Hash the payload with SHA-256 (ES256 requirement).
	h := sha256.Sum256(payload)
	// Pass nil rand to invoke RFC 6979 deterministic ECDSA (Go 1.20+).
	// Returns ASN.1 DER encoded signature.
	derSig, err := s.key.Sign(nil, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	// Parse the ASN.1 DER signature and re-encode as raw r || s.
	// go-jose expects [r (32 bytes)] || [s (32 bytes)] for ES256 (P-256).
	var ecSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(derSig, &ecSig); err != nil {
		return nil, fmt.Errorf("rfc6979Signer: unmarshal DER sig: %w", err)
	}
	const keyBytes = 32 // P-256: 256 bits / 8
	out := make([]byte, 2*keyBytes)
	rb := ecSig.R.Bytes()
	sb := ecSig.S.Bytes()
	copy(out[keyBytes-len(rb):keyBytes], rb)
	copy(out[2*keyBytes-len(sb):], sb)
	return out, nil
}

// Constants matching internal/testfix/testfix.go.
const (
	testImageName   = "ghcr.io/sns45/example:1.0.0"
	testImageDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// A clearly different digest used for the digest-mismatch fixture.
	// All-'a' hex string of the same length.
	mismatchDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	payloadType = "application/vnd.in-toto+json"
	statementV1 = "https://in-toto.io/Statement/v1"
)

// dsseEnvelope is the DSSE wire format.
type dsseEnvelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

// signature is a placeholder signature entry (no real crypto for synthetic fixtures).
type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// statement is a minimal in-toto Statement v1.
type statement struct {
	Type          string      `json:"_type"`
	Subject       []subject   `json:"subject"`
	PredicateType string      `json:"predicateType"`
	Predicate     interface{} `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// buildDSSE encodes a statement as a DSSE envelope JSON.
func buildDSSE(stmt statement) ([]byte, error) {
	stmtJSON, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	env := dsseEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(stmtJSON),
		Signatures: []signature{
			{KeyID: "", Sig: ""},
		},
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

// digestHex strips the "sha256:" prefix from a digest string.
func digestHex(d string) string {
	if len(d) > 7 && d[:7] == "sha256:" {
		return d[7:]
	}
	return d
}

// subjectFor builds a subject list for the given image and digest.
func subjectFor(name, digest string) []subject {
	return []subject{
		{
			Name:   name,
			Digest: map[string]string{"sha256": digestHex(digest)},
		},
	}
}

func writeDSSE(path string, stmt statement) {
	data, err := buildDSSE(stmt)
	if err != nil {
		log.Fatalf("build DSSE for %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	// Resolve output directory relative to this file (repo root / testdata).
	// When invoked as "go run testdata/gen/main.go" from the repo root, the
	// working directory is the repo root.
	root := "testdata"

	// 1. testdata/slsa/valid-l3.dsse.json
	//
	// SLSA Provenance v1 with builder.id present and hosted — this meets the
	// minimum bar for SLSA Build L3 under the SLSA v1.0 specification:
	//   - predicateType: https://slsa.dev/provenance/v1
	//   - buildDefinition.buildType identifies the build system
	//   - runDetails.builder.id is a fully-qualified HTTPS URI (hosted builder)
	//   - runDetails.builder.builderDependencies is empty (trusted builder, no
	//     external deps injected at build time — a L3 requirement)
	//
	// NOTE: actual L3 verification requires a Sigstore-signed bundle attesting
	// to a SLSA-conformant builder. This fixture has a placeholder signature and
	// is for non-crypto predicate parsing tests only.
	writeDSSE(filepath.Join(root, "slsa", "valid-l3.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]interface{}{
			"buildDefinition": map[string]interface{}{
				"buildType": "https://github.com/sns45/ci/build-system@v1",
				"externalParameters": map[string]interface{}{
					"ref": "refs/heads/main",
				},
				"internalParameters":   map[string]interface{}{},
				"resolvedDependencies": []interface{}{},
			},
			"runDetails": map[string]interface{}{
				"builder": map[string]interface{}{
					"id":                  "https://github.com/sns45/ci",
					"builderDependencies": []interface{}{},
					"version":             map[string]string{},
				},
				"metadata": map[string]interface{}{
					"invocationId": "https://github.com/sns45/example/actions/runs/1",
					"startedOn":    "2024-01-01T00:00:00Z",
					"finishedOn":   "2024-01-01T00:05:00Z",
				},
				"byproducts": []interface{}{},
			},
		},
	})

	// 2. testdata/slsa/digest-mismatch.dsse.json
	//
	// Same structure as valid-l3 but the subject digest does NOT match
	// TestImageDigest. Used for the subject-digest-mismatch negative test.
	writeDSSE(filepath.Join(root, "slsa", "digest-mismatch.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, mismatchDigest),
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]interface{}{
			"buildDefinition": map[string]interface{}{
				"buildType": "https://github.com/sns45/ci/build-system@v1",
			},
			"runDetails": map[string]interface{}{
				"builder": map[string]interface{}{
					"id": "https://github.com/sns45/ci",
				},
			},
		},
	})

	// 3. testdata/sbom/cyclonedx.dsse.json
	//
	// CycloneDX 1.5 SBOM with two representative components.
	writeDSSE(filepath.Join(root, "sbom", "cyclonedx.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://cyclonedx.org/bom",
		Predicate: map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"version":     1,
			"metadata": map[string]interface{}{
				"timestamp": "2024-01-01T00:00:00Z",
				"component": map[string]interface{}{
					"type":    "container",
					"name":    testImageName,
					"version": "1.0.0",
				},
			},
			"components": []interface{}{
				map[string]interface{}{
					"type":     "library",
					"name":     "left-pad",
					"version":  "1.3.0",
					"purl":     "pkg:npm/left-pad@1.3.0",
					"licenses": []interface{}{map[string]interface{}{"license": map[string]string{"id": "MIT"}}},
					"supplier": map[string]interface{}{"name": "Organization: npm"},
					"bom-ref":  "pkg:npm/left-pad@1.3.0",
				},
				map[string]interface{}{
					"type":     "library",
					"name":     "example.com/x",
					"version":  "1.0.0",
					"purl":     "pkg:golang/example.com/x@1.0.0",
					"licenses": []interface{}{map[string]interface{}{"license": map[string]string{"id": "Apache-2.0"}}},
					"supplier": map[string]interface{}{"name": "Organization: example.com"},
					"bom-ref":  "pkg:golang/example.com/x@1.0.0",
				},
			},
		},
	})

	// 4. testdata/vex/affected-critical.dsse.json
	//
	// OpenVEX document with one statement: CVE-2024-0001 is "affected" with no
	// justification (used for negative/critical-finding tests).
	writeDSSE(filepath.Join(root, "vex", "affected-critical.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate: map[string]interface{}{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.com/vex/affected-critical-1",
			"author":    "sns45-ci",
			"timestamp": "2024-01-01T00:00:00Z",
			"version":   1,
			"statements": []interface{}{
				map[string]interface{}{
					"vulnerability": map[string]interface{}{
						"@id":         "https://osv.dev/CVE-2024-0001",
						"name":        "CVE-2024-0001",
						"description": "Critical synthetic vulnerability for fixture testing.",
					},
					"products": []interface{}{
						map[string]interface{}{
							"@id": "pkg:oci/example@sha256:" + digestHex(testImageDigest),
							"subcomponents": []interface{}{
								map[string]interface{}{"@id": "pkg:npm/left-pad@1.3.0"},
							},
						},
					},
					"status": "affected",
					// No justification field — status is "affected", justification not applicable.
					"action_statement": "Component is directly vulnerable; no mitigations in place.",
				},
			},
		},
	})

	// 5. testdata/vex/not-affected.dsse.json
	//
	// OpenVEX document with same vuln (CVE-2024-0001) but status "not_affected"
	// with a justification. Used for the positive/mitigated-vuln tests.
	writeDSSE(filepath.Join(root, "vex", "not-affected.dsse.json"), statement{
		Type:          statementV1,
		Subject:       subjectFor(testImageName, testImageDigest),
		PredicateType: "https://openvex.dev/ns/v0.2.0",
		Predicate: map[string]interface{}{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.com/vex/not-affected-1",
			"author":    "sns45-ci",
			"timestamp": "2024-01-01T00:00:00Z",
			"version":   1,
			"statements": []interface{}{
				map[string]interface{}{
					"vulnerability": map[string]interface{}{
						"@id":         "https://osv.dev/CVE-2024-0001",
						"name":        "CVE-2024-0001",
						"description": "Critical synthetic vulnerability for fixture testing.",
					},
					"products": []interface{}{
						map[string]interface{}{
							"@id": "pkg:oci/example@sha256:" + digestHex(testImageDigest),
						},
					},
					"status":           "not_affected",
					"justification":    "vulnerable_code_not_in_execute_path",
					"impact_statement": "The vulnerable code path in left-pad is never called by this image.",
				},
			},
		},
	})

	// 6-11. SVID fixtures (task 1.7).
	writeSVIDFixtures(root)

	fmt.Println("done — all fixtures written to testdata/")
}

// writeSVIDFixtures generates all SVID-related fixtures into testdata/svid/.
//
// DETERMINISM: all keys are derived via deriveKey (pure SHA-256 scalar). JWT
// signing uses rfc6979Signer (jose.OpaqueSigner) with nil rand => RFC 6979.
// X.509 signing uses nil rand => RFC 6979. All timestamps are fixed constants.
//
// SYNTHETIC PLACEHOLDERS: all keys and certs here are freshly generated at
// generation time and are NOT real svidmint credentials. They will be replaced
// before v0.1 ships.
func writeSVIDFixtures(root string) {
	svidDir := filepath.Join(root, "svid")
	if err := os.MkdirAll(svidDir, 0o755); err != nil {
		log.Fatalf("mkdir svid: %v", err)
	}

	// Generate the primary JWT signing key deterministically.
	jwtKey := deriveKey("jwt-signing-key")

	// --- JWT-SVID fixtures ---

	// jwt-bundle.json: JWKS containing the public key for trust domain sns45.dev.
	bundleBytes := mustMarshalJWKS(jwtKey)
	writeFile(filepath.Join(svidDir, "jwt-bundle.json"), bundleBytes)
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "jwt-bundle.json"))

	// jwt-valid.jwt: valid JWT-SVID, sub = spiffe://sns45.dev/ci/release,
	// aud = [testImageDigest], exp far future (fixed to 2099-01-01).
	validToken := mustSignJWT(jwtKey, "spiffe://sns45.dev/ci/release", testImageDigest, fixedIssuedAt, fixedNotAfter, "svid-test-key-1")
	writeFile(filepath.Join(svidDir, "jwt-valid.jwt"), []byte(validToken))
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "jwt-valid.jwt"))

	// jwt-expired.jwt: same as valid but exp in the past (fixed to 2020-06-01).
	expiredToken := mustSignJWT(jwtKey, "spiffe://sns45.dev/ci/release", testImageDigest, fixedExpiredBefore, fixedExpiredAfter, "svid-test-key-1")
	writeFile(filepath.Join(svidDir, "jwt-expired.jwt"), []byte(expiredToken))
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "jwt-expired.jwt"))

	// jwt-wrong-domain.jwt: sub = spiffe://evil.example/ci/release, aud =
	// [testImageDigest]. Rejected because the verifier looks up the bundle for
	// "sns45.dev" (the only trusted domain) and evil.example has no entry there
	// (missing-bundle rejection, NOT a cryptographic signature rejection).
	wrongDomainKey := deriveKey("jwt-wrong-domain-key")
	wrongDomainToken := mustSignJWT(wrongDomainKey, "spiffe://evil.example/ci/release", testImageDigest, fixedIssuedAt, fixedNotAfter, "svid-test-key-1")
	writeFile(filepath.Join(svidDir, "jwt-wrong-domain.jwt"), []byte(wrongDomainToken))
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "jwt-wrong-domain.jwt"))

	// jwt-wrong-key.jwt: sub = spiffe://sns45.dev/ci/release, aud =
	// [testImageDigest], far-future exp. Signed by a SECOND key (wrongSignKey)
	// whose public key is NOT in jwt-bundle.json. Trust domain sns45.dev IS
	// found in the bundle, so this exercises cryptographic signature rejection
	// (not a missing-bundle rejection).
	wrongSignKey := deriveKey("jwt-wrong-sign-key")
	wrongKeyToken := mustSignJWT(wrongSignKey, "spiffe://sns45.dev/ci/release", testImageDigest, fixedIssuedAt, fixedNotAfter, "svid-test-key-wrong")
	writeFile(filepath.Join(svidDir, "jwt-wrong-key.jwt"), []byte(wrongKeyToken))
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "jwt-wrong-key.jwt"))

	// --- X509-SVID fixtures ---

	// Generate a self-signed CA key and cert. Pass nil rand to x509.CreateCertificate
	// to use RFC 6979 deterministic ECDSA signing (Go 1.20+).
	caKey := deriveKey("x509-ca-key")
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sns45.dev SVID Test CA"},
		NotBefore:             fixedNotBefore,
		NotAfter:              fixedNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(nil, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		log.Fatalf("parse CA cert: %v", err)
	}

	// x509-bundle.pem: PEM of the X509-SVID CA root.
	caBundlePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	writeFile(filepath.Join(svidDir, "x509-bundle.pem"), caBundlePEM)
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "x509-bundle.pem"))

	// Generate a leaf key and cert signed by the CA.
	leafKey := deriveKey("x509-leaf-key")
	spiffeURI, err := url.Parse("spiffe://sns45.dev/ci/release")
	if err != nil {
		log.Fatalf("parse SPIFFE URI: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sns45.dev/ci/release"},
		NotBefore:    fixedNotBefore,
		NotAfter:     fixedNotAfter,
		URIs:         []*url.URL{spiffeURI},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	leafCertDER, err := x509.CreateCertificate(nil, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create leaf cert: %v", err)
	}

	// x509-valid.pem: PEM leaf cert chain with URI SAN spiffe://sns45.dev/ci/release.
	var leafChainPEM []byte
	leafChainPEM = append(leafChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})...)
	writeFile(filepath.Join(svidDir, "x509-valid.pem"), leafChainPEM)
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "x509-valid.pem"))

	// x509-expired.pem: PEM leaf cert with URI SAN spiffe://sns45.dev/ci/release,
	// signed by the SAME caKey/caCert, but with NotAfter fixed to 2020-06-01
	// (in the past). Tests expiry rejection.
	expiredLeafKey := deriveKey("x509-expired-leaf-key")
	expiredLeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sns45.dev/ci/release"},
		NotBefore:    fixedExpiredBefore,
		NotAfter:     fixedExpiredAfter,
		URIs:         []*url.URL{spiffeURI},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	expiredLeafCertDER, err := x509.CreateCertificate(nil, expiredLeafTemplate, caCert, &expiredLeafKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("create expired leaf cert: %v", err)
	}
	expiredLeafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredLeafCertDER})
	writeFile(filepath.Join(svidDir, "x509-expired.pem"), expiredLeafPEM)
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "x509-expired.pem"))

	// x509-wrong-ca.pem: PEM leaf cert signed by a SECOND, separate CA
	// (wrongCACert/wrongCAKey) that is NOT in x509-bundle.pem.
	// Tests unknown-CA rejection.
	wrongCAKey := deriveKey("x509-wrong-ca-key")
	wrongCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "untrusted-ca.example SVID Test CA"},
		NotBefore:             fixedNotBefore,
		NotAfter:              fixedNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	wrongCACertDER, err := x509.CreateCertificate(nil, wrongCATemplate, wrongCATemplate, &wrongCAKey.PublicKey, wrongCAKey)
	if err != nil {
		log.Fatalf("create wrong CA cert: %v", err)
	}
	wrongCACert, err := x509.ParseCertificate(wrongCACertDER)
	if err != nil {
		log.Fatalf("parse wrong CA cert: %v", err)
	}

	wrongCALeafKey := deriveKey("x509-wrong-ca-leaf-key")
	wrongCALeafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "sns45.dev/ci/release"},
		NotBefore:    fixedNotBefore,
		NotAfter:     fixedNotAfter,
		URIs:         []*url.URL{spiffeURI},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	wrongCALeafCertDER, err := x509.CreateCertificate(nil, wrongCALeafTemplate, wrongCACert, &wrongCALeafKey.PublicKey, wrongCAKey)
	if err != nil {
		log.Fatalf("create wrong-CA leaf cert: %v", err)
	}
	wrongCALeafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongCALeafCertDER})
	writeFile(filepath.Join(svidDir, "x509-wrong-ca.pem"), wrongCALeafPEM)
	fmt.Printf("wrote %s\n", filepath.Join(svidDir, "x509-wrong-ca.pem"))
}

// mustMarshalJWKS marshals the public key of key into a JWKS document suitable
// for use as a SPIFFE JWT bundle.
func mustMarshalJWKS(key *ecdsa.PrivateKey) []byte {
	jwk := jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "svid-test-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	b, err := json.Marshal(jwks)
	if err != nil {
		log.Fatalf("marshal JWKS: %v", err)
	}
	return b
}

// mustSignJWT creates and signs a compact JWT-SVID token with the given kid.
//
// Uses rfc6979Signer (jose.OpaqueSigner) so the ECDSA nonce is derived
// deterministically via RFC 6979 — no randomness involved. iat and exp must
// be fixed constants, never time.Now().
func mustSignJWT(key *ecdsa.PrivateKey, sub, aud string, iat, exp time.Time, kid string) string {
	opaque := &rfc6979Signer{key: key, kid: kid}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: opaque},
		(&jose.SignerOptions{}).WithHeader("kid", kid).WithType("JWT"),
	)
	if err != nil {
		log.Fatalf("new signer: %v", err)
	}

	claims := josejwt.Claims{
		Subject:  sub,
		Audience: josejwt.Audience{aud},
		IssuedAt: josejwt.NewNumericDate(iat),
		Expiry:   josejwt.NewNumericDate(exp),
	}

	token, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		log.Fatalf("sign JWT: %v", err)
	}
	return token
}

// writeFile writes data to path, creating the file (overwriting if existing).
func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
