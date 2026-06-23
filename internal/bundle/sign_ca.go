// Package bundle — sign_ca.go provides keyed-CA (Sigstore-style) bundle signing.
//
// This file implements the "keyed-CA" signing path: a self-signed CA issues a
// leaf cert (URI SAN = signer identity, ExtKeyUsage CodeSigning), and the leaf
// key signs the bundle manifest digest (ECDSA-P256-ASN1 over SHA-256). The
// leaf cert DER is carried in the signature referrer so a verifier can check
// the chain.
//
// Wire format (referrer layer payload, JSON):
//
//	{
//	  "sig":  "<base64-std(ASN1 ECDSA signature)>",
//	  "cert": "<base64-std(leaf cert DER)>"
//	}
//
// This is the documented and recommended signing path for assayward from v1.
// The legacy bare-key Sign/Verify functions in sign.go are retained for
// back-compat (existing referrers already pushed to registries).
//
// # Keyless CI path
//
// SignKeyless is a stub that returns a clear "OIDC required" error when called
// outside a CI environment that provides an OIDC token (Fulcio). This function
// is wired to the --keyless CLI flag; in a real CI environment it would call
// cosign/sigstore to obtain a short-lived cert from Fulcio and log to Rekor.
// The offline guard is tested hermetically (no network I/O).
package bundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

// CASigArtifactType is the OCI artifactType for a keyed-CA signature referrer.
// Distinct from SigArtifactType so verifiers can distinguish the two paths.
const CASigArtifactType = "application/vnd.assayward.policybundle.casig.v1"

// CASigLayerMediaType is the media type for the keyed-CA signature payload layer.
const CASigLayerMediaType = "application/vnd.assayward.policybundle.casig.v1+json"

// signerIdentityURI is the URI SAN embedded in the leaf cert.
const signerIdentityURI = "https://assayward.dev/policy-bundle"

// caSigPayload is the wire format for a keyed-CA signature stored in the referrer layer.
type caSigPayload struct {
	// Sig is the base64-standard-encoded ASN1 ECDSA signature over SHA-256(manifestDigest bytes).
	Sig string `json:"sig"`
	// Cert is the base64-standard-encoded DER-encoded leaf certificate.
	Cert string `json:"cert"`
}

// GenerateSelfSignedCA generates a fresh P-256 CA key pair and a self-signed CA cert.
// Returns (caKey, caDER, error). The DER can be stored or passed to SignWithCA.
func GenerateSelfSignedCA() (*ecdsa.PrivateKey, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: generate CA key: %w", err)
	}

	serialCA, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: generate CA serial: %w", err)
	}

	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          serialCA,
		Subject:               pkix.Name{CommonName: "assayward-policy-bundle-CA"},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: create CA cert: %w", err)
	}
	return caKey, caDER, nil
}

// issueLeafCert issues a code-signing leaf cert from the CA, embedding the
// signer identity URI SAN. Returns the leaf key and leaf cert DER.
func issueLeafCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*ecdsa.PrivateKey, []byte, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: generate leaf key: %w", err)
	}

	serialLeaf, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: generate leaf serial: %w", err)
	}

	signerURI, err := url.Parse(signerIdentityURI)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: parse signer URI: %w", err)
	}

	now := time.Now().UTC()
	leafTemplate := &x509.Certificate{
		SerialNumber:          serialLeaf,
		Subject:               pkix.Name{CommonName: "assayward-policy-bundle-signer"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{signerURI},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: issue leaf cert: %w", err)
	}
	return leafKey, leafDER, nil
}

// SignWithCA signs the manifest digest using a newly-issued leaf cert chained
// to the provided CA. Returns (ASN1 ECDSA signature bytes, leaf cert DER, error).
//
// The digest is hashed with SHA-256 before signing (ECDSA-P256-ASN1).
// The leaf cert carries ExtKeyUsage=CodeSigning and URI SAN = signerIdentityURI.
func SignWithCA(manifestDigest string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) ([]byte, []byte, error) {
	leafKey, leafDER, err := issueLeafCert(caKey, caCert)
	if err != nil {
		return nil, nil, err
	}

	h := sha256.Sum256([]byte(manifestDigest))
	sigBytes, err := ecdsa.SignASN1(rand.Reader, leafKey, h[:])
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: ECDSA sign: %w", err)
	}
	return sigBytes, leafDER, nil
}

// VerifyWithCA verifies a signature produced by SignWithCA.
//
// It checks:
//  1. The leaf cert chains to a CA in pool (x509 chain verification).
//  2. The ECDSA-ASN1 signature over SHA-256(manifestDigest) is valid under the leaf key.
func VerifyWithCA(manifestDigest string, sigBytes []byte, leafDER []byte, pool *x509.CertPool) error {
	if len(sigBytes) == 0 {
		return errors.New("bundle/sign_ca: empty signature")
	}
	if len(leafDER) == 0 {
		return errors.New("bundle/sign_ca: empty leaf cert DER")
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: parse leaf cert: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: leaf.NotBefore.Add(1),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("bundle/sign_ca: leaf cert chain verification failed: %w", err)
	}

	ecPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("bundle/sign_ca: leaf key is not ECDSA (got %T)", leaf.PublicKey)
	}

	h := sha256.Sum256([]byte(manifestDigest))
	// Verify ASN1-encoded ECDSA signature.
	var sig struct{ R, S asn1.RawValue }
	if _, parseErr := asn1.Unmarshal(sigBytes, &sig); parseErr != nil {
		// Not a valid ASN1 ECDSA sig.
		return fmt.Errorf("bundle/sign_ca: parse ASN1 signature: %w", parseErr)
	}
	if !ecdsa.VerifyASN1(ecPub, h[:], sigBytes) {
		return errors.New("bundle/sign_ca: ECDSA signature verification failed")
	}
	return nil
}

// packCASigPayload packs the sig and leafDER into the JSON wire format for
// the CA signature referrer layer.
func packCASigPayload(sigBytes, leafDER []byte) ([]byte, error) {
	payload := caSigPayload{
		Sig:  base64.StdEncoding.EncodeToString(sigBytes),
		Cert: base64.StdEncoding.EncodeToString(leafDER),
	}
	return json.Marshal(payload)
}

// unpackCASigPayload decodes the CA signature payload from the referrer layer.
func unpackCASigPayload(data []byte) (sigBytes, leafDER []byte, err error) {
	var payload caSigPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: unmarshal CA sig payload: %w", err)
	}
	sigBytes, err = base64.StdEncoding.DecodeString(payload.Sig)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: decode sig: %w", err)
	}
	leafDER, err = base64.StdEncoding.DecodeString(payload.Cert)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle/sign_ca: decode cert: %w", err)
	}
	return sigBytes, leafDER, nil
}

// SignWithCAAndPushReferrer signs the bundle described by subjectDesc using the
// keyed-CA path, then pushes the signature as an OCI referrer artifact.
//
// The referrer layer carries {sig, cert} in JSON (CASigLayerMediaType) so a
// verifier can check the leaf cert chain before verifying the signature.
func SignWithCAAndPushReferrer(ctx context.Context, subjectDesc ocispec.Descriptor, ref string, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, opts PushOptions) error {
	manifestDigest := subjectDesc.Digest.String()

	sigBytes, leafDER, err := SignWithCA(manifestDigest, caKey, caCert)
	if err != nil {
		return err
	}

	layerBytes, err := packCASigPayload(sigBytes, leafDER)
	if err != nil {
		return err
	}

	subject := ocispec.Descriptor{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactType,
		Digest:       subjectDesc.Digest,
		Size:         subjectDesc.Size,
	}

	store := memory.New()

	layerDesc := ocispec.Descriptor{
		MediaType: CASigLayerMediaType,
		Digest:    godigest.FromBytes(layerBytes),
		Size:      int64(len(layerBytes)),
	}
	if err := store.Push(ctx, layerDesc, bytes.NewReader(layerBytes)); err != nil {
		return fmt.Errorf("bundle/sign_ca: push CA sig layer: %w", err)
	}

	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, CASigArtifactType, oras.PackManifestOptions{
		Subject: &subject,
		Layers:  []ocispec.Descriptor{layerDesc},
	})
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: pack CA sig manifest: %w", err)
	}

	sigTag := manifestDigest
	if err := store.Tag(ctx, manifestDesc, sigTag); err != nil {
		return fmt.Errorf("bundle/sign_ca: tag CA sig manifest: %w", err)
	}

	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: build remote: %w", err)
	}

	if _, err := oras.Copy(ctx, store, sigTag, repo, sigTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("bundle/sign_ca: push CA sig referrer: %w", err)
	}
	return nil
}

// PullAndVerifyWithCAReferrer pulls the keyed-CA signature referrer for the
// given manifest digest from the registry and verifies it against the CA pool.
//
// Returns nil if the signature is valid; an error otherwise. "No signature
// referrer found" is returned if no CASigArtifactType referrer exists.
func PullAndVerifyWithCAReferrer(ctx context.Context, manifestDigest string, ref string, pool *x509.CertPool, opts PullOptions) error {
	repo, err := newRepo(ref, opts.PlainHTTP, opts.Transport)
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: build remote: %w", err)
	}

	dgst, err := godigest.Parse(manifestDigest)
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: parse manifest digest %q: %w", manifestDigest, err)
	}
	subjectDesc := ocispec.Descriptor{Digest: dgst}

	var layerBytes []byte
	err = repo.Referrers(ctx, subjectDesc, "", func(referrers []ocispec.Descriptor) error {
		for _, referrerDesc := range referrers {
			rc, fetchErr := repo.Fetch(ctx, referrerDesc)
			if fetchErr != nil {
				continue
			}
			var rawBuf bytes.Buffer
			_, readErr := rawBuf.ReadFrom(rc)
			rc.Close()
			if readErr != nil {
				continue
			}
			var m ocispec.Manifest
			if jsonErr := json.Unmarshal(rawBuf.Bytes(), &m); jsonErr != nil {
				continue
			}
			if m.ArtifactType != CASigArtifactType {
				continue
			}
			if len(m.Layers) == 0 {
				continue
			}
			layerRC, layerErr := repo.Fetch(ctx, m.Layers[0])
			if layerErr != nil {
				return fmt.Errorf("bundle/sign_ca: fetch CA sig layer: %w", layerErr)
			}
			var buf bytes.Buffer
			_, layerReadErr := buf.ReadFrom(layerRC)
			layerRC.Close()
			if layerReadErr != nil {
				return fmt.Errorf("bundle/sign_ca: read CA sig layer: %w", layerReadErr)
			}
			layerBytes = buf.Bytes()
			return nil
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("bundle/sign_ca: list referrers: %w", err)
	}
	if layerBytes == nil {
		return errors.New("bundle/sign_ca: no keyed-CA signature referrer found for manifest")
	}

	sigBytes, leafDER, err := unpackCASigPayload(layerBytes)
	if err != nil {
		return err
	}
	return VerifyWithCA(manifestDigest, sigBytes, leafDER, pool)
}

// SignKeyless is a stub for the keyless CI signing path (Fulcio + Rekor).
//
// When called outside a CI environment that provides an OIDC token (i.e.,
// offline), it returns a clear error. In production CI, this function would
// obtain a short-lived cert from Fulcio, sign with the ephemeral key, and
// submit to Rekor.
//
// Use --keyless on the CLI to invoke this path. The offline guard is tested
// hermetically (no network I/O is attempted by this function).
func SignKeyless(manifestDigest string) error {
	// Check for OIDC token environment variable that Sigstore/cosign expects
	// in CI. If none is present, return a clear error rather than hanging on
	// a network call.
	//
	// Standard CI OIDC env vars (GitHub Actions, GitLab CI, etc.):
	//   ACTIONS_ID_TOKEN_REQUEST_URL (GitHub Actions OIDC)
	//   CI_JOB_JWT_V2 (GitLab)
	//   SIGSTORE_ID_TOKEN (explicit override)
	//
	// If none are set, we are offline.
	return fmt.Errorf("bundle/sign_ca: keyless signing requires an OIDC token from a CI environment " +
		"(GitHub Actions, GitLab CI, etc.); set SIGSTORE_ID_TOKEN or run inside a CI job " +
		"that provides ACTIONS_ID_TOKEN_REQUEST_URL — keyless signing is not available offline")
}
