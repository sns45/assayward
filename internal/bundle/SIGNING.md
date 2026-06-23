# Bundle Signing

## Keyed-CA (default, offline-verifiable)

`sign_ca.go` implements the recommended signing path: a self-signed or external
CA issues a leaf certificate (URI SAN = `https://assayward.dev/policy-bundle`,
ExtKeyUsage CodeSigning), and the bundle manifest digest is signed using the
leaf key (ECDSA-P256-ASN1 over SHA-256). The leaf certificate DER is stored
alongside the signature bytes in the OCI referrer artifact so a verifier can
check the chain without trusting just a bare public key.

### OCI referrer format

- `artifactType: application/vnd.assayward.policybundle.casig.v1`
- `subject`: the bundle manifest descriptor
- one layer (`application/vnd.assayward.policybundle.casig.v1+json`):
  JSON `{"sig": "<base64-ASN1-ECDSA>", "cert": "<base64-leaf-DER>"}`

### CLI usage

```
# Generate a CA (one-time; for testing, use GenerateSelfSignedCA)
assayward bundle sign  <ref> --ca-key <ca-private-key.pem> --ca-cert <ca-cert.pem>
assayward bundle verify <ref> --ca-cert <ca-cert.pem>
```

Exit codes for verify: 0 = valid, 1 = invalid/missing, 2 = usage error.

### Verification logic

1. Pull the `casig.v1` referrer from the registry.
2. Decode the JSON payload; base64-decode the leaf cert DER and ASN1 signature.
3. Parse and verify the leaf cert chains to the provided CA pool
   (`x509.Verify` with `ExtKeyUsageCodeSigning`).
4. Verify the ECDSA-ASN1 signature over `SHA-256(manifestDigest bytes)` with
   the leaf public key.

This mirrors `pkg/core/verify/keyed_signature.go`'s approach for forgeseal
bundles so both sides of the trust loop are symmetric.

## Keyless CI (Sigstore Fulcio + Rekor)

`sign_ca.go` exports `SignKeyless`, which is wired to `--keyless` on the CLI.
When invoked outside a CI environment that provides an OIDC token, it returns a
clear "OIDC required" error without making any network calls. In a real CI job
(GitHub Actions, GitLab CI, etc.) this path would:

1. Obtain a short-lived cert from Fulcio (OIDC-backed identity).
2. Sign the manifest digest with the ephemeral key.
3. Submit the signed bundle to Rekor (transparency log).

```
assayward bundle sign <ref> --keyless   # CI only; requires OIDC token
```

The offline guard is tested hermetically (`TestKeylessSigning_RequiresOIDC`).

## Legacy bare-key (back-compat)

The original M5 path (`sign.go`) signs with a bare ECDSA private key and stores
a JSON `{r, s}` pair in the referrer. This path is still functional for
backwards compatibility with bundles already signed this way.

```
assayward bundle sign  <ref> --key <ecdsa-private-key.pem>
assayward bundle verify <ref> --key <ecdsa-public-key.pem>
```

New bundles should use the keyed-CA path. The bare-key path may be removed in a
future milestone.

## Symmetric trust model

```
                   [bundle sign --ca-key/--ca-cert]
                              |
              SignWithCAAndPushReferrer
                              |
               OCI referrer: casig.v1 {sig, cert}
                              |
              PullAndVerifyWithCAReferrer
                              |
                   [bundle verify --ca-cert]

          --- mirrors ---

          [forgeseal keyed bundle verification]
               pkg/core/verify/keyed_signature.go
               VerifyKeyedBundle (leaf cert chain + ECDSA-ASN1)
```

Both sides verify: leaf cert chains to CA + ECDSA-ASN1 over SHA-256(digest).
