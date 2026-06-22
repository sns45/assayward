# Bundle Signing

## v0.1 (current): ECDSA Keyed Proxy (offline, hermetic)

`sign.go` implements an offline ECDSA-P256-SHA256 signing proxy for hermetic
testing without network access. The signature is stored as an OCI referrer
artifact (cosign referrer pattern) with:

- `artifactType: application/vnd.assayward.policybundle.sig.v1`
- `subject`: the bundle manifest descriptor
- one layer: JSON-encoded `{r, s}` ECDSA signature bytes

CLI usage:

```
assayward bundle sign  <ref> --key <ecdsa-private-key.pem>
assayward bundle verify <ref> --key <ecdsa-public-key.pem>
```

Exit codes for verify: 0 = valid, 1 = invalid/missing, 2 = usage error.

## Production (M6): cosign keyless + forgeseal (trilogy loop, §6.6)

In production the signing flow is:

1. **Sign**: `cosign sign` (keyless, Fulcio CA issues a short-lived cert,
   entry logged to Rekor transparency log).
2. **Distribute**: the cosign signature is pushed as an OCI referrer artifact
   to the same registry as the bundle (identical OCI wiring to the keyed proxy
   above).
3. **Verify**: `forgeseal` pulls the OCI referrer, verifies the Rekor
   inclusion proof and Fulcio certificate chain, and emits a trust decision
   that closes the trilogy loop (§6.6).

The OCI referrer/subject plumbing in `sign.go` matches the cosign referrer
pattern exactly. Swapping in production requires:

- Replacing `bundle.Sign` with `cosign.Sign` (keyless).
- Replacing `bundle.Verify`/`bundle.PullAndVerifyReferrer` with the forgeseal
  verifier client (wired at M6).
- Exposing a `--sigstore` flag on `assayward bundle verify` (TODO stub
  already present in `bundle.go`).

No changes to the OCI push/pull wiring are required; the production swap is
purely a function substitution at the Sign/Verify call sites.

## TODO

- `TODO(M6)`: wire `--sigstore` flag in `registerBundleVerifyCmd` and
  `registerBundleSignCmd` for cosign keyless signing and forgeseal
  verification.
