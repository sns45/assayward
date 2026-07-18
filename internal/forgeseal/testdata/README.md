# Real forgeseal fixtures (Task 11)

These fixtures are the **actual, unedited output** of forgeseal built from source
(`github.com/sns45/forgeseal`, v0.5.1 line). They exist to prove the assayward
adapter and the keyed blob-signature verifier work against genuine forgeseal
artifacts, not hand-authored look-alikes. Do **not** hand-edit the signed bundles
or the CA: regenerate them if the format changes.

## How they were generated

Build forgeseal:

```
cd /path/to/forgeseal && go build -o /tmp/forgeseal ./cmd/forgeseal
```

A single shared, auto-generated keyed CA is used for everything so every
signature verifies against one committed certificate. The CA key/cert paths did
not exist beforehand, so forgeseal's `LoadOrGenerateCA` minted them:

```
--ca-key /tmp/fxca.key --ca-cert /tmp/fxca.crt --keyed
```

A tiny throwaway Go project (`/tmp/fxproj`) served as the lockfile input: a
`go.mod` with `module example.com/fxproj`, `go 1.23`, one real `require`
(`github.com/google/uuid v1.6.0`), a matching `go.sum` (from `go mod tidy`), and
a `main.go` that imports the dependency so `tidy` keeps it.

### pipeline-output/

```
/tmp/forgeseal pipeline \
  --dir /tmp/fxproj \
  --output-dir internal/forgeseal/testdata/pipeline-output \
  --sign --attest --vex-triage --keyed \
  --ca-key /tmp/fxca.key --ca-cert /tmp/fxca.crt
```

Files written:

- `sbom.cdx.json` — CycloneDX SBOM.
- `sbom.cdx.json.sigstore.json` — keyed messageSignature (blob) bundle over the SBOM.
- `sbom.cdx.json.intoto.jsonl` — raw in-toto SLSA provenance statement.
- `sbom.cdx.json.intoto.jsonl.sigstore.json` — keyed **DSSE** Sigstore bundle carrying the SLSA statement (the signed SLSA attestation).
- `vex.json` — real OpenVEX doc emitted by `--vex-triage` (no vulns found → empty `statements`).
- `forgeseal-signing-ca.crt` — the shared self-signed signing CA (PEM).

The SLSA subject is the SBOM file, and its subject digest equals
`sha256(sbom.cdx.json)`. Tests derive the artifact digest from that file rather
than hard-coding it.

### blob/

```
printf 'assayward-release-artifact-bytes-v0.5.1' > internal/forgeseal/testdata/blob/artifact.bin
/tmp/forgeseal sign \
  --artifact internal/forgeseal/testdata/blob/artifact.bin \
  --keyed --ca-key /tmp/fxca.key --ca-cert /tmp/fxca.crt \
  --bundle internal/forgeseal/testdata/blob/artifact.bin.sigstore.json
shasum -a 256 internal/forgeseal/testdata/blob/artifact.bin | cut -d' ' -f1 \
  > internal/forgeseal/testdata/blob/artifact.sha256
```

Files:

- `artifact.bin` — the standalone release artifact bytes.
- `artifact.bin.sigstore.json` — keyed messageSignature (blob) bundle over the artifact.
- `artifact.sha256` — hex sha256 of `artifact.bin` (the artifact digest).
- `forgeseal-signing-ca.crt` — byte-identical to `pipeline-output/forgeseal-signing-ca.crt` (same shared CA); tests read the pipeline copy.

## VEX note

`--vex-triage` scanned the single component and found no vulnerabilities, so
forgeseal emitted a valid but empty-`statements` OpenVEX document
(`@context: https://openvex.dev/ns/v0.2.0`). This is genuine forgeseal output, so
no hand-authored VEX was needed.

## Keyed blob crypto (why VerifyBlobBundle matches)

forgeseal's keyed `SignBlob` computes `digest = sha256(content)`, signs it with
`ecdsa.SignASN1` (DER), and emits `messageDigest.digest = base64(digest)`,
`signature = base64(DER)`, with the ephemeral leaf cert in
`verificationMaterial.certificate` and no `tlogEntries`. `VerifyBlobBundle`
base64-decodes the digest, chains the leaf to `roots.SignatureCAs`, and runs
`ecdsa.VerifyASN1(pub, digest, sig)` — an exact match. The real blob verified on
the first try; no crypto-format fix was required.
