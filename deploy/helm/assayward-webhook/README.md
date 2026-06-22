# assayward-webhook Helm Chart

Kubernetes validating admission webhook for assayward container image trust.

## Install

```bash
# Audit-first (recommended for initial rollout)
helm install assayward-webhook ./deploy/helm/assayward-webhook \
  --namespace assayward-system --create-namespace

# Or from GHCR (once published)
helm install assayward-webhook oci://ghcr.io/sns45/charts/assayward-webhook \
  --namespace assayward-system --create-namespace \
  --version 0.1.0
```

## Audit to Enforce Migration (§3)

The chart ships with `mode=audit` and `failurePolicy=Ignore` so the webhook
never blocks pods during initial rollout. Follow this migration path:

**Step 1: Install in audit mode and watch warnings**

```bash
# Watch all audit warnings from the webhook
kubectl get events -A --field-selector reason=Warning | grep assayward

# Or watch pod descriptions for Warning annotations
kubectl describe pod <pod> -n <ns> | grep -A5 "assayward"

# Tail webhook logs
kubectl logs -n assayward-system \
  -l app.kubernetes.io/name=assayward-webhook -f
```

**Step 2: Tune the policy until false-positive rate is acceptable**

```bash
# Switch to a different builtin policy
helm upgrade assayward-webhook ./deploy/helm/assayward-webhook \
  --reuse-values --set policy.builtin=baseline

# Or supply a custom policy file
helm upgrade assayward-webhook ./deploy/helm/assayward-webhook \
  --reuse-values --set-file policy.inline=./my-policy.yaml
```

**Step 3: Flip to enforce**

```bash
helm upgrade assayward-webhook ./deploy/helm/assayward-webhook \
  --reuse-values \
  --set mode=enforce \
  --set failurePolicy=Fail
```

> **Note**: Set `failurePolicy=Fail` alongside `mode=enforce` so that if the
> webhook is unreachable, pods are blocked rather than silently admitted.

## Decision 4: Reduced Identity Mode

Identity verification (Sigstore TUF, SPIFFE bundles) is **optional**. In
reduced mode (the default) the webhook enforces supply-chain policy without
requiring identity attestation. This is safe for environments that do not yet
have Sigstore or SPIFFE infrastructure.

To enable Sigstore identity verification:

```bash
helm upgrade assayward-webhook ./deploy/helm/assayward-webhook \
  --reuse-values \
  --set-file trustRoots.sigstoreTUF=./trusted_root.json
```

To enable SPIFFE bundle verification:

```yaml
# in a values override file
trustRoots:
  spiffeBundles:
    example.org: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

## Container Image

The webhook image is published to GHCR:

```
ghcr.io/sns45/assayward-webhook:<tag>
```

Build locally:

```bash
docker build -f surfaces/k8s-webhook/Dockerfile \
  -t ghcr.io/sns45/assayward-webhook:dev .
```

## Values Reference

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `audit` | Admission mode: `audit`, `warn`, or `enforce` |
| `failurePolicy` | `Ignore` | `Ignore` or `Fail`; set `Fail` with `enforce` |
| `policy.builtin` | `slsa-l3` | Builtin policy: `baseline`, `slsa-l3`, `serverless-edge` |
| `policy.inline` | `""` | Inline TrustPolicy YAML; takes precedence over `policy.builtin` |
| `image.repository` | `ghcr.io/sns45/assayward-webhook` | Container registry and image name |
| `image.tag` | `""` (appVersion) | Image tag |
| `tls.mode` | `helm` | `helm` (self-signed) or `certManager` |
| `trustRoots.sigstoreTUF` | `""` | Sigstore TUF trusted-root JSON content |
| `trustRoots.spiffeBundles` | `{}` | Map of trustDomain to PEM/JWKS bundle |
| `webhook.namespaceSelector` | excludes `kube-system` | Namespace selector for the webhook |
| `webhook.timeoutSeconds` | `10` | Webhook admission timeout |
| `replicaCount` | `2` | Number of webhook replicas |

## TLS Notes

**`tls.mode: helm`** (default): Helm generates a self-signed CA and leaf cert
at install time using `genCA`/`genSignedCert`. The same CA is referenced in
both the TLS Secret and the `ValidatingWebhookConfiguration.caBundle`, so they
always match within a single `helm install` or `helm upgrade` call. However:

- Running `helm template | kubectl apply` twice will produce two different CAs
  (one per render), causing a cert mismatch. Always pipe from a single render.
- `helm upgrade` regenerates the cert, causing a brief TLS re-handshake. Use
  `tls.mode: certManager` for production workloads requiring stable certs.

**`tls.mode: certManager`**: emits a `cert-manager.io/v1 Certificate` resource.
Requires cert-manager to be installed and a `ClusterIssuer` configured per
`tls.certManager.issuerRef`.

## Namespace Bootstrap Deadlock Prevention

The `webhook.namespaceSelector` defaults to excluding `kube-system` and the
release namespace. This prevents a deadlock where the webhook must admit its
own pods before it can start. If you customise the namespace selector ensure
the webhook's own namespace is excluded:

```yaml
webhook:
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values:
          - kube-system
          - assayward-system  # your release namespace
```
