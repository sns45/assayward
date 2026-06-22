# assayward Kustomize manifests

Kustomize is the **fallback install path** for the assayward admission webhook.
Use Helm (`deploy/helm/assayward-webhook`) when you have Helm available; use
Kustomize on clusters where you want plain YAML with no Helm dependency.

## Directory layout

```
deploy/kustomize/
  base/                              Plain manifests (all clusters)
    namespace.yaml                   Namespace assayward-system
    serviceaccount.yaml
    configmap.yaml                   Built-in slsa-l3 TrustPolicy (replace to customise)
    deployment.yaml                  Webhook; --mode=audit; probes on /healthz HTTPS:8443
    service.yaml                     ClusterIP 443 -> 8443
    validatingwebhookconfiguration.yaml   Pods CREATE /validate; caBundle left empty
    kustomization.yaml
  overlays/
    cert-manager/                    Adds cert-manager Issuer + Certificate; patches annotation
      issuer.yaml                    selfSigned Issuer in assayward-system
      certificate.yaml               Certificate -> Secret assayward-webhook-tls
      patch-webhook-ca-annotation.yaml   Adds cert-manager.io/inject-ca-from annotation
      kustomization.yaml
  README.md                          This file
```

## Option A: cert-manager overlay (recommended)

Requires [cert-manager](https://cert-manager.io/) v1.x installed on the cluster.

```bash
kubectl apply -k deploy/kustomize/overlays/cert-manager
```

cert-manager automatically:

1. Creates a self-signed `Issuer` in `assayward-system`.
2. Issues a `Certificate` and stores it as `Secret/assayward-webhook-tls`.
3. Reads the `cert-manager.io/inject-ca-from: assayward-system/assayward-webhook-tls`
   annotation and injects the CA bundle into `webhooks[*].clientConfig.caBundle`
   on every renewal.

No manual caBundle patching is needed.

## Option B: base only (manual TLS)

Use this when cert-manager is not available.

### Step 1: create the TLS secret

Generate a self-signed CA and serving cert (or use your PKI):

```bash
# Example using openssl
openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout ca.key -out ca.crt -days 365 \
  -subj "/CN=assayward-webhook-ca"

openssl req -newkey rsa:4096 -nodes \
  -keyout tls.key -out tls.csr \
  -subj "/CN=assayward-webhook.assayward-system.svc"

openssl x509 -req -days 365 \
  -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:assayward-webhook.assayward-system.svc,DNS:assayward-webhook.assayward-system.svc.cluster.local") \
  -out tls.crt

kubectl create secret tls assayward-webhook-tls \
  --cert=tls.crt --key=tls.key \
  -n assayward-system
```

### Step 2: apply the base

```bash
kubectl apply -k deploy/kustomize/base
```

### Step 3: patch the caBundle

The `ValidatingWebhookConfiguration` ships with an empty `caBundle`. Patch it
with the base64-encoded CA certificate:

```bash
CA_B64=$(base64 -w0 ca.crt)   # Linux; macOS: base64 -i ca.crt

kubectl patch validatingwebhookconfiguration assayward-webhook \
  --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/webhooks/0/clientConfig/caBundle\",\"value\":\"${CA_B64}\"}]"
```

## Audit-first rollout

The webhook ships in **audit mode** (`--mode=audit`) with `failurePolicy: Ignore`.
In this state:

- Every pod is admitted regardless of policy outcome.
- Policy violations appear as Kubernetes Warning events and `kubectl describe pod`
  annotations prefixed with `assayward/`.
- A webhook outage does NOT block pod scheduling.

**To migrate to enforce mode** after confirming the policy is clean:

1. Patch the Deployment to pass `--mode=enforce`:

   ```bash
   kubectl set env deployment/assayward-webhook -n assayward-system \
     ASSAYWARD_MODE=enforce   # or edit the args list directly
   ```

   Or update `deploy/kustomize/base/deployment.yaml` line `- --mode=audit` to
   `- --mode=enforce` and re-apply.

2. Patch the `ValidatingWebhookConfiguration` to use `failurePolicy: Fail`:

   ```bash
   kubectl patch validatingwebhookconfiguration assayward-webhook \
     --type=json \
     -p='[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Fail"}]'
   ```

## Customising the policy

The default ConfigMap embeds the `slsa-l3` built-in policy. To replace it:

```bash
kubectl create configmap assayward-webhook-config \
  --from-file=policy.yaml=/path/to/my-policy.yaml \
  -n assayward-system \
  --dry-run=client -o yaml | kubectl apply -f -
```

Then update the Deployment args to use `--policy-file=/config/policy.yaml`
instead of `--policy=slsa-l3`.

## Namespace exclusions

The webhook's `namespaceSelector` excludes `kube-system` and `assayward-system`
to prevent:

- Bootstrap deadlocks: the webhook pods themselves start in `assayward-system`
  before the admission path is ready.
- Self-deny scenarios: the webhook must not evaluate its own pod updates.

Do not remove these exclusions unless you have an alternative bootstrap strategy.
