# gcp-wif-credential-provider

A kubelet image credential provider that pulls from **Google Artifact Registry**
using **Workload Identity Federation**, on Kubernetes clusters that are **not GKE**.
No service account keys, no `imagePullSecrets`, no Secret to rotate.

```
kubelet ──(pod's ServiceAccount token, KEP-4412)──▶ plugin
plugin  ──(token exchange)──▶ sts.googleapis.com ──▶ federated access token
plugin  ──(optional)──▶ iamcredentials generateAccessToken ──▶ SA access token
plugin  ──▶ kubelet: oauth2accesstoken:<token> for <region>-docker.pkg.dev
```

## Why this exists

Kubernetes 1.34 made ServiceAccount tokens for image credential providers beta
and on by default. That lets a pod pull with **its own** identity rather than a
node-wide one or a long-lived Secret. Off GKE, nothing existed to turn such a
token into Artifact Registry credentials:

- Google's `auth-provider-gcp` (kubernetes/cloud-provider-gcp) expects the GCE
  metadata server. Its newer STS flow hardcodes the GKE fleet audience
  (`identitynamespace:<project>.svc.id.goog:…`), so it cannot target a
  self-managed pool. It also publishes no release binaries.
- The other plugins that use this mode serve their own registries (Cloudsmith,
  JFrog, Harbor), or support GCP only on GKE.

This plugin is about 300 lines of Go using only the standard library. It makes
two HTTPS calls and has no dependencies.

## Requirements

- Kubernetes **1.34+** (`KubeletServiceAccountTokenForCredentialProviders`,
  beta and on by default).
- A GCP **workload identity pool** with an **OIDC provider** that trusts your
  cluster's ServiceAccount issuer. A cluster with no public issuer works:
  upload the JWKS instead of letting GCP fetch it.

  ```sh
  kubectl get --raw /openid/v1/jwks > jwks.json
  gcloud iam workload-identity-pools providers create-oidc PROVIDER \
    --location=global --workload-identity-pool=POOL \
    --issuer-uri="$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)" \
    --attribute-mapping="google.subject=assertion.sub" \
    --jwk-json-path=jwks.json
  ```

  An uploaded JWKS is **not refreshed**. If the cluster's SA signing key
  rotates, upload a JWKS holding both keys **before** the rotation, or every
  pull fails.

## Install

1. Put the binary in the kubelet's credential-provider bin dir. Pin it by
   `sha256` from `SHA256SUMS`, and optionally verify its provenance:
   `gh attestation verify <file> --repo dlouwers/gcp-wif-credential-provider`.
2. Write the CredentialProviderConfig:
   [`examples/credential-provider-config.yaml`](examples/credential-provider-config.yaml).
   On k3s, the defaults are `/var/lib/rancher/credentialprovider/{config.yaml,bin/}`
   and nothing else needs configuring.
3. Allow nodes to request tokens for the audience (`ServiceAccountNodeAudienceRestriction`,
   on by default since 1.33). Without this the plugin is never invoked:
   [`examples/rbac.yaml`](examples/rbac.yaml).
4. Annotate each ServiceAccount that should pull, and grant it access in GCP.

## ServiceAccount annotations

| Annotation | Required | Meaning |
|---|---|---|
| `gcp-wif-credential-provider.dlouwers.github.io/workload-identity-provider` | yes | `projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER`. This is the same format as Flux's `gcp.auth.fluxcd.io/workload-identity-provider`. It must match `serviceAccountTokenAudience`; the plugin checks before calling STS. |
| `gcp-wif-credential-provider.dlouwers.github.io/service-account` | no | A GCP service account email to impersonate. When it is absent, the federated token is used directly. |

**Direct access (recommended):** no GCP service account at all. Grant the
repository role to the federated principal:

```sh
gcloud artifacts repositories add-iam-policy-binding REPO --location=REGION \
  --role=roles/artifactregistry.reader \
  --member="principal://iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/subject/system:serviceaccount:NAMESPACE:NAME"
```

**Impersonation:** grant `roles/iam.workloadIdentityUser` on the GCP service
account to that same principal. The **IAM Service Account Credentials API**
must be enabled on the project. If it is not, impersonation fails with an error
that does not point at the missing API.

## Behaviour

- It only speaks `credentialprovider.kubelet.k8s.io/v1`, because the kubelet
  sends tokens only in v1.
- It returns credentials for `*.pkg.dev` hosts only, even when `matchImages` is
  broader, because a GCP token handed back for any other host would be sent to
  that host.
- `cacheDuration` is the token's remaining lifetime minus 5 minutes. Use
  `cacheType: Token`.
- Errors carry Google's error body and never the token.

## Licence

Apache-2.0.
