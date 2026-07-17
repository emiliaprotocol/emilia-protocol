# EMILIA Gate service Terraform module

This Kubernetes module deploys the BYOC image built from `Dockerfile.gate`. It
does not publish, default, or make a claim about an official EMILIA image.

The module creates a dedicated token-free ServiceAccount, migration Job,
two-replica Deployment, ClusterIP Service, PDB, and additive default-deny
NetworkPolicies. The migration Job is network-restricted, waits to complete,
and gates Deployment creation. Its immutable name includes the image, command,
and `migration_revision`; bump the revision when migration inputs change
without changing the image.

Only existing Secret names and keys enter Terraform. The operator config,
Postgres URL, Gate API token, and issuer roots are read at pod start with
non-optional references. Their values are not module variables and therefore
are not written to Terraform state by this module. The configuration Secret
must contain `gate.config.mjs` and `migrate.mjs`; these remain operator-owned
because `apps/gate-service` defines durable adapter contracts rather than
shipping an unsafe generic production fallback.

Set `migration_postgres_secret_name` and `migration_postgres_secret_key` to a
separate DDL-capable login Secret. Migrations enabled with a missing Secret or
the runtime Secret name are rejected; there is no fallback. The module cannot
compare Secret contents, so provision genuinely distinct credentials. The
long-lived service should use a least-privilege role that cannot alter schema.

## Example

```hcl
module "emilia_gate" {
  source = "./packages/gate/deploy/terraform/service"

  namespace = "emilia-gate"
  image     = "registry.example.com/security/emilia-gate-service@sha256:REPLACE"

  configuration_secret_name = "emilia-gate-configuration"
  postgres_secret_name     = "emilia-gate-postgres"
  migration_postgres_secret_name = "emilia-gate-postgres-migrate"
  migration_postgres_secret_key  = "database-url"
  api_token_secret_name    = "emilia-gate-api-token"
  issuer_roots_secret_name = "emilia-gate-issuer-roots"
  github_token_secret_name = "emilia-gate-github"

  secret_env = {
    SIEM_TOKEN = {
      secret_name = "emilia-gate-siem"
      secret_key  = "token"
    }
  }

  # For managed Postgres, disable the in-cluster selector and allow only the
  # stable database endpoint or egress-proxy CIDR.
  postgres_pod_labels  = {}
  postgres_egress_cidrs = ["10.40.12.8/32"]

  # Standard NetworkPolicy cannot select FQDNs. Prefer stable egress proxies
  # or an FQDN-aware CNI policy for KMS, GitHub, and SaaS SIEM endpoints.
  kms_egress_cidrs    = ["10.40.20.10/32"]
  github_egress_cidrs = ["10.40.20.11/32"]
  siem_egress_cidrs   = ["10.40.20.12/32"]
}
```

Configure the `kubernetes` provider in the calling root module. Create the
namespace and all Secrets outside this module. GitHub and generic secret-backed
environment inputs render only non-optional `secretKeyRef` metadata; Secret
values never become variables, Deployment literals, or module-managed state.
Prefer an immutable image digest
and a remote Terraform state backend with encryption and access logging even
though this module stores Secret references only.

## Clusterless validation

```bash
packages/gate/deploy/terraform/service/tests/validate.sh
```

The script runs formatting checks, initializes the Kubernetes provider schema
in a temporary directory, runs `terraform validate`, and executes mocked plan
tests for migration credential separation and Secret-backed environment wiring.
It does not configure credentials or contact a Kubernetes cluster.
