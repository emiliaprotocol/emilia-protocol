# Branch Protection Rules

This document describes the branch protection configuration required for the
EMILIA Protocol repository. Apply these settings in
**GitHub → Settings → Branches → Branch protection rules**.

## `main` branch

| Setting | Value | Rationale |
|---------|-------|-----------|
| Require a pull request before merging | ✅ Enabled | No direct pushes to main |
| Required approvals | **2** | Two independent eyes on every change |
| Dismiss stale reviews when new commits are pushed | ✅ Enabled | Re-approval required after force push |
| Require review from Code Owners | ✅ Enabled | CODEOWNERS gates critical protocol paths on `@futureenterprises` |
| Require status checks to pass | ✅ Enabled | See required checks below |
| Require branches to be up to date | ✅ Enabled | No merging on stale base |
| Require conversation resolution | ✅ Enabled | All review threads must be resolved |
| Require signed commits | ✅ Enabled | GPG/SSH commit signing enforced |
| Do not allow bypassing the above settings | ✅ Enabled | Applies to admins as well |
| Allow force pushes | ❌ Disabled | History is immutable |
| Allow deletions | ❌ Disabled | `main` cannot be deleted |

## Required status checks (all must pass)

These checks are defined in `.github/workflows/ci.yml` and related workflow files:

| Check name | Workflow | Description |
|------------|----------|-------------|
| `test` | `ci.yml` | Vitest unit + integration tests (100% pass rate) |
| `build` | `ci.yml` | Next.js production build |
| `write-discipline` | `ci.yml` | Write-path guard enforcement |
| `invariant-coverage` | `ci.yml` | All invariants backed by tests |
| `language-governance` | `ci.yml` | Approved terminology only |
| `type-check` | `ci.yml` | TypeScript type correctness |
| `lint` | `ci.yml` | Next.js lint (errors only) |
| `protocol-discipline` | `ci.yml` | No direct receipt inserts, no raw env reads |
| `mcp-server-pack` | `ci.yml` | MCP server packages cleanly |
| `sdk-typescript` | `ci.yml` | TypeScript SDK builds and tests pass |
| `sdk-python` | `ci.yml` | Python SDK installs and tests pass |
| `openapi-lint` | `ci.yml` | OpenAPI spec valid (Redocly) |
| `docs-consistency` | `ci.yml` | No stale counts, names, or versions |
| `secret-scan` | `ci.yml` | Gitleaks finds no secrets |
| `docs-secrets-check` | `ci.yml` | Docs free of leaked secrets |
| `docker-build` | `ci.yml` | Docker image builds cleanly |
| `integration-postgres` | `ci.yml` | Postgres DB-level invariant tests |
| `DCO` | `dco.yml` | All commits signed off (DCO 1.1) |
| `tlc` | `tlc.yml` | TLA+ spec verified by TLC 2.19 (on formal changes) |
| `CodeQL` | `codeql.yml` | Static security analysis |

## `release/*` branches

Release branches follow the same rules as `main` with one change:

- Required approvals: **1** (single approver sufficient for patch releases)

## Applying these settings

Use the GitHub API or the web UI. To apply via `gh` CLI:

```bash
gh api repos/futureenterprises/emilia-protocol/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test","build","write-discipline","invariant-coverage","language-governance","lint","protocol-discipline","secret-scan","DCO"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true}' \
  --field restrictions=null \
  --field allow_force_pushes=false \
  --field allow_deletions=false
```

> **Note:** The full list of required checks above should be added to `contexts`
> before applying in production. The `gh` example above shows the minimum set.

## Rationale

The EMILIA Protocol enforces write-path discipline and formal invariants at the
code level (see `lib/write-guard.js`, `lib/canonical-writer.js`, `formal/`).
Branch protection is the organizational complement — it ensures that no commit
bypasses peer review, status checks, or CODEOWNERS approval, closing the gap
between formal model and deployed code.
