# Evidence autopilot App provisioning

Two workflows publish regenerated derived evidence through the evidence
autopilot GitHub App:

- `.github/workflows/evidence-autopilot-publish.yml` commits regenerated
  evidence back to Dependabot pull requests and to pull requests labeled
  `evidence-autopilot`. It mints a token with Contents: write.
- The `publish` job of `.github/workflows/volatile-evidence-refresh.yml` keeps
  `main`'s volatile evidence current after each merge (the security case's
  derived digests, the measured test counts and the LLM context; see
  [CONTRIBUTING.md](../../CONTRIBUTING.md#volatile-evidence)). It creates a
  branch, commits, opens the `chore(evidence): refresh volatile evidence` pull
  request, enables auto-merge and closes superseded refresh pull requests, so
  it mints a token with Contents: write and Pull requests: write.

Until the refresh can publish, `main` stays stale after every merge that
changes a pinned file: the `security-case` job of `main`'s push runs fails,
and the test counts fail `main` once they lag for more than 24 hours. Pull requests are not affected;
their CI treats that drift as advisory.

Merging the pull request that adds this file changes no GitHub setting. Every
step below is a maintainer action. No secret value appears in this repository.

## Status (checked 2026-10-01)

- The `evidence-autopilot` environment holds both secrets,
  `EVIDENCE_AUTOPILOT_CLIENT_ID` and `EVIDENCE_AUTOPILOT_PRIVATE_KEY`, and only
  `main` may deploy to it. The repository variable
  `EVIDENCE_AUTOPILOT_BOT_LOGIN` is set, and "Allow auto-merge" is enabled.
- The App's installation on this repository grants Contents: Read and write
  and Metadata: Read only. The refresh's `publish` job therefore fails when it
  mints its token, with "The permissions requested are not granted to this
  installation". The pull request autopilot, which asks for Contents only,
  publishes normally.

So the open step is step 1. Steps 2 to 4 are for a new environment or a key
rotation.

## 1. Grant the App the permissions both publishers request

Repository permissions, and nothing else (no organization or account
permissions, no webhook events):

| Permission | Access |
| --- | --- |
| Contents | Read and write |
| Pull requests | Read and write |
| Metadata | Read-only (mandatory) |

1. Open the App's settings: the owning account's Settings, Developer settings,
   GitHub Apps, then Edit on the evidence autopilot App.
2. Under Permissions & events, Repository permissions, set Pull requests to
   Read and write, and save.
3. GitHub does not apply a permission change to an existing installation until
   its owner accepts it. Open the organization's Settings, GitHub Apps, the
   evidence autopilot installation, and accept the requested permissions.
   Until then every token request that includes Pull requests fails.
4. Keep the installation limited to this repository.

## 2. The App private key

Only when the secret is missing or the key is being rotated:

1. In the App's settings, General, Private keys, choose Generate a private key.
   GitHub downloads a `.pem` file.
2. Store it as an environment secret, never a repository secret, so only jobs
   that may deploy to `evidence-autopilot` (that is, `main`) can read it:

   ```bash
   gh secret set EVIDENCE_AUTOPILOT_PRIVATE_KEY --env evidence-autopilot \
     --repo emiliaprotocol/emilia-protocol < key.pem
   ```

3. Delete the local `.pem`. After a publish run succeeds with the new key,
   delete the previous key in the App's settings.

## 3. Client ID and bot login

Both come from the App's General settings page (the Client ID, and the App's
slug).

```bash
gh secret set EVIDENCE_AUTOPILOT_CLIENT_ID --env evidence-autopilot \
  --repo emiliaprotocol/emilia-protocol --body '<Client ID>'
gh variable set EVIDENCE_AUTOPILOT_BOT_LOGIN \
  --repo emiliaprotocol/emilia-protocol --body '<app-slug>[bot]'
```

The bot login must be exact: `dco.yml` exempts an autopilot commit from
sign-off only when GitHub reports it verified and authored by that login, and
the refresh reuses an open refresh pull request only when that login opened
it.

## 4. Environment and repository settings

- Environment `evidence-autopilot`: deployment branches limited to `main`
  (custom branch policy). Check with
  `gh api repos/emiliaprotocol/emilia-protocol/environments/evidence-autopilot --jq .deployment_branch_policy`.
- Repository setting "Allow auto-merge": enabled.

## Verify

```bash
gh workflow run volatile-evidence-refresh.yml --repo emiliaprotocol/emilia-protocol --ref main
gh run list --repo emiliaprotocol/emilia-protocol --workflow volatile-evidence-refresh.yml --limit 1
```

On a stale `main` the `publish` job opens (or reuses) the refresh pull request
with auto-merge enabled, and that pull request's required checks re-derive
every file strictly before it merges. On a current `main` `regenerate`
publishes nothing and `publish` is skipped. Secret names, never values, can be
listed with
`gh api repos/emiliaprotocol/emilia-protocol/environments/evidence-autopilot/secrets --jq '.secrets[].name'`.
