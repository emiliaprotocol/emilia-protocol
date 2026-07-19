# Trusted release checklist

Long-lived npm/PyPI tokens, direct local publication, and automatic tag-triggered
publication are not part of the release path. A release requires two explicit
owner actions after the matching tag exists on `main`: manually dispatch the
package workflow with a version-bound confirmation, then approve its protected
`registry-publishing-approval` job. Only then does the workflow test the source,
create one reproducible artifact, attest those exact bytes through GitHub OIDC,
publish that same file through registry trusted publishing, and download and
byte-compare the registry copy.

## One-time owner configuration

These settings live at the registries. Repository checks prove the intended
mapping and workflow behavior, but live activation requires an authenticated
registry readback. npm 11.15.0 and later expose that operation through
`npm trust`; PyPI currently exposes it through each project's Publishing page.

### GitHub owner gate

The repository has two live controls in addition to the workflow checks:

- environment `registry-publishing-approval` requires approval by
  `FutureEnterprises` before any package build receives permission to proceed;
- active ruleset `Immutable registry release tags` (ID `18796507`) blocks update
  and deletion of every tag prefix declared in
  `release/release-packages.v1.json`, with no bypass actor.

These controls were created and read back through the GitHub API on 2026-07-10.
Self-review remains enabled because this is a solo-founder repository; the
manual dispatch, exact typed confirmation, environment review, immutable tag,
and registry OIDC identity are separate recorded events. A credential acting as
`FutureEnterprises` remains an external account-security root and must never be
treated as an autonomous release mandate. GitHub currently reports
`can_admins_bypass: true`; using that escape hatch is itself an explicit,
audited owner action and does not bypass the workflow's actor, tag, version, or
typed-confirmation checks.

### npm

For each `@emilia-protocol/*` package, add a GitHub Actions trusted publisher:

- organization: `emiliaprotocol`
- repository: `emilia-protocol`
- workflow: the package's `publish-*.yml` filename
- environment: blank unless the workflow is later changed to use one
- allowed action: `npm publish`

Use npm 11.18.0 or later. Earlier trust clients do not send the required
permission field and can fail with an unhelpful `400 Bad Request`:

```sh
npx --yes npm@11.18.0 trust github <package> \
  --repo emiliaprotocol/emilia-protocol \
  --file <publish-workflow.yml> \
  --allow-publish --yes
npx --yes npm@11.18.0 trust list <package> --json
```

Both commands require maintainer authentication and proof of presence. A
successful create response is followed by `trust list`; the returned
repository, workflow filename, and publish permission must exactly match
`release/release-packages.v1.json`. All seven npm relationships were created
and read back with that procedure on 2026-07-10.

The actual npm publish jobs do not declare an environment; a separate job uses
the protected approval environment before the publish job can start. The
complete package/workflow inventory is machine-checked in
`release/release-packages.v1.json`. The six smaller npm workflows call the
shared `_publish-npm-package.yml`, but npm validates the package's calling
`publish-*.yml` filename. The core verifier uses `publish-verify-sdk.yml`. Do not add `NPM_TOKEN` as a
fallback: a broken OIDC link must fail closed instead of silently changing the
release identity.

### PyPI

For `emilia-verify`, `emilia-protocol`, and `langchain-emilia`, add matching
GitHub trusted publishers under each project's Publishing settings. The
workflow filenames are `publish-python-verify.yml`, `publish-python-sdk.yml`,
and `publish-langchain-python.yml`. Leave the registry publisher's environment
blank because the OIDC-bearing publish jobs do not declare one; their separate
approval jobs do. Live activation and first-release proof are
tracked in GitHub issue #251.

## Core verifier release

1. Bump `packages/verify/package.json`.
2. Run the local release gates:

   ```sh
   npm run security-case:emit
   npm run conformance:manifest:check
   npm run check:release-chain
   npm run release:verify:reproducible
   npm run test:mutation:security
   ```

3. Create and push `verify-v<version>` from the merged `main` commit. A tag push
   does not publish anything.
4. Manually dispatch `publish-verify-sdk.yml` with that exact tag and the exact
   confirmation `PUBLISH @emilia-protocol/verify@<version>`, then approve the
   `registry-publishing-approval` job in GitHub.
5. Confirm the workflow's post-publication `cmp` step and provenance
   attestation both passed.

## Python release

1. Bump the relevant `pyproject.toml` version.
2. Run with pinned build tooling:

   ```sh
   python -m pip install build==1.3.0 hatchling==1.27.0
   npm run release:verify:python
   ```

3. Create and push `python-verify-v<version>`, `py-sdk-v<version>`, or
   `langchain-emilia-v<version>` from the merged `main` commit.
4. Manually dispatch the matching workflow with that exact tag and
   `PUBLISH <registry-package-name>@<version>`, then approve the protected job.
5. Confirm PyPI returned the exact attested wheel and source-distribution bytes
   in the final `cmp` steps.

## Other npm package releases

The Gate, Issue, LangChain, MCP server, Require-Receipt, and TypeScript SDK
workflows all call `_publish-npm-package.yml`. Each caller still has its own npm
trusted-publisher identity. Before tagging, run `npm run check:release-chain`;
it refuses an undeclared publisher or a workflow missing tests, version binding,
reproducible packing, exact-byte attestation, OIDC publication, or registry
comparison. A pushed tag never starts a package publication workflow.

## Evidence retained per approved release

- tested npm tarball or Python wheel and source distribution;
- SHA-256/reproducibility manifest;
- canonical npm file modes (`0644` for regular files, `0755` for declared package binaries);
- `security/security-case.json`;
- `conformance/conformance-manifest.json`;
- GitHub artifact attestations bound to the workflow identity and source ref;
- a post-publication byte comparison against npm or PyPI.

`release.yml` also runs for every `*-v*` tag as a repository-level provenance
record. Every individual package workflow now carries the full artifact,
security-case, and conformance chain itself.

## Failure doctrine

| Failure | Required response |
|---|---|
| OIDC/trusted-publisher refusal | Fix the registry publisher link; do not publish manually. |
| Reproducible builds differ | Stop; inspect source epoch, build backend, and included files. |
| Registry bytes differ | Treat as a release-integrity incident; do not mark the release complete. |
| Security or conformance manifest is stale | Regenerate and rerun before tagging. |
| Missing or incorrect owner confirmation | Refuse the run; do not bypass the approval script. |
| Unapproved protected-environment job | No publication is authorized; leave it waiting or reject it. |
| Existing version | Bump the version; immutable registries and protected release tags must not be overwritten. |

Repository workflows prove the build and publication path. They do not prove
that registry-side trusted-publisher settings are currently enabled until an
owner-approved workflow succeeds.
