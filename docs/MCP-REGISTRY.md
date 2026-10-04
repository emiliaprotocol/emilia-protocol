# Publishing EMILIA to the MCP Registry

`@emilia-protocol/mcp-server` is published to npm. This is how we get it discoverable
through the official MCP Registry. npm publication and MCP Registry publication are
separate states; neither should be inferred from the other.

## 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

The official community registry is at `registry.modelcontextprotocol.io`. We publish
with the `mcp-publisher` CLI, which reads [`/server.json`](../server.json) at the repo
root.

Live state checked on 2026-10-04:

- npm serves `@emilia-protocol/mcp-server@2.1.4`, marked latest, with
  `mcpName=io.github.emiliaprotocol/mcp-server`. Its complete tarball passed
  SHA-512 integrity and GitHub provenance verification against `mcp-v2.1.4`.
- The official Registry still returns `2.1.1` as active/latest. Versions `1.0.0`
  and `1.0.4` are also registered. `2.1.4` is not registered in this snapshot.
- A fresh device login succeeded, but organization publication returned HTTP
  403 even though the account is an active owner with public membership. This
  matches the upstream GitHub App authentication bug described below.
- The protected Registry-only workflow is the next publication path. This
  dated snapshot is not a claim that its publication has completed.

Recheck the live Registry without relying on this dated snapshot:

```bash
curl -fsS \
  'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.emiliaprotocol%2Fmcp-server' \
  | jq '.servers[] | {version: .server.version, status: ._meta["io.modelcontextprotocol.registry/official"].status, latest: ._meta["io.modelcontextprotocol.registry/official"].isLatest}'
```

```bash
# Run only after the reviewed workflow has merged into main and the
# registry-publishing-approval environment is restricted to main with
# FutureEnterprises as its required reviewer.
gh workflow run publish-mcp-registry.yml \
  --repo emiliaprotocol/emilia-protocol --ref main \
  -f release_tag=mcp-v2.1.4 \
  -f 'confirmation=REGISTER io.github.emiliaprotocol/mcp-server@2.1.4'
```

The workflow does not republish npm. Before requesting a Registry token, it
checks the dispatch owner, protected main source, exact MCP release tag,
unchanged manifest bytes, npm identity and SHA-512 integrity. It also verifies
the whole npm tarball's signed GitHub provenance: the immutable MCP tag commit,
source `refs/heads/main`, our reusable npm publisher, and a GitHub-hosted runner.
Replacing the runtime while keeping `package.json` unchanged must fail this
check. A tag may precede the workflow's main commit, but must be its ancestor.

Publication uses the [official GitHub OIDC
method](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx),
with only `contents: read` and `id-token: write` in the owner-approved job. The
CLI binary is version- and checksum-pinned; its auth cache stays in a fresh
runner temporary directory. No PAT, npm credential or auth file is uploaded.

Completion requires fresh exact-version and latest Registry responses marked
active/latest, with the full manifest matching the approved source. Only
omitted false-valued environment-variable defaults are normalized. Save the
workflow run URL and public receipt; a successful npm release alone is not
completion. The preflight refuses an already registered version rather than
silently publishing over it. If publication succeeds but verification fails,
inspect that version before attempting another dispatch.

Notes:

- **A 403 does not prove private membership.** The official device-login GitHub
  App can fail to read organization ownership even when membership is public.
  [The upstream maintainer confirmed this
  limitation](https://github.com/modelcontextprotocol/registry/issues/1468#issuecomment-5093147856)
  and identified GitHub Actions publishing as a working path. Do not respond by
  changing membership visibility, changing our namespace, installing broader
  access, or handing the Registry a general `gh` authentication token.
- **Protected source bindings.** The read-only workflow checks active MCP tag
  update/deletion rules with no namespace exclusions. GitHub hides bypass
  actors from ruleset readers, so an omitted field is reported as
  `unobservable-under-readonly-token`, not as proof of no bypass. Any reported
  bypass is refused. The owner separately checked the live ruleset's empty
  bypass list on 2026-10-04; exact tag/source/provenance bindings are rechecked
  on every dispatch.
- **npm ownership and versions must match.** The published package must carry
  `"mcpName": "io.github.emiliaprotocol/mcp-server"`; its version, `server.json`
  version and `packages[0].version` must agree. Publish npm through its existing
  protected release workflow first, then dispatch Registry publication with
  the corresponding `mcp-vX.Y.Z` tag and exact confirmation.
- **Schema validation is separate from publication.** `mcp-publisher validate`
  checks the live schema and package without registering them. Descriptions
  are limited to 100 characters; `tests/mcp-registry-manifest.test.ts` covers
  this and package alignment. Fix and review any schema change rather than
  replacing the manifest with an unreviewed `mcp-publisher init` skeleton.

## 2. Optional aggregator directories

The entries below are submission targets, not verified current EMILIA listings. Check each live
directory before saying EMILIA is listed there.

| Directory | Action | URL |
|---|---|---|
| **Glama** | Auto-indexes public GitHub repos — usually picks us up on its own; claim the listing to manage it | glama.ai/mcp/servers |
| **Smithery** | Submit via their form / connect the GitHub repo | smithery.ai |
| **mcp.so** | "Submit" button (or open a GitHub issue on their repo) | mcp.so |
| **PulseMCP** | "Submit" button — hand-reviewed daily; also a newsletter that features servers | pulsemcp.com |
| **awesome-mcp-servers** | Open a PR (needs README + working install) | github.com/punkpeye/awesome-mcp-servers |

One-shot option: the `mcp-submit` CLI pushes to 10+ directories in a single command.

## 3. What we list

- **Package:** `@emilia-protocol/mcp-server` (npx, stdio)
- **One-liner:** *Trust & human sign-off for AI agents.*
- **Hook for the description / launch:** most MCP servers connect data; this one makes an
  agent **accountable** — it can require a named human's signed "yes" before an irreversible
  action, and every action leaves an offline-verifiable receipt.
- **Landing page:** https://www.emiliaprotocol.ai/mcp
