# Publishing EMILIA to the MCP Registry

`@emilia-protocol/mcp-server` is published to npm. This is how we get it discoverable
through the official MCP Registry. npm publication and MCP Registry publication are
separate states; neither should be inferred from the other.

## 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

The official community registry is at `registry.modelcontextprotocol.io`. We publish
with the `mcp-publisher` CLI, which reads [`/server.json`](../server.json) at the repo
root.

Live state checked on 2026-08-22:

- The Registry API returned active versions `1.0.0` and `1.0.4`, with `1.0.4` marked
  latest.
- npm returned `@emilia-protocol/mcp-server@2.1.1` with
  `mcpName=io.github.emiliaprotocol/mcp-server`; that is the last live npm state
  established by this dated snapshot.
- The repository manifest prepares `2.1.2` with verifier `3.21.0`. It is not a
  published or registered version until the protected npm workflow completes.
- npm publication is still not Registry publication. Version `2.1.2` is
  registered only after `mcp-publisher validate` and `mcp-publisher publish`
  succeed and a fresh Registry API response marks it latest.

Recheck the live Registry without relying on this dated snapshot:

```bash
curl -fsS \
  'https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.emiliaprotocol%2Fmcp-server' \
  | jq '.servers[] | {version: .server.version, status: ._meta["io.modelcontextprotocol.registry/official"].status, latest: ._meta["io.modelcontextprotocol.registry/official"].isLatest}'
```

```bash
# Install the publisher CLI (Homebrew, or download a release binary)
brew install mcp-publisher        # or: see github.com/modelcontextprotocol/registry releases

# From the repo root (where server.json lives):
mcp-publisher login github        # opens GitHub OAuth — authorizes the
                                  # `io.github.emiliaprotocol/*` namespace
mcp-publisher validate            # live schema and package validation only
mcp-publisher publish             # validates server.json and publishes
```

Notes:
- **Namespace = public org membership.** The name `io.github.emiliaprotocol/mcp-server` is granted
  only if your authenticated GitHub identity is a **public** member of the `emiliaprotocol` org.
  If publish 403s with "you have permission to publish io.github.<you>/*", your membership is
  private: Org → People → your row → **Membership: Public** (owners can toggle directly), then
  re-run `mcp-publisher login github` to mint a fresh token that sees it.
- **npm package must declare ownership.** `@emilia-protocol/mcp-server`'s `package.json` carries
  `"mcpName": "io.github.emiliaprotocol/mcp-server"`. The registry fetches the published package
  and rejects publish (400) if that field is missing — so changing the namespace means
  re-publishing the npm package with a matching `mcpName`.
- **Versions must line up.** `server.json` `version` + `packages[0].version` must point at a
  published npm version whose `package.json` contains `mcpName`. Bump all three together, then
  tag `mcp-vX.Y.Z` to republish npm before re-running `mcp-publisher publish`.
- **Descriptions are limited to 100 characters.** The Registry rejects an otherwise aligned
  manifest with HTTP 422 when `server.json.description` exceeds the schema limit. The
  `tests/mcp-registry-manifest.test.ts` regression test locks this constraint and package alignment.
- To use a domain namespace instead (`ai.emiliaprotocol/mcp-server`), switch to
  `mcp-publisher login dns` and add the TXT record it prints.
- Bump the `version` in `server.json` to match each new npm release, then re-run `publish`.
- If the CLI reports a schema mismatch, regenerate against the latest schema:
  `mcp-publisher init` writes a fresh `server.json` skeleton you can merge.

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
