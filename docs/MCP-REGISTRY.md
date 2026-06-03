# Listing EMILIA on the MCP registries

`@emilia-protocol/mcp-server` is published to npm. This is how we get it discoverable
in the directories AI clients actually query. Do the official registry first — it's the
canonical source — then the aggregators.

## 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

The canonical, Anthropic-maintained registry. We publish with the `mcp-publisher` CLI,
which reads [`/server.json`](../server.json) at the repo root.

```bash
# Install the publisher CLI (Homebrew, or download a release binary)
brew install mcp-publisher        # or: see github.com/modelcontextprotocol/registry releases

# From the repo root (where server.json lives):
mcp-publisher login github        # opens GitHub OAuth — authorizes the
                                  # `io.github.emiliaprotocol/*` namespace
mcp-publisher publish             # validates server.json and publishes
```

Notes:
- The server **name** must live in a namespace you control. `io.github.emiliaprotocol/mcp-server`
  is verified automatically by the GitHub login above (you must be able to push to the
  `emiliaprotocol` org). To use a domain namespace instead (`ai.emiliaprotocol/mcp-server`),
  switch to `mcp-publisher login dns` and add the TXT record it prints.
- Bump the `version` in `server.json` to match each new npm release, then re-run `publish`.
- If the CLI reports a schema mismatch, regenerate against the latest schema:
  `mcp-publisher init` writes a fresh `server.json` skeleton you can merge.

## 2. Aggregator directories

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
