# MCP registry listings — ready-to-submit

Get EMILIA discovered where developers look for MCP tools. These are **drafted
for you to submit** from the `FutureEnterprises` / EMILIA accounts — listing
yourself in a registry is welcome (unlike unsolicited code PRs).

What to list:
- **`@emilia-protocol/mcp-server`** (the EP MCP server — issue/verify receipts, guard tool calls)
- **`@emilia-protocol/mcp-guard`** (drop-in MCP guard)
- **`@emilia-protocol/fire-drill`** (the Agent Action Firewall Test — a security tool, not a server)

---

## 1. Official MCP Registry — `registry.modelcontextprotocol.io`

Publish with the registry CLI (`mcp-publisher`) using a `server.json`. Draft:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-07-09/server.schema.json",
  "name": "io.github.emiliaprotocol/mcp-server",
  "description": "Authorization receipts for agent actions: require a verifiable human/quorum signoff before money, data, permissions, deploys, or regulated state change — and prove what executed.",
  "repository": { "url": "https://github.com/emiliaprotocol/emilia-protocol", "source": "github" },
  "version": "1.0.4",
  "packages": [
    {
      "registry_type": "npm",
      "identifier": "@emilia-protocol/mcp-server",
      "version": "1.0.4",
      "transport": { "type": "stdio" }
    }
  ]
}
```

> Verify ownership via the GitHub OIDC / DNS flow the registry requires, then
> `mcp-publisher publish`.

## 2. mcp.so

Submit at https://mcp.so/submit. Fields:
- **Name:** EMILIA Protocol — Authorization Receipts
- **Repo:** https://github.com/emiliaprotocol/emilia-protocol
- **npm:** `@emilia-protocol/mcp-server`
- **Category:** Security / Auth
- **One-liner:** No receipt, no execution — verifiable human/quorum authorization before irreversible agent actions, offline-verifiable.

## 3. Smithery (`smithery.ai`)

`npx @smithery/cli install @emilia-protocol/mcp-server` works once published; submit
the server via the Smithery dashboard with the same description and the
`security`, `authorization`, `receipt`, `human-in-the-loop` tags.

## 4. Glama (`glama.ai/mcp`)

Glama auto-indexes from GitHub + npm; ensure the repo topics include
`mcp`, `model-context-protocol`, `authorization`, `security` so it classifies correctly.

## 5. `punkpeye/awesome-mcp-servers` (GitHub PR — a welcome listing PR)

Add under **Security** (alphabetical). Markdown line:

```md
- [emiliaprotocol/emilia-protocol](https://github.com/emiliaprotocol/emilia-protocol) 📇 🏠 - Authorization receipts: require a verifiable human/quorum signoff before an agent moves money, deletes data, changes permissions, or deploys — and prove what executed. Includes `npx @emilia-protocol/fire-drill` to test any MCP server.
```

> This is the one PR worth opening — it's a listing addition the maintainer expects, and it puts `fire-drill` in front of exactly the audience that needs it.
