# EMILIA Protocol — Agent Skills

Skills that guide Claude to use the EMILIA Protocol MCP connector well.

| Skill | Description |
|---|---|
| [emilia-trust-verification](emilia-trust-verification/SKILL.md) | Verify AI-agent authorization receipts and human device signoffs, and read EMILIA trust profiles. Triggers when a user shares a receipt/signoff and asks whether it is genuine, tampered, or who approved an action. Pairs with the EMILIA MCP connector (https://www.emiliaprotocol.ai/api/mcp/mcp). |

Each skill is a directory containing a `SKILL.md` with YAML frontmatter
(`name`, `description`) and instructions. Apache-2.0.
