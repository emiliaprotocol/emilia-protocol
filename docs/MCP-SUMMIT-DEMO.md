# MCP Dev Summit — 5-Minute Live Demo Script

**Title:** EP: Trust Evaluation and Appeals for MCP Servers, Software, and Machine Counterparties

**Goal:** In 5 minutes, show EP is a live trust layer with entity registration, receipt submission, trust profile query, install preflight, and dispute filing — working through MCP tools in Claude.

---

## Setup (before you walk on stage)

- Local or hosted EP instance running at emiliaprotocol.ai
- Claude Desktop connected to EP MCP server
- Entity `mcp-server-ep-v1` already registered
- Two agent entities ready: `rex-booking-v1`, `ruby-retention-v1`
- At least one API key ready for fallback
- Terminal + Claude side by side
- Backup screenshots of each step in case Wi-Fi dies

---

## 0:00–0:30 — Opening

> MCP gives agents access to tools.
> EP gives agents and humans a way to decide whether those tools, servers, and counterparties should be trusted.
> In five minutes, I'm going to register an entity, submit trust evidence, query a trust profile, run install preflight on an MCP server, and challenge trust through a dispute — all live.

---

## 0:30–1:10 — Register an entity

Terminal:
```bash
curl -X POST https://emiliaprotocol.ai/api/entities/register \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "demo-mcp-server",
    "display_name": "Demo MCP Server",
    "entity_type": "mcp_server",
    "description": "Live demo entity",
    "category": "agent_tool"
  }'
```

> That gives us a trust surface. Not a review page — a machine-readable principal in the trust graph.

---

## 1:10–2:00 — Submit receipts

```bash
curl -X POST https://emiliaprotocol.ai/api/receipts/submit \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "mcp-server-ep-v1",
    "transaction_ref": "demo-receipt-001",
    "transaction_type": "tool_use",
    "agent_behavior": "completed",
    "context": {
      "host": "mcp",
      "tool_scope": "repo_read",
      "data_sensitivity": "private_workspace"
    }
  }'
```

> EP weights trust by behavior, provenance, context, and policy. Two clean receipts improve the profile — but don't create fake certainty.

---

## 2:00–3:00 — Query trust profile in Claude

**Prompt Claude:**
> Show me the trust profile for mcp-server-ep-v1.

**While Claude runs, say:**
> This is the canonical object in EP — not a score, but a trust profile: confidence, behavioral outcomes, provenance, disputes, and legacy compatibility only as a fallback.

**Highlight:** confidence, behavioral completion, provenance, disputes = 0

> This is the key shift: trust profiles, not scores.

---

## 3:00–4:00 — Install preflight

**Prompt Claude:**
> Run install preflight for mcp-server-ep-v1 with policy mcp_server_safe_v1 in a private_workspace context.

> This is one of EP's most important use cases: not just "what is this?" but "is it safe enough to install in this specific context?"

**Highlight:** pass/review/fail, reasons, confidence, context awareness

> That's the future trust question for software: not "is this popular?" but "is this safe enough for this policy and scope?"

---

## 4:00–4:40 — File a dispute

**Prompt Claude:**
> File a dispute against the latest receipt for mcp-server-ep-v1 with the reason: demo challenge.

> A real trust layer cannot only compute trust. It has to handle contested trust.

**Highlight:** dispute created, status open, trust auditable, correction doesn't delete history

> EP is built so trust can be challenged and corrected without erasing what happened.

---

## 4:40–5:00 — Closing

> MCP provides tool access.
> EP provides trust evaluation and appeals for counterparties, software, and machine actors.
> That means not just better routing — but safer installs, safer automation, and trust that can be challenged when it's wrong.

---

## Prepared Claude prompts (copy these)

1. `Show me the trust profile for mcp-server-ep-v1.`
2. `Run install preflight for mcp-server-ep-v1 with policy mcp_server_safe_v1 in a private_workspace context.`
3. `File a dispute against the latest receipt for mcp-server-ep-v1 with the reason: demo challenge.`

## Demo tips

- Do NOT over-explain blockchain
- Do NOT spend time on legacy compatibility score
- Keep saying "trust profile," "policy," and "install preflight"
- If slow, narrate the meaning, not the latency
- If something fails, say: "That's exactly why appeals and operational trust matter."
