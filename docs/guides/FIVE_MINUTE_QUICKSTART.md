# EP in 5 Minutes

**From zero to verified trust receipt in 5 minutes. No Supabase. No Vercel. No blockchain wallet. Just Node.js.**

---

## Step 1: Create your trust system (30 seconds)

```bash
npx create-ep-app my-trust-system
cd my-trust-system
npm install
npm run dev
```

Open http://localhost:3000. Click **Run Trust Demo**. Watch the full EP lifecycle execute in 60 seconds.

---

## Step 2: What you just saw (2 minutes reading)

The demo ran the complete EP trust lifecycle:

```
1. REGISTER    Two entities created with Ed25519 key pairs
2. RECEIPT     Trust receipts issued — each signed by the issuer's private key
3. PROFILE     Trust profile computed from receipt evidence
4. VERIFY      Receipt verified using ONLY the signature — no API call needed
5. HANDSHAKE   Pre-action ceremony with nonce + expiry + binding hash
6. REPLAY      Replay attack blocked — handshake consumed exactly once
```

Every receipt is a self-contained, cryptographically signed document. Anyone can verify it with just the signer's public key. No EP server needed. No account. No trust relationship. Just math.

---

## Step 3: Issue your first receipt (1 minute)

```bash
# Register an entity
curl -s http://localhost:3000/api/entity \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name": "My AI Agent"}' | jq .

# Save the entity_id from the response, then register a second entity
curl -s http://localhost:3000/api/entity \
  -X POST -H 'Content-Type: application/json' \
  -d '{"name": "Service Provider"}' | jq .

# Submit a trust receipt (replace entity IDs)
curl -s http://localhost:3000/api/receipt \
  -X POST -H 'Content-Type: application/json' \
  -d '{
    "issuer": "ep_entity_YOUR_FIRST_ID",
    "subject": "ep_entity_YOUR_SECOND_ID",
    "action_type": "api_call",
    "outcome": "positive",
    "context": {"task": "data_retrieval"}
  }' | jq .
```

The response is an **EP-RECEIPT-v1** document — self-contained, Ed25519-signed, verifiable offline.

---

## Step 4: Verify a receipt offline (1 minute)

```bash
# Save the receipt
curl -s http://localhost:3000/api/receipt \
  -X POST -H 'Content-Type: application/json' \
  -d '{"issuer": "ep_entity_...", "subject": "ep_entity_...", "outcome": "positive"}' \
  > receipt.json

# Get the signer's public key
curl -s http://localhost:3000/.well-known/ep-keys.json | jq .

# Verify offline (no server needed!)
node verify-receipt.js YOUR_PUBLIC_KEY < receipt.json
```

Output:
```json
{
  "valid": true,
  "receipt_id": "ep_r_...",
  "verified_at": "2026-04-07T...",
  "_note": "Receipt signature is valid. This was verified OFFLINE — no EP server contacted."
}
```

**This is the key property:** verification doesn't require EP infrastructure. Like a Bitcoin transaction, the proof is self-contained.

---

## Step 5: Run a handshake ceremony (30 seconds)

```bash
# Initiate a pre-action authorization
curl -s http://localhost:3000/api/handshake \
  -X POST -H 'Content-Type: application/json' \
  -d '{
    "initiator": "ep_entity_...",
    "action_type": "deploy_production",
    "resource_ref": "service/payment-gateway"
  }' | jq .

# Verify and consume the handshake (save the handshake_id)
curl -s http://localhost:3000/api/handshake/verify \
  -X POST -H 'Content-Type: application/json' \
  -d '{"handshake_id": "ep_hs_..."}' | jq .

# Try to replay it (should fail with "Already consumed")
curl -s http://localhost:3000/api/handshake/verify \
  -X POST -H 'Content-Type: application/json' \
  -d '{"handshake_id": "ep_hs_..."}' | jq .
```

The handshake is consumed exactly once. Replay attacks are structurally impossible.

---

## What's Next

| I want to... | Do this |
|-------------|---------|
| Use the full production protocol | Deploy [emilia-protocol](https://github.com/emilia-protocol) with Supabase + Vercel |
| Add trust to my AI agent | Use the [MCP server](https://github.com/emilia-protocol/mcp-server) (34 tools) |
| Integrate via SDK | `npm install @emilia-protocol/sdk` (TypeScript) or `pip install emilia-protocol` (Python) |
| Read the specification | [PROTOCOL-STANDARD.md](https://github.com/emilia-protocol/docs/PROTOCOL-STANDARD.md) |
| Check compliance mappings | [NIST AI RMF](../compliance/NIST-AI-RMF-MAPPING.md) · [EU AI Act](../compliance/EU-AI-ACT-MAPPING.md) |
| Run conformance tests | `npx ep-conformance-test https://your-ep-server.com` |
| Request a pilot | [emiliaprotocol.ai/partners](https://emiliaprotocol.ai/partners) |

---

## The One Thing to Remember

> Every EP receipt is self-verifying. Anyone can check it with just the signer's public key. No API. No account. No trust. Just math.

That's what makes EP a protocol, not a product.
