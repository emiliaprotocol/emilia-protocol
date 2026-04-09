# EP LLM Function-Calling Schema

**Version:** 1.0  
**Date:** 2026-04-07  
**Compatibility:** OpenAI function calling, Anthropic tool use, Google Gemini  

---

## Overview

This schema defines a standardized set of function/tool definitions that any LLM provider can implement to make their models trust-aware. These are not EP API wrappers — they are **reasoning primitives** that models can use to make trust-informed decisions.

---

## Core Functions (3 primitives)

### 1. `ep_check_trust` — Should I trust this entity for this action?

```json
{
  "name": "ep_check_trust",
  "description": "Check whether an entity should be trusted for a specific action. Returns a trust decision (allow/review/deny) with reasons and evidence. Call this BEFORE taking any consequential action involving another entity.",
  "parameters": {
    "type": "object",
    "required": ["entity_id", "action_type"],
    "properties": {
      "entity_id": {
        "type": "string",
        "description": "The entity to evaluate (e.g., 'ep_entity_abc123')"
      },
      "action_type": {
        "type": "string",
        "description": "The action being considered (e.g., 'install_package', 'send_payment', 'grant_access')"
      },
      "domain": {
        "type": "string",
        "enum": ["financial", "code_execution", "communication", "delegation", "infrastructure", "content_creation", "data_access"],
        "description": "Domain context for domain-specific trust evaluation"
      },
      "policy": {
        "type": "string",
        "enum": ["strict", "standard", "permissive", "discovery"],
        "description": "Policy tier to evaluate against (default: standard)"
      }
    }
  },
  "returns": {
    "decision": "allow | review | deny",
    "confidence": "pending | insufficient | provisional | emerging | confident",
    "reasons": ["array of human-readable reasons"],
    "evidence_sufficient": true,
    "appeal_available": true
  }
}
```

### 2. `ep_record_interaction` — Record what happened

```json
{
  "name": "ep_record_interaction",
  "description": "Record the outcome of an interaction with another entity. Creates a trust receipt that contributes to the entity's trust profile. Call this AFTER completing any significant interaction.",
  "parameters": {
    "type": "object",
    "required": ["entity_id", "outcome"],
    "properties": {
      "entity_id": {
        "type": "string",
        "description": "The entity the interaction was with"
      },
      "outcome": {
        "type": "string",
        "enum": ["positive", "negative", "neutral", "disputed"],
        "description": "The outcome of the interaction"
      },
      "action_type": {
        "type": "string",
        "description": "What action was performed"
      },
      "domain": {
        "type": "string",
        "description": "Domain context"
      },
      "context": {
        "type": "object",
        "description": "Additional context (task_type, category, value_band, risk_class)"
      }
    }
  }
}
```

### 3. `ep_request_authorization` — Get pre-action authorization

```json
{
  "name": "ep_request_authorization",
  "description": "Request cryptographic pre-action authorization for a high-risk action. Initiates an EP Handshake ceremony. The returned handshake_id is your proof that the action was authorized. Call this BEFORE any irreversible or high-stakes action.",
  "parameters": {
    "type": "object",
    "required": ["action_type", "resource_ref"],
    "properties": {
      "action_type": {
        "type": "string",
        "description": "The action to authorize (e.g., 'deploy_production', 'transfer_funds', 'delete_data')"
      },
      "resource_ref": {
        "type": "string",
        "description": "What resource is being acted upon"
      },
      "policy_id": {
        "type": "string",
        "description": "Specific policy to evaluate against (optional)"
      },
      "requires_human_signoff": {
        "type": "boolean",
        "description": "Whether this action requires a named human to assume responsibility"
      }
    }
  },
  "returns": {
    "handshake_id": "ep_hs_...",
    "status": "verified | rejected | pending_signoff",
    "binding_hash": "sha256:...",
    "expires_at": "ISO-8601"
  }
}
```

---

## Extended Functions (5 additional tools)

### 4. `ep_verify_receipt` — Verify a trust receipt offline

```json
{
  "name": "ep_verify_receipt",
  "description": "Verify a self-contained EP trust receipt document. No API call needed — verification uses Ed25519 signature and optional Merkle anchor proof. Use this to verify trust evidence from any EP operator.",
  "parameters": {
    "type": "object",
    "required": ["receipt_document", "public_key"],
    "properties": {
      "receipt_document": { "type": "object", "description": "EP-RECEIPT-v1 document" },
      "public_key": { "type": "string", "description": "Signer's Ed25519 public key (base64url)" }
    }
  }
}
```

### 5. `ep_prove_trust` — Generate a privacy-preserving trust proof

```json
{
  "name": "ep_prove_trust",
  "description": "Generate a commitment proof that demonstrates your trust score exceeds a threshold in a given domain, without revealing your receipts or counterparties. Share the proof_id with verifiers.",
  "parameters": {
    "type": "object",
    "required": ["claim_type", "threshold"],
    "properties": {
      "claim_type": { "type": "string", "enum": ["score_above", "receipt_count_above", "domain_score_above"] },
      "threshold": { "type": "number" },
      "domain": { "type": "string" }
    }
  }
}
```

### 6. `ep_get_trust_profile` — Get an entity's trust profile

```json
{
  "name": "ep_get_trust_profile",
  "description": "Retrieve the trust profile of any entity. Returns structured trust data: score, confidence, evidence depth, domain scores, anomaly flags.",
  "parameters": {
    "type": "object",
    "required": ["entity_id"],
    "properties": {
      "entity_id": { "type": "string" }
    }
  }
}
```

### 7. `ep_file_dispute` — Contest a trust decision

```json
{
  "name": "ep_file_dispute",
  "description": "File a formal dispute against a trust receipt or decision. EP guarantees due process: every dispute gets reviewed, and appeals are always available.",
  "parameters": {
    "type": "object",
    "required": ["receipt_id", "reason"],
    "properties": {
      "receipt_id": { "type": "string" },
      "reason": { "type": "string", "enum": ["fraudulent", "inaccurate", "context_missing", "identity_error"] },
      "description": { "type": "string" }
    }
  }
}
```

### 8. `ep_human_signoff` — Request human accountability

```json
{
  "name": "ep_human_signoff",
  "description": "Request that a named human assume responsibility for a specific action outcome. The human sees the exact consequences and must explicitly approve. Use when the action is too consequential for autonomous execution.",
  "parameters": {
    "type": "object",
    "required": ["handshake_id", "principal_id", "consequences_summary"],
    "properties": {
      "handshake_id": { "type": "string" },
      "principal_id": { "type": "string" },
      "consequences_summary": { "type": "string", "description": "Human-readable description of what the human is taking responsibility for" }
    }
  }
}
```

---

## System Prompt Integration

For LLM providers who want to make their models trust-aware by default:

```
You have access to the EMILIA Protocol (EP) for trust evaluation and 
pre-action authorization. When you encounter a high-risk action:

1. BEFORE acting: call ep_check_trust to verify the entity is trustworthy
2. For irreversible actions: call ep_request_authorization to get 
   cryptographic pre-action authorization
3. AFTER acting: call ep_record_interaction to record the outcome
4. If something went wrong: call ep_file_dispute to contest the decision

Trust decisions are not opinions — they are evidence-based, policy-bound,
cryptographically verifiable, and appealable.
```

---

## Model-Readable Receipt Format (Compact)

For receipts that need to fit in a model's context window:

```
EP-R alice→bob positive code_execution 2026-04-07 sig:ed25519:abc... anchor:base:8453:0xdef...
```

One line. Parseable by any model. Verifiable with the standalone library.

Expanded:
```json
{"v":"EP-R","from":"alice","to":"bob","out":"positive","dom":"code_execution","t":"2026-04-07","sig":"ed25519:abc...","anc":"base:8453:0xdef..."}
```
