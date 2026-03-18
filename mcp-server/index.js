#!/usr/bin/env node

/**
 * EMILIA Protocol — MCP Server
 *
 * Trust evaluation tools for AI agents.
 * Add this server to any MCP-compatible client to give your agent
 * access to EP trust profiles and policy evaluation.
 *
 * PRIMARY TOOLS (trust-profile-first):
 *   ep_trust_profile   — Get an entity's full trust profile (canonical)
 *   ep_trust_evaluate  — Evaluate an entity against a trust policy
 *   ep_submit_receipt  — Submit a transaction receipt
 *
 * SECONDARY TOOLS:
 *   ep_search_entities — Search for entities
 *   ep_verify_receipt  — Verify receipt against Merkle root
 *   ep_register_entity — Register a new entity
 *   ep_leaderboard     — Get top entities
 *
 * V1.0 ADDITIONS:
 *   ep_create_delegation    — Create a delegation record (principal → agent)
 *   ep_verify_delegation    — Verify an agent's delegation for an action
 *   ep_trust_gate           — Pre-action trust check (canonical gate)
 *   ep_batch_submit         — Batch receipt submission (up to 50)
 *   ep_domain_score         — Per-domain trust breakdown
 *
 * SPRINT 4A: Attribution Chain
 *   ep_delegation_judgment  — Principal delegation judgment score (how well they choose agents)
 *
 * SPRINT 5A: Zero-Knowledge Proof layer
 *   ep_generate_zk_proof    — Prove trust threshold without revealing receipt contents or counterparties
 *   ep_verify_zk_proof      — Verify a ZK trust proof by proof_id (public, no transaction history revealed)
 *
 * Setup:
 *   EP_BASE_URL=https://emiliaprotocol.ai
 *   EP_API_KEY=ep_live_...  (for authenticated writes; registration is public)
 *
 * @license Apache-2.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { AutoReceiptMiddleware } from './auto-receipt.js';

const BASE_URL = process.env.EP_BASE_URL || 'https://emiliaprotocol.ai';
const API_KEY = process.env.EP_API_KEY || '';

// =============================================================================
// Auto-Receipt Middleware (Sprint 2)
// =============================================================================

/**
 * Global middleware instance. Shared across all tool calls in this process.
 *
 * Opt-in is false by default — agents must call ep_configure_auto_receipt
 * to enable. The entity_id and epApiKey are pre-populated from environment
 * variables so the operator doesn't need to expose them to the agent.
 */
const autoReceipt = new AutoReceiptMiddleware({
  epApiUrl: process.env.EP_AUTO_RECEIPT_URL || 'https://emiliaprotocol.ai',
  epApiKey: process.env.EP_AUTO_RECEIPT_KEY || API_KEY,
  optIn: process.env.EP_AUTO_RECEIPT_OPT_IN === 'true',
  entityId: process.env.EP_AUTO_RECEIPT_ENTITY_ID || '',
});

async function epFetch(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.auth && API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {}),
  };
  const res = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `EP API error: ${res.status}`);
  return data;
}

// =============================================================================
// Tool definitions — trust-profile-first
// =============================================================================

const TOOLS = [
  // PRIMARY: Trust profile (canonical read surface)
  {
    name: 'ep_trust_profile',
    description:
      'Get an entity\'s full trust profile. This is the CANONICAL way to check trust in EP. ' +
      'Returns behavioral rates (completion, retry, abandon, dispute), signal breakdowns, ' +
      'provenance composition, consistency, anomaly alerts, current confidence, historical establishment, ' +
      'and dispute summary. Use this before transacting with any counterparty or installing any software.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'Entity ID (slug like "merchant-xyz") or UUID',
        },
      },
      required: ['entity_id'],
    },
  },

  // PRIMARY: Trust evaluation (policy consumption)
  {
    name: 'ep_trust_evaluate',
    description:
      'Evaluate an entity against a trust policy. Returns pass/fail with specific failure reasons. ' +
      'Built-in policies: "strict" (high-value), "standard" (normal), "permissive" (low-risk), "discovery" (allow unevaluated). ' +
      'Accepts optional context for context-aware evaluation. Use this to make routing and payment decisions.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'Entity ID to evaluate',
        },
        policy: {
          type: 'string',
          description: 'Policy name: "strict", "standard", "permissive", "discovery"',
        },
        context: {
          type: 'object',
          description: 'Context key for context-aware evaluation: { task_type, category, geo, modality, value_band }',
        },
      },
      required: ['entity_id'],
    },
  },

  // PRIMARY: Submit receipt
  {
    name: 'ep_submit_receipt',
    description:
      'Submit a transaction receipt to the EP ledger. Requires an API key. ' +
      'Receipts are append-only, cryptographically hashed, and chain-linked. ' +
      'transaction_ref is REQUIRED. agent_behavior is the strongest signal.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity to evaluate' },
        transaction_ref: { type: 'string', description: 'External transaction reference (required)' },
        transaction_type: {
          type: 'string',
          enum: ['purchase', 'service', 'task_completion', 'delivery', 'return'],
        },
        agent_behavior: {
          type: 'string',
          enum: ['completed', 'retried_same', 'retried_different', 'abandoned', 'disputed'],
          description: 'Observable behavioral outcome (strongest Phase 1 signal)',
        },
        delivery_accuracy: { type: 'number', description: '0-100' },
        product_accuracy: { type: 'number', description: '0-100' },
        price_integrity: { type: 'number', description: '0-100' },
        return_processing: { type: 'number', description: '0-100' },
        claims: { type: 'object', description: 'Structured claims (delivered, on_time, price_honored, as_described)' },
        evidence: { type: 'object', description: 'Supporting evidence references' },
        context: {
          type: 'object',
          description: 'Context key: { task_type, category, geo, modality, value_band, risk_class }',
        },
      },
      required: ['entity_id', 'transaction_type', 'transaction_ref'],
    },
  },

  // SECONDARY
  {
    name: 'ep_search_entities',
    description: 'Search for entities by name, capability, or category.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        entity_type: { type: 'string', enum: ['agent','merchant','service_provider','github_app','github_action','mcp_server','npm_package','chrome_extension','shopify_app','marketplace_plugin','agent_tool'] },
      },
      required: ['query'],
    },
  },
  {
    name: 'ep_verify_receipt',
    description: 'Verify a receipt against the on-chain Merkle root.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt_id: { type: 'string', description: 'Receipt ID (ep_rcpt_...)' },
      },
      required: ['receipt_id'],
    },
  },
  {
    name: 'ep_register_entity',
    description: 'Register a new entity. Public — returns the first API key.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Slug (lowercase, hyphens)' },
        display_name: { type: 'string' },
        entity_type: { type: 'string', enum: ['agent','merchant','service_provider','github_app','github_action','mcp_server','npm_package','chrome_extension','shopify_app','marketplace_plugin','agent_tool'] },
        description: { type: 'string' },
        capabilities: { type: 'array', items: { type: 'string' } },
      },
      required: ['entity_id', 'display_name', 'entity_type', 'description'],
    },
  },
  {
    name: 'ep_leaderboard',
    description: 'Get top entities ranked by trust confidence.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max entities (default 10, max 50)' },
        entity_type: { type: 'string', enum: ['agent','merchant','service_provider','github_app','github_action','mcp_server','npm_package','chrome_extension','shopify_app','marketplace_plugin','agent_tool'] },
      },
    },
  },
  // DUE PROCESS
  {
    name: 'ep_dispute_file',
    description:
      'File a dispute against a receipt. Any affected party can challenge. ' +
      'Reasons: fraudulent_receipt, inaccurate_signals, identity_dispute, context_mismatch, duplicate_transaction, coerced_receipt, other. ' +
      'The receipt submitter has 7 days to respond.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt_id: { type: 'string', description: 'Receipt ID to dispute (ep_rcpt_...)' },
        reason: { type: 'string', description: 'Reason for dispute' },
        description: { type: 'string', description: 'Explanation of the dispute' },
        evidence: { type: 'object', description: 'Supporting evidence' },
      },
      required: ['receipt_id', 'reason'],
    },
  },
  {
    name: 'ep_dispute_status',
    description: 'Check the status of a dispute. Public — transparency is a protocol value.',
    inputSchema: {
      type: 'object',
      properties: {
        dispute_id: { type: 'string', description: 'Dispute ID (ep_disp_...)' },
      },
      required: ['dispute_id'],
    },
  },
  {
    name: 'ep_report_trust_issue',
    description:
      'Report a trust issue as a human. No authentication required. ' +
      'For when someone is wrongly downgraded, harmed by a trusted entity, or sees fraud. ' +
      'EP must never make trust more powerful than appeal.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity the report is about' },
        report_type: {
          type: 'string',
          enum: ['wrongly_downgraded', 'harmed_by_trusted_entity', 'fraudulent_entity', 'inaccurate_profile', 'other'],
        },
        description: { type: 'string', description: 'What happened' },
        contact_email: { type: 'string', description: 'Email for follow-up (optional)' },
      },
      required: ['entity_id', 'report_type', 'description'],
    },
  },
  // EP-SX: Software Trust
  {
    name: 'ep_appeal_dispute',
    description:
      'Appeal a dispute resolution. Only dispute participants can appeal. ' +
      'Requires the dispute to be in upheld, reversed, or dismissed state. ' +
      '"Trust must never be more powerful than appeal."',
    inputSchema: {
      type: 'object',
      properties: {
        dispute_id: { type: 'string', description: 'The dispute ID to appeal' },
        reason: { type: 'string', description: 'Why the resolution should be reconsidered (min 10 chars)' },
        evidence: { type: 'object', description: 'Optional supporting evidence for the appeal' },
      },
      required: ['dispute_id', 'reason'],
    },
  },
  {
    name: 'ep_install_preflight',
    description:
      'EP-SX: Should I install this plugin/app/package/extension? ' +
      'Evaluates a software entity against a software-specific trust policy with context. ' +
      'Returns allow/review/deny with specific reasons covering publisher, permissions, provenance, and trust history.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Software entity ID (e.g. github_app:acme/code-helper)' },
        policy: {
          type: 'string',
          description: 'Software policy: github_private_repo_safe_v1, npm_buildtime_safe_v1, browser_extension_safe_v1, mcp_server_safe_v1, or standard EP policies',
        },
        context: {
          type: 'object',
          description: 'Install context: { host, install_scope, permission_class, data_sensitivity, execution_mode }',
        },
      },
      required: ['entity_id'],
    },
  },
  // EP-IX Identity Continuity
  {
    name: 'ep_principal_lookup',
    description: 'Look up a principal — the enduring actor behind entities. Returns bindings, controlled entities, and continuity history.',
    inputSchema: {
      type: 'object',
      properties: {
        principal_id: { type: 'string', description: 'Principal ID (e.g. ep_principal_abc)' },
      },
      required: ['principal_id'],
    },
  },
  {
    name: 'ep_lineage',
    description: 'View entity lineage — predecessors, successors, continuity decisions, and whitewashing flags. Use to check if an entity has suspicious continuity gaps.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity ID to check lineage for' },
      },
      required: ['entity_id'],
    },
  },
  {
    name: 'ep_list_policies',
    description: 'List all available trust policies with their requirements and families. Use to discover which policy to evaluate against.',
    inputSchema: { type: 'object', properties: {} },
  },

  // V1.0: Delegation
  {
    name: 'ep_create_delegation',
    description:
      'Create a delegation record: a human or principal authorizes an agent to act on their behalf. ' +
      'The delegation is recorded in the EP ledger with scope, expiry, and optional constraints. ' +
      'Every delegated action can reference this delegation to prove authorization.',
    inputSchema: {
      type: 'object',
      properties: {
        principal_id: { type: 'string', description: 'The principal (human/org) granting the delegation' },
        agent_entity_id: { type: 'string', description: 'The agent entity being authorized' },
        scope: { type: 'array', items: { type: 'string' }, description: 'List of permitted action types (e.g. ["purchase", "book", "send_email"])' },
        max_value_usd: { type: 'number', description: 'Maximum transaction value in USD this delegation authorizes (optional)' },
        expires_at: { type: 'string', description: 'ISO8601 expiry timestamp. If omitted, defaults to 24 hours.' },
        constraints: { type: 'object', description: 'Additional constraints (geo, merchant_category, etc.)' },
      },
      required: ['principal_id', 'agent_entity_id', 'scope'],
    },
  },

  // V1.0: Verify delegation
  {
    name: 'ep_verify_delegation',
    description:
      'Verify that an agent currently holds a valid delegation from a principal for a specific action. ' +
      'Use this before accepting a task from an agent claiming to act on behalf of a human. ' +
      'Returns: valid/expired/not_found with scope details.',
    inputSchema: {
      type: 'object',
      properties: {
        delegation_id: { type: 'string', description: 'Delegation ID (ep_dlg_...)' },
        action_type: { type: 'string', description: 'The action type to check (must be in delegation scope)' },
      },
      required: ['delegation_id'],
    },
  },

  // V1.0: Trust gate
  {
    name: 'ep_trust_gate',
    description:
      'Trust gate: check if an entity meets the required trust threshold BEFORE executing a high-stakes action. ' +
      'This is the canonical pre-action check. Always call this before: payments, sending messages on behalf of users, ' +
      'installing software, or any irreversible action. Returns allow/block with reason.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity requesting to perform the action' },
        action: { type: 'string', description: 'Action being requested (e.g. "process_payment", "send_email", "install_package")' },
        policy: { type: 'string', description: 'Policy to enforce: "strict", "standard", "permissive". Default: "standard"' },
        value_usd: { type: 'number', description: 'Transaction value in USD (used for risk calibration)' },
        delegation_id: { type: 'string', description: 'If agent is acting on behalf of a human, the delegation ID' },
      },
      required: ['entity_id', 'action'],
    },
  },

  // V1.0: Batch receipt submission
  {
    name: 'ep_batch_submit',
    description:
      'Submit multiple receipts atomically. All receipts share the same submitter (your API key). ' +
      'Useful for bulk reconciliation or recording a session of agent-entity interactions. ' +
      'Returns per-receipt success/failure. Max 50 receipts per batch.',
    inputSchema: {
      type: 'object',
      properties: {
        receipts: {
          type: 'array',
          description: 'Array of receipt objects (same schema as ep_submit_receipt)',
          items: {
            type: 'object',
            properties: {
              entity_id: { type: 'string' },
              transaction_ref: { type: 'string' },
              transaction_type: { type: 'string' },
              agent_behavior: { type: 'string' },
              delivery_accuracy: { type: 'number' },
              product_accuracy: { type: 'number' },
              price_integrity: { type: 'number' },
              return_processing: { type: 'number' },
            },
            required: ['entity_id', 'transaction_ref', 'transaction_type'],
          },
        },
      },
      required: ['receipts'],
    },
  },

  // Sprint 2: Auto-receipt configuration
  {
    name: 'ep_configure_auto_receipt',
    description:
      'Enable or disable automatic receipt generation for this session. ' +
      'When enabled, every EP tool call generates a behavioral receipt automatically. ' +
      'Privacy-preserving: sensitive fields (passwords, tokens, API keys) are redacted before storage. ' +
      'Receipts are marked unilateral — they cannot be bilateral without counterparty confirmation. ' +
      'Auto-receipt is opt-in and disabled by default.',
    inputSchema: {
      type: 'object',
      properties: {
        enabled: {
          type: 'boolean',
          description: 'Enable (true) or disable (false) auto-receipt generation for this session',
        },
        entity_id: {
          type: 'string',
          description: 'Entity ID to attribute auto-generated receipts to (your EP entity slug)',
        },
      },
      required: ['enabled', 'entity_id'],
    },
  },

  // V1.0: Domain score
  {
    name: 'ep_domain_score',
    description:
      'Get an entity\'s trust score broken down by behavioral domain. ' +
      'Trust is not a scalar — an agent excellent at financial transactions may be unreliable at creative tasks. ' +
      'Domains: financial, code_execution, communication, delegation, infrastructure, content_creation, data_access. ' +
      'Returns per-domain confidence, evidence count, and behavioral rates.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Entity to query' },
        domains: {
          type: 'array',
          items: { type: 'string' },
          description: 'Domains to query. If omitted, returns all domains.',
        },
      },
      required: ['entity_id'],
    },
  },

  // Sprint 5A: Zero-Knowledge Proof layer
  {
    name: 'ep_generate_zk_proof',
    description:
      'Generate a zero-knowledge trust proof. Proves a trust claim (e.g., score > 0.85 in the ' +
      'financial domain, or > 50 verified receipts) WITHOUT revealing receipt contents, counterparty ' +
      'identities, or transaction details. ' +
      'Returns a proof_id you can share publicly — verifiers call ep_verify_zk_proof with only the ' +
      'proof_id and learn nothing about your transaction history. ' +
      'Essential for privacy-sensitive contexts: healthcare (HIPAA), legal (privilege), ' +
      'finance (NDA/MNPI), and any situation where sharing transaction history is not possible. ' +
      'Requires your EP API key (you can only prove claims about your own entity).',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'Your EP entity ID. Must match the API key used to authenticate.',
        },
        claim_type: {
          type: 'string',
          enum: ['score_above', 'domain_score_above', 'receipt_count_above'],
          description:
            'score_above: global behavioral score > threshold. ' +
            'domain_score_above: per-domain score > threshold (requires domain). ' +
            'receipt_count_above: total receipts > threshold (integer count).',
        },
        threshold: {
          type: 'number',
          description:
            '0.0–1.0 for score claims (e.g. 0.85 = 85th percentile behavioral score). ' +
            'Positive integer for receipt_count_above (e.g. 50 = at least 50 receipts).',
        },
        domain: {
          type: 'string',
          enum: [
            'financial', 'code_execution', 'communication', 'delegation',
            'infrastructure', 'content_creation', 'data_access',
          ],
          description: 'Required for domain_score_above claims. Which behavioral domain to prove.',
        },
      },
      required: ['entity_id', 'claim_type', 'threshold'],
    },
  },
  {
    name: 'ep_verify_zk_proof',
    description:
      'Verify a zero-knowledge trust proof by proof_id. ' +
      'Returns whether the claim is currently valid — without revealing anything about the ' +
      'entity\'s transaction history, counterparties, or receipt contents. ' +
      'The proof holder shares only the proof_id. You verify without learning who they transacted with. ' +
      'Use this to accept trust claims from entities in privacy-sensitive industries ' +
      '(healthcare, legal, finance) who cannot share raw transaction history.',
    inputSchema: {
      type: 'object',
      properties: {
        proof_id: {
          type: 'string',
          description: 'The proof identifier (ep_zkp_...) shared by the proving entity.',
        },
      },
      required: ['proof_id'],
    },
  },

  // Sprint 4A: Delegation judgment
  {
    name: 'ep_delegation_judgment',
    description:
      'Get a principal\'s delegation judgment score — how well they choose and authorize agents. ' +
      'High judgment principals consistently authorize well-behaved agents. ' +
      'Low judgment principals frequently authorize agents that fail, dispute, or abandon tasks. ' +
      'This signal is deliberately weak (0.15 weight per outcome): a single bad delegation should not ' +
      'define a principal, but a pattern of them should be legible. ' +
      'Returns: judgment_score (0–1), agents_authorized, good_outcome_rate, and signal counts.',
    inputSchema: {
      type: 'object',
      properties: {
        principal_id: {
          type: 'string',
          description: 'Principal entity ID or human identifier (e.g. ep_principal_abc or user@example.com)',
        },
      },
      required: ['principal_id'],
    },
  },
];

// =============================================================================
// Tool handlers
// =============================================================================

async function handleTool(name, args) {
  switch (name) {
    case 'ep_trust_profile': {
      const data = await epFetch(`/api/trust/profile/${encodeURIComponent(args.entity_id)}`);
      return formatTrustProfile(data);
    }

    case 'ep_trust_evaluate': {
      const body = { entity_id: args.entity_id, policy: args.policy || 'standard' };
      if (args.context) body.context = args.context;
      const data = await epFetch('/api/trust/evaluate', { method: 'POST', body });
      return formatEvaluation(data);
    }

    case 'ep_submit_receipt': {
      if (!API_KEY) return 'Error: EP_API_KEY required. Set it in MCP server config.';
      const body = { ...args };
      const data = await epFetch('/api/receipts/submit', { method: 'POST', auth: true, body });
      return `Receipt submitted.\n` +
        `ID: ${data.receipt.receipt_id}\n` +
        `Hash: ${data.receipt.receipt_hash}\n` +
        `Entity trust profile updated. Query with ep_trust_profile for current state.`;
    }

    case 'ep_search_entities': {
      const params = new URLSearchParams({ q: args.query });
      if (args.entity_type) params.set('type', args.entity_type);
      const data = await epFetch(`/api/entities/search?${params}`);
      const entities = data.entities || data.results || [];
      if (!entities.length) return 'No entities found.';
      return entities.map(e => {
        const conf = e.confidence || 'pending';
        const ee = e.effective_evidence != null ? ` · evidence: ${e.effective_evidence.toFixed(2)}` : '';
        return `${e.display_name} (${e.entity_id})\n  confidence: ${conf}${ee} · trust profile available`;
      }).join('\n\n');
    }

    case 'ep_verify_receipt': {
      const data = await epFetch(`/api/verify/${encodeURIComponent(args.receipt_id)}`);
      return `Receipt: ${data.receipt_id}\nHash: ${data.receipt_hash}\nAnchored: ${data.anchored ? 'Yes' : 'No'}\nVerified: ${data.verified ? 'YES' : 'FAILED'}`;
    }

    case 'ep_register_entity': {
      const data = await epFetch('/api/entities/register', { method: 'POST', body: args });
      return `Registered: ${data.entity.entity_id}\nAPI Key: ${data.api_key}\n⚠️ Save this key — it won't be shown again.`;
    }

    case 'ep_leaderboard': {
      const params = new URLSearchParams();
      if (args?.limit) params.set('limit', String(Math.min(args.limit, 50)));
      if (args?.entity_type) params.set('type', args.entity_type);
      const data = await epFetch(`/api/leaderboard?${params}`);
      const lb = data.leaderboard || [];
      if (!lb.length) return 'No entities in leaderboard yet.';
      return lb.map(e => {
        const conf = e.confidence || 'pending';
        return `#${e.rank} ${e.display_name} (${e.entity_id})\n  confidence: ${conf} · trust profile available`;
      }).join('\n\n');
    }

    case 'ep_dispute_file': {
      if (!API_KEY) return 'Error: EP_API_KEY required to file disputes.';
      const body = {
        receipt_id: args.receipt_id,
        reason: args.reason,
        description: args.description || null,
        evidence: args.evidence || null,
      };
      const data = await epFetch('/api/disputes/file', { method: 'POST', auth: true, body });
      return `Dispute filed.\n` +
        `Dispute ID: ${data.dispute_id}\n` +
        `Receipt: ${data.receipt_id}\n` +
        `Status: ${data.status}\n` +
        `Response deadline: ${data.response_deadline}\n` +
        `${data._message}`;
    }

    case 'ep_dispute_status': {
      const data = await epFetch(`/api/disputes/${encodeURIComponent(args.dispute_id)}`);
      let out = `Dispute: ${data.dispute_id}\n`;
      out += `Status: ${data.status}\n`;
      out += `Reason: ${data.reason}\n`;
      out += `Entity: ${data.entity?.display_name} (${data.entity?.entity_id})\n`;
      out += `Filed by: ${data.filed_by?.display_name} (${data.filed_by_type})\n`;
      if (data.response) out += `Response: ${data.response}\n`;
      if (data.resolution) out += `Resolution: ${data.resolution}\nRationale: ${data.resolution_rationale}\n`;
      return out;
    }

    case 'ep_report_trust_issue': {
      const body = {
        entity_id: args.entity_id,
        report_type: args.report_type,
        description: args.description,
        contact_email: args.contact_email || null,
      };
      const data = await epFetch('/api/disputes/report', { method: 'POST', body });
      return `Report filed.\n` +
        `Report ID: ${data.report_id}\n` +
        `${data._message}\n` +
        `${data._principle}`;
    }

    case 'ep_appeal_dispute': {
      if (!API_KEY) return 'Error: EP_API_KEY required to file appeals.';
      const body = {
        dispute_id: args.dispute_id,
        reason: args.reason,
        evidence: args.evidence || null,
      };
      const data = await epFetch('/api/disputes/appeal', { method: 'POST', auth: true, body });
      return `Appeal filed.\n` +
        `Appeal ID: ${data.appeal_id || data.dispute_id}\n` +
        `Status: ${data.status}\n` +
        `${data._message || 'Your appeal has been submitted for review.'}`;
    }

    case 'ep_install_preflight': {
      const body = { entity_id: args.entity_id, policy: args.policy || 'standard' };
      if (args.context) body.context = args.context;
      const data = await epFetch('/api/trust/install-preflight', { method: 'POST', body });
      let out = `Install Preflight: ${data.display_name} (${data.entity_id})\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      out += `Decision: ${data.decision === 'allow' ? '✓ ALLOW' : data.decision === 'deny' ? '✗ DENY' : '⚠ REVIEW'}\n`;
      out += `Policy: ${data.policy_used}\n`;
      out += `Confidence: ${data.confidence}\n\n`;
      if (data.reasons?.length) {
        out += `Reasons:\n`;
        for (const r of data.reasons) out += `  ${r}\n`;
      }
      if (data.software_meta) {
        out += `\nSoftware:\n`;
        out += `  Publisher verified: ${data.software_meta.publisher_verified}\n`;
        out += `  Provenance verified: ${data.software_meta.provenance_verified}\n`;
        out += `  Permission class: ${data.software_meta.permission_class || 'unknown'}\n`;
      }
      out += `\n(Legacy compatibility score (fallback only): ${data.score}/100)\n`;
      return out;
    }

    case 'ep_principal_lookup': {
      const data = await epFetch(`/api/identity/principal/${encodeURIComponent(args.principal_id)}`);
      if (data.error) return `Principal not found: ${args.principal_id}`;
      const p = data.principal;
      let out = `Principal: ${p.display_name} (${p.principal_id})\n`;
      out += `Type: ${p.principal_type} · Status: ${p.status}\n`;
      if (p.bootstrap_verified) out += `Bootstrap verified: yes\n`;
      if (data.entities?.length) {
        out += `\nControlled entities (${data.entities.length}):\n`;
        for (const e of data.entities) out += `  ${e.display_name} (${e.entity_id}) — ${e.entity_type}\n`;
      }
      if (data.bindings?.length) {
        out += `\nIdentity bindings (${data.bindings.length}):\n`;
        for (const b of data.bindings) out += `  ${b.binding_type}: ${b.binding_target} [${b.status}] provenance: ${b.provenance}\n`;
      }
      if (data.continuity_claims?.length) {
        out += `\nContinuity history (${data.continuity_claims.length}):\n`;
        for (const c of data.continuity_claims) out += `  ${c.old_entity_id} → ${c.new_entity_id} (${c.reason}) [${c.status}]\n`;
      }
      return out;
    }

    case 'ep_lineage': {
      const data = await epFetch(`/api/identity/lineage/${encodeURIComponent(args.entity_id)}`);
      let out = `Lineage: ${data.entity_id}\n`;
      if (data.predecessors?.length) {
        out += `\nPredecessors:\n`;
        for (const p of data.predecessors) out += `  ← ${p.from} (${p.reason}) [${p.status}] transfer: ${p.transfer_policy || 'pending'}\n`;
      } else {
        out += `\nNo predecessors — this is an original entity.\n`;
      }
      if (data.successors?.length) {
        out += `\nSuccessors:\n`;
        for (const s of data.successors) out += `  → ${s.to} (${s.reason}) [${s.status}] transfer: ${s.transfer_policy || 'pending'}\n`;
      } else {
        out += `No successors.\n`;
      }
      return out;
    }

    case 'ep_list_policies': {
      const data = await epFetch('/api/policies');
      let out = `Available Trust Policies (${data.policies.length})\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      for (const p of data.policies) {
        out += `\n${p.name} [${p.family}]\n`;
        out += `  ${p.description}\n`;
        if (p.min_confidence) out += `  min confidence: ${p.min_confidence}\n`;
      }
      out += `\nUse ep_trust_evaluate with a policy name to evaluate an entity.`;
      return out;
    }

    case 'ep_create_delegation': {
      if (!API_KEY) return 'Error: EP_API_KEY required to create delegations.';
      const body = {
        principal_id: args.principal_id,
        agent_entity_id: args.agent_entity_id,
        scope: args.scope,
        max_value_usd: args.max_value_usd || null,
        expires_at: args.expires_at || null,
        constraints: args.constraints || null,
      };
      const data = await epFetch('/api/delegations/create', { method: 'POST', auth: true, body });
      return `Delegation created.\n` +
        `ID: ${data.delegation_id}\n` +
        `Principal: ${data.principal_id}\n` +
        `Agent: ${data.agent_entity_id}\n` +
        `Scope: ${data.scope.join(', ')}\n` +
        `Expires: ${data.expires_at}\n` +
        `Status: ${data.status}`;
    }

    case 'ep_verify_delegation': {
      const params = new URLSearchParams();
      if (args.action_type) params.set('action_type', args.action_type);
      const data = await epFetch(`/api/delegations/${encodeURIComponent(args.delegation_id)}/verify?${params}`);
      let out = `Delegation: ${data.delegation_id}\n`;
      out += `Status: ${data.valid ? '✓ VALID' : '✗ ' + (data.status || 'INVALID')}\n`;
      if (data.principal_id) out += `Principal: ${data.principal_id}\n`;
      if (data.agent_entity_id) out += `Agent: ${data.agent_entity_id}\n`;
      if (data.scope) out += `Scope: ${data.scope.join(', ')}\n`;
      if (data.expires_at) out += `Expires: ${data.expires_at}\n`;
      if (data.action_type && data.action_permitted != null) {
        out += `Action "${data.action_type}": ${data.action_permitted ? '✓ Permitted' : '✗ Not in scope'}\n`;
      }
      if (data.reason) out += `Reason: ${data.reason}\n`;
      return out;
    }

    case 'ep_trust_gate': {
      const body = {
        entity_id: args.entity_id,
        action: args.action,
        policy: args.policy || 'standard',
        value_usd: args.value_usd || null,
        delegation_id: args.delegation_id || null,
      };
      const data = await epFetch('/api/trust/gate', { method: 'POST', body });
      let out = `Trust Gate: ${args.action}\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      out += `Entity: ${data.entity_id}\n`;
      out += `Decision: ${data.decision === 'allow' ? '✓ ALLOW' : '✗ BLOCK'}\n`;
      out += `Policy: ${data.policy_used}\n`;
      out += `Confidence: ${data.confidence}\n`;
      if (data.delegation_verified != null) out += `Delegation: ${data.delegation_verified ? '✓ Verified' : '✗ Not verified'}\n`;
      if (data.reasons?.length) {
        out += `\nReasons:\n`;
        for (const r of data.reasons) out += `  ${data.decision === 'allow' ? '✓' : '✗'} ${r}\n`;
      }
      if (data.decision === 'block' && data.appeal_path) {
        out += `\nAppeal path: ${data.appeal_path}\n`;
        out += `Trust must never be more powerful than appeal.\n`;
      }
      return out;
    }

    case 'ep_batch_submit': {
      if (!API_KEY) return 'Error: EP_API_KEY required for batch submission.';
      const receipts = (args.receipts || []).slice(0, 50);
      if (!receipts.length) return 'Error: No receipts provided.';
      const data = await epFetch('/api/receipts/batch', { method: 'POST', auth: true, body: { receipts } });
      const results = data.results || [];
      const succeeded = results.filter(r => r.success).length;
      const failed = results.filter(r => !r.success).length;
      let out = `Batch submission: ${succeeded} succeeded, ${failed} failed\n`;
      for (const r of results) {
        out += r.success
          ? `  ✓ ${r.entity_id} — ${r.receipt_id}\n`
          : `  ✗ ${r.entity_id} — ${r.error}\n`;
      }
      return out;
    }

    case 'ep_domain_score': {
      const params = new URLSearchParams();
      if (args.domains?.length) params.set('domains', args.domains.join(','));
      const data = await epFetch(`/api/trust/domain-score/${encodeURIComponent(args.entity_id)}?${params}`);
      let out = `Domain Scores: ${data.entity_id}\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      const domains = data.domains || {};
      for (const [domain, score] of Object.entries(domains)) {
        out += `\n${domain}:\n`;
        out += `  Confidence: ${score.confidence ?? 'pending'}\n`;
        out += `  Evidence: ${score.evidence_count ?? 0} receipts\n`;
        if (score.completion_rate != null) out += `  Completion: ${score.completion_rate}%\n`;
        if (score.dispute_rate != null) out += `  Dispute rate: ${score.dispute_rate}%\n`;
      }
      if (!Object.keys(domains).length) out += 'No domain data available yet.\n';
      return out;
    }

    case 'ep_configure_auto_receipt': {
      const previousState = autoReceipt.optIn;
      autoReceipt.configure(args.enabled, args.entity_id);
      const stateChanged = previousState !== autoReceipt.optIn;
      if (args.enabled) {
        return (
          `Auto-receipt enabled for entity: ${args.entity_id}\n` +
          `Every EP tool call will now generate a behavioral receipt automatically.\n` +
          `Receipts are privacy-preserving (sensitive fields redacted) and marked unilateral.\n` +
          `${stateChanged ? 'Status changed from disabled → enabled.' : 'Was already enabled.'}\n` +
          `To disable: call ep_configure_auto_receipt with enabled: false.`
        );
      } else {
        return (
          `Auto-receipt disabled.\n` +
          `${stateChanged ? 'Status changed from enabled → disabled.' : 'Was already disabled.'}\n` +
          `No further automatic receipts will be generated for this session.`
        );
      }
    }

    case 'ep_delegation_judgment': {
      const data = await epFetch(`/api/attribution/delegation-judgment/${encodeURIComponent(args.principal_id)}`);
      let out = `Delegation Judgment: ${args.principal_id}\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      if (data.judgment_score == null) {
        out += `Score: pending (no delegation signals yet)\n`;
      } else {
        const pct = Math.round(data.judgment_score * 100);
        const label = pct >= 80 ? 'High' : pct >= 50 ? 'Moderate' : 'Low';
        out += `Score: ${pct}/100 (${label} judgment)\n`;
      }
      out += `Agents authorized: ${data.agents_authorized ?? 0}\n`;
      if (data.good_outcome_rate != null) {
        out += `Good outcome rate: ${Math.round(data.good_outcome_rate * 100)}%\n`;
      }
      out += `Total signals: ${data.total_signals ?? 0}`;
      if (data.total_signals > 0) {
        out += ` (${data.positive_signals} positive, ${data.negative_signals} negative)`;
      }
      out += `\n`;
      out += `\nSignal weight: 0.15 per delegation outcome (weak signal by design).\n`;
      out += `A pattern of low judgment signals that a principal repeatedly authorizes misbehaving agents.`;
      return out;
    }

    case 'ep_generate_zk_proof': {
      if (!API_KEY) return 'Error: EP_API_KEY required to generate ZK proofs.';
      const body = {
        entity_id: args.entity_id,
        claim: {
          type: args.claim_type,
          threshold: args.threshold,
          ...(args.domain ? { domain: args.domain } : {}),
        },
      };
      let data;
      try {
        data = await epFetch('/api/trust/zk-proof', { method: 'POST', auth: true, body });
      } catch (err) {
        if (err.message?.includes('CLAIM_NOT_PROVABLE') || err.message?.includes('claim_not_provable')) {
          return (
            `ZK Proof: Claim Not Provable\n` +
            `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n` +
            `Your current trust data does not meet the specified threshold.\n` +
            `Claim: ${args.claim_type} > ${args.threshold}` +
            (args.domain ? ` in ${args.domain}` : '') + `\n` +
            `Accumulate more receipts or lower the threshold and try again.`
          );
        }
        throw err;
      }
      let out = `ZK Proof Generated\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      out += `Proof ID:       ${data.proof_id}\n`;
      out += `Entity:         ${data.entity_id}\n`;
      out += `Claim:          ${data.claim.type} > ${data.claim.threshold}`;
      if (data.claim.domain) out += ` (${data.claim.domain})`;
      out += `\n`;
      out += `Receipts:       ${data.receipt_count} (hidden from verifiers)\n`;
      out += `Expires:        ${data.expires_at}\n`;
      if (data.anchor_block) out += `Anchor:         ${data.anchor_block}\n`;
      out += `\nShare this proof_id with any verifier:\n  ${data.proof_id}\n`;
      out += `\nThe verifier calls ep_verify_zk_proof with only the proof_id.\n`;
      out += `They confirm your claim without seeing your receipt history, counterparties, or transaction details.`;
      return out;
    }

    case 'ep_verify_zk_proof': {
      const params = new URLSearchParams({ proof_id: args.proof_id });
      const data = await epFetch(`/api/trust/zk-proof?${params}`);
      let out = `ZK Proof Verification\n`;
      out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
      out += `Proof ID:    ${data.proof_id}\n`;
      out += `Entity:      ${data.entity_id}\n`;
      out += `Result:      ${data.valid ? '✓ VALID' : '✗ INVALID'}\n`;
      if (data.claim) {
        out += `Claim:       ${data.claim.type} > ${data.claim.threshold}`;
        if (data.claim.domain) out += ` (${data.claim.domain})`;
        out += `\n`;
      }
      out += `Verified at: ${data.verified_at}\n`;
      if (data.valid) {
        out += `Receipt count: ${data.receipt_count} (counterparties and contents remain hidden)\n`;
        out += `Expires:       ${data.expires_at}\n`;
        if (data.anchor_block) out += `Anchor:        ${data.anchor_block}\n`;
        out += `\n✓ The entity has proven the stated trust claim.\n`;
        out += `You have learned nothing about their transaction history or counterparties.`;
      } else {
        out += `Reason: ${data.reason || 'unknown'}\n`;
        if (data.expired_at) out += `Expired: ${data.expired_at}\n`;
        out += `\n${data._note || 'Proof could not be verified.'}`;
      }
      return out;
    }

    default:
      return `Unknown tool: ${name}`;
  }
}

// =============================================================================
// Formatters
// =============================================================================

function formatTrustProfile(data) {
  let out = `Trust Profile: ${data.display_name} (${data.entity_id})\n`;
  out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  out += `Confidence: ${data.current_confidence}\n`;
  out += `Established: ${data.historical_establishment ? 'Yes' : 'No'}\n`;
  out += `Evidence: ${data.effective_evidence_current} (current) / ${data.effective_evidence_historical} (historical)\n`;
  out += `Receipts: ${data.receipt_count ?? 'N/A'} from ${data.unique_submitters ?? 'N/A'} submitters\n`;

  const p = data.trust_profile;
  if (p) {
    if (p.behavioral) {
      out += `\nBehavioral:\n`;
      out += `  Completion rate: ${p.behavioral.completion_rate ?? 'N/A'}%\n`;
      out += `  Retry rate:      ${p.behavioral.retry_rate ?? 'N/A'}%\n`;
      out += `  Abandon rate:    ${p.behavioral.abandon_rate ?? 'N/A'}%\n`;
      out += `  Dispute rate:    ${p.behavioral.dispute_rate ?? 'N/A'}%\n`;
    }
    if (p.signals) {
      out += `\nSignals:\n`;
      out += `  Delivery:  ${p.signals.delivery_accuracy ?? 'N/A'}\n`;
      out += `  Product:   ${p.signals.product_accuracy ?? 'N/A'}\n`;
      out += `  Price:     ${p.signals.price_integrity ?? 'N/A'}\n`;
      out += `  Returns:   ${p.signals.return_processing ?? 'N/A'}\n`;
    }
    out += `  Consistency: ${p.consistency ?? 'N/A'}\n`;
    if (p.provenance) {
      const bd = p.provenance.breakdown || {};
      const tiers = Object.entries(bd).map(([k,v]) => `${k}: ${v}`).join(', ');
      out += `\nProvenance: ${tiers}\n`;
      if (p.provenance.bilateral_rate != null) out += `  Bilateral rate: ${p.provenance.bilateral_rate}%\n`;
    }
  }

  if (data.disputes && data.disputes.total > 0) {
    out += `\nDisputes: ${data.disputes.total} total, ${data.disputes.active} active, ${data.disputes.reversed} reversed\n`;
  }

  if (data.anomaly) {
    out += `\n⚠️ ANOMALY: ${data.anomaly.type} (${data.anomaly.delta} points, ${data.anomaly.alert})\n`;
  }

  out += `\n(Legacy compatibility score (fallback only): ${data.compat_score}/100 — use trust profile for decisions)\n`;
  return out;
}

function formatEvaluation(data) {
  let out = `Trust Evaluation: ${data.display_name} (${data.entity_id})\n`;
  out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  out += `Policy: ${data.policy_used}\n`;
  out += `Decision: ${data.pass ? '✓ PASS' : '✗ FAIL'}\n`;
  out += `Confidence: ${data.confidence}\n`;
  out += `Context: ${JSON.stringify(data.context_used) || 'global'}\n`;

  if (data.failures?.length > 0) {
    out += `\nFailures:\n`;
    for (const f of data.failures) out += `  ✗ ${f}\n`;
  }
  if (data.warnings?.length > 0) {
    out += `\nWarnings:\n`;
    for (const w of data.warnings) out += `  ⚠ ${w}\n`;
  }

  return out;
}

// =============================================================================
// Server
// =============================================================================

const server = new Server(
  { name: 'emilia-protocol', version: '1.0.0' },
  { capabilities: { tools: {}, resources: {}, prompts: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    // Wrap handleTool with auto-receipt instrumentation.
    // The middleware measures latency, generates a receipt draft from the outcome,
    // and submits it asynchronously — the tool response is never delayed.
    // ep_configure_auto_receipt itself is excluded from auto-receipt to avoid
    // a bootstrap loop where enabling the feature immediately records itself.
    const isMetaTool = name === 'ep_configure_auto_receipt';
    const invoker = isMetaTool
      ? (a) => handleTool(name, a)
      : autoReceipt.wrap(name, (a) => handleTool(name, a));

    const result = await invoker(args || {});
    return { content: [{ type: 'text', text: result }] };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
});

// =============================================================================
// MCP Resources
// =============================================================================

const RESOURCES = [
  {
    uri: 'entity://{id}',
    name: 'Entity Trust Profile',
    description: 'Full trust profile for any entity by ID or slug. Equivalent to ep_trust_profile tool but as a resource.',
    mimeType: 'application/json',
  },
  {
    uri: 'score://{id}',
    name: 'Entity Trust Score',
    description: 'Current trust confidence and score breakdown for an entity.',
    mimeType: 'application/json',
  },
  {
    uri: 'receipt://{id}',
    name: 'Receipt',
    description: 'Full receipt data including hash, provenance, and verification status.',
    mimeType: 'application/json',
  },
  {
    uri: 'delegation://{id}',
    name: 'Delegation Record',
    description: 'Delegation details: principal, agent, scope, expiry, and status.',
    mimeType: 'application/json',
  },
];

server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: RESOURCES }));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;
  let data;
  let text;

  if (uri.startsWith('entity://')) {
    const id = uri.slice('entity://'.length);
    data = await epFetch(`/api/trust/profile/${encodeURIComponent(id)}`);
    text = JSON.stringify(data, null, 2);
  } else if (uri.startsWith('score://')) {
    const id = uri.slice('score://'.length);
    data = await epFetch(`/api/trust/profile/${encodeURIComponent(id)}`);
    text = JSON.stringify({
      entity_id: data.entity_id,
      confidence: data.current_confidence,
      effective_evidence: data.effective_evidence_current,
      established: data.historical_establishment,
      compat_score: data.compat_score,
    }, null, 2);
  } else if (uri.startsWith('receipt://')) {
    const id = uri.slice('receipt://'.length);
    data = await epFetch(`/api/verify/${encodeURIComponent(id)}`);
    text = JSON.stringify(data, null, 2);
  } else if (uri.startsWith('delegation://')) {
    const id = uri.slice('delegation://'.length);
    data = await epFetch(`/api/delegations/${encodeURIComponent(id)}/verify`);
    text = JSON.stringify(data, null, 2);
  } else {
    throw new Error(`Unknown resource URI: ${uri}`);
  }

  return { contents: [{ uri, mimeType: 'application/json', text }] };
});

// =============================================================================
// MCP Prompts
// =============================================================================

const PROMPTS = [
  {
    name: 'trust_decision',
    description: 'Get a structured prompt for making a trust-based routing or payment decision about an entity.',
    arguments: [
      { name: 'entity_id', description: 'Entity to evaluate', required: true },
      { name: 'action', description: 'Action being considered (e.g. process_payment, install_plugin)', required: true },
      { name: 'value_usd', description: 'Transaction value in USD', required: false },
    ],
  },
  {
    name: 'receipt_quality_check',
    description: 'Get a prompt for evaluating the quality and accuracy of a receipt before submission.',
    arguments: [
      { name: 'entity_id', description: 'Entity the receipt is about', required: true },
      { name: 'transaction_ref', description: 'Transaction reference', required: true },
    ],
  },
  {
    name: 'install_decision',
    description: 'Get a structured prompt for deciding whether to install a software package or plugin.',
    arguments: [
      { name: 'entity_id', description: 'Software entity ID', required: true },
      { name: 'install_context', description: 'Where it will be installed (e.g. private_repo, production_server)', required: false },
    ],
  },
];

server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: PROMPTS }));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === 'trust_decision') {
    const entity_id = args?.entity_id || '[entity_id]';
    const action = args?.action || '[action]';
    const value = args?.value_usd ? ` (value: $${args.value_usd})` : '';
    return {
      description: `Trust decision for ${entity_id}`,
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `I need to decide whether to allow entity "${entity_id}" to perform "${action}"${value}.\n\n` +
            `Please:\n` +
            `1. Call ep_trust_gate with entity_id="${entity_id}", action="${action}"${args?.value_usd ? `, value_usd=${args.value_usd}` : ''}\n` +
            `2. If the gate passes, call ep_trust_profile to get the full profile\n` +
            `3. Summarize: ALLOW or BLOCK, with the key trust signals that drove the decision\n` +
            `4. If BLOCK, explain what the entity would need to do to qualify`,
        },
      }],
    };
  }

  if (name === 'receipt_quality_check') {
    const entity_id = args?.entity_id || '[entity_id]';
    const ref = args?.transaction_ref || '[transaction_ref]';
    return {
      description: `Receipt quality check for ${entity_id}`,
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `Before I submit a receipt for entity "${entity_id}" (ref: ${ref}), help me ensure it's accurate:\n\n` +
            `1. Call ep_trust_profile to see their current trust state\n` +
            `2. Ask me: What was the agent_behavior? (completed/retried_same/retried_different/abandoned/disputed)\n` +
            `3. Ask me: What signal scores should I set? (delivery_accuracy, product_accuracy, price_integrity, return_processing — each 0-100)\n` +
            `4. Warn me if any signals seem inconsistent with the agent_behavior\n` +
            `5. Only submit with ep_submit_receipt when I confirm the data is accurate`,
        },
      }],
    };
  }

  if (name === 'install_decision') {
    const entity_id = args?.entity_id || '[entity_id]';
    const ctx = args?.install_context || 'production';
    return {
      description: `Install decision for ${entity_id}`,
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `Should I install "${entity_id}" in my ${ctx} environment?\n\n` +
            `Please:\n` +
            `1. Call ep_install_preflight with entity_id="${entity_id}"\n` +
            `2. Call ep_lineage to check for suspicious continuity gaps\n` +
            `3. Call ep_trust_profile for full behavioral history\n` +
            `4. Give me a clear INSTALL / REVIEW / DENY recommendation with reasons\n` +
            `5. If REVIEW or DENY, list specific questions to investigate before proceeding`,
        },
      }],
    };
  }

  throw new Error(`Unknown prompt: ${name}`);
});

// =============================================================================
// Start
// =============================================================================

const transport = new StdioServerTransport();
await server.connect(transport);
