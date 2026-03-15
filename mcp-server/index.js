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
 * Setup:
 *   EP_BASE_URL=https://emiliaprotocol.ai
 *   EP_API_KEY=ep_live_...  (for write operations)
 *
 * @license Apache-2.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

const BASE_URL = process.env.EP_BASE_URL || 'https://emiliaprotocol.ai';
const API_KEY = process.env.EP_API_KEY || '';

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
        entity_type: { type: 'string', enum: ['agent', 'merchant', 'service_provider'] },
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
    description: 'Register a new entity. Requires an API key.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: { type: 'string', description: 'Slug (lowercase, hyphens)' },
        display_name: { type: 'string' },
        entity_type: { type: 'string', enum: ['agent', 'merchant', 'service_provider'] },
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
        entity_type: { type: 'string', enum: ['agent', 'merchant', 'service_provider'] },
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
      if (!API_KEY) return 'Error: EP_API_KEY required.';
      const data = await epFetch('/api/entities/register', { method: 'POST', auth: true, body: args });
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
      out += `\n(Legacy compat score: ${data.score}/100)\n`;
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

  out += `\n(Legacy compat score: ${data.compat_score}/100 — use trust profile for decisions)\n`;
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
  { name: 'emilia-protocol', version: '0.2.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const result = await handleTool(name, args || {});
    return { content: [{ type: 'text', text: result }] };
  } catch (err) {
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
