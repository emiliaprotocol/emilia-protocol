#!/usr/bin/env node

/**
 * EMILIA Protocol — MCP Server
 *
 * Trust layer tools for AI agents.
 * Add this server to any MCP-compatible client (Claude, etc.)
 * to give your agent access to EMILIA Scores.
 *
 * Tools provided:
 *   ep_score_lookup   — Check any entity's EMILIA Score (no auth)
 *   ep_submit_receipt — Submit a transaction receipt (requires API key)
 *   ep_verify_receipt — Verify a receipt against on-chain Merkle root (no auth)
 *   ep_search_entities — Search for entities by name or capability
 *   ep_register_entity — Register a new entity in the EMILIA network
 *   ep_leaderboard     — Get the top-scored entities
 *
 * Setup:
 *   EP_BASE_URL=https://emiliaprotocol.ai  (or your self-hosted instance)
 *   EP_API_KEY=ep_live_...                  (for write operations)
 *
 * Claude Desktop config (~/.claude/claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "emilia": {
 *         "command": "npx",
 *         "args": ["@emilia-protocol/mcp-server"],
 *         "env": {
 *           "EP_BASE_URL": "https://emiliaprotocol.ai",
 *           "EP_API_KEY": "ep_live_your_key_here"
 *         }
 *       }
 *     }
 *   }
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

// =============================================================================
// HTTP helpers
// =============================================================================

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
  if (!res.ok) {
    throw new Error(data.error || `EP API error: ${res.status}`);
  }
  return data;
}

// =============================================================================
// Tool definitions
// =============================================================================

const TOOLS = [
  {
    name: 'ep_score_lookup',
    description:
      'Look up an entity\'s EMILIA Score. Scores are public — no authentication required. ' +
      'Returns the trust score (0-100), breakdown by signal, receipt count, and verification status. ' +
      'Use this before transacting with any agent, merchant, or service provider.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'The entity ID (slug like "rex-booking-v1") or UUID to look up',
        },
      },
      required: ['entity_id'],
    },
  },
  {
    name: 'ep_submit_receipt',
    description:
      'Submit a transaction receipt to the EMILIA ledger. Requires an EP API key. ' +
      'Receipts are append-only, cryptographically hashed, and chain-linked. ' +
      'Each signal is 0-100: delivery_accuracy, product_accuracy, price_integrity, ' +
      'return_processing, agent_satisfaction. At least one signal is required.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'UUID of the entity being scored',
        },
        transaction_type: {
          type: 'string',
          enum: ['purchase', 'service', 'task_completion', 'delivery', 'return'],
          description: 'Type of transaction',
        },
        transaction_ref: {
          type: 'string',
          description: 'External reference (UCP order ID, A2A task ID, etc.)',
        },
        delivery_accuracy: {
          type: 'number',
          description: '0-100: Did it arrive when promised?',
        },
        product_accuracy: {
          type: 'number',
          description: '0-100: Did the listing match reality?',
        },
        price_integrity: {
          type: 'number',
          description: '0-100: Was the price honored?',
        },
        return_processing: {
          type: 'number',
          description: '0-100: Was the return policy followed?',
        },
        agent_satisfaction: {
          type: 'number',
          description: '0-100: Was the purchasing agent satisfied?',
        },
        evidence: {
          type: 'object',
          description: 'Structured evidence — e.g. { promised_delivery: "2d", actual_delivery: "3d" }',
        },
      },
      required: ['entity_id', 'transaction_type'],
    },
  },
  {
    name: 'ep_verify_receipt',
    description:
      'Verify a receipt against the on-chain Merkle root. No auth required. ' +
      'Returns the Merkle proof, verification status, and a link to the Base L2 transaction. ' +
      '"Don\'t trust EMILIA. Verify the math yourself."',
    inputSchema: {
      type: 'object',
      properties: {
        receipt_id: {
          type: 'string',
          description: 'The receipt ID (e.g. "ep_rcpt_abc123...")',
        },
      },
      required: ['receipt_id'],
    },
  },
  {
    name: 'ep_search_entities',
    description:
      'Search for entities in the EMILIA network by name, capability, or category. ' +
      'Returns matching entities with their scores and capabilities.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query — entity name, capability, or category',
        },
        entity_type: {
          type: 'string',
          enum: ['agent', 'merchant', 'service_provider'],
          description: 'Filter by entity type',
        },
        min_score: {
          type: 'number',
          description: 'Minimum EMILIA Score (0-100)',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'ep_register_entity',
    description:
      'Register a new entity in the EMILIA network. Requires an EP API key. ' +
      'Returns the entity ID, entity number, and a new API key for the entity.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_id: {
          type: 'string',
          description: 'Human-readable slug (e.g. "my-agent-v1"). Lowercase, hyphens, no spaces.',
        },
        display_name: {
          type: 'string',
          description: 'Display name (e.g. "My AI Shopping Agent")',
        },
        entity_type: {
          type: 'string',
          enum: ['agent', 'merchant', 'service_provider'],
          description: 'Type of entity',
        },
        description: {
          type: 'string',
          description: 'What this entity does',
        },
        capabilities: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of capabilities (e.g. ["price_comparison", "booking"])',
        },
        website_url: {
          type: 'string',
          description: 'Website URL',
        },
        a2a_endpoint: {
          type: 'string',
          description: 'A2A Agent Card endpoint URL',
        },
        ucp_profile_url: {
          type: 'string',
          description: 'UCP merchant profile URL',
        },
      },
      required: ['entity_id', 'display_name', 'entity_type', 'description'],
    },
  },
  {
    name: 'ep_leaderboard',
    description:
      'Get the top-scored entities in the EMILIA network. ' +
      'Returns entities ranked by EMILIA Score with their breakdowns.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Number of entities to return (default: 10, max: 50)',
        },
        entity_type: {
          type: 'string',
          enum: ['agent', 'merchant', 'service_provider'],
          description: 'Filter by entity type',
        },
      },
    },
  },
];

// =============================================================================
// Tool handlers
// =============================================================================

async function handleTool(name, args) {
  switch (name) {
    case 'ep_score_lookup': {
      const data = await epFetch(`/api/score/${encodeURIComponent(args.entity_id)}`);
      return formatScore(data);
    }

    case 'ep_submit_receipt': {
      if (!API_KEY) {
        return 'Error: EP_API_KEY is required for submitting receipts. Set it in your MCP server config.';
      }
      const data = await epFetch('/api/receipts/submit', {
        method: 'POST',
        auth: true,
        body: {
          entity_id: args.entity_id,
          transaction_type: args.transaction_type,
          transaction_ref: args.transaction_ref,
          delivery_accuracy: args.delivery_accuracy,
          product_accuracy: args.product_accuracy,
          price_integrity: args.price_integrity,
          return_processing: args.return_processing,
          agent_satisfaction: args.agent_satisfaction,
          evidence: args.evidence,
        },
      });
      return `Receipt submitted.\n` +
        `Receipt ID: ${data.receipt.receipt_id}\n` +
        `Composite Score: ${data.receipt.composite_score}\n` +
        `Hash: ${data.receipt.receipt_hash}\n` +
        `Entity Score Updated: ${data.entity_score.emilia_score} (${data.entity_score.total_receipts} receipts)`;
    }

    case 'ep_verify_receipt': {
      const data = await epFetch(`/api/verify/${encodeURIComponent(args.receipt_id)}`);
      return formatVerification(data);
    }

    case 'ep_search_entities': {
      const params = new URLSearchParams({ q: args.query });
      if (args.entity_type) params.set('type', args.entity_type);
      if (args.min_score) params.set('min_score', args.min_score.toString());
      const data = await epFetch(`/api/entities/search?${params}`);
      return formatSearch(data);
    }

    case 'ep_register_entity': {
      if (!API_KEY) {
        return 'Error: EP_API_KEY is required for registration. Set it in your MCP server config.';
      }
      const data = await epFetch('/api/entities/register', {
        method: 'POST',
        auth: true,
        body: args,
      });
      return `Entity registered!\n` +
        `Entity ID: ${data.entity.entity_id}\n` +
        `Entity #: ${data.entity.entity_number || 'N/A'}\n` +
        `EMILIA Score: ${data.entity.emilia_score} (new entity — score starts at 50)\n` +
        `API Key: ${data.api_key}\n\n` +
        `⚠️  Save this API key — it won't be shown again.`;
    }

    case 'ep_leaderboard': {
      const params = new URLSearchParams();
      if (args?.limit) params.set('limit', Math.min(args.limit, 50).toString());
      if (args?.entity_type) params.set('type', args.entity_type);
      const data = await epFetch(`/api/leaderboard?${params}`);
      return formatLeaderboard(data);
    }

    default:
      return `Unknown tool: ${name}`;
  }
}

// =============================================================================
// Formatters
// =============================================================================

function formatScore(data) {
  let out = `EMILIA Score for ${data.display_name} (${data.entity_id})\n`;
  out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  out += `Score: ${data.emilia_score}/100`;
  out += data.established ? ' (established)' : ' (new entity — score dampened)';
  out += `\nType: ${data.entity_type}\n`;
  out += `Total Receipts: ${data.total_receipts}\n`;
  out += `Verified: ${data.verified ? 'Yes' : 'No'}\n`;

  if (data.breakdown) {
    out += `\nBreakdown:\n`;
    out += `  Delivery Accuracy:  ${data.breakdown.delivery_accuracy ?? 'N/A'}\n`;
    out += `  Product Accuracy:   ${data.breakdown.product_accuracy ?? 'N/A'}\n`;
    out += `  Price Integrity:    ${data.breakdown.price_integrity ?? 'N/A'}\n`;
    out += `  Return Processing:  ${data.breakdown.return_processing ?? 'N/A'}\n`;
    out += `  Agent Satisfaction: ${data.breakdown.agent_satisfaction ?? 'N/A'}\n`;
    out += `  Consistency:        ${data.breakdown.consistency ?? 'N/A'}\n`;
  }

  if (data.description) {
    out += `\n${data.description}\n`;
  }

  return out;
}

function formatVerification(data) {
  let out = `Verification for ${data.receipt_id}\n`;
  out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
  out += `Receipt Hash: ${data.receipt_hash}\n`;
  out += `Anchored: ${data.anchored ? 'Yes (on Base L2)' : 'No'}\n`;
  out += `Proof Valid: ${data.verified ? '✓ VERIFIED' : '✗ FAILED'}\n`;

  if (data.batch) {
    out += `\nBatch Details:\n`;
    out += `  Merkle Root: ${data.batch.merkle_root}\n`;
    out += `  Leaf Count: ${data.batch.leaf_count}\n`;
    if (data.batch.tx_hash) {
      out += `  TX Hash: ${data.batch.tx_hash}\n`;
      out += `  Explorer: https://basescan.org/tx/${data.batch.tx_hash}\n`;
    }
  }

  return out;
}

function formatSearch(data) {
  const entities = data.entities || data.results || [];
  if (entities.length === 0) {
    return 'No entities found matching your query.';
  }

  let out = `Found ${entities.length} entities:\n\n`;
  for (const e of entities) {
    out += `${e.display_name} (${e.entity_id})\n`;
    out += `  Score: ${e.emilia_score}/100 | Type: ${e.entity_type} | Receipts: ${e.total_receipts}\n`;
    if (e.description) out += `  ${e.description}\n`;
    out += `\n`;
  }
  return out;
}

function formatLeaderboard(data) {
  if (!data.entities || data.entities.length === 0) {
    return 'No entities in the leaderboard yet.';
  }

  let out = `EMILIA Leaderboard\n`;
  out += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
  for (let i = 0; i < data.entities.length; i++) {
    const e = data.entities[i];
    out += `#${i + 1}  ${e.display_name} — ${e.emilia_score}/100 (${e.total_receipts} receipts)\n`;
  }
  return out;
}

// =============================================================================
// Server setup
// =============================================================================

const server = new Server(
  {
    name: 'emilia-protocol',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const result = await handleTool(name, args || {});
    return {
      content: [{ type: 'text', text: result }],
    };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error: ${err.message}` }],
      isError: true,
    };
  }
});

// Start
const transport = new StdioServerTransport();
await server.connect(transport);
