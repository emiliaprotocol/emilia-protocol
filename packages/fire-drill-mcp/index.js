#!/usr/bin/env node

/**
 * @emilia-protocol/fire-drill-mcp
 * @license Apache-2.0
 *
 * The Agent Action Firewall Test, exposed over MCP.
 *
 * A directory of MCP servers, plus one server whose job is to audit the others:
 * given any MCP manifest, OpenAPI spec, or tool list, it reports which dangerous
 * actions an agent can take WITHOUT an accountable human receipt.
 *
 * Pure wrapper — all scoring logic lives in @emilia-protocol/fire-drill (zero-dep,
 * the same source of truth as `npx @emilia-protocol/fire-drill` and the web /fire-drill).
 *
 * Tools:
 *   fire_drill_scan        — score a target (manifest / OpenAPI / tool list)
 *   fire_drill_leaderboard — the Agent Action Safety Index (pre-scanned corpus, worst first)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { scan, FIRE_DRILL_VERSION, TAGLINE } from '@emilia-protocol/fire-drill';
import { REPRESENTATIVE_CORPUS } from '@emilia-protocol/fire-drill/corpus.js';

const TOOLS = [
  {
    name: 'fire_drill_scan',
    description:
      'Run the Agent Action Firewall Test on an MCP server manifest, an OpenAPI spec, or a tool list. ' +
      'Flags every dangerous operation (money movement, data destruction, production deploy, permission ' +
      'change, bulk export, regulated override) that can run WITHOUT an accountable human receipt. Returns ' +
      'an Agent Action Firewall score (0–100), EG-1 pass/fail, the failing operations, and the fix. Static ' +
      'assessment of the documented tool surface — not a live deployment scan and not a vulnerability report.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'object',
          description:
            'The thing to scan, as a JSON object: an MCP manifest ({ tools: [...] }), an OpenAPI spec, ' +
            'or a bare tool array wrapped as { tools: [...] }. The scanner auto-detects the shape.',
        },
        target_json: {
          type: 'string',
          description: 'Alternative to `target`: the same payload as a JSON string. Used if `target` is omitted.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'fire_drill_leaderboard',
    description:
      'The Agent Action Safety Index: a representative corpus of MCP servers pre-scored by the Agent Action ' +
      'Firewall Test, worst first (most ungated dangerous actions at the top). Use to show how a given server ' +
      'compares, or to find which popular servers let agents act without a receipt.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

function ok(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}
function fail(message) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

const server = new Server(
  { name: 'emilia-fire-drill', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  if (name === 'fire_drill_scan') {
    let input = args.target;
    if (input === undefined && typeof args.target_json === 'string') {
      try {
        input = JSON.parse(args.target_json);
      } catch {
        return fail('target_json must be valid JSON (an MCP manifest, OpenAPI spec, or { tools: [...] }).');
      }
    }
    if (input === undefined || input === null || typeof input !== 'object') {
      return fail('Provide `target` (a JSON object) or `target_json` (a JSON string) to scan.');
    }
    try {
      const report = scan(input);
      return ok({ fire_drill_version: FIRE_DRILL_VERSION, tagline: TAGLINE, report });
    } catch (e) {
      return fail(`Scan failed: ${e?.message || e}`);
    }
  }

  if (name === 'fire_drill_leaderboard') {
    const scanned = REPRESENTATIVE_CORPUS.map((c) => {
      const report = scan(c.manifest);
      return {
        name: c.name,
        slug: c.slug,
        repo: c.repo,
        score: report.score,
        eg1: report.eg1,
        dangerous: report.summary?.dangerous ?? 0,
        ungated: report.summary?.ungated ?? 0,
      };
    }).sort((a, b) => a.score - b.score);
    return ok({ fire_drill_version: FIRE_DRILL_VERSION, index: 'Agent Action Safety Index', servers: scanned });
  }

  return fail(`Unknown tool: ${name}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);
