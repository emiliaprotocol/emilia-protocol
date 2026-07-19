#!/usr/bin/env node

/**
 * @emilia-protocol/fire-drill-mcp
 * @license Apache-2.0
 *
 * The static receipt-declaration scanner, exposed over MCP.
 *
 * A directory of MCP servers, plus one server whose job is to audit the others:
 * given any MCP manifest, OpenAPI spec, or tool list, it reports which detected
 * dangerous actions omit a required receipt declaration. Runtime is unassessed.
 *
 * Pure wrapper — all scoring logic lives in @emilia-protocol/fire-drill (zero-dep,
 * the same source of truth as `npx @emilia-protocol/fire-drill` and the web /fire-drill).
 *
 * Tools:
 *   fire_drill_scan        — score a target (manifest / OpenAPI / tool list)
 *   fire_drill_leaderboard — static declaration corpus (missing first)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

let scan;
let FIRE_DRILL_VERSION;
let TAGLINE;
let REPRESENTATIVE_CORPUS;
try {
  ({ scan, FIRE_DRILL_VERSION, TAGLINE } = await import('@emilia-protocol/fire-drill'));
  ({ REPRESENTATIVE_CORPUS } = await import('@emilia-protocol/fire-drill/corpus.js'));
} catch {
  ({ scan, FIRE_DRILL_VERSION, TAGLINE } = await import('../fire-drill/index.js'));
  ({ REPRESENTATIVE_CORPUS } = await import('../fire-drill/corpus.js'));
}

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../verify/strict-json.js')); }

const MAX_INPUT_BYTES = 8 * 1024 * 1024;

export const TOOLS = [
  {
    name: 'fire_drill_scan',
    description:
      'Scan an MCP manifest, OpenAPI spec, or tool list for detected high-risk operations that omit a ' +
      'required receipt declaration. Returns static declaration coverage; it never certifies runtime ' +
      'verification, consumption, human presence, or EG-1 enforcement.',
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
      'A representative static declaration corpus, sorted by missing required receipt declarations. ' +
      'It is not a vulnerability ranking and does not assess deployed enforcement.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
];

function ok(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}
function fail(message) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

export async function handleToolRequest(request) {
  const { name, arguments: args = {} } = request.params;

  if (name === 'fire_drill_scan') {
    if (!args || typeof args !== 'object' || Array.isArray(args)) return fail('Tool arguments must be an object.');
    if (args.target !== undefined && args.target_json !== undefined) {
      return fail('Provide exactly one of `target` or `target_json`, not both.');
    }
    let input = args.target;
    if (input === undefined && typeof args.target_json === 'string') {
      try {
        if (Buffer.byteLength(args.target_json, 'utf8') > MAX_INPUT_BYTES) throw new Error('input too large');
        const gate = strictJsonGate(args.target_json);
        if (!gate.ok) throw new Error(gate.reason);
        input = JSON.parse(args.target_json);
      } catch (error) {
        return fail(`target_json refused: ${error.message}`);
      }
    }
    if (input === undefined || input === null || typeof input !== 'object') {
      return fail('Provide `target` (a JSON object/array) or `target_json` to scan.');
    }
    try {
      const encoded = JSON.stringify(input);
      if (Buffer.byteLength(encoded, 'utf8') > MAX_INPUT_BYTES) throw new Error('target exceeds input limit');
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
        static_result: report.static_result,
        dangerous: report.summary?.dangerous ?? 0,
        missing_declaration: report.summary?.missing_declaration ?? 0,
      };
    }).sort((a, b) => a.score - b.score);
    return ok({
      fire_drill_version: FIRE_DRILL_VERSION,
      index: 'Static Receipt Declaration Index',
      runtime_enforcement_assessed: false,
      servers: scanned,
    });
  }

  return fail(`Unknown tool: ${name}`);
}

export function createServer() {
  const server = new Server(
    { name: 'emilia-fire-drill', version: '0.2.0' },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, handleToolRequest);
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const transport = new StdioServerTransport();
  await createServer().connect(transport);
}
