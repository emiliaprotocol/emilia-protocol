// SPDX-License-Identifier: Apache-2.0
// Browser-only declaration inspection. The shared scanner owns all risk rules.
import { scanActions, type ActionInput, type Classification } from '../../packages/scan/src/index';
import scannerPackage from '../../packages/scan/package.json';

export const AGENT_SCAN_VERSION = 'emilia-declared-action-scan/v1';
export const AGENT_SCAN_LIMITS = Object.freeze({ bytes: 1_048_576, actions: 500, depth: 32, nodes: 20_000 });
export type AgentScanFormat = 'mcp_tools_list' | 'actions' | 'openapi';

const RESERVED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const BIDI = /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/u;
const HTTP_METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);
const ADVISORY_HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'] as const;
const BLIND_SPOTS = [
  'This report reads names, descriptions, advisory annotations and declared HTTP operations. It does not run an agent or inspect its implementation.',
  'Undeclared tools, dynamic capabilities, prompts, credentials, runtime configuration and actual provider effects are unknown.',
  'A read-like name or readOnlyHint is not proof that an action only reads data. Misleading or incomplete declarations can hide consequential behavior.',
  'Schema validity, identity, ownership, authorization, complete mediation, security and work quality are not verified. This is not certification or a safety assessment.',
  'References are not resolved and URLs are not fetched. Input parameters and response schemas are not analyzed for risk.',
];

export class AgentScanInputError extends Error {
  constructor(message: string) { super(message); this.name = 'AgentScanInputError'; }
}

function fail(message: string): never { throw new AgentScanInputError(message); }
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Validate before materializing deep structures; reject duplicate keys instead of silently taking the last value. */
function boundedJson(text: string): unknown {
  let cursor = 0;
  let nodes = 0;
  const whitespace = () => { while (/[\x20\t\r\n]/u.test(text[cursor] ?? '') && cursor < text.length) cursor++; };
  const invalid = () => fail('Invalid JSON. Use a JSON export, not YAML, JavaScript or a web address.');
  const string = (): string => {
    const start = cursor++;
    while (cursor < text.length) {
      const char = text[cursor++];
      if (char === '\\') { cursor++; continue; }
      if (char === '"') {
        let decoded: string;
        try { decoded = JSON.parse(text.slice(start, cursor)); } catch { return invalid(); }
        if (BIDI.test(decoded)) fail('Remove bidirectional control characters from the JSON before scanning.');
        for (let index = 0; index < decoded.length; index++) {
          const code = decoded.charCodeAt(index);
          if (code >= 0xd800 && code <= 0xdbff) {
            const next = decoded.charCodeAt(++index);
            if (!(next >= 0xdc00 && next <= 0xdfff)) fail('The JSON contains an unpaired Unicode surrogate.');
          } else if (code >= 0xdc00 && code <= 0xdfff) fail('The JSON contains an unpaired Unicode surrogate.');
        }
        return decoded;
      }
    }
    return invalid();
  };
  const value = (depth: number): unknown => {
    if (depth > AGENT_SCAN_LIMITS.depth) fail(`JSON is too deeply nested. The limit is ${AGENT_SCAN_LIMITS.depth} levels.`);
    if (++nodes > AGENT_SCAN_LIMITS.nodes) fail(`JSON has too many values. The limit is ${AGENT_SCAN_LIMITS.nodes.toLocaleString('en-US')}.`);
    whitespace();
    if (text[cursor] === '"') return string();
    if (text[cursor] === '{') {
      cursor++;
      const output: Record<string, unknown> = Object.create(null);
      const keys = new Set<string>();
      whitespace();
      if (text[cursor] === '}') { cursor++; return output; }
      while (cursor < text.length) {
        if (text[cursor] !== '"') return invalid();
        const key = string();
        if (RESERVED_KEYS.has(key)) fail('JSON contains a reserved object key. Remove __proto__, prototype and constructor keys.');
        if (keys.has(key)) fail('JSON contains a duplicate object key. Each key must appear only once.');
        keys.add(key);
        whitespace();
        if (text[cursor++] !== ':') return invalid();
        output[key] = value(depth + 1);
        whitespace();
        if (text[cursor] === '}') { cursor++; return output; }
        if (text[cursor++] !== ',') return invalid();
        whitespace();
      }
      return invalid();
    }
    if (text[cursor] === '[') {
      cursor++;
      const output: unknown[] = [];
      whitespace();
      if (text[cursor] === ']') { cursor++; return output; }
      while (cursor < text.length) {
        output.push(value(depth + 1));
        whitespace();
        if (text[cursor] === ']') { cursor++; return output; }
        if (text[cursor++] !== ',') return invalid();
      }
      return invalid();
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(text.slice(cursor));
    if (!token) return invalid();
    cursor += token[0].length;
    const parsed: unknown = JSON.parse(token[0]);
    if (typeof parsed === 'number' && !Number.isFinite(parsed)) fail('JSON numbers must be finite.');
    return parsed;
  };
  const output = value(0);
  whitespace();
  if (cursor !== text.length) invalid();
  return output;
}

function actionList(values: unknown[]): ActionInput[] {
  if (values.length > AGENT_SCAN_LIMITS.actions) fail(`Use at most ${AGENT_SCAN_LIMITS.actions} declared actions per scan.`);
  return values.map((value, index) => {
    const action = typeof value === 'string' ? { name: value } : value;
    if (!record(action) || typeof action.name !== 'string') fail(`Action ${index + 1} needs a string name.`);
    if (action.description !== undefined && typeof action.description !== 'string') fail(`Action ${index + 1} has a non-text description.`);
    if (action.annotations !== undefined && !record(action.annotations)) fail(`Action ${index + 1} annotations must be a JSON object.`);
    const annotations = action.annotations as Record<string, unknown> | undefined;
    for (const hint of ADVISORY_HINTS) {
      if (annotations?.[hint] !== undefined && typeof annotations[hint] !== 'boolean') fail(`Action ${index + 1} has a non-boolean ${hint}.`);
    }
    if (action.http_method !== undefined && (typeof action.http_method !== 'string' || !HTTP_METHODS.has(action.http_method.toLowerCase()))) fail(`Action ${index + 1} has an unsupported HTTP method.`);
    if (action.route_path !== undefined && (typeof action.route_path !== 'string' || !action.route_path.startsWith('/') || action.route_path.length > 2048 || /[\u0000-\u001f\u007f-\u009f]/u.test(action.route_path))) fail(`Action ${index + 1} needs a bounded route path beginning with /.`);
    // Export the declared action and standard advisory hints, never opaque
    // annotation extensions that might hide credentials or private metadata.
    return {
      name: action.name,
      ...(action.description !== undefined ? { description: action.description as string } : {}),
      ...(annotations ? { annotations: Object.fromEntries(ADVISORY_HINTS.filter(hint => annotations[hint] !== undefined).map(hint => [hint, annotations[hint]])) } : {}),
      ...(action.http_method !== undefined ? { http_method: (action.http_method as string).toUpperCase() } : {}),
      ...(action.route_path !== undefined ? { route_path: action.route_path as string } : {}),
    };
  });
}

export function parseAgentScanInput(text: string): { format: AgentScanFormat; actions: ActionInput[]; bytes: number; blindSpots: string[] } {
  if (typeof text !== 'string' || !text.trim()) fail('Paste JSON or choose a JSON file to begin.');
  if (text.length > AGENT_SCAN_LIMITS.bytes) fail('The input is too large. Use a JSON file no larger than 1 MiB.');
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes > AGENT_SCAN_LIMITS.bytes) fail('The input is too large. Use a JSON file no larger than 1 MiB.');
  const input = boundedJson(text);
  const blindSpots = [...BLIND_SPOTS];
  if (Array.isArray(input)) return { format: 'actions', actions: actionList(input), bytes, blindSpots };
  if (!record(input)) fail('Unsupported JSON. Use an actions array, MCP tools/list response or OpenAPI JSON document.');

  const hasMcp = Object.hasOwn(input, 'tools') || (record(input.result) && Object.hasOwn(input.result, 'tools'));
  const formats = [hasMcp, Object.hasOwn(input, 'actions'), Object.hasOwn(input, 'openapi') || Object.hasOwn(input, 'swagger')].filter(Boolean).length;
  if (formats > 1) fail('The input mixes declaration formats. Scan one actions list, MCP response or OpenAPI document at a time.');
  if (hasMcp) {
    if (Object.hasOwn(input, 'tools') && record(input.result) && Object.hasOwn(input.result, 'tools')) fail('The input contains two MCP tool lists. Keep only one.');
    if (Object.hasOwn(input, 'error')) fail('This is an MCP error response, not a tool declaration.');
    const envelope = Object.hasOwn(input, 'tools') ? input : input.result as Record<string, unknown>;
    if (!Array.isArray(envelope.tools)) fail('MCP tools must be an array.');
    if (envelope.nextCursor !== undefined) blindSpots.push('This MCP response declares a nextCursor. Later pages are not included and were not fetched.');
    blindSpots.push('MCP annotations are advisory declarations. A tool description can be inaccurate or omit side effects.');
    return { format: 'mcp_tools_list', actions: actionList(envelope.tools), bytes, blindSpots };
  }
  if (Object.hasOwn(input, 'actions')) {
    if (!Array.isArray(input.actions)) fail('The actions field must be an array.');
    return { format: 'actions', actions: actionList(input.actions), bytes, blindSpots };
  }
  if (Object.hasOwn(input, 'openapi') || Object.hasOwn(input, 'swagger')) {
    if (!(typeof input.openapi === 'string' && /^3\.\d+\.\d+(?:[-+].*)?$/u.test(input.openapi)) && input.swagger !== '2.0') fail('Use an OpenAPI 3.x or Swagger 2.0 JSON document.');
    if (!record(input.paths)) fail('The OpenAPI document needs a paths object.');
    const actions: ActionInput[] = [];
    let skippedReferences = 0;
    for (const [path, item] of Object.entries(input.paths)) {
      if (!path.startsWith('/')) { if (path.startsWith('x-')) continue; fail('Each OpenAPI path must begin with /.'); }
      if (!record(item)) fail('Each OpenAPI path item must be an object.');
      if (Object.hasOwn(item, '$ref')) skippedReferences++;
      for (const [method, operation] of Object.entries(item)) {
        if (!HTTP_METHODS.has(method)) continue;
        if (!record(operation)) fail('Each OpenAPI operation must be an object.');
        if (Object.hasOwn(operation, '$ref')) { skippedReferences++; continue; }
        for (const field of ['operationId', 'summary', 'description']) {
          if (operation[field] !== undefined && typeof operation[field] !== 'string') fail(`OpenAPI ${field} must be text.`);
        }
        if (actions.length >= AGENT_SCAN_LIMITS.actions) fail(`Use at most ${AGENT_SCAN_LIMITS.actions} declared actions per scan.`);
        actions.push({
          name: (operation.operationId as string | undefined) ?? `${method.toUpperCase()} ${path}`,
          description: [operation.summary, operation.description].filter(value => typeof value === 'string').join('\n'),
          http_method: method.toUpperCase(), route_path: path,
        });
      }
    }
    blindSpots.push('Only operations declared under paths are inspected. Callbacks, webhooks, external references and runtime routes are not covered. HTTP methods are declarations, not proof of behavior.');
    if (skippedReferences) blindSpots.push(`${skippedReferences} referenced path items or operations were not resolved. Their capabilities remain unknown.`);
    return { format: 'openapi', actions, bytes, blindSpots };
  }
  return fail('Unsupported JSON. Use an actions array, MCP tools/list response or OpenAPI JSON document. No repository or URL scan was performed.');
}

export function classificationLabel(classification: Classification): string {
  if (classification.decision === 'gate') return 'Potential consequential action';
  if (classification.decision === 'pass_through') return 'Read-like declaration · not verified';
  return 'Unknown behavior · review needed';
}

export function scanAgentDeclarations(text: string) {
  const parsed = parseAgentScanInput(text);
  const scan = scanActions(parsed.actions, {
    source: parsed.format === 'openapi' ? 'openapi' : parsed.format === 'mcp_tools_list' ? 'mcp' : 'list',
    blindSpots: parsed.blindSpots,
  });
  return {
    version: AGENT_SCAN_VERSION,
    classifier: { package: scannerPackage.name, version: scannerPackage.version, analysis: 'BUNDLED_DECLARATION_RULES' as const },
    source: { format: parsed.format, provenance: 'USER_SUPPLIED_DECLARATION' as const, input_bytes: parsed.bytes },
    scope: {
      analysis: 'DECLARED_ACTIONS_ONLY' as const,
      actual_behavior: 'UNKNOWN' as const,
      enforcement: 'UNKNOWN' as const,
      safety: 'NOT_ASSESSED' as const,
      certification: 'NONE' as const,
      publication_authorized: false as const,
    },
    summary: {
      declared_actions: scan.counts.total,
      potential_consequential: scan.counts.gate,
      needs_review: scan.counts.review_fail_closed + scan.counts.review,
      read_like_unverified: scan.counts.pass_through,
    },
    results: scan.results,
    blind_spots: parsed.actions.length ? parsed.blindSpots : [...parsed.blindSpots, 'No inline actions were found. This does not establish that the agent has no capabilities.'],
  };
}

export async function createAgentScanReport(text: string) {
  const report = scanAgentDeclarations(text);
  if (!globalThis.crypto?.subtle) fail('This browser cannot create a SHA-256 report. Open this page over HTTPS in a current browser.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  const input_sha256 = `sha256:${Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')}`;
  return { ...report, source: { ...report.source, input_sha256, digest_scope: 'EXACT_INPUT_UTF8_BYTES' as const } };
}

export type AgentScanReport = Awaited<ReturnType<typeof createAgentScanReport>>;

export const SYNTHETIC_AGENT_SCAN_SAMPLE = JSON.stringify({
  tools: [
    { name: 'list_invoices', description: 'Return existing invoice records.', annotations: { readOnlyHint: true } },
    { name: 'refund_payment', description: 'Issue a refund to a customer.', annotations: { readOnlyHint: true } },
    { name: 'process_account', description: 'Handle the next account request.' },
  ],
}, null, 2);
