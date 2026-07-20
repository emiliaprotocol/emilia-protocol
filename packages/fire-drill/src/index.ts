// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/fire-drill — the Agent Action Firewall Test.
 *
 * The vortex. People don't wake up wanting authorization receipts; they wake up
 * afraid of being the screenshot: "our agent deleted prod and nobody can prove
 * who approved it." This is the test they're scared to fail.
 *
 * Point it at an MCP manifest, an OpenAPI spec, or a tool list. It classifies
 * each operation into the high-risk families (money / data destruction /
 * production deploy / permission change / data export / regulated override) and
 * checks whether a dangerous one DECLARES a required receipt input. Output is a
 * static coverage score and a list of missing declarations. Static metadata
 * cannot prove runtime verification, trust anchoring, or consumption.
 *
 * This is a STATIC assessment from the manifest/spec — like SSL Labs or
 * `npm audit`. It reveals the gap; EG-1 conformance verifies the fix at runtime.
 * Zero dependencies so `npx` is instant.
 */

export const FIRE_DRILL_VERSION = 'EP-FIRE-DRILL-v2';
type Obj = Record<string, any>;
const MAX_OPERATIONS = 10_000;

// High-risk families, mirrored from the EMILIA Gate default action packs. Each
// matcher is a hardcoded literal (no dynamic RegExp) — a stem alternation plus a
// bounded, non-backtracking suffix group `(?:s|es|d|ed|ing|ment|ments|ion|ions|
// er|ers|al)?` at word boundaries. Text has separators normalized to spaces.
// Tolerant of plurals/verb forms ("permissions", "deleted", "payment") without
// over-matching ("payload" does not match "pay").
const FAMILIES = [
  {
    family: 'money_movement', label: 'Money movement', tier: 'class_a', adapter: 'stripe',
    name: /\b(?:pay|payout|payment|refund|transfer|wire|charge|disburse|invoice|withdraw|remit|payroll)(?:s|es|d|ed|ing|ment|ments|ion|ions|er|ers|al)?\b/i,
    why: 'Moves funds or releases value.',
  },
  {
    family: 'permission_change', label: 'Permission / admin change', tier: 'quorum', adapter: 'aws',
    name: /\b(?:permission|role|grant|revoke|iam|admin|privileg|polic|scope|rbac|collaborator)(?:s|es|d|ed|ing|ment|ments|ion|ions|er|ers|al)?\b/i,
    why: 'Changes who can act next.',
  },
  {
    family: 'production_deploy', label: 'Production deploy', tier: 'quorum', adapter: 'github',
    name: /\b(?:deploy|release|rollout|promote|provision|terraform|migrate|apply)(?:s|es|d|ed|ing|ment|ments|ion|ions|er|ers|al)?\b/i,
    why: 'Changes live production behavior or infrastructure.',
  },
  {
    family: 'data_export', label: 'Bulk data export', tier: 'class_a', adapter: 'supabase',
    name: /\b(?:export|dump|download|extract|backup|exfil)(?:s|es|d|ed|ing|ment|ments|ion|ions|er|ers|al)?\b/i,
    why: 'Moves sensitive data out of its system of record.',
  },
  {
    family: 'regulated_override', label: 'Regulated decision override', tier: 'quorum', adapter: null,
    name: /\b(?:override|adjudicat|reverse|approv)\w{0,8}\b.{0,24}\b(?:claim|benefit|credit|decision|case|loan|patient)/i,
    why: 'Changes a decision with legal, benefit, credit, clinical, or safety impact.',
  },
  {
    family: 'data_destruction', label: 'Data destruction', tier: 'class_a', adapter: 'supabase',
    name: /\b(?:delete|destroy|drop|truncate|purge|wipe|erase|remove|teardown)(?:s|es|d|ed|ing|ment|ments|ion|ions|er|ers|al)?\b/i,
    why: 'Destroys or hides system-of-record state.',
  },
];

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Classify one operation. Returns the strongest matching family (or {dangerous:false}).
 * @returns {{ dangerous: boolean, family?: string, label?: string, tier?: string, adapter?: string, why?: string }}
 */
export function classifyOperation({ name = '', description = '', method = '', path = '' }: Obj = {}): Obj {
  // Normalize separators to spaces: tool names like `release_payment` or
  // `delete-customer` must produce word boundaries, since \b treats `_` as a
  // word char (so \bpayment\b would NOT match `release_payment`).
  const text = `${name} ${description} ${path}`.replace(/[_/.-]+/g, ' ');
  const m = String(method || '').toUpperCase();
  // An HTTP DELETE is destructive regardless of naming.
  if (m === 'DELETE') {
    const fam = FAMILIES.find((f) => f.family === 'data_destruction');
    return { dangerous: true, ...famOut(fam) };
  }
  for (const f of FAMILIES) {
    if (f.name.test(text)) {
      // A read-only GET that merely mentions a word is not a mutation, EXCEPT
      // export/download which is dangerous even via GET.
      if (m === 'GET' && f.family !== 'data_export') continue;
      return { dangerous: true, ...famOut(f) };
    }
  }
  return { dangerous: false };
}
const famOut = (f: any): Obj => ({ family: f.family, label: f.label, tier: f.tier, adapter: f.adapter, why: f.why });

const RECEIPT_NAME = /^[a-z0-9_-]{0,32}(?:receipt|emilia|signoff)[a-z0-9_-]{0,32}$/i;

function schemaRequiresReceipt(schema: any): boolean {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return false;
  const properties = schema.properties;
  const required = Array.isArray(schema.required) ? new Set(schema.required) : new Set();
  return properties && typeof properties === 'object' && !Array.isArray(properties)
    && Object.keys(properties).some((name) => RECEIPT_NAME.test(name) && required.has(name));
}

/**
 * Detect a structural declaration that receipt evidence is required.
 * This does NOT detect or certify runtime enforcement.
 * @param {object} [op]
 * @param {any} [raw] the original MCP tool / OpenAPI operation object, shape unknown until narrowed below
 */
export function detectReceiptGate(op: Obj = {}, raw: any = null): boolean {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
  if (raw.x_emilia_receipt_required === true || raw.emilia_gate === true
      || raw['x-emilia']?.receipt_required === true) return true;
  if (schemaRequiresReceipt(raw.inputSchema) || schemaRequiresReceipt(raw.input_schema)) return true;
  if (Array.isArray(raw.parameters) && raw.parameters.some((parameter: any) => parameter?.required === true
      && typeof parameter.name === 'string' && RECEIPT_NAME.test(parameter.name))) return true;
  if (raw.requestBody?.required === true && raw.requestBody.content
      && typeof raw.requestBody.content === 'object') {
    return Object.values(raw.requestBody.content)
      .some((media: any) => schemaRequiresReceipt(media?.schema));
  }
  return false;
}

function operationFinding(op: Obj, raw: any): Obj {
  const cls = classifyOperation(op);
  const receiptDeclared = cls.dangerous ? detectReceiptGate(op, raw) : true;
  return {
    name: op.name,
    method: op.method || null,
    path: op.path || null,
    dangerous: cls.dangerous,
    family: cls.family || null,
    label: cls.label || null,
    tier: cls.tier || null,
    adapter: cls.adapter || null,
    why: cls.why || null,
    receipt_declared: receiptDeclared,
  };
}

// ── Input adapters ───────────────────────────────────────────────────────────

export function scanMcpManifest(manifest: Obj = {}): Obj {
  const tools = manifest.tools || manifest.capabilities?.tools || [];
  if (!Array.isArray(tools) || tools.length > MAX_OPERATIONS) {
    throw new Error(`fire-drill: MCP tools must be an array with at most ${MAX_OPERATIONS} entries`);
  }
  const ops = tools.map((t) => operationFinding(
    { name: t.name, description: t.description || '', method: '', path: '' }, t,
  ));
  return buildReport(ops, 'mcp');
}

export function scanOpenApi(spec: Obj = {}): Obj {
  const ops = [];
  const paths = spec.paths || {};
  if (!paths || typeof paths !== 'object' || Array.isArray(paths)) throw new Error('fire-drill: OpenAPI paths must be an object');
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods || {})) {
      if (!MUTATING_METHODS.has(method.toUpperCase()) && method.toUpperCase() !== 'GET') continue;
      if (!op || typeof op !== 'object' || Array.isArray(op)) continue;
      if (ops.length >= MAX_OPERATIONS) throw new Error(`fire-drill: OpenAPI operation limit exceeds ${MAX_OPERATIONS}`);
      const finding = operationFinding({
        name: op.operationId || `${method.toUpperCase()} ${path}`,
        description: op.summary || op.description || '',
        method, path,
      }, op);
      ops.push(finding);
    }
  }
  return buildReport(ops, 'openapi');
}

export function scanToolList(list: Obj[] = []): Obj {
  if (!Array.isArray(list) || list.length > MAX_OPERATIONS) {
    throw new Error(`fire-drill: tool list must contain at most ${MAX_OPERATIONS} entries`);
  }
  return buildReport(list.map((t) => operationFinding({ name: t.name, description: t.description || '' }, t)), 'tools');
}

/** Auto-detect the input shape and scan. */
export function scan(input: Obj): Obj {
  if (Array.isArray(input)) return scanToolList(input);
  if (input && (input.openapi || input.swagger || input.paths)) return scanOpenApi(input);
  if (input && (input.tools || input.capabilities?.tools)) return scanMcpManifest(input);
  throw new Error('fire-drill: unrecognized input. Expected an MCP manifest ({tools}), an OpenAPI spec ({paths}), or a tool array.');
}

// ── Report ───────────────────────────────────────────────────────────────────

export function buildReport(operations: Obj[], targetType = 'unknown'): Obj {
  const dangerous = operations.filter((o) => o.dangerous);
  const missing = dangerous.filter((o) => !o.receipt_declared);
  const score = dangerous.length === 0 ? 100 : Math.round(((dangerous.length - missing.length) / dangerous.length) * 100);
  const findings = missing.map((o) => ({
    severity: o.tier === 'quorum' ? 'critical' : 'high',
    operation: o.name,
    family: o.family,
    message: `MISSING DECLARATION: \`${o.name}\` does not declare a required receipt input (${o.label}).`,
    fix: o.adapter
      ? `Add EMILIA Gate — @emilia-protocol/gate/adapters/${o.adapter} (or gateMcpTool) requiring a ${o.tier} receipt.`
      : `Add EMILIA Gate — require a ${o.tier} receipt for this action.`,
    earn: 'eligible for a separate runtime EG-1 test',
  }));
  return {
    '@version': FIRE_DRILL_VERSION,
    target_type: targetType,
    score,
    eg1: 'not_assessed',
    static_result: missing.length === 0 ? 'complete' : 'incomplete',
    summary: {
      operations: operations.length,
      dangerous: dangerous.length,
      declared: dangerous.length - missing.length,
      missing_declaration: missing.length,
    },
    findings,
    operations,
    note: 'Static declaration assessment only. It does not verify runtime receipt validation, trust anchors, exact-action binding, or one-time consumption. Run EG-1 conformance separately.',
  };
}

export const TAGLINE = 'Static declarations locate review targets; only runtime conformance can establish enforcement.';

// ── Shareable badge ──────────────────────────────────────────────────────────

/** Approximate pixel width of a label segment (flat-badge sizing, no font metrics). */
function segWidth(text: string): number {
  return Math.max(40, Math.round(String(text).length * 6.6) + 20);
}

/**
 * A shields-style badge for static declaration coverage. It is deliberately
 * never green and never says EG-1 Enforced; this scanner cannot prove runtime.
 * @param {object} o
 * @param {number} [o.score] 0..100
 * @param {string} [o.label='receipt declarations']
 */
export function badgeSvg({ score, label = 'receipt declarations' }: Obj = {}): string {
  const normalizedScore = typeof score === 'number' && Number.isFinite(score)
    ? Math.max(0, Math.min(100, Math.round(score))) : null;
  const message = normalizedScore === null ? 'static only' : `static ${normalizedScore}/100`;
  const color = normalizedScore !== null && normalizedScore < 50 ? '#DC2626' : '#D97706';
  label = String(label).slice(0, 80);
  const lw = segWidth(label);
  const mw = segWidth(message);
  const w = lw + mw;
  // Escape ALL XML-significant chars — including quotes — because `label`/`message`
  // are interpolated into a double-quoted SVG attribute (aria-label). Missing the
  // quote escape allowed attribute breakout / event-handler injection when the SVG
  // is served as image/svg+xml from a public route.
  const esc = (s: any): string => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(message)}">`
    + `<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`
    + `<rect rx="3" width="${w}" height="20" fill="#555"/>`
    + `<rect rx="3" x="${lw}" width="${mw}" height="20" fill="${color}"/>`
    + `<rect rx="3" width="${w}" height="20" fill="url(#s)"/>`
    + `<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">`
    + `<text x="${lw / 2}" y="14">${esc(label)}</text>`
    + `<text x="${lw + mw / 2}" y="14">${esc(message)}</text>`
    + `</g></svg>`;
}

// ── Corpus aggregation (the Report) ──────────────────────────────────────────

/**
 * Aggregate static declaration reports. The caller owns corpus selection and
 * this output makes no claim about runtime enforcement.
 * @param {object[]} reports  buildReport() results
 */
export function aggregate(reports: Obj[] = []): Obj {
  const servers = reports.length;
  let dangerous = 0;
  let missing = 0;
  let withMissing = 0;
  let scoreSum = 0;
  const byFamily: Obj = {};
  for (const r of reports) {
    dangerous += r.summary.dangerous;
    missing += r.summary.missing_declaration;
    if (r.summary.missing_declaration > 0) withMissing += 1;
    scoreSum += r.score;
    for (const f of (r.findings || [])) byFamily[f.family] = (byFamily[f.family] || 0) + 1;
  }
  return {
    '@version': FIRE_DRILL_VERSION,
    servers,
    servers_missing_declaration: withMissing,
    pct_servers_missing_declaration: servers ? Math.round((withMissing / servers) * 100) : 0,
    dangerous_operations: dangerous,
    missing_declarations: missing,
    mean_score: servers ? Math.round(scoreSum / servers) : 100,
    by_family: byFamily,
  };
}

// ── Generate-PR ──────────────────────────────────────────────────────────────

/**
 * Turn a report into a ready-to-open pull request (title + Markdown body) that
 * tells a maintainer which dangerous tools lack a required evidence declaration.
 * @param {object} report  a buildReport() result
 * @param {object} [o]
 * @param {string} [o.project] project/repo name for the title
 */
export function generatePullRequest(report: Obj, { project }: Obj = {}): Obj {
  const name = project ? ` for ${project}` : '';
  const failing = report.findings || [];
  const title = failing.length
    ? `Declare required receipt evidence for ${failing.length} high-risk action${failing.length > 1 ? 's' : ''}${name}`
    : `Review runtime receipt enforcement${name}`;
  const lines = [];
  lines.push(`## Static receipt declaration coverage: ${report.score}/100`, '');
  if (!failing.length) {
    lines.push('Every detected dangerous action declares a required receipt input. **Runtime enforcement is not assessed by this scan.**', '');
  } else {
    lines.push('These tool calls can mutate money, data, permissions, or production but do not declare required receipt evidence:', '');
    for (const f of failing) lines.push(`- \`${f.operation}\` — ${f.family} — ${f.fix}`);
    lines.push('', '### Fix', '', '```js', `import { createGate } from '@emilia-protocol/gate';`, `import { gateMcpTool } from '@emilia-protocol/gate/mcp';`, '', `const gate = createGate({ manifest, trustedKeys: [process.env.EMILIA_ISSUER] });`);
    for (const f of failing) lines.push(`server.tool('${f.operation}', gateMcpTool(gate, { tool: '${f.operation}' }, handler));`);
    lines.push('```', '', `Then rerun \`npx @emilia-protocol/fire-drill <manifest>\` and separately execute the EG-1 runtime conformance suite.`);
  }
  lines.push('', '---', `_Generated by [@emilia-protocol/fire-drill](https://www.npmjs.com/package/@emilia-protocol/fire-drill) — the Agent Action Firewall Test._`);
  return { title, body: lines.join('\n') };
}

export default {
  FIRE_DRILL_VERSION, TAGLINE,
  classifyOperation, detectReceiptGate, buildReport,
  scan, scanMcpManifest, scanOpenApi, scanToolList,
  badgeSvg, generatePullRequest, aggregate,
};
