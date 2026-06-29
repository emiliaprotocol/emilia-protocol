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
 * checks whether a dangerous one can execute WITHOUT an accountable human
 * receipt. Output: an Agent Action Firewall score, the failing operations, the
 * fix (EMILIA Gate), and EG-1 pass/fail.
 *
 * This is a STATIC assessment from the manifest/spec — like SSL Labs or
 * `npm audit`. It reveals the gap; EG-1 conformance verifies the fix at runtime.
 * Zero dependencies so `npx` is instant.
 */

export const FIRE_DRILL_VERSION = 'EP-FIRE-DRILL-v1';

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

/** Classify one operation. Returns the strongest matching family (or {dangerous:false}). */
export function classifyOperation({ name = '', description = '', method = '', path = '' } = {}) {
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
const famOut = (f) => ({ family: f.family, label: f.label, tier: f.tier, adapter: f.adapter, why: f.why });

/** Does this operation require a receipt (any receipt-shaped parameter / marker)? */
export function detectReceiptGate(op = {}, raw = null) {
  const blob = JSON.stringify(raw ?? op ?? {});
  // A JSON KEY shaped like a receipt (MCP inputSchema property, request-body field).
  if (/"[a-z0-9_-]{0,20}(?:receipt|emilia|signoff)[a-z0-9_-]{0,20}"\s*:/i.test(blob)) return true;
  // A parameter/header whose NAME value is receipt-shaped (OpenAPI parameters).
  if (/"name"\s*:\s*"[a-z0-9_\- ]{0,20}(?:receipt|emilia)[a-z0-9_\- ]{0,20}"/i.test(blob)) return true;
  // An explicit marker some manifests set.
  if (raw && (raw['x-emilia'] || raw.emilia_gate === true || raw.x_emilia_receipt_required === true)) return true;
  return false;
}

function operationFinding(op, raw) {
  const cls = classifyOperation(op);
  const gated = cls.dangerous ? detectReceiptGate(op, raw) : true;
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
    gated,
  };
}

// ── Input adapters ───────────────────────────────────────────────────────────

export function scanMcpManifest(manifest = {}) {
  const tools = manifest.tools || manifest.capabilities?.tools || [];
  const ops = tools.map((t) => operationFinding(
    { name: t.name, description: t.description || '', method: '', path: '' }, t,
  ));
  return buildReport(ops, 'mcp');
}

export function scanOpenApi(spec = {}) {
  const ops = [];
  const paths = spec.paths || {};
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods || {})) {
      if (!MUTATING_METHODS.has(method.toUpperCase()) && method.toUpperCase() !== 'GET') continue;
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

export function scanToolList(list = []) {
  return buildReport(list.map((t) => operationFinding({ name: t.name, description: t.description || '' }, t)), 'tools');
}

/** Auto-detect the input shape and scan. */
export function scan(input) {
  if (Array.isArray(input)) return scanToolList(input);
  if (input && (input.openapi || input.swagger || input.paths)) return scanOpenApi(input);
  if (input && (input.tools || input.capabilities?.tools)) return scanMcpManifest(input);
  throw new Error('fire-drill: unrecognized input. Expected an MCP manifest ({tools}), an OpenAPI spec ({paths}), or a tool array.');
}

// ── Report ───────────────────────────────────────────────────────────────────

export function buildReport(operations, targetType = 'unknown') {
  const dangerous = operations.filter((o) => o.dangerous);
  const ungated = dangerous.filter((o) => !o.gated);
  const score = dangerous.length === 0 ? 100 : Math.round(((dangerous.length - ungated.length) / dangerous.length) * 100);
  const findings = ungated.map((o) => ({
    severity: o.tier === 'quorum' ? 'critical' : 'high',
    operation: o.name,
    family: o.family,
    message: `FAIL: \`${o.name}\` can execute without an accountable human receipt (${o.label}).`,
    fix: o.adapter
      ? `Add EMILIA Gate — @emilia-protocol/gate/adapters/${o.adapter} (or gateMcpTool) requiring a ${o.tier} receipt.`
      : `Add EMILIA Gate — require a ${o.tier} receipt for this action.`,
    earn: 'EG-1 Enforced',
  }));
  return {
    '@version': FIRE_DRILL_VERSION,
    target_type: targetType,
    score,
    eg1: ungated.length === 0 ? 'pass' : 'fail',
    summary: {
      operations: operations.length,
      dangerous: dangerous.length,
      gated: dangerous.length - ungated.length,
      ungated: ungated.length,
    },
    findings,
    operations,
    note: 'Static assessment from the manifest/spec. Verify the fix at runtime with EG-1 conformance (@emilia-protocol/gate).',
  };
}

export const TAGLINE = 'If your agent can take an irreversible action without a receipt, you do not have control. You have hope.';

export default {
  FIRE_DRILL_VERSION, TAGLINE,
  classifyOperation, detectReceiptGate, buildReport,
  scan, scanMcpManifest, scanOpenApi, scanToolList,
};
