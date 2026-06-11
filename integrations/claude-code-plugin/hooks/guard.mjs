#!/usr/bin/env node
/**
 * EMILIA Guard — Claude Code PreToolUse hook.
 *
 * Catches irreversible / high-risk tool calls BEFORE they execute and requires
 * a named human's approval. Two modes, both FAIL-CLOSED:
 *
 *   • Local mode (no account): a high-risk call returns `ask`, forcing a human
 *     permission prompt. Zero config, works offline. A free safety net.
 *   • EMILIA mode (EP_API_KEY + EP_ORG_ID set): the call is minted against
 *     EMILIA's formally-verified policy engine; if policy requires signoff, a
 *     named human approves on their own device (Face ID / passkey) and the
 *     action proceeds only with an offline-verifiable Trust Receipt.
 *
 * Fail-closed invariant: on ANY error, timeout, or ambiguity the decision is
 * `ask` or `deny` — NEVER `allow`. A trust gate that fails open is not a gate.
 *
 * Reads a PreToolUse event on stdin; writes a permissionDecision on stdout.
 * https://code.claude.com/docs/en/hooks
 */

import process from 'node:process';

const BASE_URL  = process.env.EP_BASE_URL || 'https://www.emiliaprotocol.ai';
const API_KEY   = process.env.EP_API_KEY || '';
const ORG_ID    = process.env.EP_ORG_ID || '';
const TIMEOUT_S = Math.min(Number(process.env.EP_SIGNOFF_TIMEOUT_S) || 280, 590);
const POLL_MS   = 3000;

// ── decision emitters ───────────────────────────────────────────────────────
function emit(decision, reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision, // 'allow' | 'deny' | 'ask'
      permissionDecisionReason: reason,
    },
  }));
  process.exit(0);
}
const passThrough = () => process.exit(0); // emit nothing → normal permission flow
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── HTTP (no deps; Node 18+ global fetch) ────────────────────────────────────
async function ep(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.title || `HTTP ${res.status}`);
  return data;
}

// ── read the hook event ──────────────────────────────────────────────────────
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
let evt;
try { evt = JSON.parse(raw || '{}'); } catch { passThrough(); }
const tool = evt.tool_name || '';
const ti = evt.tool_input || {};

// ── risk classifier (conservative; extend via EP_GUARD_PATTERNS, one regex/line)
const DESTRUCTIVE_SHELL = [
  /\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r/i, /\bgit\s+push\s+(-f\b|--force\b)/i,
  /\bgit\s+reset\s+--hard/i, /\b(drop|truncate)\s+(table|database)\b/i, /\bdelete\s+from\b/i,
  /\bdd\s+if=/i, /\bmkfs\b/i, /\b(shutdown|reboot|halt)\b/i, /:\s*\(\s*\)\s*\{/,
  /\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh/i, /\bwget\b[^|]*\|\s*(ba)?sh/i,
  /\bchmod\s+-R\s+777/i, /\bnpm\s+publish\b/i, /\bterraform\s+(apply|destroy)/i,
  /\bkubectl\s+delete/i, /\baws\s+\S+\s+(delete|terminate|rm)\b/i, /\bsudo\b/i,
  /\b(cat|base64|curl)\b[^\n]*\.env\b/i,
];
const SENSITIVE_PATH = /(^|\/)(\.env|id_rsa|.*\.pem|credentials|secrets?)|\.aws\/|\.ssh\/|\/etc\/|\.github\/workflows\//i;
const RISKY_MCP_VERB = /(pay|transfer|wire|withdraw|payout|charge|refund|send|email|message|post|publish|deploy|delete|terminate|disable|revoke|grant|trade|order|invoice|provision)/i;
// EP_GUARD_PATTERNS lets an operator add their own high-risk triggers, one per
// line — matched as plain case-insensitive substrings (not regex), so there is
// no ReDoS surface and operators don't need to know regex. e.g. "wire",
// "production", a vendor name, an internal hostname.
const customTerms = (process.env.EP_GUARD_PATTERNS || '')
  .split('\n').map((t) => t.trim().toLowerCase()).filter(Boolean)
  .slice(0, 50);
const hasCustom = (s) => { const h = String(s).toLowerCase(); return customTerms.some((t) => h.includes(t)); };

function classify() {
  const flags = [];
  if (tool === 'Bash') {
    const cmd = ti.command || '';
    if (DESTRUCTIVE_SHELL.some((re) => re.test(cmd))) flags.push('destructive_shell');
    if (hasCustom(cmd)) flags.push('custom_pattern');
  } else if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') {
    if (SENSITIVE_PATH.test(ti.file_path || '')) flags.push('sensitive_path');
    if (hasCustom(ti.file_path || '')) flags.push('custom_pattern');
  } else if (tool.startsWith('mcp__')) {
    if (RISKY_MCP_VERB.test(tool)) flags.push('external_or_money_action');
    if (hasCustom(`${tool} ${JSON.stringify(ti)}`)) flags.push('custom_pattern');
  }
  return [...new Set(flags)];
}

const flags = classify();
if (flags.length === 0) passThrough(); // not high-risk → zero overhead, normal flow

const label = tool === 'Bash' ? `\`${(ti.command || '').slice(0, 120)}\``
  : tool.startsWith('mcp__') ? tool
    : `${tool} ${ti.file_path || ''}`.trim();
const moneyOnly = flags.every((f) => f === 'external_or_money_action');

// ── local mode: no account → force a human prompt (fail-closed) ──────────────
if (!API_KEY || !ORG_ID) {
  emit('ask', `EMILIA — high-risk action (${flags.join(', ')}): ${label}. `
    + `Confirm a human intends this. Connect EMILIA (EP_API_KEY + EP_ORG_ID) for `
    + `device signoff + an offline-verifiable receipt.`);
}

// ── EMILIA mode: mint → require device signoff → receipt ─────────────────────
// Only money/external MCP actions go to the policy engine — its action_type
// vocabulary is financial. Purely local risk (shell, secret files) stays a
// local human prompt rather than polluting the financial audit trail.
if (!flags.includes('external_or_money_action')) {
  emit('ask', `EMILIA — locally high-risk (${flags.join(', ')}): ${label}. Confirm a human intends this.`);
}
function mapActionType() {
  const t = tool.toLowerCase();
  if (/bank|account|payee/.test(t)) return 'vendor_bank_account_change';
  return 'ai_agent_payment_action';
}
function parseAmount() {
  for (const v of [ti.amount, ti.value, ti.total]) {
    const n = Number(v);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return undefined;
}

try {
  const mint = await ep('/api/v1/trust-receipts', {
    method: 'POST',
    body: {
      organization_id: ORG_ID,
      action_type: mapActionType(),
      target_resource_id: (tool === 'Bash' ? ti.command : ti.file_path || tool || '').slice(0, 200),
      amount: parseAmount(),
      currency: 'USD',
      risk_flags: flags,
    },
  });

  if (mint.decision === 'deny') {
    emit('deny', `EMILIA — BLOCKED by policy: ${(mint.reasons || []).join('; ') || 'denied'}. receipt ${mint.receipt_id}. Do not proceed.`);
  }
  if (!mint.signoff_required) {
    // EMILIA adjudicates money/external actions. For purely-local risk it has no
    // policy — never let a "no signoff" answer silently allow it; ask the human.
    if (moneyOnly) emit('allow', `EMILIA — allowed by policy. receipt ${mint.receipt_id} (verifiable offline).`);
    emit('ask', `EMILIA — no money/external policy matched, but locally high-risk (${flags.join(', ')}): ${label}. Confirm a human intends this.`);
  }

  const sign = await ep('/api/v1/signoffs/request', {
    method: 'POST',
    body: { receipt_id: mint.receipt_id, comment: label },
  });
  const url = `${BASE_URL}/signoff/${sign.signoff_id}`;

  const deadline = Date.now() + TIMEOUT_S * 1000;
  while (Date.now() < deadline) {
    await sleep(POLL_MS);
    const r = await ep(`/api/v1/trust-receipts/${encodeURIComponent(mint.receipt_id)}`);
    const st = r.receipt_status || r.status || 'pending';
    if (['approved_pending_consume', 'approved', 'consumed', 'fulfilled'].includes(st)) {
      emit('allow', `EMILIA — APPROVED by a named human on their device. receipt ${mint.receipt_id}. Verify offline: npx @emilia-protocol/verify`);
    }
    if (['denied', 'rejected', 'revoked'].includes(st)) {
      emit('deny', `EMILIA — a named human REJECTED this action. receipt ${mint.receipt_id}. Do not proceed.`);
    }
  }
  emit('ask', `EMILIA — signoff timed out after ${TIMEOUT_S}s. Approve at ${url}, or confirm manually. Failing closed.`);
} catch (err) {
  // Network down, API error, anything: fail closed to a human prompt.
  emit('ask', `EMILIA unreachable (${err.message}) — failing closed. Confirm a human intends: ${label}.`);
}
