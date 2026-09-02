#!/usr/bin/env node
// Generated from guard.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EMILIA Guard — Claude Code PreToolUse hook.
 *
 * Heuristically catches common irreversible or high-risk tool calls before
 * they execute and requires a human confirmation. This hook is a safety net,
 * not an exact-action authorization boundary. Encoded, split, or novel command
 * shapes can evade classification. Exact command mapping and receipt
 * enforcement belong in the credential-owning shell or provider integration.
 * Two modes, both fail closed for anything this hook classifies:
 *
 *   • Local mode (no account): a high-risk call returns `ask`, forcing a human
 *     permission prompt. Zero config, works offline. A free safety net.
 *   • EMILIA mode (EP_API_KEY + EP_ORG_ID set): the call is minted against
 *     EMILIA's formally-verified policy engine; if policy requires signoff, a
 *     named human approves on their own device (Face ID / passkey) and the
 *     action proceeds only with an offline-verifiable Trust Receipt.
 *
 * This heuristic layer never emits `allow`. On a matched call, error, timeout,
 * or ambiguity it emits `ask` or `deny`. Unmatched calls return to Claude
 * Code's normal permission flow and are not evidence that the call is safe.
 *
 * Reads a PreToolUse event on stdin; writes a permissionDecision on stdout.
 * https://code.claude.com/docs/en/hooks
 */
import process from 'node:process';
const BASE_URL = process.env.EP_BASE_URL || 'https://www.emiliaprotocol.ai';
const API_KEY = process.env.EP_API_KEY || '';
const ORG_ID = process.env.EP_ORG_ID || '';
const requestedTimeout = Number(process.env.EP_SIGNOFF_TIMEOUT_S);
const TIMEOUT_S = Math.min(Number.isFinite(requestedTimeout) && requestedTimeout > 0 ? requestedTimeout : 30, 60);
const POLL_MS = 3000;
// ── authorization telemetry ─────────────────────────────────────────────────
// A PreToolUse hook is a separate short-lived process. It has no handle on the
// execute_tool span the host may be recording, and starting an OpenTelemetry SDK
// here to create one would be a new runtime dependency this hook does not take.
// So this integration CANNOT set attributes on a span. What it can do without a
// dependency is write the same attribute map as one structured stderr line, for
// a collector or log pipeline to lift onto the call.
//
// Off by default: set EP_OTEL_AUTHORIZATION=1 to enable. stdout stays the hook
// protocol and is never touched by this.
//
// The hook's own vocabulary is 'ask' | 'deny' and it never emits 'allow'. 'ask'
// is NOT an authorization status: the decision has been handed to a human who
// has not answered. Recording that as auto_approved would be the exact false
// negative this attribute group exists to expose, so 'ask' emits nothing.
const OTEL_AUTHORIZATION_ENABLED = process.env.EP_OTEL_AUTHORIZATION === '1';
const AUTHORIZATION_ATTRIBUTE_KEYS = {
    status: 'emilia.tool.authorization.status',
    evidenceGrade: 'emilia.tool.authorization.evidence.grade',
    evidenceFormat: 'emilia.tool.authorization.evidence.format',
    evidenceLocator: 'emilia.tool.authorization.evidence.locator',
};
function writeAuthorizationTelemetry(decision, receiptId) {
    if (!OTEL_AUTHORIZATION_ENABLED)
        return;
    if (decision !== 'deny' && decision !== 'allow')
        return; // 'ask' is unresolved
    const attributes = {
        [AUTHORIZATION_ATTRIBUTE_KEYS.status]: decision === 'deny' ? 'rejected' : 'auto_approved',
        // This hook is a heuristic classifier. Whatever it says about the call is
        // its own assertion, so the grade is self_attested and nothing above it.
        [AUTHORIZATION_ATTRIBUTE_KEYS.evidenceGrade]: 'self_attested',
    };
    if (typeof receiptId === 'string' && receiptId !== '') {
        attributes[AUTHORIZATION_ATTRIBUTE_KEYS.evidenceFormat] = 'application/vnd.emilia.receipt.v1+json';
        attributes[AUTHORIZATION_ATTRIBUTE_KEYS.evidenceLocator] = `emilia-receipt:${receiptId}`;
    }
    try {
        process.stderr.write(`${JSON.stringify({
            emilia_tool_authorization: attributes,
            tool_name: typeof tool === 'string' ? tool : null,
        })}\n`);
    }
    catch {
        // Telemetry never breaks the hook.
    }
}
// ── decision emitters ───────────────────────────────────────────────────────
function emit(decision, reason, receiptId) {
    writeAuthorizationTelemetry(decision, receiptId);
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
/**
 * @param {string} path
 * @param {{method?: string, body?: unknown}} [options]
 */
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
    if (!res.ok)
        throw new Error(data.detail || data.title || `HTTP ${res.status}`);
    return data;
}
// ── read the hook event ──────────────────────────────────────────────────────
let raw = '';
for await (const chunk of process.stdin)
    raw += chunk;
let evt;
try {
    evt = JSON.parse(raw || '{}');
}
catch {
    passThrough();
}
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
        if (DESTRUCTIVE_SHELL.some((re) => re.test(cmd)))
            flags.push('destructive_shell');
        if (hasCustom(cmd))
            flags.push('custom_pattern');
    }
    else if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') {
        if (SENSITIVE_PATH.test(ti.file_path || ''))
            flags.push('sensitive_path');
        if (hasCustom(ti.file_path || ''))
            flags.push('custom_pattern');
    }
    else if (tool.startsWith('mcp__')) {
        if (RISKY_MCP_VERB.test(tool))
            flags.push('external_or_money_action');
        if (hasCustom(`${tool} ${JSON.stringify(ti)}`))
            flags.push('custom_pattern');
    }
    return [...new Set(flags)];
}
const flags = classify();
if (flags.length === 0)
    passThrough(); // not high-risk → zero overhead, normal flow
const label = tool === 'Bash' ? `\`${(ti.command || '').slice(0, 120)}\``
    : tool.startsWith('mcp__') ? tool
        : `${tool} ${ti.file_path || ''}`.trim();
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
    if (/bank|account|payee/.test(t))
        return 'vendor_bank_account_change';
    return 'ai_agent_payment_action';
}
function parseAmount() {
    for (const v of [ti.amount, ti.value, ti.total]) {
        const n = Number(v);
        if (Number.isFinite(n) && n > 0)
            return n;
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
        emit('deny', `EMILIA — BLOCKED by policy: ${(mint.reasons || []).join('; ') || 'denied'}. receipt ${mint.receipt_id}. Do not proceed.`, mint.receipt_id);
    }
    if (!mint.signoff_required) {
        emit('ask', `EMILIA recorded the heuristic projection but this hook cannot authorize the exact provider action. receipt ${mint.receipt_id}. Confirm the actual command and arguments at the credential-owning boundary.`);
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
            emit('ask', `EMILIA received a named-human approval for the heuristic projection. receipt ${mint.receipt_id}. Review the exact command and arguments before proceeding; exact authorization must be enforced at the credential-owning boundary.`);
        }
        if (['denied', 'rejected', 'revoked'].includes(st)) {
            emit('deny', `EMILIA — a named human REJECTED this action. receipt ${mint.receipt_id}. Do not proceed.`, mint.receipt_id);
        }
    }
    emit('ask', `EMILIA — signoff timed out after ${TIMEOUT_S}s. Approve at ${url}, or confirm manually. Failing closed.`);
}
catch (err) {
    // Network down, API error, anything: fail closed to a human prompt.
    emit('ask', `EMILIA unreachable (${err.message}) — failing closed. Confirm a human intends: ${label}.`);
}
