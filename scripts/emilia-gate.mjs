#!/usr/bin/env node
/**
 * emilia-gate — EMILIA's pre-action gate, as one dependency-light file.
 * @license Apache-2.0
 *
 * Runs EMILIA's REAL policy engine (lib/guard-policies.js — the same
 * formally-modeled logic behind GovGuard/FinGuard) in-process to decide whether
 * a high-risk action may proceed:  allow  /  allow_with_signoff  /  deny.
 * No network. No API key. Emits a signed, offline-verifiable receipt of the
 * decision (Ed25519, verifiable with @emilia-protocol/verify).
 *
 * Three ways to use it:
 *   1. Direct:   node scripts/emilia-gate.mjs --command "stripe payouts create ..."
 *   2. CI step:  run before a deploy/migration; exit 2 blocks the pipeline.
 *   3. Agent harness — Claude Code PreToolUse hook:
 *        node scripts/emilia-gate.mjs --hook    (reads the tool call on stdin)
 *      → the agent literally cannot run an irreversible command without EMILIA.
 *
 * Exit 0 = allow.   Exit 2 = blocked (human signoff required, denied, or
 * the gate cannot parse/classify the action safely).
 */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readFileSync as _r } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { evaluateGuardPolicy, GUARD_ACTION_TYPES, GUARD_DECISIONS } from '../lib/guard-policies.js';
import { strictJsonGate } from '../lib/strict-json.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// ── Shell-command → action classifier ────────────────────────────────────────
// Money/benefit actions are decided by the REAL engine (evaluateGuardPolicy).
// Irreversible-infra actions use the gate's own high-risk rule (clearly labeled
// so we never claim the formal engine covers what it doesn't).
const MONEY_PATTERNS = [
  { re: /\bsk_live_[A-Za-z0-9]+/, what: 'a live Stripe secret key' },
  { re: /\bstripe\b[\s\S]*\b(payout|charge|transfer|refund|paymentlink|price|subscription)s?\b[\s\S]*\b(create|update|cancel|del)/i, what: 'a Stripe money/billing mutation' },
  { re: /\b(wire|ach|payout|disburse)\b[\s\S]*\b(send|release|execute|create)/i, what: 'a payment release' },
];
const INFRA_PATTERNS = [
  { re: /\brm\s+-rf?\s+(\/(?!Users\/\S+\/(?:tmp|cache))|~|\$HOME|\*|\.git\b|--no-preserve-root)/, what: 'a recursive force-delete of a protected path' },
  { re: /\bgit\s+push\b[\s\S]*--force(?!-with-lease)/i, what: 'a force-push (rewrites remote history)' },
  { re: /\b(drop\s+table|truncate\s+table|delete\s+from)\b/i, what: 'destructive SQL' },
  { re: /\bsupabase\b[\s\S]*\b(reset|delete|--force)\b/i, what: 'a destructive Supabase operation' },
];
const SAFE_READ_ONLY_PATTERNS = [
  /^\s*(pwd|date|whoami|id)(\s|$)/i,
  /^\s*(ls|find|rg|grep|sed|cat|head|tail|wc)\b/i,
  /^\s*git\s+(status|diff|log|show|branch|rev-parse|remote)(\s|$)/i,
  /^\s*(node|npm|npx|python3?|go|cargo|gh)\s+(-v|--version|version)(\s|$)/i,
];

function classifyCommand(cmd) {
  for (const p of MONEY_PATTERNS) {
    if (p.re.test(cmd)) {
      const base = evaluateGuardPolicy({ actionType: GUARD_ACTION_TYPES.AI_AGENT_PAYMENT_ACTION, riskFlags: [] });
      return { actionType: 'ai_agent_payment_action', engine: 'guard-policies', what: p.what, ...base };
    }
  }
  for (const p of INFRA_PATTERNS) {
    if (p.re.test(cmd)) {
      return {
        actionType: 'irreversible_infrastructure_action',
        engine: 'agent-gate',
        what: p.what,
        decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
        reasons: [`Irreversible action (${p.what}) by an autonomous agent requires a human signoff.`],
        signoffRequired: true,
      };
    }
  }
  for (const p of SAFE_READ_ONLY_PATTERNS) {
    if (p.test(cmd)) {
      return { actionType: 'low_risk', engine: 'agent-gate', what: 'an explicitly read-only command', decision: GUARD_DECISIONS.ALLOW, reasons: ['Matched the read-only allowlist.'], signoffRequired: false };
    }
  }
  return {
    actionType: 'unclassified_agent_command',
    engine: 'agent-gate',
    what: 'an unclassified shell command',
    decision: GUARD_DECISIONS.ALLOW_WITH_SIGNOFF,
    reasons: ['Command did not match the read-only allowlist. Fail closed until a human signs off or the classifier is extended.'],
    signoffRequired: true,
  };
}

// ── Tiny canonical JSON (matches lib/guard-policies + @emilia-protocol/verify) ─
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

// ── Stable agent-gate signing identity (generated once, gitignored) ───────────
function agentKey() {
  const dir = join(ROOT, '.emilia');
  const path = join(dir, 'agent-gate-key.json');
  if (existsSync(path)) {
    const jwk = JSON.parse(readFileSync(path, 'utf8'));
    return crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  }
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(privateKey.export({ format: 'jwk' })), { mode: 0o600 });
  return privateKey;
}

function signReceipt(verdict, subject, command) {
  const priv = agentKey();
  const pub = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: `agtgate_${crypto.randomUUID()}`,
    issuer: 'ep_agent_gate',
    subject,
    claim: {
      action_type: verdict.actionType,
      outcome: verdict.decision,
      context: {
        command_sha256: `sha256:${crypto.createHash('sha256').update(command).digest('hex')}`,
        engine: verdict.engine,
        reasons: verdict.reasons,
      },
    },
    created_at: new Date().toISOString(),
    protocol_version: 'EP-CORE-v1.0',
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), priv).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', signer: 'ep_agent_gate', value, key_source: 'inline' }, public_key: pub };
}

// ── I/O helpers ───────────────────────────────────────────────────────────────
function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function readStdin() {
  try { return _r(0, 'utf8'); } catch { return ''; }
}
function parseBoundaryJson(raw, maxBytes = 1024 * 1024) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > maxBytes) throw new Error('JSON input is too large');
  const strict = strictJsonGate(raw);
  if (!strict.ok) throw new Error(`strict JSON required: ${strict.reason}`);
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('JSON input must be an object');
  return value;
}

// ── Main ──────────────────────────────────────────────────────────────────────
function blockedDecision(d) {
  return d === GUARD_DECISIONS.ALLOW_WITH_SIGNOFF || d === GUARD_DECISIONS.DENY;
}

function failClosed(message, detail = '') {
  process.stderr.write(
    `\n⛔ EMILIA gate: action HELD.\n` +
    `   ${message}\n` +
    (detail ? `   ${detail}\n` : '') +
    `   Exit 2 blocks the tool call until a named human authorizes it.\n`,
  );
  process.exit(2);
}

async function main() {
  if (process.env.EMILIA_GATE === 'off') {
    failClosed('EMILIA_GATE=off was requested, but this hook is fail-closed by design.');
  }

  const hookMode = process.argv.includes('--hook');
  let command = arg('--command');
  let subject = 'agent:local';
  let verdict;

  if (hookMode) {
    let evt = {};
    try { evt = parseBoundaryJson(readStdin() || '{}'); } catch { failClosed('Could not parse the Claude Code hook event.'); }
    if (evt.tool_name && evt.tool_name !== 'Bash') process.exit(0);
    command = evt.tool_input?.command || '';
    subject = 'agent:claude-code';
    if (!command) failClosed('Bash hook event did not include a command.');
    verdict = classifyCommand(command);
    if (blockedDecision(verdict.decision)) {
      // stderr is fed back to the model; exit 2 blocks the tool call.
      process.stderr.write(
        `\n⛔ EMILIA gate: this action is HELD pending a human signed-yes.\n` +
        `   Action:  ${verdict.what}\n` +
        `   Decision: ${verdict.decision} (${verdict.engine})\n` +
        `   ${verdict.reasons.join('\n   ')}\n` +
        `   A named human must approve before this runs.\n`,
      );
      process.exit(2);
    }
    process.exit(0);
  }

  const actionJson = arg('--action');
  if (actionJson) {
    let input;
    try { input = parseBoundaryJson(actionJson); } catch { failClosed('Could not parse the action as strict JSON.'); }
    const base = evaluateGuardPolicy(input);
    verdict = { actionType: input.actionType || 'custom', engine: 'guard-policies', what: 'a policy-engine action', ...base };
    subject = input.actorId ? `actor:${input.actorId}` : subject;
  } else if (command) {
    verdict = classifyCommand(command);
  } else {
    process.stdout.write('usage: emilia-gate (--command "<shell>" | --action \'{json}\' | --hook)\n');
    process.exit(64);
  }

  // Human-readable verdict + a signed, verifiable receipt of the decision.
  const icon = verdict.decision === GUARD_DECISIONS.ALLOW ? '✅ ALLOW' : verdict.decision === GUARD_DECISIONS.DENY ? '⛔ DENY' : '✋ HOLD — human signoff required';
  const receipt = signReceipt(verdict, subject, command || actionJson || '');
  if (process.argv.includes('--json')) {
    process.stdout.write(JSON.stringify({ verdict, receipt }, null, 2) + '\n');
  } else {
    process.stdout.write(
      `\n  EMILIA gate — ${icon}\n` +
      `  ${'-'.repeat(54)}\n` +
      `  action:   ${verdict.what}\n` +
      `  decision: ${verdict.decision}  ·  engine: ${verdict.engine}\n` +
      verdict.reasons.map((r) => `  reason:   ${r}`).join('\n') + '\n' +
      `  receipt:  ${receipt.payload.receipt_id} (Ed25519-signed, verify with @emilia-protocol/verify)\n\n`,
    );
  }
  process.exit(blockedDecision(verdict.decision) ? 2 : 0);
}

main().catch((err) => failClosed('Unhandled gate error.', String(err?.message ?? err)));
