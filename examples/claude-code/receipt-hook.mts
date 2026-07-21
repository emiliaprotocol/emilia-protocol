#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EMILIA receipt hook for Claude Code — the zero-friction wedge.
 *
 * PreToolUse hook: dangerous commands require an offline-verifiable,
 * named-human authorization receipt bound to the EXACT command. Safe
 * commands pass through untouched — the existing UX doesn't change; the
 * dangerous path starts emitting evidence.
 *
 * Wire into .claude/settings.json (see settings.snippet.json), then:
 *   EMILIA_TRUSTED_KEYS=<b64url spki[,more]>   pinned approver keys (REQUIRED)
 *   EMILIA_RECEIPT=<path>                      receipt for the next action
 *                                              (default .emilia/receipt.json)
 *   EMILIA_HOOK_PATTERNS=<regex||regex>        extend the dangerous list
 *
 * Exit 0 = allow. Exit 2 = block (stderr becomes Claude's feedback, and it
 * contains the machine-readable challenge naming exactly what to bring).
 * FAIL-CLOSED: no trusted keys, no receipt, wrong command, stale, reused,
 * or tampered all block.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { verifyEmiliaReceipt } from '../../packages/require-receipt/dist/emilia-gate.mjs';

const DANGEROUS = [
  /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)[a-z]*\b/i, // rm -rf and friends
  /\bgit\s+push\s+.*--force/i,
  /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b/i,
  /\bterraform\s+(apply|destroy)\b/i,
  /\bkubectl\s+delete\b/i,
  /\baws\s+\S+\s+(delete|terminate|remove)-/i,
  /\b(stripe|wire|payout|transfer)\b.*\b(create|send|post)\b/i,
  /\bcurl\b.*-X\s*(POST|PUT|DELETE)\b.*\bprod/i,
];
const extra = (process.env.EMILIA_HOOK_PATTERNS ?? '').split('||').filter(Boolean).map((p) => new RegExp(p, 'i'));

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const command = input?.tool_input?.command ?? '';
if (input?.tool_name !== 'Bash' || !command) process.exit(0);
if (![...DANGEROUS, ...extra].some((re) => re.test(command))) process.exit(0); // safe: untouched

// ── dangerous: a named human must have approved THIS exact command ──────────
const block = (msg) => { process.stderr.write(msg + '\n'); process.exit(2); };
const cmdDigest = crypto.createHash('sha256').update(command, 'utf8').digest('hex');
const ACTION = `claude-code.bash:${cmdDigest.slice(0, 16)}`;
const challenge = JSON.stringify({
  '@version': 'AE-CHALLENGE-v1',
  required_evidence: [{ type: 'authorization_receipt', action_type: ACTION, fresh_max_sec: 900 }],
  note: 'mint with: node examples/claude-code/mint-poc-receipt.mjs <command>',
});

const trustedKeys = (process.env.EMILIA_TRUSTED_KEYS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
if (trustedKeys.length === 0) {
  block(`EMILIA: blocked — no trusted approver keys configured (set EMILIA_TRUSTED_KEYS). This command is classified dangerous and requires a named-human authorization receipt.\n${challenge}`);
}

const receiptPath = process.env.EMILIA_RECEIPT ?? path.join(process.cwd(), '.emilia', 'receipt.json');
let doc = null;
try { doc = JSON.parse(fs.readFileSync(receiptPath, 'utf8')); } catch { /* absent */ }
if (!doc) block(`EMILIA: blocked — dangerous command, no authorization receipt at ${receiptPath}.\n${challenge}`);

const res = verifyEmiliaReceipt(doc, { trustedKeys, action: ACTION, maxAgeSec: 900 });
if (!res.ok) block(`EMILIA: blocked — receipt rejected (${res.reason}${res.detail ? `: ${res.detail}` : ''}). The receipt must bind THIS exact command.\n${challenge}`);

// one-time consumption: a receipt authorizes ONE execution. The ledger is
// content-addressed by receipt digest; a reused receipt is refused, so an
// approval cannot be replayed across two dangerous commands.
const ledgerPath = process.env.EMILIA_CONSUMED_LEDGER ?? path.join(process.cwd(), '.emilia', 'consumed.json');
const receiptDigest = crypto.createHash('sha256').update(JSON.stringify(doc), 'utf8').digest('hex');
let ledger: any[] = [];
try { ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8')); } catch { /* first use */ }
if (Array.isArray(ledger) && ledger.includes(receiptDigest)) {
  block(`EMILIA: blocked — this receipt was already consumed (replay refused). Mint a fresh approval for this command.\n${challenge}`);
}

// Commit consumption BEFORE allowing execution: if writing the ledger fails,
// fail closed rather than allow an unrecorded (replayable) execution.
try {
  ledger = Array.isArray(ledger) ? ledger : [];
  ledger.push(receiptDigest);
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2));
} catch (e) {
  block(`EMILIA: blocked — could not record one-time consumption (${e.message}); refusing to allow an unrecorded execution.\n${challenge}`);
}

// Verified, bound to THIS command, fresh, and now consumed. Allow.
process.stderr.write(`EMILIA: allowed — receipt ${res.receipt_id ?? '(unknown id)'} authorizes this command (approver-signed, one-time).\n`);
process.exit(0);