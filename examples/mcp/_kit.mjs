// SPDX-License-Identifier: Apache-2.0
//
// Shared kit for the canonical MCP examples — the "Receipt Required" rail.
//
// The gate is MANIFEST-DRIVEN: it reads /.well-known/agent-actions.json to
// learn which tools require a receipt (and at what assurance/quorum), then
// enforces the full ritual against the REAL verifier in
// @emilia-protocol/require-receipt — no API, no key, no EP server trusted:
//
//   1. dangerous tool, NO receipt        -> 428 Receipt Required (refused)
//   2. named human signs the exact action -> EP-RECEIPT-v1, retry -> runs
//   3. the SAME receipt replayed          -> refused (one-time consumption)
//   4. a forged receipt                   -> refused (signature fails)

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
} from '../../packages/require-receipt/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, '../../public/.well-known/agent-actions.json'), 'utf8'));
const MANIFEST_URL = MANIFEST.service?.manifest_url || '/.well-known/agent-actions.json';
const RR = RECEIPT_REQUIRED_STATUS; // 428

const FAST = !!process.env.FAST;
const pause = (ms) => (FAST ? Promise.resolve() : new Promise((r) => setTimeout(r, ms)));
export const line = (s = '') => console.log(s);
const rule = () => line('─'.repeat(66));

// EP-RECEIPT-v1 canonical signer (byte-identical to @emilia-protocol/verify).
const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
      : JSON.stringify(v));

// A named human's device signs the EXACT action. Minted locally here so the
// demo is self-contained; in production it's a real Face ID / passkey signoff.
export function signAction(action, { approver, tamper = false } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver },
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url');
  const doc = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
  if (tamper) doc.payload = { ...payload, claim: { ...payload.claim, action_type: 'something.harmless' } };
  return doc;
}

// A manifest-driven MCP tool dispatcher. The manifest decides whether a tool
// requires a receipt; the gate enforces verify + one-time consumption (replay)
// + action-binding. Read-only / unlisted tools pass straight through.
export function makeGuardedServer({ tool }) {
  const consumed = new Set(); // one-time-consumption store (replay refusal)
  return async function callTool(name, args = {}, receipt = null) {
    const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });
    if (!req || !req.receipt_required) {
      return { status: 200, body: { ran: true, note: 'read-only / unlisted in manifest — passes through' } };
    }
    const action = req.action_type;
    const opts = { statusCode: RR, manifestUrl: MANIFEST_URL, maxAgeSec: req.max_age_sec, assuranceClass: req.assurance_class, quorum: req.quorum };
    if (!receipt) {
      return { status: RR, body: receiptChallenge(action, `MCP tool "${name}" requires a receipt (per ${MANIFEST_URL}).`, opts) };
    }
    const v = verifyEmiliaReceipt(receipt, { allowInlineKey: true, action, maxAgeSec: req.max_age_sec });
    if (!v.ok) {
      return { status: RR, body: { ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`, opts), rejected: v } };
    }
    if (consumed.has(v.receipt_id)) {
      return { status: RR, body: { ...receiptChallenge(action, `Receipt ${v.receipt_id} already consumed.`, opts), rejected: { reason: 'replay_refused' } } };
    }
    consumed.add(v.receipt_id); // one-time consumption
    return { status: 200, body: { ran: true, action, ...args, evidence: { receipt_id: v.receipt_id, outcome: v.outcome, signer: v.signer } } };
  };
}

const show = (r) => line(`     ← ${r.status} ${r.status === 200 ? 'OK — tool ran' : (r.body.title || 'REFUSED')}${r.body.rejected ? ` (${r.body.rejected.reason})` : ''}`);

// Runs the full Receipt Required ritual for one dangerous tool.
export async function runDemo({ title, tool, args, approver, agentLine }) {
  const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool });
  if (!req) throw new Error(`tool "${tool}" not found in the Action Risk Manifest`);
  const action = req.action_type;
  const server = makeGuardedServer({ tool });
  line();
  line(`  ${title}`);
  rule();
  line(`  manifest: ${tool} → ${action} · receipt_required=${req.receipt_required} · assurance=${req.assurance_class}${req.quorum?.required ? ` · quorum ${req.quorum.m}-of-N` : ''}`);
  await pause(700);

  line(`\n  [agent]  ${agentLine}`);
  line(`           → ${tool}(${Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')})`);
  await pause(900);

  line('\n  1. Agent calls the tool with NO receipt');
  let res = await server(tool, args, null);
  show(res);
  line(`     ${res.status} Receipt-Required → bring an ${res.body?.required?.proof_header || 'X-EMILIA-Receipt'} bound to "${action}"`);
  await pause(1000);

  line(`\n  2. A named human reviews the exact action and signs it (${approver})`);
  const receipt = signAction(action, { approver });
  line(`     receipt_id ${receipt.payload.receipt_id} · outcome ${receipt.payload.claim.outcome}`);
  line('     agent retries WITH the receipt:');
  res = await server(tool, args, receipt);
  show(res);
  if (res.status === 200) line(`     tool performed; evidence ${res.body.evidence.receipt_id} verifies offline, trusting no one`);
  await pause(900);

  line('\n  3. The SAME receipt is presented again (replay)');
  res = await server(tool, args, receipt);
  show(res);
  await pause(700);

  line('\n  4. A forged receipt (a signed field altered) is presented');
  res = await server(tool, args, signAction(action, { approver, tamper: true }));
  show(res);

  if (req.quorum?.required) {
    line(`\n  note: the manifest escalates ${tool} to a ${req.quorum.m}-of-N quorum (EP-QUORUM-v1);`);
    line('        this shows the single-signoff base rail — the quorum path adds distinct human #2.');
  }
  line('\n  No receipt, no irreversible action. If it ran, anyone can verify who authorized exactly what.');
  line();
}
