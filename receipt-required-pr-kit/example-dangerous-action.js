// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required, dropped in front of ONE dangerous action.
//
// The gate is manifest-driven: it reads agent-actions.json to learn which tool
// requires a receipt, then enforces the full rail against the REAL verifier in
// @emilia-protocol/require-receipt — no API, no key, no EMILIA server trusted:
//
//   missing receipt   -> 428 Receipt Required (refused)
//   valid receipt     -> the action runs
//   replayed receipt  -> refused (one-time consumption)
//   forged receipt    -> refused (signature / action-binding fails)
//
// To adopt: copy this file + agent-actions.json into your repo, point your
// dangerous tool at `dispatch()`, and wire your own receipt source.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
} from '@emilia-protocol/require-receipt';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));
const MANIFEST_URL = MANIFEST.service?.manifest_url || '/.well-known/agent-actions.json';
const RR = RECEIPT_REQUIRED_STATUS; // 428

// The actual dangerous work. Replace the body with your real action.
function performDangerousAction(name, args) {
  return { ran: true, tool: name, ...args };
}

const consumed = new Set(); // one-time-consumption store (replay refusal)

// dispatch(toolName, args, receipt|null) -> { status, body }
// In a real server this is your route/tool handler; `receipt` is the verified
// X-EMILIA-Receipt header (a parsed EP-RECEIPT-v1 JSON document) or null.
export async function dispatch(name, args = {}, receipt = null) {
  const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });

  // Tools not listed as receipt_required pass straight through.
  if (!req || !req.receipt_required) {
    return { status: 200, body: performDangerousAction(name, args) };
  }

  const action = req.action_type;
  const opts = { statusCode: RR, manifestUrl: MANIFEST_URL, maxAgeSec: req.max_age_sec, assuranceClass: req.assurance_class };

  // 1. No receipt -> 428 Receipt Required, telling the caller exactly what to bring.
  if (!receipt) {
    return { status: RR, body: receiptChallenge(action, `"${name}" requires an authorization receipt (per ${MANIFEST_URL}).`, opts) };
  }

  // 2/4. Verify offline: signature, freshness, and action-binding.
  //
  // SECURITY NOTE: `allowInlineKey: true` trusts the key embedded in the
  // receipt — fine for a self-contained demo, NOT for production. In production
  // pass `trustedKeys: [<issuer SPKI you trust>]` and drop allowInlineKey so a
  // self-signed receipt cannot authorize anything.
  const v = verifyEmiliaReceipt(receipt, { allowInlineKey: true, action, maxAgeSec: req.max_age_sec });
  if (!v.ok) {
    return { status: RR, body: { ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`, opts), rejected: v } };
  }

  // 3. Replay -> refused (one-time consumption).
  if (consumed.has(v.receipt_id)) {
    return { status: RR, body: { rejected: { reason: 'replay_refused' }, ...receiptChallenge(action, `Receipt ${v.receipt_id} already consumed.`, opts) } };
  }
  consumed.add(v.receipt_id);

  // Valid, fresh, action-bound, first use -> the action runs.
  return { status: 200, body: { ...performDangerousAction(name, args), evidence: { receipt_id: v.receipt_id, outcome: v.outcome, signer: v.signer } } };
}
