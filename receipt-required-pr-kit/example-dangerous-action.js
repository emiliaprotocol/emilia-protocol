// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required, dropped in front of ONE dangerous action — built on the
// canonical hardened gate from @emilia-protocol/require-receipt.
//
//   missing receipt   -> 428 Receipt Required (refused)
//   valid receipt     -> the action runs (and the receipt is consumed)
//   replayed receipt  -> refused (one-time consumption)
//   forged receipt    -> refused (signature / action-binding fails)
//
// The gate (makeReceiptGate) encodes the easy-to-get-wrong parts in one reviewed
// place: target binding (a receipt for one resource can't act on another),
// consume-after-success (a failed action never burns a valid approval), and
// sanitized {reason}-only rejections. Don't hand-roll these.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  makeReceiptGate,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
} from '@emilia-protocol/require-receipt';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(resolve(HERE, 'agent-actions.json'), 'utf8'));
const MANIFEST_URL = MANIFEST.service?.manifest_url || '/.well-known/agent-actions.json';

// The actual dangerous work. Replace the body with your real action; THROW on
// failure so the gate leaves the approval retryable instead of burning it.
function performDangerousAction(name, args) {
  return { ran: true, tool: name, ...args };
}

// One gate per action type (each keeps its own one-time-consumption store).
const gates = new Map();
function gateFor(req) {
  if (!gates.has(req.action_type)) {
    gates.set(req.action_type, makeReceiptGate({
      action: req.action_type,
      // Demo: trust the receipt's inline key. PRODUCTION: pass
      // `trustedKeys: [<issuer SPKI>]` and drop allowInlineKey.
      allowInlineKey: true,
      maxAgeSec: req.max_age_sec,
      statusCode: RECEIPT_REQUIRED_STATUS,
      manifestUrl: MANIFEST_URL,
      assuranceClass: req.assurance_class,
      // store: <durable {has,add}> for restart/multi-instance one-time use.
    }));
  }
  return gates.get(req.action_type);
}

// dispatch(toolName, args, receipt|null) -> { status, body }
export async function dispatch(name, args = {}, receipt = null) {
  const req = findActionRequirement(MANIFEST, { protocol: 'mcp', tool: name });

  // Tools not listed as receipt_required pass straight through.
  if (!req || !req.receipt_required) {
    return { status: 200, body: performDangerousAction(name, args) };
  }

  // Bind the receipt to the SPECIFIC target (the dangerous tool's `table`), so a
  // receipt approving "wipe customers" can't also wipe "orders". The gate runs
  // the action and consumes the receipt only on success.
  const r = await gateFor(req).run(
    receipt,
    { target: args?.table },
    async () => performDangerousAction(name, args),
  );

  if (r.ok) {
    return { status: 200, body: { ...r.result, evidence: { receipt_id: r.receiptId, outcome: r.outcome, signer: r.signer } } };
  }
  return { status: r.status, body: r.body };
}
