// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required, in front of ONE dangerous action — built on the canonical
// hardened gate from @emilia-protocol/require-receipt.
//
//   missing receipt   -> 428 Receipt Required (refused)
//   valid receipt     -> the action runs (and the receipt is consumed)
//   replayed receipt  -> refused (one-time consumption; see store note below)
//   forged receipt    -> refused (signature / action-binding fails)
//
// SECURE BY DEFAULT: a destructive action will NOT accept a self-signed
// (inline-key) receipt. Pin the issuer key(s) you trust via EMILIA_TRUSTED_KEYS
// (comma-separated base64url SPKI). With enforcement on and no trusted keys
// configured, the gate FAILS CLOSED — the action is refused, never run under an
// untrusted key. Set EMILIA_ALLOW_INLINE_KEY=1 to accept inline keys for
// NON-PRODUCTION demos only.

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

// Posture is read from the environment at call time, so deployment config — not
// a hardcoded demo default — decides how receipts are trusted.
const trustedKeys = () =>
  (process.env.EMILIA_TRUSTED_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
const allowInlineKey = () => /^(1|true)$/i.test(process.env.EMILIA_ALLOW_INLINE_KEY || '');
// Only advertise a manifest URL the host actually serves. Set EMILIA_MANIFEST_URL
// once you serve agent-actions.json (e.g. at /.well-known/agent-actions.json);
// otherwise the 428 challenge won't point at a URL that 404s.
const manifestUrl = () => process.env.EMILIA_MANIFEST_URL || undefined;

// The actual dangerous work. Replace the body with your real action; THROW on
// failure so the gate leaves the approval retryable instead of burning it.
function performDangerousAction(name, args) {
  return { ran: true, tool: name, ...args };
}

// One gate per action type (each keeps its own one-time-consumption store).
// NOTE: the default store is process-local (in-memory) — it does NOT survive a
// restart and does NOT span multiple instances. For durable / multi-instance
// one-time consumption, pass a durable `store` ({ has, add }) below (Redis/DB).
const gates = new Map();
function gateFor(req) {
  if (!gates.has(req.action_type)) {
    const keys = trustedKeys();
    gates.set(req.action_type, makeReceiptGate({
      action: req.action_type,
      // Pinned issuer keys (secure) if configured; inline only in explicit demo
      // mode. dispatch() fails closed before we get here if neither is set.
      ...(keys.length ? { trustedKeys: keys } : { allowInlineKey: true }),
      maxAgeSec: req.max_age_sec,
      statusCode: RECEIPT_REQUIRED_STATUS,
      ...(manifestUrl() ? { manifestUrl: manifestUrl() } : {}),
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

  // FAIL CLOSED: enforcement is on but no issuer key is trusted. Refuse the
  // destructive action rather than accept a self-signed receipt. Configure
  // EMILIA_TRUSTED_KEYS (pinned issuer SPKI), or EMILIA_ALLOW_INLINE_KEY=1 for
  // non-production demos only.
  if (!trustedKeys().length && !allowInlineKey()) {
    return {
      status: 500,
      body: {
        rejected: { reason: 'receipt_enforcement_misconfigured' },
        detail: 'Set EMILIA_TRUSTED_KEYS to the issuer key(s) you trust; '
          + 'refusing to accept self-signed receipts for a destructive action.',
      },
    };
  }

  // Bind the receipt to the SPECIFIC target (e.g. the table), so a receipt
  // approving "wipe customers" can't also wipe "orders". The gate runs the
  // action and consumes the receipt only on success.
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
