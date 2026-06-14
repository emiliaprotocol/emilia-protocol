/**
 * POST /api/demo/require-receipt
 * @license Apache-2.0
 *
 * Public, unauthenticated demo of the DEMAND side of EMILIA — the
 * "No receipt, no irreversible action" loop made runnable.
 *
 * A counterparty drops `requireEmiliaReceipt(...)` in front of an
 * irreversible agent action. The action below ("delete the production
 * customer database") is irreversible by construction, so the endpoint
 * REFUSES to run it unless the caller presents a verifiable EMILIA
 * authorization receipt:
 *
 *   • No receipt        → 402 "EMILIA Receipt Required" + machine-readable
 *                         challenge telling the agent exactly what to bring
 *                         (so a well-behaved agent self-serves one and
 *                         retries, like a browser handling 401).
 *   • Invalid receipt   → 402 + the verifier's rejection reason
 *                         (expired / action_mismatch / bad_signature / …).
 *   • Valid receipt     → 200. The action is "performed" (this is a demo:
 *                         nothing is actually destroyed) and the endpoint
 *                         echoes back the portable evidence it would retain
 *                         for its own liability.
 *
 * This is NOT auth ("who are you") and NOT permissions ("are you allowed").
 * It is *portable accountability evidence the service keeps* — proof that a
 * named human accountably authorized THIS exact action. The receipt is the
 * record; it does not by itself grant access.
 *
 * Reference semantics: integrity-only trust (`allowInlineKey: true`) so
 * anyone can try the loop with a self-signed EP-RECEIPT-v1 document — it
 * proves the receipt was not tampered with, NOT that EMILIA vouches for the
 * issuer. In production the verifier PINS the trusted issuer keys it accepts
 * (e.g. from /.well-known/ep-keys.json). See @emilia-protocol/require-receipt.
 *
 * Present a receipt via header `X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)`
 * or body `{ "emilia_receipt": <doc> }`.
 *
 * Privacy: this endpoint never echoes the caller's raw action parameters or
 * the full receipt payload — only the non-sensitive verification facts
 * (receipt_id, subject, outcome, truncated signer) the integrator would log.
 */

import { NextResponse } from 'next/server';
import { verifyEmiliaReceipt, receiptChallenge } from '@/packages/require-receipt/index.js';

export const runtime = 'nodejs';

// The sample irreversible action this demo guards. Fixed so the loop is
// deterministic: a receipt must be bound to THIS action_type to pass.
const SAMPLE_ACTION = 'demo.delete_production_database';

const WWW_AUTH = `EMILIA realm="agent-actions", action="${SAMPLE_ACTION}"`;

export async function POST(request) {
  // 1) Look for a presented receipt — header first, then body.
  let doc = null;
  const body = await request.json().catch(() => ({}));
  if (body && body.emilia_receipt) doc = body.emilia_receipt;
  if (!doc) {
    const hdr = request.headers.get('x-emilia-receipt');
    if (hdr) {
      try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough → no receipt */ }
    }
  }

  // 2) No receipt → refuse the irreversible action with a 402 challenge.
  if (!doc) {
    return NextResponse.json(
      {
        ...receiptChallenge(
          SAMPLE_ACTION,
          'Refusing an irreversible action: no EMILIA authorization receipt was presented.',
        ),
        loop: {
          rule: 'No receipt, no irreversible action.',
          sample_action: SAMPLE_ACTION,
          why: 'This action cannot be undone. The service requires portable, verifiable proof that a named human accountably authorized THIS exact action before it will run — and keeps that proof as its own accountability evidence. This is not auth and not permissions.',
          to_proceed: [
            'Obtain an EP-RECEIPT-v1 authorization receipt bound to action_type "' + SAMPLE_ACTION + '" (run emilia-gate, the SDK, or POST /api/trust/gate).',
            'Resend this request with header  X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)  (or body { "emilia_receipt": <doc> }).',
          ],
          verifier: 'Offline Ed25519 over canonical JSON. This demo accepts self-signed receipts (allowInlineKey) to prove integrity; production pins trusted issuer keys.',
        },
      },
      { status: 402, headers: { 'WWW-Authenticate': WWW_AUTH } },
    );
  }

  // 3) Receipt present but invalid → 402 with the verifier's reason.
  const v = verifyEmiliaReceipt(doc, {
    allowInlineKey: true,           // demo only: integrity, not trust
    action: SAMPLE_ACTION,          // receipt MUST be bound to this action
    maxAgeSec: 900,                 // and fresh
    allowedOutcomes: ['allow', 'allow_with_signoff'],
  });
  if (!v.ok) {
    return NextResponse.json(
      {
        ...receiptChallenge(SAMPLE_ACTION, `Refusing an irreversible action: receipt rejected (${v.reason}).`),
        rejected: v,
        loop: { rule: 'No receipt, no irreversible action.', sample_action: SAMPLE_ACTION },
      },
      { status: 402, headers: { 'WWW-Authenticate': WWW_AUTH } },
    );
  }

  // 4) Valid receipt → the irreversible action is authorized.
  //    (Demo: nothing is actually destroyed.) We retain only the
  //    non-sensitive verification facts as our accountability record.
  return NextResponse.json({
    status: 200,
    allowed: true,
    action: SAMPLE_ACTION,
    note: 'Demo only — no data was destroyed. With a valid receipt the irreversible action would run, and the service would keep this receipt as its own portable accountability evidence.',
    evidence: {
      receipt_id: v.receipt_id,
      subject: v.subject,
      outcome: v.outcome,
      signer: v.signer,             // already truncated by the verifier
    },
  });
}

/** Convenience: GET explains the loop and how to drive it. */
export async function GET() {
  return NextResponse.json({
    title: 'EMILIA require-receipt demo',
    rule: 'No receipt, no irreversible action.',
    sample_action: SAMPLE_ACTION,
    try_it: {
      refuse: 'POST here with no receipt → 402 EMILIA Receipt Required.',
      allow: 'POST here with header X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>) bound to action "' + SAMPLE_ACTION + '" → 200.',
    },
    docs: 'https://www.emiliaprotocol.ai/agent-guard',
  });
}
