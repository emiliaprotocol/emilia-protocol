/**
 * POST /api/demo/x402  — the demand-side rail, spoken in x402.
 * @license Apache-2.0
 *
 * The "No receipt, no irreversible action" loop, made x402/AP2-native so an
 * agent client recognizes the demand without bespoke code:
 *
 *   • No proof      → 402 with an x402 `accepts` block naming the authorization
 *                     proof to bring (an EP-ENVELOPE-v1 for any registered
 *                     profile, or a bare EP-RECEIPT-v1), carried in X-PAYMENT.
 *   • Invalid proof → 402 + the verifier's reason.
 *   • Valid proof   → 200, action released, with an X-PAYMENT-RESPONSE settlement
 *                     header (the x402 analogue of a paid-receipt).
 *
 * The proof is verified OFFLINE. An EP-ENVELOPE rides the registry verifier
 * (verifyEnvelope) — the keystone as the demand currency: one rail accepts the
 * whole profile family. This is NOT auth or permissions; it is portable
 * accountability evidence the service keeps for its own liability. Demo accepts
 * self-signed receipts (integrity, not trust); production pins issuer keys.
 */

import { NextResponse } from 'next/server';
import { x402ReceiptChallenge, verifyX402Proof } from '@/lib/require-receipt/x402.js';

export const runtime = 'nodejs';

const SAMPLE_ACTION = 'demo.delete_production_database';

function challenge(request) {
  return x402ReceiptChallenge({
    resource: new URL(request.url).pathname,
    action: SAMPLE_ACTION,
    description: 'Refusing an irreversible action (delete production database): present a verifiable EMILIA authorization proof that a named human approved THIS exact action.',
  });
}

export async function POST(request) {
  // Proof carried in X-PAYMENT (x402) — fall back to legacy header / body.
  let payment = request.headers.get('x-payment') || request.headers.get('x-emilia-receipt') || null;
  if (!payment) {
    const body = await request.json().catch(() => ({}));
    if (body?.emilia_receipt) payment = body.emilia_receipt; // already-decoded object
  }

  if (!payment) {
    return NextResponse.json(challenge(request), { status: 402, headers: { 'WWW-Authenticate': `x402 scheme="emilia-receipt", action="${SAMPLE_ACTION}"` } });
  }

  // Verify. Demo: integrity-only for bare receipts (allowInlineKey) bound to the
  // sample action; an EP-ENVELOPE rides the registry verifier and fails closed
  // on its own (unpinned keys etc.).
  const v = verifyX402Proof(payment, {
    allowInlineKey: true,
    action: SAMPLE_ACTION,
    maxAgeSec: 900,
    allowedOutcomes: ['allow', 'allow_with_signoff'],
  });

  if (!v.valid) {
    return NextResponse.json(
      { ...challenge(request), rejected: { reason: v.reason, detail: v.detail, errors: v.errors } },
      { status: 402, headers: { 'WWW-Authenticate': `x402 scheme="emilia-receipt", action="${SAMPLE_ACTION}"` } },
    );
  }

  return NextResponse.json(
    {
      status: 200,
      allowed: true,
      action: SAMPLE_ACTION,
      proof_profile: v.profile,
      note: 'Demo only — nothing was destroyed. With a valid proof the irreversible action would run; the service keeps the proof as its accountability evidence.',
      settlement: v.settlement,
    },
    { status: 200, headers: { 'X-PAYMENT-RESPONSE': Buffer.from(JSON.stringify(v.settlement)).toString('base64') } },
  );
}

export async function GET(request) {
  return NextResponse.json({
    title: 'EMILIA × x402 — require-receipt (demand-side rail)',
    rule: 'No receipt, no irreversible action.',
    sample_action: SAMPLE_ACTION,
    accepts: x402ReceiptChallenge({ action: SAMPLE_ACTION }).accepts,
    try_it: {
      refuse: 'POST with no X-PAYMENT → 402 with an x402 accepts block.',
      allow: 'POST with X-PAYMENT: base64(<EP-ENVELOPE-v1 or EP-RECEIPT-v1>) bound to the action → 200 + X-PAYMENT-RESPONSE.',
    },
    registry: '/.well-known/ep-profiles.json',
    docs: 'https://www.emiliaprotocol.ai/agent-guard',
  });
}
