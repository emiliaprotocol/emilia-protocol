// SPDX-License-Identifier: Apache-2.0
//
// Public, unauthenticated demo evidence endpoint — the URL the
// "verify yourself" code block on /r/example targets.
//
// The production endpoint at /api/v1/trust-receipts/{id}/evidence
// requires authentication (correct, as it returns evidence over real
// tenant data). For the public demo, that auth requirement is a
// credibility-killer: a cold buyer is told to copy a curl + a verify
// snippet, runs it, gets back 401, and concludes the protocol is hand-
// wavy.
//
// This endpoint serves ONLY the synthetic /r/example demo receipt and
// is unauth'd by design. It returns:
//   {
//     document: <signed EP-RECEIPT-v1>,
//     public_key: <base64url SPKI DER Ed25519 public key>,
//     evidence: <full evidence packet — narrative + risk signals +
//                approvers + timeline + consume>
//   }
//
// A buyer pipes `document` and `public_key` into verifyReceipt() from
// @emilia-protocol/verify@1.0.1+ and gets `{ valid: true, ... }` —
// proving the entire deeply-nested payload (claim, context, risk_signals,
// change.after_bank_hash, etc.) is cryptographically bound.
//
// CORS: open. The endpoint is intentionally browseable from anywhere.

import { NextResponse } from 'next/server';
import { getDemoReceipt, isDemoReceiptId, getDemoPublicKeyBase64url } from '@/lib/demo-receipt.js';
import { logger } from '@/lib/logger.js';

const HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Cache-Control': 'public, max-age=60',
};

export async function GET(_request, { params }) {
  try {
    const { receiptId } = await params;
    if (!isDemoReceiptId(receiptId)) {
      logger.info('[demo-evidence] non-demo receiptId requested:', receiptId);
      return NextResponse.json(
        {
          type: 'about:blank',
          title: 'demo_receipt_only',
          status: 404,
          detail: 'This endpoint serves only the public /r/example demo receipt. For real receipts use /api/v1/trust-receipts/{id}/evidence (auth required).',
        },
        { status: 404, headers: HEADERS },
      );
    }

    const r = getDemoReceipt();
    logger.debug?.('[demo-evidence] served', { receiptId });

    return NextResponse.json(
    {
      receipt_id: r.receipt_id,
      document: r.document,
      public_key: getDemoPublicKeyBase64url(),
      evidence: {
        organization_id: r.organization_id,
        action_type: r.action_type,
        decision: r.decision,
        enforcement_mode: r.enforcement_mode,
        narrative: r.narrative,
        risk_signals: r.risk_signals,
        change_hashes: r.change_hashes,
        payments_at_risk_usd: r.payments_at_risk_usd,
        signoff: r.signoff,
        consume: r.consume,
        timeline: r.timeline,
        expires_at: r.expires_at,
      },
      is_demo: true,
      verify_with: '@emilia-protocol/verify',
      verify_command: 'npm install @emilia-protocol/verify',
    },
    { status: 200, headers: HEADERS },
  );
  } catch (err) {
    logger.error('[demo-evidence] handler error:', err);
    return NextResponse.json(
      { type: 'about:blank', title: 'internal_error', status: 500, detail: 'Demo evidence fetch failed' },
      { status: 500, headers: HEADERS },
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: HEADERS });
}
