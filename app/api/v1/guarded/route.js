import { NextResponse } from 'next/server';
import { verifyEmiliaReceipt, receiptChallenge } from '@/packages/require-receipt/index.js';

export const runtime = 'nodejs';

/**
 * POST /api/v1/guarded[?action=payment.release]
 *
 * A live reference of the DEMAND side: a protected endpoint that refuses to run
 * an irreversible action unless it arrives with a verifiable EMILIA receipt.
 * No receipt → 402 with a machine-readable challenge (so an agent self-serves
 * one and retries). This is what any counterparty drops in front of an
 * agent-facing action to start *demanding* accountability.
 *
 * Reference semantics: integrity-only trust (allowInlineKey) so anyone can try
 * the flow with a self-signed receipt. In production the verifier PINS trusted
 * issuer keys (from /.well-known/ep-keys.json) — see @emilia-protocol/require-receipt.
 *
 * Present a receipt via header `X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)`
 * or body `{ "emilia_receipt": <doc> }`.
 */
export async function POST(request) {
  const action = new URL(request.url).searchParams.get('action') || 'payment.release';

  let doc = null;
  const body = await request.json().catch(() => ({}));
  if (body && body.emilia_receipt) doc = body.emilia_receipt;
  if (!doc) {
    const hdr = request.headers.get('x-emilia-receipt');
    if (hdr) { try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough */ } }
  }

  if (!doc) {
    return NextResponse.json(receiptChallenge(action, 'No EMILIA receipt presented.'), {
      status: 402,
      headers: { 'WWW-Authenticate': `EMILIA realm="agent-actions", action="${action}"` },
    });
  }

  const v = verifyEmiliaReceipt(doc, { allowInlineKey: true, action, maxAgeSec: 900 });
  if (!v.ok) {
    return NextResponse.json({ ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`), rejected: v }, { status: 402 });
  }

  return NextResponse.json({
    status: 200,
    allowed: true,
    action,
    receipt_id: v.receipt_id,
    subject: v.subject,
    note: 'Reference endpoint — receipt integrity verified. Production pins trusted issuer keys instead of allowInlineKey.',
  });
}
