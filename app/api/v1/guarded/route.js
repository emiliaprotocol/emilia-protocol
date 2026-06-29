import { NextResponse } from 'next/server';
import { receiptChallenge } from '@/packages/require-receipt/index.js';
import { verifyReceiptForProduction, assertGovVerifierReady } from '@/lib/gov-receipt-verifier.js';
import { readLimitedJson } from '@/lib/http/body-limit';

export const runtime = 'nodejs';

const MAX_GUARDED_BYTES = 256 * 1024;

/**
 * POST /api/v1/guarded[?action=payment.release]
 *
 * A live reference of the DEMAND side: a protected endpoint that refuses to run
 * an irreversible action unless it arrives with a verifiable EMILIA receipt.
 * No receipt → 402 with a machine-readable challenge (so an agent self-serves
 * one and retries). This is what any counterparty drops in front of an
 * agent-facing action to start *demanding* accountability.
 *
 * Production semantics: trusted issuer keys are pinned and inline/self-asserted
 * keys are refused. The self-signed try-it flow lives under /api/demo/* only.
 *
 * Present a receipt via header `X-EMILIA-Receipt: base64(<EP-RECEIPT-v1 JSON>)`
 * or body `{ "emilia_receipt": <doc> }`.
 */
export async function POST(request) {
  const action = new URL(request.url).searchParams.get('action') || 'payment.release';
  const parsed = await readLimitedJson(request, MAX_GUARDED_BYTES, { invalidValue: {} });
  if (!parsed.ok) return NextResponse.json(receiptChallenge(action, 'Request body too large.'), { status: parsed.status });

  let doc = null;
  const body = parsed.value;
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

  const ready = assertGovVerifierReady();
  if (!ready.ok) {
    return NextResponse.json({
      ...receiptChallenge(action, 'Receipt verifier is not configured with pinned issuer keys. To try the self-signed flow, use POST /api/demo/require-receipt.'),
      rejected: { ok: false, reason: 'verifier_not_ready', errors: ready.errors },
    }, { status: 503 });
  }

  const v = verifyReceiptForProduction(doc, { action, maxAgeSec: 900 });
  if (!v.ok) {
    return NextResponse.json({ ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`), rejected: v }, { status: 402 });
  }

  return NextResponse.json({
    status: 200,
    allowed: true,
    action,
    receipt_id: v.receipt_id,
    subject: v.subject,
    note: 'Receipt verified against pinned issuer keys; inline/self-asserted keys are refused on this endpoint.',
  });
}
