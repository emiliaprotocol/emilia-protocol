import { NextResponse } from 'next/server';
import { parseReceiptCarrier, receiptChallenge } from '@/packages/require-receipt/index.js';
import {
  verifyReceiptForProduction,
  assertGovVerifierReady,
  requiredAssuranceForAction,
  enforceReceiptAssuranceForProduction,
} from '@/lib/gov-receipt-verifier.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { getGuardedConsumptionStore, consumeKey } from '@/lib/http/guarded-consumption.js';
import { logger } from '@/lib/logger.js';

export const runtime = 'nodejs';

const MAX_GUARDED_BYTES = 256 * 1024;
const MAX_RECEIPT_AGE_SEC = 900;

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
    if (hdr) doc = parseReceiptCarrier(hdr, { maxBytes: MAX_GUARDED_BYTES });
  }

  if (!doc) {
    return NextResponse.json(receiptChallenge(action, 'No EMILIA receipt presented.'), {
      status: 402,
      headers: { 'WWW-Authenticate': `EMILIA realm="agent-actions", action="${action}"` },
    });
  }

  const requiredTier = requiredAssuranceForAction(action);
  const ready = assertGovVerifierReady(undefined, { action: /** @type {any} */ (action), requiredTier });
  if (!ready.ok) {
    return NextResponse.json({
      ...receiptChallenge(action, 'Receipt verifier is not configured with pinned issuer keys. To try the self-signed flow, use POST /api/demo/require-receipt.'),
      rejected: { ok: false, reason: 'verifier_not_ready', errors: ready.errors },
    }, { status: 503 });
  }

  // Freshness fail-closed: an undated receipt is refused when a max age is
  // enforced. verifyEmiliaReceipt (as of require-receipt 0.5.2) already treats a
  // missing/unparseable created_at as `receipt_expired`, so this is defense in
  // depth — but we run it FIRST to return the more precise `missing_created_at`
  // diagnostic (tells the agent exactly what to fix) rather than the generic
  // expired label. Both are 402; both fail closed.
  const createdAt = doc?.payload?.created_at;
  if (MAX_RECEIPT_AGE_SEC && !createdAt) {
    const rejected = { ok: false, reason: 'missing_created_at', detail: 'receipt has no created_at; cannot verify freshness' };
    return NextResponse.json({ ...receiptChallenge(action, 'Receipt rejected: missing_created_at.'), rejected }, { status: 402 });
  }

  const v = verifyReceiptForProduction(doc, { action, maxAgeSec: MAX_RECEIPT_AGE_SEC });
  if (!v.ok) {
    return NextResponse.json({ ...receiptChallenge(action, `Receipt rejected: ${v.reason}.`), rejected: v }, { status: 402 });
  }

  // A verified receipt with no receipt_id cannot be bound to a one-time
  // consumption record, so it could be replayed indefinitely (every no-id
  // receipt would collapse to the same empty consume key). Refuse it outright.
  if (!v.receipt_id) {
    const rejected = { ok: false, reason: 'missing_receipt_id', detail: 'receipt has no receipt_id; cannot enforce one-time consumption' };
    return NextResponse.json({ ...receiptChallenge(action, 'Receipt rejected: missing_receipt_id.'), rejected }, { status: 402 });
  }

  // Assurance tier fail-closed: a valid signature only proves the receipt is
  // authentic and action-bound — it does NOT prove the human-authorization tier
  // the action demands. The action-control manifest sets that tier
  // (payment.release=class_a, deploy.production/permission.admin.change=quorum,
  // …). A Class-A/quorum tier is PROVEN only when the receipt carries an
  // assurance_proof that verifies against pinned approver keys; a self-asserted
  // `allow_with_signoff` / `quorum` claim is software-tier until proven. Refuse
  // when the proven tier is below the required tier (428 assurance_too_low), so
  // a software-tier receipt can never authorize a quorum action. Enforce BEFORE
  // consuming the receipt — don't burn a receipt we're going to refuse.
  if (requiredTier && requiredTier !== 'software') {
    const assurance = enforceReceiptAssuranceForProduction(doc, { action, requiredTier });
    if (!assurance.ok) {
      const rejected = {
        ok: false,
        reason: assurance.reason || 'assurance_too_low',
        have_tier: assurance.have,
        need_tier: assurance.need,
      };
      return NextResponse.json({
        ...receiptChallenge(action, `Receipt rejected: ${rejected.reason}.`),
        rejected,
      }, { status: 428 });
    }
  }

  // One-time consumption (replay defense): a verified receipt authorizes ONE
  // action, once. Reserve the receipt id (action-scoped) atomically; a replay of
  // the same receipt loses the race and is refused. Commit after we decide to
  // allow. Fail CLOSED — if the durable store is unavailable in production we
  // cannot prove non-replay, so we refuse rather than allow.
  const key = consumeKey(action, v.receipt_id || '');
  let store;
  try {
    store = await getGuardedConsumptionStore();
  } catch (err) {
    logger.error('[guarded] consumption store unavailable — failing closed', { message: err?.message });
    return NextResponse.json({
      ...receiptChallenge(action, 'Replay-defense store is unavailable; the action cannot be authorized right now.'),
      rejected: { ok: false, reason: 'consumption_store_unavailable' },
    }, { status: 503 });
  }

  if (!store) {
    // Defense in depth: getGuardedConsumptionStore() is only meant to throw
    // (caught above) or resolve to a usable store, never resolve to null/undefined.
    // Fail closed anyway rather than dereference an absent store.
    logger.error('[guarded] consumption store resolved empty — failing closed', {});
    return NextResponse.json({
      ...receiptChallenge(action, 'Replay-defense store is unavailable; the action cannot be authorized right now.'),
      rejected: { ok: false, reason: 'consumption_store_unavailable' },
    }, { status: 503 });
  }

  let reserved;
  try {
    reserved = await store.reserve(key);
  } catch (err) {
    logger.error('[guarded] reserve failed — failing closed', { message: err?.message });
    return NextResponse.json({
      ...receiptChallenge(action, 'Replay-defense store errored; the action cannot be authorized right now.'),
      rejected: { ok: false, reason: 'consumption_store_error' },
    }, { status: 503 });
  }

  if (!reserved) {
    // Already reserved or committed → this is a replay of a consumed receipt.
    return NextResponse.json({
      ...receiptChallenge(action, 'Receipt rejected: already_consumed (replay).'),
      rejected: { ok: false, reason: 'receipt_replayed', receipt_id: v.receipt_id },
    }, { status: 409 });
  }

  try {
    await store.commit(key);
  } catch (err) {
    // Commit failed after a successful reserve. Fail closed: the reservation
    // already blocks replay, so refuse this attempt rather than allow an action
    // whose consumption we couldn't durably record.
    logger.error('[guarded] commit failed — failing closed', { message: err?.message });
    await store.release(key).catch(() => {});
    return NextResponse.json({
      ...receiptChallenge(action, 'Replay-defense store errored while recording consumption.'),
      rejected: { ok: false, reason: 'consumption_commit_failed' },
    }, { status: 503 });
  }

  return NextResponse.json({
    status: 200,
    allowed: true,
    action,
    receipt_id: v.receipt_id,
    subject: v.subject,
    note: 'Receipt verified against pinned issuer keys and consumed once; replays of this receipt are refused. Inline/self-asserted keys are refused on this endpoint.',
  });
}
