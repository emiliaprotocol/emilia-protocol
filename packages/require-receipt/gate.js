/**
 * @emilia-protocol/require-receipt — makeReceiptGate
 * @license Apache-2.0
 *
 * The canonical, hardened Receipt-Required gate. Encodes, in ONE reviewed place,
 * the three properties that are easy to get wrong when hand-rolling a guard:
 *
 *   1. TARGET BINDING — a receipt is bound to the exact resource, not just the
 *      action type, so a valid receipt for resource A cannot act on resource B.
 *   2. CONSUME-AFTER-SUCCESS (+ replay safety) — a receipt is RESERVED for the
 *      duration of the side effect, COMMITTED (one-time-consumed) only if the
 *      action succeeds, and RELEASED if it fails — so a transient failure never
 *      burns a valid approval, and a reserved/consumed receipt can never drive a
 *      second action (concurrent or after restart, given a shared store).
 *   3. SANITIZED REJECTIONS — a refusal returns only a `{ reason }` code, never
 *      the verified receipt's signer/subject/library detail.
 *
 * Prefer `gate.run(receipt, { target }, fn)` — it orchestrates verify → run →
 * commit/release so a caller cannot get the ordering wrong. Use the lower-level
 * `check` / `commit` / `release` only when you must gate and act in separate steps.
 */
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  RECEIPT_REQUIRED_STATUS,
} from './index.js';

/** Default in-memory consumed-store. Process-local — pass a shared/durable store
 *  ({ has, add }) for multi-instance or restart-durable one-time consumption. */
function inMemoryStore() {
  const consumed = new Set();
  return { has: (id) => consumed.has(id), add: (id) => consumed.add(id) };
}

function normalizeTarget(target) {
  if (target === undefined || target === null) return null;
  if (Array.isArray(target)) return target.map(String).sort().join(',');
  return String(target);
}

export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

function normalizeAssuranceClass(value) {
  return ASSURANCE_TIERS.includes(value) ? value : 'software';
}

/**
 * Conservative tier earned by the receipt itself.
 * - software: a valid software-held receipt.
 * - class_a: a human signoff receipt (`allow_with_signoff` or explicit signoff).
 * - quorum: explicit quorum evidence with threshold >= 2 and >= 2 distinct humans.
 */
export function receiptAssuranceTier(doc) {
  const p = doc?.payload || {};
  const q = p.quorum || p.claim?.quorum;
  const signers = q && (q.signers || q.approvers);
  const threshold = Number(q && (q.m ?? q.threshold ?? (Array.isArray(signers) ? signers.length : 0)));
  if (q && Array.isArray(signers) && Number.isFinite(threshold) && threshold >= 2) {
    const distinct = new Set(signers.map((s) => String(s))).size;
    if (distinct >= 2) return 'quorum';
  }
  if (p.signoff || p.claim?.outcome === 'allow_with_signoff') return 'class_a';
  return 'software';
}

/**
 * Build a hardened Receipt-Required gate for one action type.
 *
 * @param {object} opts
 * @param {string|((target:any)=>string)} opts.action  base action_type, or a fn
 *   that derives the fully-bound action from the target.
 * @param {string[]} [opts.trustedKeys]      issuer SPKI keys you trust (recommended).
 * @param {boolean} [opts.allowInlineKey=false] also accept the receipt's own key
 *   (proves integrity, NOT issuer trust) — demo only; leave off in production.
 * @param {number} [opts.maxAgeSec=900]
 * @param {string[]} [opts.allowedOutcomes]
 * @param {number} [opts.statusCode=428]
 * @param {string} [opts.manifestUrl]
 * @param {string} [opts.assuranceClass]
 * @param {object} [opts.quorum]
 * @param {{has:(id:string)=>boolean, add:(id:string)=>void}} [opts.store]
 *   consumed-receipt store; defaults to in-memory (process-local). A durable
 *   store makes one-time consumption survive restarts and span instances. The
 *   in-flight reservation that blocks *concurrent* replay is always process-local.
 */
export function makeReceiptGate(opts = {}) {
  const {
    action,
    trustedKeys = [],
    allowInlineKey = false,
    maxAgeSec = 900,
    allowedOutcomes,
    statusCode = RECEIPT_REQUIRED_STATUS,
    manifestUrl,
    assuranceClass,
    quorum,
    store = inMemoryStore(),
  } = opts;

  if (!action) throw new Error('makeReceiptGate: `action` is required');

  const inflight = new Set(); // reservations held during an in-progress action

  const boundActionFor = (target) => {
    const base = typeof action === 'function' ? action(target) : action;
    if (typeof action === 'function') return base; // fn already folds in the target
    const t = normalizeTarget(target);
    return t === null ? base : `${base}:${t}`;
  };

  const requiredTier = normalizeAssuranceClass(assuranceClass);
  const challengeOpts = () => ({ statusCode, manifestUrl, assuranceClass: requiredTier, quorum, maxAgeSec });

  function refuse(boundAction, reason) {
    return {
      ok: false,
      status: statusCode,
      body: { ...receiptChallenge(boundAction, `Receipt rejected: ${reason}.`, challengeOpts()), rejected: { reason } },
    };
  }

  /**
   * Verify + reserve a receipt WITHOUT consuming it. On ok, the caller MUST
   * later call commit(receiptId) on success or release(receiptId) on failure.
   * @returns {{ok:true, receiptId, outcome, signer, subject, boundAction}
   *          | {ok:false, status, body}}
   */
  function check(receipt, { target } = {}) {
    const boundAction = boundActionFor(target);

    if (!receipt) {
      return {
        ok: false,
        status: statusCode,
        body: receiptChallenge(boundAction, 'This action requires an accountable, verifiable authorization receipt.', challengeOpts()),
      };
    }

    const v = verifyEmiliaReceipt(receipt, { trustedKeys, allowInlineKey, action: boundAction, maxAgeSec, allowedOutcomes });
    if (!v.ok) return refuse(boundAction, v.reason); // sanitized: reason code only

    const haveTier = receiptAssuranceTier(receipt);
    if ((TIER_RANK[haveTier] ?? 0) < (TIER_RANK[requiredTier] ?? 0)) {
      return refuse(boundAction, 'assurance_too_low');
    }

    if (store.has(v.receipt_id) || inflight.has(v.receipt_id)) return refuse(boundAction, 'replay_refused');

    inflight.add(v.receipt_id); // reserve for the duration of the action
    return { ok: true, receiptId: v.receipt_id, outcome: v.outcome, signer: v.signer, subject: v.subject, boundAction };
  }

  /** Finalize one-time consumption after the action SUCCEEDS. */
  function commit(receiptId) {
    inflight.delete(receiptId);
    store.add(receiptId);
  }

  /** Release the reservation after the action FAILS — the approval stays retryable. */
  function release(receiptId) {
    inflight.delete(receiptId);
  }

  /**
   * The safe path: verify+reserve, run the side effect, then commit on success
   * or release on failure. `fn` MUST throw on failure (so the approval is not
   * consumed). Receives the check result: fn({ receiptId, outcome, signer, ... }).
   * @returns {Promise<{ok:true, receiptId, outcome, signer, result}|{ok:false, status, body}>}
   */
  async function run(receipt, ctx, fn) {
    if (typeof ctx === 'function') { fn = ctx; ctx = {}; }
    const c = check(receipt, ctx || {});
    if (!c.ok) return c;
    try {
      const result = await fn(c);
      commit(c.receiptId);
      return { ok: true, receiptId: c.receiptId, outcome: c.outcome, signer: c.signer, result };
    } catch (err) {
      release(c.receiptId); // failure -> not consumed -> retryable
      throw err;
    }
  }

  return { check, commit, release, run, boundActionFor };
}
