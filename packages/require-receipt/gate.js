/**
 * @emilia-protocol/require-receipt — makeReceiptGate
 * @license Apache-2.0
 *
 * The canonical, hardened Receipt-Required gate. Encodes, in ONE reviewed place,
 * the three properties that are easy to get wrong when hand-rolling a guard:
 *
 *   1. TARGET BINDING — a receipt is bound to the exact resource, not just the
 *      action type, so a valid receipt for resource A cannot act on resource B.
 *   2. CONSUME-BEFORE-RETRY (+ replay safety) — a receipt is RESERVED before the
 *      side effect and permanently COMMITTED after any execution attempt. Once
 *      execution begins, an exception cannot distinguish "nothing happened"
 *      from "the effect happened but its response was lost", so automatic retry
 *      would risk duplicating an irreversible action.
 *   3. SANITIZED REJECTIONS — a refusal returns only a `{ reason }` code, never
 *      the verified receipt's signer/subject/library detail.
 *
 * Prefer `gate.run(receipt, { target }, fn)` — it orchestrates verify → reserve →
 * attempt → commit so a caller cannot get the ordering wrong. Use the lower-level
 * `check` / `commit` / `release` only when you can prove the effect has not begun.
 */
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  RECEIPT_REQUIRED_STATUS,
  evaluateReceiptAssurance,
  receiptAssuranceTier,
} from './index.js';

/** Default process-local atomic store. Fleets must pass an ownership-fenced
 * shared store implementing the same reserve/commit/release contract. */
function inMemoryStore() {
  const states = new Map();
  return {
    durable: false,
    ownershipFenced: true,
    async reserve(id) {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id) {
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.delete(id);
      return true;
    },
  };
}

function normalizeTarget(target) {
  if (target === undefined || target === null) return null;
  if (Array.isArray(target)) return target.map(String).sort().join(',');
  return String(target);
}

const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

function normalizeGateAssuranceClass(value) {
  return Object.prototype.hasOwnProperty.call(TIER_RANK, value) ? value : 'software';
}

export { receiptAssuranceTier };

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
 * @param {object} [opts.quorumPolicy] relying-party-pinned organizational quorum rule
 * @param {{reserve:(id:string)=>Promise<boolean>|boolean,
 *   commit:(id:string)=>Promise<boolean>|boolean,
 *   release:(id:string)=>Promise<boolean>|boolean}} [opts.store]
 *   Atomic ownership-fenced consumption store; defaults to process-local memory.
 *   Fleet stores MUST make reserve() an atomic insert-if-absent and MUST leave an
 *   uncertain reservation closed until operator reconciliation.
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
    quorumPolicy,
    approverKeys,
    approver_keys,
    verifyAssurance,
    rpId,
    allowedOrigins,
    store = inMemoryStore(),
  } = opts;

  if (!action) throw new Error('makeReceiptGate: `action` is required');
  for (const method of ['reserve', 'commit', 'release']) {
    if (typeof store?.[method] !== 'function') {
      throw new Error(`makeReceiptGate: store must implement atomic ${method}(); legacy {has, add} stores are not fleet-safe`);
    }
  }

  const boundActionFor = (target) => {
    const base = typeof action === 'function' ? action(target) : action;
    if (typeof action === 'function') return base; // fn already folds in the target
    const t = normalizeTarget(target);
    return t === null ? base : `${base}:${t}`;
  };

  const requiredTier = normalizeGateAssuranceClass(assuranceClass);
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
   * later call commit(receiptId) after an execution attempt, or release(receiptId)
   * only when it can prove the external effect never began.
   * @returns {{ok:true, receiptId, outcome, signer, subject, boundAction}
   *          | {ok:false, status, body}}
   */
  async function check(receipt, { target } = {}) {
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

    const assurance = evaluateReceiptAssurance(receipt, requiredTier, {
      approverKeys, approver_keys, verifyAssurance, rpId, allowedOrigins, quorumPolicy,
    });
    if (!assurance.ok || (TIER_RANK[assurance.have] ?? 0) < (TIER_RANK[requiredTier] ?? 0)) {
      return refuse(boundAction, assurance.reason || 'assurance_too_low');
    }

    let reserved;
    try {
      reserved = await store.reserve(v.receipt_id);
    } catch {
      return refuse(boundAction, 'consumption_store_unavailable');
    }
    if (reserved !== true) return refuse(boundAction, 'replay_refused');
    return { ok: true, receiptId: v.receipt_id, outcome: v.outcome, signer: v.signer, subject: v.subject, boundAction };
  }

  /** Finalize one-time consumption after an execution attempt begins. */
  async function commit(receiptId) {
    const committed = await store.commit(receiptId);
    if (committed !== true) throw new Error('consumption commit failed closed');
  }

  /** Release only when the caller can prove the external effect never began. */
  async function release(receiptId) {
    const released = await store.release(receiptId);
    if (released !== true) throw new Error('consumption release failed closed');
  }

  /**
   * The safe path: verify+reserve, run the side effect, then commit regardless
   * of its return value. An exception after invocation is an indeterminate
   * outcome and MUST consume the approval to prevent duplicate execution.
   * Receives the check result: fn({ receiptId, outcome, signer, ... }).
   * @returns {Promise<{ok:true, receiptId, outcome, signer, result}|{ok:false, status, body}>}
   */
  async function run(receipt, ctx, fn) {
    if (typeof ctx === 'function') { fn = ctx; ctx = {}; }
    if (typeof fn !== 'function') throw new Error('makeReceiptGate.run: fn is required');
    const c = await check(receipt, ctx || {});
    if (!c.ok) return c;
    let attempted = false;
    let committed = false;
    try {
      attempted = true;
      const result = await fn(c);
      await commit(c.receiptId);
      committed = true;
      return { ok: true, receiptId: c.receiptId, outcome: c.outcome, signer: c.signer, result };
    } catch (err) {
      if (attempted && !committed) {
        try {
          await commit(c.receiptId); // effect may have occurred before the exception
        } catch (commitError) {
          if (err && typeof err === 'object') {
            err.consumption_error = String(commitError?.message ?? commitError);
          }
        }
      }
      throw err;
    }
  }

  return { check, commit, release, run, boundActionFor };
}
