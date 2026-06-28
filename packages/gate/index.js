/**
 * @emilia-protocol/gate — EMILIA Gate: the Trusted Action Firewall.
 * @license Apache-2.0
 *
 * Deny-by-default enforcement for consequential machine actions. A guarded
 * action runs ONLY if it arrives with a receipt that is:
 *   1. valid          — Ed25519 over canonical JSON, signed by a pinned issuer;
 *   2. in-scope       — bound to the exact action the manifest guards;
 *   3. sufficiently   — meets the action's required assurance tier
 *      assured           (software / class_a device signoff / quorum);
 *   4. fresh          — within max age; and
 *   5. unused         — not a replay (one-time consumption).
 * Otherwise it is refused with a machine-readable Receipt-Required challenge
 * (HTTP 428). Every decision is appended to a tamper-evident evidence log.
 *
 * It is NOT authentication ("who are you") and NOT permissions ("are you
 * allowed here"). It is a policy-enforcement point that requires portable proof
 * a named human authorized THIS exact action before the world is mutated.
 *
 * Composes @emilia-protocol/require-receipt (manifest + verify + challenge) and
 * adds the three things a firewall needs over a bare verifier: assurance-tier
 * enforcement, replay defense, and the evidence log. Fails closed.
 */
import {
  verifyEmiliaReceipt,
  receiptChallenge,
  receiptRequiredHeader,
  validateActionRiskManifest,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
  RECEIPT_REQUIRED_HEADER,
} from '../require-receipt/index.js';
import { MemoryConsumptionStore } from './store.js';
import { createEvidenceLog } from './evidence.js';

export { MemoryConsumptionStore, createEvidenceLog };
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

/**
 * The assurance tier a receipt demonstrably meets. Conservative / fail-closed:
 * if a higher tier's structure is not present, the receipt only earns the lower
 * tier, and a guard that needs more will refuse it.
 *   quorum   — a quorum block with >= 2 distinct signers and threshold >= 2.
 *   class_a  — a device signoff (or claim.outcome === 'allow_with_signoff').
 *   software — any otherwise-valid receipt (a software-held key).
 */
export function receiptAssuranceTier(doc) {
  const p = doc?.payload || {};
  const q = p.quorum || p.claim?.quorum;
  const signers = q && (q.signers || q.approvers);
  const threshold = q && (q.m ?? q.threshold ?? (Array.isArray(signers) ? signers.length : 0));
  if (q && Array.isArray(signers) && signers.length >= 2 && threshold >= 2) return 'quorum';
  if (p.signoff || p.claim?.outcome === 'allow_with_signoff') return 'class_a';
  return 'software';
}

/**
 * Create a gate.
 * @param {object} opts
 * @param {object} [opts.manifest]      EP-ACTION-RISK-MANIFEST-v0.1 (which actions are guarded, their tier)
 * @param {string[]} [opts.trustedKeys] base64url SPKI-DER issuer keys you trust
 * @param {number} [opts.maxAgeSec=900] reject receipts older than this
 * @param {object} [opts.store]         consumption store (default in-memory)
 * @param {object} [opts.log]           evidence log (default in-memory, hash-chained)
 * @param {boolean} [opts.allowInlineKey=false] accept the receipt's own key (integrity, NOT trust)
 */
export function createGate({ manifest = null, trustedKeys = [], maxAgeSec = 900, store, log, allowInlineKey = false, allowEphemeralStore = false, strictEvidence = true, now = Date.now } = {}) {
  if (manifest) {
    const m = validateActionRiskManifest(manifest);
    if (!m.ok) throw new Error('EMILIA Gate: invalid action-risk manifest: ' + m.errors.join('; '));
  }
  if (allowInlineKey) {
    // eslint-disable-next-line no-console
    console.warn('EMILIA Gate: allowInlineKey=true accepts a receipt\'s OWN key. This proves INTEGRITY (the receipt was not tampered with) but NOT issuer TRUST (anyone can mint a receipt with their own key). Use for demos only; pin trustedKeys in production.');
  }
  // Replay defense is only sound if the consumption store is shared across every
  // instance that can serve the action. The in-memory default is per-process, so
  // a receipt consumed on one pod/lambda could be replayed on another. Fail
  // CLOSED in production unless the operator explicitly accepts a single instance.
  let consumption = store;
  if (!consumption) {
    const isProd = typeof process !== 'undefined' && process.env && process.env.NODE_ENV === 'production';
    if (isProd && !allowEphemeralStore) {
      throw new Error('EMILIA Gate: no consumption store provided. The default in-memory store is per-process and is NOT safe for multi-instance or serverless deployments — a receipt consumed on one instance can be replayed on another, defeating one-time consumption. Provide a shared store ({ async consume(key) {...} }, e.g. Redis/DB-backed), or pass allowEphemeralStore:true to acknowledge a single-instance deployment.');
    }
    consumption = new MemoryConsumptionStore();
  }
  const evidence = log || createEvidenceLog({ strict: strictEvidence });

  async function check({ selector = {}, receipt = null } = {}) {
    const requirement = manifest ? findActionRequirement(manifest, selector) : null;
    const action = requirement?.action_type || selector.action_type || selector.action || null;
    const requiredTier = requirement?.assurance_class || selector.assurance_class || 'software';

    async function decide(allow, status, reason, extra = {}) {
      const entry = {
        kind: 'decision',
        at: new Date(typeof now === 'function' ? now() : now).toISOString(),
        action,
        allow,
        status,
        reason,
        selector: { ...selector },
        required_tier: requiredTier,
        receipt_id: receipt?.payload?.receipt_id ?? null,
        subject: receipt?.payload?.subject ?? null,
        ...extra,
      };
      let record;
      try {
        record = await evidence.record(entry);
      } catch (e) {
        // The decision could not be durably recorded. Fail CLOSED: never
        // authorize an action we cannot account for. Downgrade any allow to a
        // refusal and best-effort note the downgrade (non-fatal if that fails too).
        allow = false;
        status = RECEIPT_REQUIRED_STATUS;
        reason = 'evidence_log_failed';
        try {
          record = await evidence.record({ ...entry, allow: false, status, reason, evidence_error: String(e?.message ?? e) });
        } catch {
          record = null;
        }
      }
      const out = { allow, status, reason, action, requirement, evidence: record };
      if (!allow) {
        out.challenge = receiptChallenge(action, reason, {
          status: RECEIPT_REQUIRED_STATUS,
          assuranceClass: requiredTier,
          maxAgeSec,
          manifest: selector.manifestUrl,
        });
        out.header = receiptRequiredHeader({ action, assuranceClass: requiredTier, maxAgeSec });
      }
      return out;
    }

    // Manifest present and this selector is not guarded (or explicitly not required): pass through.
    if (manifest && (!requirement || requirement.receipt_required === false)) {
      return decide(true, 200, 'not_guarded');
    }
    // Guarded, but no receipt was presented.
    if (!receipt) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_required');
    }
    // Signature / freshness / action-binding / outcome.
    const v = verifyEmiliaReceipt(receipt, { trustedKeys, allowInlineKey, action, maxAgeSec });
    if (!v.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, `receipt_rejected:${v.reason}`, { rejected: v });
    }
    // Assurance tier.
    const have = receiptAssuranceTier(receipt);
    if ((TIER_RANK[have] ?? 0) < (TIER_RANK[requiredTier] ?? 0)) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'assurance_too_low', { have_tier: have, need_tier: requiredTier });
    }
    // One-time consumption (replay defense). Require a stable, issuer-generated
    // receipt_id — never fall back to a content hash, whose canonicalization can
    // differ across language implementations and silently break replay detection
    // when services of different languages share a store.
    const receiptId = receipt?.payload?.receipt_id;
    if (!receiptId) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_rejected:missing_receipt_id');
    }
    const fresh = await consumption.consume(receiptId);
    if (!fresh) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'replay_refused', { consumption_key: receiptId });
    }
    return decide(true, 200, 'allow', { signer: v.signer, outcome: v.outcome, have_tier: have });
  }

  /** Express/Connect middleware: refuse the route unless a sufficient receipt is present. */
  function middleware(opts = {}) {
    return async function emiliaGate(req, res, next) {
      let selector = typeof opts.selector === 'function' ? opts.selector(req) : { ...(opts.selector || {}) };
      if (opts.action && !selector.action_type) {
        selector.action_type = typeof opts.action === 'function' ? opts.action(req) : opts.action;
      }
      let doc = null;
      const hdr = req.headers?.['x-emilia-receipt'];
      if (hdr) { try { doc = JSON.parse(Buffer.from(hdr, 'base64').toString('utf8')); } catch { /* fallthrough */ } }
      if (!doc && req.body?.emilia_receipt) doc = req.body.emilia_receipt;
      const out = await check({ selector, receipt: doc });
      if (!out.allow) {
        res.setHeader(RECEIPT_REQUIRED_HEADER, out.header);
        return res.status(out.status).json(out.challenge);
      }
      req.emiliaGate = out;
      return next();
    };
  }

  /**
   * Emit a post-execution receipt bound to a prior authorization decision — the
   * "execution emits proof" half of the loop (maps to the EP Commit seal). It
   * commits to the exact authorization decision (`authorizes_decision` = that
   * decision's evidence hash), so authorization and execution are one chain.
   */
  async function recordExecution({ authorization, outcome = 'executed', detail } = {}) {
    const auth = authorization?.evidence || authorization || {};
    return evidence.record({
      kind: 'execution',
      at: new Date(typeof now === 'function' ? now() : now).toISOString(),
      authorizes_decision: auth.hash ?? null,
      action: authorization?.action ?? auth.action ?? null,
      receipt_id: auth.receipt_id ?? null,
      outcome, // 'executed' | 'failed'
      ...(detail !== undefined ? { detail } : {}),
    });
  }

  /**
   * Wrap any function so it runs only behind a passing gate check, and (unless
   * disabled) emits an execution receipt after it runs — the full firewall loop:
   * request -> check -> execute -> execution receipt. Framework-agnostic.
   */
  function guard(fn, opts = {}) {
    return async function guarded(...args) {
      const selector = typeof opts.selector === 'function' ? opts.selector(...args) : (opts.selector || {});
      const receipt = typeof opts.receipt === 'function' ? opts.receipt(...args) : (opts.receipt ?? null);
      const out = await check({ selector, receipt });
      if (!out.allow) {
        const e = new Error(`EMILIA Gate refused (${out.reason})`);
        e.code = 'EMILIA_RECEIPT_REQUIRED';
        e.gate = out;
        throw e;
      }
      if (opts.recordExecution === false) return fn(...args);
      try {
        const result = await fn(...args);
        await recordExecution({ authorization: out, outcome: 'executed' });
        return result;
      } catch (e) {
        await recordExecution({ authorization: out, outcome: 'failed', detail: String(e?.message ?? e) });
        throw e;
      }
    };
  }

  return { check, recordExecution, middleware, guard, evidence, store: consumption };
}

export default { createGate, receiptAssuranceTier, MemoryConsumptionStore, createEvidenceLog, ASSURANCE_TIERS };
