/**
 * @emilia-protocol/gate — EMILIA Gate: the Trusted Action Firewall.
 * @license Apache-2.0
 *
 * Deny-by-default enforcement for consequential machine actions. A guarded
 * action runs ONLY if it arrives with a receipt that is:
 *   1. valid          — Ed25519 over canonical JSON, signed by a pinned issuer;
 *   2. in-scope       — bound to the exact action the manifest guards;
 *   3. sufficiently   — meets the action's required assurance tier, and the
 *      assured           credited tier is CRYPTOGRAPHICALLY VERIFIED, not read
 *                        from self-asserted payload fields: class_a requires a
 *                        valid WebAuthn device signoff, quorum requires a valid
 *                        EP-QUORUM-v1 (distinct humans + distinct keys +
 *                        threshold + per-signer assertions);
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
const {
  verifyEmiliaReceipt,
  receiptChallenge,
  receiptRequiredHeader,
  validateActionRiskManifest,
  findActionRequirement,
  RECEIPT_REQUIRED_STATUS,
  RECEIPT_REQUIRED_HEADER,
} = await import('@emilia-protocol/require-receipt').catch(() => import('../require-receipt/index.js'));
// The real per-signer verifiers (WebAuthn device-signoff + M-of-N quorum). The
// Gate MUST use these to CREDIT class_a / quorum — a receipt's self-asserted
// outcome string or a fabricated quorum block is NOT proof. Same resolution
// pattern as require-receipt: prefer the published package, fall back to the
// in-repo source so the monorepo test/build works without a node_modules link.
const { verifyWebAuthnSignoff, verifyQuorum } = await import('@emilia-protocol/verify')
  .catch(() => import('../verify/index.js'));
import { MemoryConsumptionStore } from './store.js';
import { createEvidenceLog } from './evidence.js';
import { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest } from './action-packs.js';
import { hashCanonical, verifyExecutionBinding } from './execution-binding.js';
import { buildReliancePacket } from './reliance-packet.js';
import { createEg1Harness, makeGateInvoke, runEg1, EG1_DEFAULT_SELECTOR, mintDeviceSignoff, mintQuorumEvidence } from './eg1-conformance.js';
import { createKeyRegistry, asKeyRegistry } from './key-registry.js';
import { classifyRetention, buildRetentionExport } from './retention.js';

export { MemoryConsumptionStore, createEvidenceLog };
export { createDurableConsumptionStore, createMemoryBackend } from './store.js';
export { createKeyRegistry, asKeyRegistry } from './key-registry.js';
export { classifyRetention, buildRetentionExport, RETENTION_EXPORT_VERSION } from './retention.js';
export { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest };
export { EXECUTION_BINDING_VERSION, canonicalize, hashCanonical, materialFieldsFor, verifyExecutionBinding } from './execution-binding.js';
export { RELIANCE_PACKET_VERSION, buildReliancePacket } from './reliance-packet.js';
export {
  EG1_VERSION, EG1_CHECKS, EG1_DEFAULT_ACTION, EG1_DEFAULT_SELECTOR,
  createEg1Harness, makeGateInvoke, runEg1, mintDeviceSignoff, mintQuorumEvidence,
} from './eg1-conformance.js';
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

/**
 * The assurance tier a receipt has CRYPTOGRAPHICALLY EARNED.
 *
 * SECURITY (DoD audit fix): the credited tier is NOT inferred from
 * self-asserted payload fields. A receipt earns:
 *   quorum   — only if it carries an EP-QUORUM-v1 evidence document whose
 *              per-signer WebAuthn assertions verify (distinct humans + distinct
 *              keys + threshold + action-binding + window), via verifyQuorum.
 *   class_a  — only if it carries a device signoff ({context, webauthn}) whose
 *              WebAuthn assertion verifies against the approver's own key, via
 *              verifyWebAuthnSignoff.
 *   software — every other otherwise-valid receipt (a software-held issuer key).
 *
 * A payload that merely CLAIMS quorum (e.g. `quorum:{signers:[...],threshold:2}`
 * with no verifiable signatures) or sets `outcome:'allow_with_signoff'` with no
 * WebAuthn evidence earns only `software` — it will be refused `assurance_too_low`
 * by any guard that needs more. This is fail-closed by construction.
 *
 * @param {object} doc  the EP-RECEIPT-v1 document
 * @param {object} [opts]
 * @param {string} [opts.rpId]  bind device assertions to this WebAuthn RP id
 * @returns {'software'|'class_a'|'quorum'} the highest tier proven, or a detailed
 *          result when opts.detail is set.
 */
export function receiptAssuranceTier(doc, opts = {}) {
  const detail = { tier: 'software', quorum: null, signoff: null };
  const p = doc?.payload || {};
  const verifyOpts = opts.rpId ? { rpId: opts.rpId } : {};

  // --- quorum: require a real, self-contained EP-QUORUM-v1 evidence document. ---
  // Accept it under payload.quorum or payload.claim.quorum. It only counts if it
  // is a full quorum document (policy + members with WebAuthn signoffs) AND
  // verifyQuorum returns valid. A bare {signers,threshold} block has no members
  // to verify and therefore CANNOT be credited quorum.
  const q = p.quorum || p.claim?.quorum;
  if (isQuorumEvidence(q)) {
    const qr = verifyQuorum(q, verifyOpts);
    detail.quorum = { valid: qr.valid, checks: qr.checks };
    if (qr.valid) {
      detail.tier = 'quorum';
      return opts.detail ? detail : 'quorum';
    }
  }

  // --- class_a: require a verifiable WebAuthn device signoff. ---
  // The signoff evidence is {context, webauthn}; the approver key travels with
  // it (signoff.approver_public_key) or alongside it (payload.approver_public_key).
  const so = p.signoff || p.claim?.signoff;
  if (isSignoffEvidence(so)) {
    const key = so.approver_public_key || p.approver_public_key || p.claim?.approver_public_key;
    if (key) {
      const sr = verifyWebAuthnSignoff(so, key, verifyOpts);
      detail.signoff = { valid: sr.valid, checks: sr.checks };
      if (sr.valid) {
        detail.tier = 'class_a';
        return opts.detail ? detail : 'class_a';
      }
    }
  }

  return opts.detail ? detail : 'software';
}

/** A quorum evidence doc must carry members with per-signer signoffs to be verifiable. */
function isQuorumEvidence(q) {
  return !!q && typeof q === 'object' && q.policy && Array.isArray(q.members) && q.members.length > 0
    && typeof q.action_hash === 'string' && q.action_hash.length > 0;
}
/** A device signoff must carry the WebAuthn assertion material to be verifiable. */
function isSignoffEvidence(s) {
  return !!s && typeof s === 'object' && s.context && s.webauthn;
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
 * @param {object} [opts.keyRegistry] a key registry (createKeyRegistry) for rotation + revocation;
 *   if given it supersedes trustedKeys — a receipt is verified only against keys valid (and not
 *   revoked) at its issuance time.
 */
export function createGate({ manifest = null, trustedKeys = [], maxAgeSec = 900, store, log, allowInlineKey = false, allowEphemeralStore = false, strictEvidence = true, now = Date.now, keyRegistry = null, rpId = null } = {}) {
  // Production key custody: a registry (rotation + revocation) supersedes a flat
  // trustedKeys list. A flat list is coerced to an always-valid registry, so
  // existing callers are unchanged.
  const registry = keyRegistry ? asKeyRegistry(keyRegistry) : (trustedKeys.length ? asKeyRegistry(trustedKeys) : null);
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

  async function check({ selector = {}, receipt = null, observedAction = null, consumptionMode = 'consume' } = {}) {
    const requirement = manifest ? findActionRequirement(manifest, selector) : null;
    const action = requirement?.action_type || selector.action_type || selector.action || null;
    const requiredTier = requirement?.assurance_class || selector.assurance_class || 'software';
    const observed = observedAction || selector.observedAction || selector.actionDetails || null;

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
        observed_action_hash: observed ? hashCanonical(observed) : null,
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
    // Signature / freshness / action-binding / outcome. Production key custody:
    // resolve the issuer keys valid (and not revoked) at THIS receipt's issuance
    // time. A revoked or out-of-window key is excluded, so its signature does not
    // verify and the action is refused (fail closed).
    const effectiveKeys = registry
      ? registry.keysValidAt(receipt?.payload?.created_at)
      : trustedKeys;
    const v = verifyEmiliaReceipt(receipt, { trustedKeys: effectiveKeys, allowInlineKey, action, maxAgeSec });
    if (!v.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, `receipt_rejected:${v.reason}`, { rejected: v });
    }
    // Assurance tier. CRYPTOGRAPHICALLY VERIFIED (DoD audit fix): the credited
    // tier comes from re-verifying the receipt's embedded per-signer evidence
    // (WebAuthn device signoff / EP-QUORUM-v1), not from self-asserted payload
    // fields. A receipt that only CLAIMS a higher tier earns 'software' and is
    // refused here.
    const tierResult = receiptAssuranceTier(receipt, { rpId, detail: true });
    const have = tierResult.tier;
    const needRank = TIER_RANK[requiredTier];
    // Fail CLOSED on an unknown / mis-cased required tier: never silently treat
    // it as 'software'. If a manifest asks for a tier this gate does not model,
    // no receipt can satisfy it.
    if (needRank === undefined) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'unknown_required_tier', { have_tier: have, need_tier: requiredTier, assurance_tier_source: 'cryptographic_verification' });
    }
    if ((TIER_RANK[have] ?? 0) < needRank) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'assurance_too_low', {
        have_tier: have, need_tier: requiredTier,
        assurance_tier_source: 'cryptographic_verification',
        tier_evidence: { quorum: tierResult.quorum, signoff: tierResult.signoff },
      });
    }
    // The high-risk action packs define material fields that must be observed
    // by the executor from the system of record. A signed, harmless-looking
    // claim cannot authorize a different real mutation.
    const executionBinding = verifyExecutionBinding({ requirement, receipt, observedAction: observed });
    if (!executionBinding.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'execution_binding_failed', { execution_binding: executionBinding, have_tier: have, assurance_tier_source: 'cryptographic_verification' });
    }
    // One-time consumption (replay defense). Require a stable, issuer-generated
    // receipt_id — never fall back to a content hash, whose canonicalization can
    // differ across language implementations and silently break replay detection
    // when services of different languages share a store.
    const receiptId = receipt?.payload?.receipt_id;
    if (!receiptId) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'receipt_rejected:missing_receipt_id');
    }
    let fresh;
    if (consumptionMode === 'reserve') {
      if (typeof consumption.reserve !== 'function') {
        return decide(false, RECEIPT_REQUIRED_STATUS, 'consumption_store_lacks_reserve', { consumption_key: receiptId });
      }
      fresh = await consumption.reserve(receiptId);
    } else if (consumptionMode === 'none') {
      fresh = true;
    } else {
      fresh = await consumption.consume(receiptId);
    }
    if (!fresh) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'replay_refused', { consumption_key: receiptId });
    }
    return decide(true, 200, 'allow', { signer: v.signer, outcome: v.outcome, have_tier: have, assurance_tier_source: 'cryptographic_verification', execution_binding: executionBinding, consumption_mode: consumptionMode });
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
      const observedAction = typeof opts.observedAction === 'function'
        ? opts.observedAction(req)
        : (opts.observedAction || req.emiliaObservedAction || null);
      const out = await check({ selector, receipt: doc, observedAction });
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
  async function recordExecution({ authorization, outcome = 'executed', detail, observedAction = null, executionBinding = null } = {}) {
    const auth = authorization?.evidence || authorization || {};
    return evidence.record({
      kind: 'execution',
      at: new Date(typeof now === 'function' ? now() : now).toISOString(),
      authorizes_decision: auth.hash ?? null,
      action: authorization?.action ?? auth.action ?? null,
      receipt_id: auth.receipt_id ?? null,
      outcome, // 'executed' | 'failed'
      observed_action_hash: observedAction ? hashCanonical(observedAction) : null,
      execution_binding: executionBinding || authorization?.evidence?.execution_binding || authorization?.execution_binding || null,
      ...(detail !== undefined ? { detail } : {}),
    });
  }

  /**
   * Recommended end-to-end path. Reserves the receipt, runs the side effect,
   * commits one-time consumption only after success, and records execution.
   * If the side effect throws, the reservation is released so the approval can
   * be retried safely.
   */
  async function run({ selector = {}, receipt = null, observedAction = null } = {}, fn, opts = {}) {
    if (typeof fn !== 'function') throw new Error('EMILIA Gate run(): fn is required');
    const authorization = await check({ selector, receipt, observedAction, consumptionMode: 'reserve' });
    if (!authorization.allow) {
      return { ok: false, status: authorization.status, body: authorization.challenge, authorization };
    }
    const receiptId = authorization.evidence?.receipt_id;
    let actionRan = false;
    try {
      const result = await fn(authorization);
      actionRan = true;
      if (typeof consumption.commit === 'function') await consumption.commit(receiptId);
      if (opts.recordExecution === false) return { ok: true, result, authorization, execution: null, packet: null };
      const execution = await recordExecution({ authorization, outcome: 'executed', observedAction });
      return { ok: true, result, authorization, execution, packet: reliancePacket({ authorization, execution }) };
    } catch (e) {
      if (!actionRan && typeof consumption.release === 'function') await consumption.release(receiptId);
      if (opts.recordExecution !== false) {
        await recordExecution({
          authorization,
          outcome: 'failed',
          detail: actionRan ? `post_execution_failure:${String(e?.message ?? e)}` : String(e?.message ?? e),
          observedAction,
        });
      }
      throw e;
    }
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
      const observedAction = typeof opts.observedAction === 'function'
        ? opts.observedAction(...args)
        : (opts.observedAction || selector.observedAction || null);
      const out = await run({ selector, receipt, observedAction }, () => fn(...args), { recordExecution: opts.recordExecution });
      if (!out.ok) {
        const e = new Error(`EMILIA Gate refused (${out.authorization.reason})`);
        e.code = 'EMILIA_RECEIPT_REQUIRED';
        e.gate = out.authorization;
        throw e;
      }
      return out.result;
    };
  }

  function reliancePacket({ authorization, execution = null, binding = null } = {}) {
    return buildReliancePacket({
      decision: authorization,
      execution,
      evidence,
      manifest,
      binding,
    });
  }

  /** Retention classification over this gate's evidence log (hot/cold/expired/legal-hold). */
  function retention(opts = {}) {
    return classifyRetention(evidence.all(), opts);
  }
  /** The auditor/SIEM export manifest for this gate's evidence log. */
  function retentionExport(opts = {}) {
    return buildRetentionExport(evidence.all(), opts);
  }

  return {
    check, run, recordExecution, middleware, guard, reliancePacket, evidence,
    store: consumption, keyRegistry: registry, retention, retentionExport,
  };
}

export function createTrustedActionFirewall(opts = {}) {
  const { manifest = createDefaultActionRiskManifest(), ...rest } = opts;
  return createGate({ ...rest, manifest });
}

/**
 * EG-1 conformance for an existing gate. The gate MUST have been built trusting
 * `harness.publicKey` (otherwise every valid receipt is rejected and the gate
 * cannot earn EG-1). Returns the EG-1 JSON report.
 * @param {object} o
 * @param {object} o.gate     an EMILIA Gate (createGate/createTrustedActionFirewall)
 * @param {object} o.harness  the harness whose key the gate trusts (createEg1Harness)
 * @param {object} [o.action] the high-risk action to exercise
 * @param {object} [o.selector] the manifest selector for that action
 */
export async function gateConformance({ gate, harness, action, selector = EG1_DEFAULT_SELECTOR } = {}) {
  if (!gate || typeof gate.run !== 'function') {
    throw new Error('gateConformance requires a gate built trusting harness.publicKey');
  }
  if (!harness) throw new Error('gateConformance requires the harness whose key the gate trusts');
  const act = action || harness.action;
  const invoke = makeGateInvoke(gate, { selector, action: act });
  return runEg1({ invoke, harness, action: act });
}

/**
 * Self-certify the reference gate: build a default Trusted Action Firewall that
 * trusts a fresh EG-1 harness key, then run all eight checks. This is the
 * canonical "EMILIA Gate earns EG-1" proof — runnable as a CLI (`eg1.mjs`),
 * shown on /gate, and the template an adopter copies for their integration.
 */
export async function gateConformanceSelfTest({ now } = {}) {
  const harness = createEg1Harness({ now });
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], now });
  return gateConformance({ gate, harness });
}

export default {
  createGate,
  createTrustedActionFirewall,
  receiptAssuranceTier,
  MemoryConsumptionStore,
  createEvidenceLog,
  ASSURANCE_TIERS,
  DEFAULT_GATE_MANIFEST,
  HIGH_RISK_ACTION_PACKS,
  gateConformance,
  gateConformanceSelfTest,
  createEg1Harness,
  runEg1,
  createKeyRegistry,
  asKeyRegistry,
  classifyRetention,
  buildRetentionExport,
};
