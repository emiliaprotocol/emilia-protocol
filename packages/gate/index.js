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
const {
  verifyEmiliaReceipt,
  receiptChallenge,
  receiptRequiredHeader,
  validateActionRiskManifest,
  findActionRequirement,
  evaluateReceiptAssurance,
  receiptAssuranceTier: receiptAssuranceTierFromProof,
  RECEIPT_REQUIRED_STATUS,
  RECEIPT_REQUIRED_HEADER,
} = await import('@emilia-protocol/require-receipt').catch(() => import('../require-receipt/index.js'));
import { MemoryConsumptionStore } from './store.js';
import { createEvidenceLog } from './evidence.js';
import { DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, createDefaultActionRiskManifest } from './action-packs.js';
import { hashCanonical, verifyExecutionBinding } from './execution-binding.js';
import { buildReliancePacket } from './reliance-packet.js';
import { createEg1Harness, makeGateInvoke, runEg1, EG1_DEFAULT_SELECTOR } from './eg1-conformance.js';
import { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
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
  createEg1Harness, makeGateInvoke, runEg1,
} from './eg1-conformance.js';
export { CF1_VERSION, CF1_CHECKS, runCf1 } from './cf1-conformance.js';
export const ASSURANCE_TIERS = ['software', 'class_a', 'quorum'];
const TIER_RANK = { software: 0, class_a: 1, quorum: 2 };

/**
 * Return the proof-backed assurance tier. Without pinned approver keys or a
 * caller-supplied verifier, higher tiers are not inferred from receipt fields.
 */
export function receiptAssuranceTier(doc, opts = {}) {
  return receiptAssuranceTierFromProof(doc, opts);
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
export function createGate({ manifest = null, trustedKeys = [], maxAgeSec = 900, store, log, allowInlineKey = false, allowEphemeralStore = false, strictEvidence = true, now = Date.now, keyRegistry = null, approverKeys = {}, approver_keys = null, verifyAssurance = null } = {}) {
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
    // Assurance tier: proof-backed only. A receipt's issuer may describe a human
    // signoff, but high-tier enforcement requires pinned approver proof or an
    // explicit verifier hook. Self-asserted `allow_with_signoff` / `quorum`
    // fields are software-tier until proven.
    const assurance = evaluateReceiptAssurance(receipt, requiredTier, {
      approverKeys: approver_keys || approverKeys,
      verifyAssurance,
    });
    const have = assurance.have;
    if (!assurance.ok || (TIER_RANK[have] ?? 0) < (TIER_RANK[requiredTier] ?? 0)) {
      return decide(false, RECEIPT_REQUIRED_STATUS, assurance.reason || 'assurance_too_low', {
        have_tier: have,
        need_tier: requiredTier,
        assurance_tier_source: 'proof',
      });
    }
    // The high-risk action packs define material fields that must be observed
    // by the executor from the system of record. A signed, harmless-looking
    // claim cannot authorize a different real mutation.
    const executionBinding = verifyExecutionBinding({ requirement, receipt, observedAction: observed });
    if (!executionBinding.ok) {
      return decide(false, RECEIPT_REQUIRED_STATUS, 'execution_binding_failed', { execution_binding: executionBinding, have_tier: have, assurance_tier_source: 'proof' });
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
    return decide(true, 200, 'allow', { signer: v.signer, outcome: v.outcome, have_tier: have, assurance_tier_source: 'proof', execution_binding: executionBinding, consumption_mode: consumptionMode });
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
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, now });
  return gateConformance({ gate, harness });
}

/**
 * CF-1 (Consequence Firewall) conformance for an existing gate. Runs the eight
 * EG-1 runtime checks plus the three CF-1 category checks: the action is
 * declared consequential by the manifest, a gate pinned to the WRONG issuer key
 * refuses a valid receipt, and the allowed run emits offline-verifiable reliance
 * evidence. The `gate` MUST trust `harness.publicKey`; `wrongGate` MUST trust a
 * DIFFERENT key (otherwise wrong_authority_refused cannot be demonstrated).
 * @param {object} o
 * @param {object} o.gate       an EMILIA Gate trusting harness.publicKey
 * @param {object} [o.wrongGate] a sibling gate trusting a different (wrong) key
 * @param {object} o.harness    from createEg1Harness()
 * @param {object} [o.manifest] the action-risk manifest (to resolve the requirement)
 * @param {object} [o.selector] the manifest selector for the action
 * @param {object} [o.action]   the high-risk action to exercise
 */
export async function cf1Conformance({ gate, wrongGate, harness, manifest = null, selector = EG1_DEFAULT_SELECTOR, action } = {}) {
  if (!gate || typeof gate.run !== 'function') throw new Error('cf1Conformance requires a gate built trusting harness.publicKey');
  if (!harness) throw new Error('cf1Conformance requires the harness whose key the gate trusts');
  const act = action || harness.action;
  const invoke = makeGateInvoke(gate, { selector, action: act });
  const wrongInvoke = (wrongGate && typeof wrongGate.run === 'function')
    ? makeGateInvoke(wrongGate, { selector, action: act }) : undefined;
  const requirement = manifest ? findActionRequirement(manifest, selector) : null;
  return runCf1({ invoke, wrongInvoke, harness, action: act, requirement });
}

/**
 * Self-certify the reference gate against CF-1: a default Trusted Action
 * Firewall trusting a fresh harness key, a sibling firewall trusting a DIFFERENT
 * key (for wrong_authority_refused), and the default action-risk manifest (for
 * consequential_action_declared). The canonical "reference gate earns CF-1"
 * proof — runnable as a CLI (`cf1.mjs`).
 */
export async function cf1ConformanceSelfTest({ now } = {}) {
  const harness = createEg1Harness({ now });
  const manifest = createDefaultActionRiskManifest();
  const gate = createTrustedActionFirewall({ trustedKeys: [harness.publicKey], approverKeys: harness.approverKeys, now });
  const wrongHarness = createEg1Harness({ now });
  const wrongGate = createTrustedActionFirewall({ trustedKeys: [wrongHarness.publicKey], approverKeys: wrongHarness.approverKeys, now });
  return cf1Conformance({ gate, wrongGate, harness, manifest, selector: EG1_DEFAULT_SELECTOR, action: harness.action });
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
  cf1Conformance,
  cf1ConformanceSelfTest,
  CF1_VERSION,
  CF1_CHECKS,
  runCf1,
  createEg1Harness,
  runEg1,
  createKeyRegistry,
  asKeyRegistry,
  classifyRetention,
  buildRetentionExport,
};
