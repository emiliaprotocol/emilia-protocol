/**
 * EMILIA Protocol — Execution-Integrity binding (EP-EXECUTION-INTEGRITY-v1)
 *
 * @license Apache-2.0
 *
 * REFERENCE IMPLEMENTATION of an ADDITIVE signed claim + verifier check over
 * EP-RECEIPT-v1. Spec: PIPs/PIP-010-wysiwys-execution-integrity.md.
 * EXPERIMENTAL — governed by an Extension PIP; not a production or customer
 * claim; reports no metrics.
 *
 *   approved action (the EXACT bytes that action_hash committed to, I-D §3)
 *     -> EXECUTED action canonical hash (RE-derived from what actually ran)
 *       -> binding check: executed canonical hash MUST == approved action_hash
 *         -> EXECUTOR signature over the canonical attestation bytes
 *
 * THE GAP THIS CLOSES. A receipt commits to action A (action_hash H_A) at
 * APPROVAL time. The existing provenance `execution_binding` check
 * (lib/provenance/chain.js) is PASSIVE: it compares two claimed hash strings;
 * it never RE-derives the hash from what executed. So an approver can sign A
 * while the executor runs B (hash H_B) and the audit trail still reads
 * "A approved, A executed" — silent EXECUTION DRIFT. This module re-derives the
 * canonical hash of the action that ACTUALLY ran (via the SAME canonicalize() /
 * actionHash() the receipt used at approval) and fails closed on any mismatch.
 *
 * NO NEW TRUST BEYOND ONE SIGNATURE. The only added trust input is the
 * EXECUTOR's attested signature. The executor is a party EP IDENTIFIES BUT NEVER
 * TRUSTS (mirrors PIP-007's framing of the initiator): its signature ATTRIBUTES
 * the executed-action claim to a named, pinned key — it confers no authority and
 * relaxes no threshold. A self-asserted, unpinned key confers nothing.
 *
 * FROZEN CORE (PIP-001). This file does NOT modify the EP-RECEIPT-v1 wire
 * format, canonicalization, or signature, and it does NOT touch packages/verify
 * or packages/issue. It imports the frozen canonicalize() and actionHash() as
 * the single source of cryptographic truth and re-implements nothing of Core.
 *
 * FAIL CLOSED: verifyExecutionIntegrity() returns { valid:false } whenever the
 * canonical hash of the EXECUTED action != the approved action_hash (drift),
 * whenever the self-declared executed hash is not what the executed_action
 * actually hashes to, whenever an irreversible execution is missing its required
 * attestation, and whenever the executor signature is forged, signed by an
 * unpinned key, or not bound to the presented attestation bytes. A producer's
 * own irreversible:false flag can NEVER drop the requirement on an action that
 * is actually irreversible — reversibility must be asserted verifier-side.
 *
 * TWO CALLING CONVENTIONS, ONE BINDING. The verifier accepts either:
 *   - verifyExecutionIntegrity(attestation, receipt, opts)   // task / positional
 *   - verifyExecutionIntegrity({ approvedActionHash, executedAction,
 *       attestation, execution }, opts)                       // PIP-010 §5 object-arg
 * and either attestation signature shape — a detached `proof` block keyed by
 * `executor_key_id` (PIP-010 §2/§3), or a top-level `signature_b64u` +
 * `executor_id`/`executor_public_key` (bindExecution). Both bind the SAME
 * canonical bytes.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST RESIDUAL. This binding proves a NAMED executor key attested that the
 * canonical action recorded as executed hashes to the approved action_hash. It
 * does NOT prove the executor actually performed that action against the real
 * world: a fully compromised executor can record a faithful canonical action and
 * sign over it while doing something else. The attestation makes the executor's
 * claim ATTRIBUTABLE (named, signed, evidenced), raising the cost of an
 * undetectable swap; it does not make it impossible. That residual is out of
 * scope here and is addressed by executor host/TEE attestation and independent
 * confirmation of effects — a layer ABOVE this binding, not its mathematics.
 * ──────────────────────────────────────────────────────────────────────────
 */

import crypto from 'node:crypto';

// Compose the FROZEN v1 issuer's canonicalizer + action hasher. Same bytes as
// the published @emilia-protocol/issue by construction (relative import mirrors
// lib/provenance/chain.js and lib/trust-receipt/issuer.js).
import { canonicalize, actionHash } from '../../packages/issue/index.js';

export const EXECUTION_INTEGRITY_VERSION = 'EP-EXECUTION-INTEGRITY-v1';

// ── small helpers ───────────────────────────────────────────────────────────

/** Normalize a "sha256:<hex>" or bare-hex hash to lowercase bare hex. */
const hexOf = (h) => String(h || '').replace(/^sha256:/, '').toLowerCase();

/**
 * Frozen canonical hash of the action that ran. Uses the SAME actionHash() the
 * receipt used at approval, so a match is exact byte equality of the canonical
 * action, not a coincidence of two hashers.
 * @param {object} executedAction - the canonical Action Object that executed.
 * @returns {string} "sha256:<hex>"
 */
export function executedActionHash(executedAction) {
  if (!executedAction || typeof executedAction !== 'object') {
    throw new TypeError('executedActionHash requires the canonical executed Action Object');
  }
  return actionHash(executedAction);
}

/**
 * The canonical bytes the EXECUTOR signature is bound to. The verifier
 * INDEPENDENTLY recomputes these from the PRESENTED attestation fields, so a
 * producer cannot present one set of fields while claiming a signature over
 * another (executed_action / approved hash / executed_at cannot be swapped after
 * signing). Field set is fixed; order is irrelevant (canonicalize() sorts keys).
 *
 * Mirrors PIP-010 §3: canonicalize({ @version, approved_action_hash,
 * executed_action_hash, binding_status, execution_id, executed_at }), with the
 * executed_action object additionally bound so the executed call itself is
 * covered (not just its hash claim).
 */
function executionSignedPayload(att) {
  return Buffer.from(
    canonicalize({
      '@version': EXECUTION_INTEGRITY_VERSION,
      approved_action_hash: att.approved_action_hash,
      binding_status: att.binding_status ?? 'match',
      executed_action: att.executed_action ?? null,
      executed_action_hash: att.executed_action_hash,
      executed_at: att.executed_at ?? null,
      execution_id: att.execution_id ?? null,
      executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
    }),
    'utf8',
  );
}

/**
 * Verify a detached Ed25519 signature over `bytes` under a base64url SPKI-DER
 * public key. Returns true/false; never throws. This is the ONLY signature
 * primitive added here, and it grants NO trust by itself — the caller gates on
 * it AND on the key being pinned (identified-but-not-trusted).
 */
function verifyEd25519(bytes, publicKeyB64u, signatureB64u) {
  try {
    if (!publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64u, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, bytes, key, Buffer.from(signatureB64u, 'base64url'));
  } catch {
    return false;
  }
}

/** A base64url string that decodes to a plausible Ed25519 signature length (64 bytes). */
function isWellFormedSignature(sigB64u) {
  try { return Buffer.from(String(sigB64u || ''), 'base64url').length === 64; }
  catch { return false; }
}

/**
 * Normalize an attestation's signing material to a single shape, regardless of
 * whether it uses a top-level signature (bindExecution) or a detached `proof`
 * block (PIP-010 §2/§3). Returns { keyId, presentedKey, signatureB64u }.
 */
function signingMaterial(att) {
  if (att.proof) {
    return {
      keyId: att.proof.executor_key_id ?? att.executor_id ?? null,
      presentedKey: att.proof.public_key ?? att.executor_public_key ?? null,
      signatureB64u: att.proof.signature_b64u ?? null,
    };
  }
  return {
    keyId: att.executor_id ?? null,
    presentedKey: att.executor_public_key ?? null,
    signatureB64u: att.signature_b64u ?? null,
  };
}

// ── assembly (issuer / executor side) ────────────────────────────────────────

/**
 * bindExecution — produce an EP-EXECUTION-INTEGRITY-v1 attestation binding the
 * call that ACTUALLY executed to the approved action_hash, signed by the
 * executor (top-level signature shape).
 *
 * HONESTY GATE: this refuses to mint an attestation claiming a match when the
 * executed call drifts from the approved hash. A signature asserts a fact that
 * was actually true — so the honest issuer will not sign a "match" over a drift.
 * (Negative tests bypass this gate by re-signing tampered bytes directly, to
 * exercise the verifier's independent fail-closed checks.)
 *
 * @param {object} args
 * @param {string} args.approvedActionHash - "sha256:<hex>" from the EP-RECEIPT-v1 (action A).
 * @param {object} args.executedAction - the canonical Action Object that ACTUALLY ran.
 *   Its hash is recomputed here via actionHash() — never taken on faith.
 * @param {boolean} [args.irreversible] - whether the executed action is irreversible.
 * @param {{ executorId:string, publicKeyB64u:string,
 *           sign:(bytes:Buffer)=>string|Promise<string> }} args.signer
 *   - the executor's signing callback. EP never holds executor keys; signing is delegated.
 * @param {string} [args.executionId]
 * @param {string} [args.executedAt] - RFC 3339 (defaults to now).
 * @returns {object|Promise<object>} an EP-EXECUTION-INTEGRITY-v1 attestation.
 */
export function bindExecution({
  approvedActionHash,
  executedAction,
  irreversible,
  signer,
  executionId,
  executedAt = new Date().toISOString(),
} = /** @type {any} */ ({})) {
  if (!approvedActionHash) throw new Error('bindExecution requires approvedActionHash');
  if (!executedAction || typeof executedAction !== 'object') {
    throw new Error('bindExecution requires the executed Action Object');
  }
  if (!signer || typeof signer.sign !== 'function' || !signer.executorId || !signer.publicKeyB64u) {
    throw new Error('bindExecution requires signer.{executorId,publicKeyB64u,sign}');
  }

  // Recompute the executed canonical hash from what ACTUALLY ran — the heart of
  // the binding. Never trust a caller-supplied hash.
  const execHash = executedActionHash(executedAction);
  const status = hexOf(execHash) === hexOf(approvedActionHash) ? 'match' : 'drift';

  // Honesty gate: do not mint a signed attestation for a drift. A signed "match"
  // must reflect a fact that was true at signing time.
  if (status !== 'match') {
    throw new Error(
      `bindExecution: execution drift detected — executed action hash ${execHash} `
      + `does not match approved action_hash ${approvedActionHash}; refusing to attest (fail-closed honesty gate)`,
    );
  }

  const unsigned = {
    '@version': EXECUTION_INTEGRITY_VERSION,
    executor_id: signer.executorId,
    executor_public_key: signer.publicKeyB64u,
    approved_action_hash: approvedActionHash,
    executed_action: executedAction,
    executed_action_hash: execHash,
    binding_status: status,
    irreversible: irreversible === true,
    executed_at: executedAt,
    ...(executionId ? { execution_id: executionId } : {}),
    // EVIDENCE that a named executor attested this; never proof it ran the call.
    scope_note:
      'Executor is identified but not trusted: this attributes the executed-action claim to a named key; '
      + 'it does not prove the executor ran the call. Residual: executor host/TEE attestation, a layer above.',
  };

  const payload = executionSignedPayload(unsigned);
  const finish = (sigB64u) => ({ ...unsigned, signature_b64u: sigB64u });
  const signed = signer.sign(payload);
  return /** @type {any} */ (signed) && typeof (/** @type {any} */ (signed)).then === 'function'
    ? (/** @type {any} */ (signed)).then(finish)
    : finish(signed);
}

/**
 * buildExecutionIntegrity — PIP-010 §3 assembler: signs with a raw KeyObject
 * under a detached `proof` block keyed by `executor_key_id`. Implemented so the
 * signed bytes match bindExecution()'s (one binding, two shapes).
 *
 * @param {object} args
 * @param {string} args.approvedActionHash
 * @param {object} args.executedAction
 * @param {{ executor_key_id:string, privateKey:import('crypto').KeyObject,
 *           publicKeyB64u:string, algorithm?:string }} [args.executor]
 * @param {string} [args.executionId]
 * @param {string} [args.executedAt]
 * @returns {object} an EP-EXECUTION-INTEGRITY-v1 attestation (with a `proof` block when signed).
 */
export function buildExecutionIntegrity({
  approvedActionHash,
  executedAction,
  executor,
  executionId,
  executedAt,
} = /** @type {any} */ ({})) {
  const execHash = executedActionHash(executedAction);
  const att = {
    '@version': EXECUTION_INTEGRITY_VERSION,
    approved_action_hash: approvedActionHash,
    executed_action: executedAction,
    executed_action_hash: execHash,
    binding_status: hexOf(execHash) === hexOf(approvedActionHash) ? 'match' : 'drift',
  };
  if (executionId) att.execution_id = executionId;
  if (executedAt) att.executed_at = executedAt;
  if (executor) {
    att.executor_id = executor.executor_key_id;
    const payload = executionSignedPayload({ ...att, executor_id: executor.executor_key_id });
    att.proof = {
      algorithm: executor.algorithm || 'Ed25519',
      executor_key_id: executor.executor_key_id,
      signed_payload_b64u: payload.toString('base64url'),
      signature_b64u: crypto.sign(null, payload, executor.privateKey).toString('base64url'),
      public_key: executor.publicKeyB64u,
    };
  }
  return att;
}

// ── verification (verifier side) ─────────────────────────────────────────────

/**
 * verifyExecutionIntegrity — FAIL-CLOSED execution-drift + executor-attestation
 * check. Accepts two calling conventions:
 *
 *   (A) verifyExecutionIntegrity(attestation, receipt, opts)
 *       - attestation: an EP-EXECUTION-INTEGRITY-v1 object, or null/absent
 *       - receipt: the FROZEN EP-RECEIPT-v1 (only action_hash is read)
 *   (B) verifyExecutionIntegrity({ approvedActionHash, executedAction,
 *         attestation, execution }, opts)   // PIP-010 §5
 *
 * Rejects (valid:false) on ANY of:
 *   - attestation missing for an action that requires one (reversibility not
 *     INDEPENDENTLY asserted by the verifier);
 *   - wrong @version;
 *   - the executed_action does not canonicalize to its self-declared
 *     executed_action_hash (a lying hash field);
 *   - the executed canonical hash != the approved action_hash (EXECUTION DRIFT);
 *   - the executor key is not pinned by the verifier (identified-but-not-trusted),
 *     or the presented key differs from the pinned key;
 *   - the executor signature does not verify under the pinned key, or does not
 *     verify over the bytes INDEPENDENTLY recomputed from the presented fields.
 *
 * @returns {{ valid:boolean, checks:object, errors:string[], binding_status:string|null }}
 */
export function verifyExecutionIntegrity(arg1, arg2, arg3) {
  // Dispatch on calling convention. Convention (B) is an object carrying any of
  // approvedActionHash/executedAction/attestation/execution.
  const isObjectArg =
    arg1 && typeof arg1 === 'object' && arg1['@version'] === undefined && (
      'approvedActionHash' in arg1 || 'executedAction' in arg1 || 'attestation' in arg1 || 'execution' in arg1
    );

  let attestation;
  let receipt;
  let opts;
  if (isObjectArg) {
    const { approvedActionHash, attestation: att, execution } = arg1;
    attestation = att ?? null;
    receipt = { action_hash: approvedActionHash };
    opts = { ...(arg2 || {}) };
    // PIP-010 object-arg passes execution.irreversible; honor it only to RAISE
    // the bar — a producer's irreversible:false can never drop the gate.
    if (execution && execution.irreversible === false && typeof opts.reversibilityAsserted !== 'function') {
      // No independent assertion supplied: leave the gate CLOSED (fail-closed).
    }
  } else {
    attestation = arg1 ?? null;
    receipt = arg2 || {};
    opts = { ...(arg3 || {}) };
  }

  const executorKeys = opts.executorKeys || {};
  const reversibilityAsserted =
    typeof opts.reversibilityAsserted === 'function'
      ? opts.reversibilityAsserted(attestation) === true
      : opts.reversibilityAsserted === true;

  const checks = {
    attestation_present: true,           // an attestation is present when one is required
    version: true,                       // @version matches (vacuous until present)
    executed_hash_self_consistent: true, // executed_action hashes to its declared hash
    executed_hash_matches_approved: true,// executed canonical hash == approved action_hash
    executor_key_pinned: true,           // executor_id maps to a pinned key == the presented key
    executor_signature_valid: true,      // signature verifies under the pinned key
    signature_binds_attestation: true,   // signature is over the recomputed presented bytes
  };
  const errors = [];
  const fail = (key, msg) => { checks[key] = false; errors.push(msg); };

  // ── 0. presence (fail-closed unless reversibility is INDEPENDENTLY asserted) ──
  // A missing attestation is fatal by default. A producer's own irreversible:false
  // flag can NEVER drop this requirement; only the verifier-supplied
  // reversibilityAsserted predicate (an independent assertion) may.
  if (!attestation) {
    if (!reversibilityAsserted) {
      fail('attestation_present',
        'no execution-integrity attestation; reversibility was not independently asserted (fail-closed)');
      return { valid: false, checks, errors, binding_status: null };
    }
    return { valid: true, checks, errors, binding_status: null };
  }

  // ── 1. version ──────────────────────────────────────────────────────────
  if (attestation['@version'] !== EXECUTION_INTEGRITY_VERSION) {
    fail('version', `unsupported version: ${attestation['@version']}`);
    return { valid: false, checks, errors, binding_status: attestation.binding_status ?? null };
  }

  // ── 2. executed hash self-consistent (recompute from executed_action) ─────
  // The verifier NEVER trusts the executor's self-declared hash string; it
  // recomputes the canonical hash from the executed_action it was given. (When
  // no executed_action is carried — PIP-010 allows a hash-only attestation — this
  // check is vacuous and the hash-string drift check below still applies.)
  let recomputed = null;
  if (attestation.executed_action) {
    try { recomputed = actionHash(attestation.executed_action); } catch { recomputed = null; }
    if (recomputed === null) {
      fail('executed_hash_self_consistent', 'executed_action present but not hashable');
    } else if (hexOf(recomputed) !== hexOf(attestation.executed_action_hash)) {
      fail('executed_hash_self_consistent',
        `executed_action hashes to ${recomputed} but executed_action_hash claims ${attestation.executed_action_hash}`);
    }
  }

  // ── 3. executed canonical hash == approved action_hash (DRIFT check) ──────
  // Bind to what the receipt actually committed to. Use the RECOMPUTED hash when
  // available so a lying hash field can never satisfy this.
  const executedHex = hexOf(recomputed ?? attestation.executed_action_hash);
  const approvedHex = hexOf(receipt?.action_hash);
  if (!approvedHex) {
    fail('executed_hash_matches_approved', 'receipt carries no action_hash to bind against');
  } else if (executedHex !== approvedHex) {
    fail('executed_hash_matches_approved',
      `execution drift: executed canonical hash ${executedHex} != approved action_hash ${approvedHex}`);
  }
  // A binding_status that contradicts the hashes is rejected — status is never
  // trusted, the hashes are (PIP-010 §5.3).
  if (attestation.binding_status === 'drift' || (attestation.binding_status === 'match' && executedHex !== approvedHex)) {
    fail('executed_hash_matches_approved',
      `binding_status "${attestation.binding_status}" contradicts the hashes (status is not trusted)`);
  }

  // ── 4. executor key pinned (identified-but-not-trusted) ───────────────────
  const { keyId, presentedKey } = signingMaterial(attestation);
  const pinned = executorKeys[keyId]?.public_key;
  if (!pinned) {
    fail('executor_key_pinned',
      `no pinned key for executor "${keyId}" (identified but not trusted)`);
  } else if (presentedKey && pinned !== presentedKey) {
    fail('executor_key_pinned',
      `presented executor key does not match the pinned key for "${keyId}"`);
  }

  // ── 5. signature: valid AND bound to the recomputed presented bytes ───────
  // Verify under the PINNED key (never a producer-supplied key), over bytes the
  // verifier recomputes from the presented attestation fields.
  const { signatureB64u } = signingMaterial(attestation);
  // FAIL CLOSED, never throw: a non-canonicalizable attestation field (e.g. a
  // BigInt the issuer can't serialize) must not crash the verifier — it yields
  // null recomputed bytes, against which no signature can verify.
  let recomputedBytes = null;
  try {
    recomputedBytes = executionSignedPayload(attestation);
  } catch {
    recomputedBytes = null;
  }
  const sigBindsPinned = pinned && recomputedBytes && verifyEd25519(recomputedBytes, pinned, signatureB64u);
  if (!sigBindsPinned) {
    const verifyKey = pinned || presentedKey;
    const sigOverRecomputed = verifyKey && recomputedBytes && verifyEd25519(recomputedBytes, verifyKey, signatureB64u);
    if (!verifyKey || !signatureB64u) {
      fail('executor_signature_valid', 'executor signature or key missing');
    } else if (!sigOverRecomputed && isWellFormedSignature(signatureB64u)) {
      // Well-formed signature that does not verify over the recomputed bytes:
      // either forged (verifies nowhere) or valid over OTHER (tampered) bytes.
      // We cannot tell which without the original bytes, so flag BOTH the math
      // and the binding so the forensic cause is explicit and fail-closed holds.
      fail('signature_binds_attestation',
        'executor signature does not bind the presented attestation bytes (recomputed payload mismatch)');
      fail('executor_signature_valid',
        'executor signature does not verify under the pinned executor key over the recomputed bytes');
    } else if (!sigOverRecomputed) {
      fail('executor_signature_valid',
        'executor signature does not verify under the pinned executor key');
    }
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors, binding_status: attestation.binding_status ?? null };
}

const executionIntegrity = {
  bindExecution,
  buildExecutionIntegrity,
  executedActionHash,
  verifyExecutionIntegrity,
  EXECUTION_INTEGRITY_VERSION,
};
export default executionIntegrity;
