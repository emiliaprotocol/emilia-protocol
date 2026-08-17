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
import type { KeyObject } from 'node:crypto';

// Compose the FROZEN v1 issuer's canonicalizer + action hasher. Same bytes as
// the published @emilia-protocol/issue by construction (relative import mirrors
// lib/provenance/chain.js and lib/trust-receipt/issuer.js).
import { canonicalize, actionHash } from '../../packages/issue/index.js';
import type { ActionObject } from '../../packages/issue/index.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
  type AgileSignature,
  type AgileVerificationKey,
} from '../../packages/verify/pq-signature-agility.js';

export const EXECUTION_INTEGRITY_VERSION = 'EP-EXECUTION-INTEGRITY-v1';

/** Detached PIP-010 §2/§3 proof block signing shape. */
export interface ExecutionIntegrityProof {
  algorithm?: string;
  executor_key_id?: string;
  signed_payload_b64u?: string;
  signature_b64u?: string;
  public_key?: string;
}

/**
 * An EP-EXECUTION-INTEGRITY-v1 attestation. `executed_action` is the
 * presenter-supplied canonical Action Object that actually ran — genuinely
 * dynamic, untrusted data whose hash this module always independently
 * recomputes rather than trusting.
 */
export interface ExecutionIntegrityAttestation {
  '@version'?: string;
  executor_id?: string | null;
  executor_public_key?: string | null;
  approved_action_hash?: string;
  executed_action?: unknown;
  executed_action_hash?: string;
  binding_status?: string;
  irreversible?: boolean;
  executed_at?: string | null;
  execution_id?: string;
  signature_b64u?: string;
  proof?: ExecutionIntegrityProof;
  scope_note?: string;
  [key: string]: unknown;
}

/** The executor's signing callback. EP never holds executor keys; signing is delegated. */
export interface ExecutorSigner {
  executorId: string;
  publicKeyB64u: string;
  sign: (bytes: Buffer) => string | Promise<string>;
}

export interface BindExecutionArgs {
  /** "sha256:<hex>" from the EP-RECEIPT-v1 (action A). */
  approvedActionHash?: string;
  /** The canonical Action Object that ACTUALLY ran. */
  executedAction?: unknown;
  /** Whether the executed action is irreversible. */
  irreversible?: boolean;
  signer?: ExecutorSigner;
  executionId?: string;
  /** RFC 3339 (defaults to now). */
  executedAt?: string;
}

/** Raw KeyObject signer material for the detached `proof` block shape (buildExecutionIntegrity). */
export interface ExecutionIntegrityExecutorKey {
  executor_key_id: string;
  privateKey: KeyObject;
  publicKeyB64u: string;
  algorithm?: string;
}

export interface BuildExecutionIntegrityArgs {
  approvedActionHash?: string;
  executedAction?: unknown;
  executor?: ExecutionIntegrityExecutorKey;
  executionId?: string;
  executedAt?: string;
}

export interface ExecutionIntegrityChecks {
  /** an attestation is present when one is required */
  attestation_present: boolean;
  /** @version matches (vacuous until present) */
  version: boolean;
  /** executed_action hashes to its declared hash */
  executed_hash_self_consistent: boolean;
  /** executed canonical hash == approved action_hash */
  executed_hash_matches_approved: boolean;
  /** executor_id maps to a pinned key == the presented key */
  executor_key_pinned: boolean;
  /** signature verifies under the pinned key */
  executor_signature_valid: boolean;
  /** signature is over the recomputed presented bytes */
  signature_binds_attestation: boolean;
  [key: string]: boolean;
}

export interface ExecutionIntegrityResult {
  valid: boolean;
  checks: ExecutionIntegrityChecks;
  errors: string[];
  binding_status: string | null;
}

export interface ExecutionIntegrityOpts {
  executorKeys?: Record<string, { public_key: string }>;
  reversibilityAsserted?: boolean | ((attestation: ExecutionIntegrityAttestation | null) => boolean);
}

/** PIP-010 §5 object-arg calling convention for verifyExecutionIntegrity(). */
export interface VerifyExecutionIntegrityObjectArg {
  approvedActionHash?: string;
  executedAction?: unknown;
  attestation?: ExecutionIntegrityAttestation | null;
  execution?: { irreversible?: boolean; [key: string]: unknown };
}

/** The FROZEN EP-RECEIPT-v1 — only action_hash is read here. */
export interface ExecutionIntegrityReceiptRef {
  action_hash?: string;
  [key: string]: unknown;
}

// ── small helpers ───────────────────────────────────────────────────────────

/** Normalize a "sha256:<hex>" or bare-hex hash to lowercase bare hex. */
const hexOf = (h: unknown): string => String(h || '').replace(/^sha256:/, '').toLowerCase();

/**
 * Frozen canonical hash of the action that ran. Uses the SAME actionHash() the
 * receipt used at approval, so a match is exact byte equality of the canonical
 * action, not a coincidence of two hashers.
 * @param executedAction - the canonical Action Object that executed. Runtime-checked,
 *   untrusted input — the guard below is what actually enforces the shape.
 * @returns "sha256:<hex>"
 */
export function executedActionHash(executedAction: unknown): string {
  if (!executedAction || typeof executedAction !== 'object') {
    throw new TypeError('executedActionHash requires the canonical executed Action Object');
  }
  return actionHash(executedAction as ActionObject);
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
function executionSignedPayload(att: ExecutionIntegrityAttestation): Buffer {
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
function verifyEd25519(bytes: Buffer, publicKeyB64u: string | null | undefined, signatureB64u: string | null | undefined): boolean {
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
function isWellFormedSignature(sigB64u: unknown): boolean {
  try { return Buffer.from(String(sigB64u || ''), 'base64url').length === 64; }
  catch { return false; }
}

/**
 * Normalize an attestation's signing material to a single shape, regardless of
 * whether it uses a top-level signature (bindExecution) or a detached `proof`
 * block (PIP-010 §2/§3). Returns { keyId, presentedKey, signatureB64u }.
 */
function signingMaterial(att: ExecutionIntegrityAttestation): {
  keyId: string | null;
  presentedKey: string | null;
  signatureB64u: string | null;
} {
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
 * @param args
 * @param args.approvedActionHash - "sha256:<hex>" from the EP-RECEIPT-v1 (action A).
 * @param args.executedAction - the canonical Action Object that ACTUALLY ran.
 *   Its hash is recomputed here via actionHash() — never taken on faith.
 * @param args.irreversible - whether the executed action is irreversible.
 * @param args.signer - the executor's signing callback. EP never holds executor keys; signing is delegated.
 * @param args.executionId
 * @param args.executedAt - RFC 3339 (defaults to now).
 * @returns an EP-EXECUTION-INTEGRITY-v1 attestation.
 */
export function bindExecution({
  approvedActionHash,
  executedAction,
  irreversible,
  signer,
  executionId,
  executedAt = new Date().toISOString(),
}: BindExecutionArgs = {}): ExecutionIntegrityAttestation | Promise<ExecutionIntegrityAttestation> {
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

  const unsigned: ExecutionIntegrityAttestation = {
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
  const finish = (sigB64u: string): ExecutionIntegrityAttestation => ({ ...unsigned, signature_b64u: sigB64u });
  const signed = signer.sign(payload);
  // signer.sign() may return the signature synchronously or as a Promise —
  // both are valid per ExecutorSigner. `any` here mirrors the pre-existing
  // dynamic dispatch (feature-detecting `.then`), not a persisted escape hatch.
  return (signed as any) && typeof (signed as any).then === 'function'
    ? (signed as Promise<string>).then(finish)
    : finish(signed as string);
}

/**
 * buildExecutionIntegrity — PIP-010 §3 assembler: signs with a raw KeyObject
 * under a detached `proof` block keyed by `executor_key_id`. Implemented so the
 * signed bytes match bindExecution()'s (one binding, two shapes).
 *
 * @param args
 * @returns an EP-EXECUTION-INTEGRITY-v1 attestation (with a `proof` block when signed).
 */
export function buildExecutionIntegrity({
  approvedActionHash,
  executedAction,
  executor,
  executionId,
  executedAt,
}: BuildExecutionIntegrityArgs = {}): ExecutionIntegrityAttestation {
  const execHash = executedActionHash(executedAction);
  const att: ExecutionIntegrityAttestation = {
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
 * @returns { valid, checks, errors, binding_status }
 */
export function verifyExecutionIntegrity(arg1?: any, arg2?: any, arg3?: any): ExecutionIntegrityResult {
  // Dispatch on calling convention. Convention (B) is an object carrying any of
  // approvedActionHash/executedAction/attestation/execution.
  const isObjectArg =
    arg1 && typeof arg1 === 'object' && arg1['@version'] === undefined && (
      'approvedActionHash' in arg1 || 'executedAction' in arg1 || 'attestation' in arg1 || 'execution' in arg1
    );

  let attestation: ExecutionIntegrityAttestation | null;
  let receipt: ExecutionIntegrityReceiptRef;
  let opts: ExecutionIntegrityOpts;
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
  let reversibilityAsserted = opts.reversibilityAsserted === true;
  if (typeof opts.reversibilityAsserted === 'function') {
    try {
      reversibilityAsserted = opts.reversibilityAsserted(attestation) === true;
    } catch {
      // A verifier-supplied predicate is an untrusted policy extension. Its
      // failure can never relax the execution-integrity gate or escape as an
      // exception; treat it exactly like an assertion that did not pass.
      reversibilityAsserted = false;
    }
  }

  const checks: ExecutionIntegrityChecks = {
    attestation_present: true,           // an attestation is present when one is required
    version: true,                       // @version matches (vacuous until present)
    executed_hash_self_consistent: true, // executed_action hashes to its declared hash
    executed_hash_matches_approved: true,// executed canonical hash == approved action_hash
    executor_key_pinned: true,           // executor_id maps to a pinned key == the presented key
    executor_signature_valid: true,      // signature verifies under the pinned key
    signature_binds_attestation: true,   // signature is over the recomputed presented bytes
  };
  const errors: string[] = [];
  const fail = (key: string, msg: string): void => { checks[key] = false; errors.push(msg); };

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
  let recomputed: string | null = null;
  if (attestation.executed_action) {
    try { recomputed = actionHash(attestation.executed_action as ActionObject); } catch { recomputed = null; }
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
  const pinned = executorKeys[keyId as string]?.public_key;
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
  let recomputedBytes: Buffer | null = null;
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

// ===========================================================================
// EP-EXECUTION-INTEGRITY-v2 -- the hybrid (Ed25519 + ML-DSA-65) attestation
// ===========================================================================
/**
 * HYBRID MIGRATION following the reference pattern in
 * docs/protocol/pq-hybrid-program.md ("PATTERN: the reference hybrid
 * migration") and packages/verify/src/revocation.ts's EP-REVOCATION-v2. Five
 * moves, in order: (1) VERSION BUMP, not a field bump — a second signature
 * changes the SHAPE of the proof, so the attestation takes a new `@version`
 * (EP-EXECUTION-INTEGRITY-v1 -> -v2); verifyExecutionIntegrity() above is
 * untouched and refuses a v2 attestation on the version marker;
 * (2) SET SHAPE — `proof.signatures` is the EP-SIG-AGILITY-v1 AgileSignature
 * array, one entry per algorithm in the registered order; (3) ANTI-STRIPPING
 * BYTES — the required algorithm set is inside the signed bytes
 * (executionV2SignedPayload), rebuilt by the verifier from the REGISTERED set;
 * (4) V1 COMPATIBILITY — the v1 sync verifier is unchanged; v2 verification is
 * ASYNC and a SEPARATE entry point; (5) NAMED REFUSALS — every failure names a
 * check, nothing throws on caller input, and an absent ML-DSA backend is a
 * refusal, never a pass on the classical leg.
 *
 * The drift binding is unchanged: the verifier RE-DERIVES the executed
 * canonical hash and refuses any attestation whose executed action does not
 * hash to the approved action_hash. The executor is identified but not trusted;
 * its Ed25519 and ML-DSA-65 halves are pinned out of band per executor_key_id.
 *
 * HONEST RESIDUAL is exactly the v1 residual. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently
 * audited and not a FIPS validated module; v2 does not retroactively protect v1
 * attestations.
 */

export const EXECUTION_INTEGRITY_V2_VERSION = 'EP-EXECUTION-INTEGRITY-v2';
export const EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

const EXECUTOR_PQ_KEY_ID = /^ep:executor-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;

export interface ExecutionIntegrityV2Proof {
  profile: string;
  required_algorithms: string[];
  executor_key_id: string;
  public_key: string;
  pq_key_id: string;
  pq_public_key: string;
  signatures: AgileSignature[];
}

export interface ExecutionIntegrityV2Attestation {
  '@version'?: string;
  executor_id?: string | null;
  approved_action_hash?: string;
  executed_action?: unknown;
  executed_action_hash?: string;
  binding_status?: string;
  irreversible?: boolean;
  executed_at?: string | null;
  execution_id?: string;
  proof?: ExecutionIntegrityV2Proof;
  scope_note?: string;
  [key: string]: unknown;
}

export interface ExecutionIntegrityV2ExecutorKey {
  executor_key_id: string;
  /** Ed25519 signing key. */
  privateKey: KeyObject;
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  pqSecretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  pqPublicKey: Uint8Array | string;
}

export interface BuildExecutionIntegrityV2Args {
  approvedActionHash?: string;
  executedAction?: unknown;
  executor?: ExecutionIntegrityV2ExecutorKey;
  executionId?: string;
  executedAt?: string;
  deterministic?: boolean;
}

export interface ExecutionIntegrityV2ExecutorKeyPin { public_key: string; pq_public_key: string; }

export interface ExecutionIntegrityV2Opts extends AgilityOptions {
  executorKeys?: Record<string, ExecutionIntegrityV2ExecutorKeyPin>;
  reversibilityAsserted?: boolean | ((attestation: ExecutionIntegrityV2Attestation | null) => boolean);
}

function executionAlgorithmSetMatches(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS[i]);
}

function executionEdSpkiB64u(key: KeyObject): string {
  return crypto.createPublicKey(key as unknown as crypto.PublicKeyInput)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
}

function executorPqKeyIdOf(rawB64u: string): string {
  return `ep:executor-key:ml-dsa-65:sha256:${crypto
    .createHash('sha256').update(Buffer.from(rawB64u, 'base64url')).digest('hex')}`;
}

function executionPqRawB64u(value: Uint8Array | string, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
  if (bytes.length !== expectedLength) {
    throw new Error(`buildExecutionIntegrityV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

/**
 * The bytes BOTH legs sign — the same fixed field set as v1's
 * executionSignedPayload, plus the v2 marker and the required algorithm set.
 * Recomputed by the verifier from the PRESENTED fields and the REGISTERED set.
 */
export function executionV2SignedPayload(
  att: ExecutionIntegrityV2Attestation,
  requiredAlgorithms: readonly string[] = EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!executionAlgorithmSetMatches(requiredAlgorithms)) {
    throw new Error('executionV2SignedPayload: algorithm set is not the registered EP-EXECUTION-INTEGRITY-v2 set');
  }
  return Buffer.from(canonicalize({
    '@version': EXECUTION_INTEGRITY_V2_VERSION,
    approved_action_hash: att.approved_action_hash,
    binding_status: att.binding_status ?? 'match',
    executed_action: att.executed_action ?? null,
    executed_action_hash: att.executed_action_hash,
    executed_at: att.executed_at ?? null,
    execution_id: att.execution_id ?? null,
    executor_id: att.executor_id ?? att.proof?.executor_key_id ?? null,
    required_algorithms: [...requiredAlgorithms],
  }), 'utf8');
}

/**
 * buildExecutionIntegrityV2 — assemble a hybrid attestation binding the executed
 * call to the approved action_hash, signed under BOTH registered algorithms.
 * THROWS on issuer-side misuse or an unavailable ML-DSA backend.
 */
export async function buildExecutionIntegrityV2({
  approvedActionHash,
  executedAction,
  executor,
  executionId,
  executedAt,
  deterministic = false,
}: BuildExecutionIntegrityV2Args = {}): Promise<ExecutionIntegrityV2Attestation> {
  if (!executor || !executor.executor_key_id || !executor.privateKey || !executor.pqSecretKey || !executor.pqPublicKey) {
    throw new Error('buildExecutionIntegrityV2 requires executor.{executor_key_id,privateKey,pqSecretKey,pqPublicKey}');
  }
  const execHash = executedActionHash(executedAction);
  const att: ExecutionIntegrityV2Attestation = {
    '@version': EXECUTION_INTEGRITY_V2_VERSION,
    executor_id: executor.executor_key_id,
    approved_action_hash: approvedActionHash,
    executed_action: executedAction,
    executed_action_hash: execHash,
    binding_status: hexOf(execHash) === hexOf(approvedActionHash) ? 'match' : 'drift',
  };
  if (executionId) att.execution_id = executionId;
  if (executedAt) att.executed_at = executedAt;

  const edPublic = executionEdSpkiB64u(executor.privateKey);
  const pqPublic = executionPqRawB64u(executor.pqPublicKey, ML_DSA_65_PUBLIC_KEY_BYTES, 'executor.pqPublicKey');
  const pqSecret = executionPqRawB64u(executor.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'executor.pqSecretKey');
  const pqKeyId = executorPqKeyIdOf(pqPublic);

  const messageBytes = executionV2SignedPayload(att, EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(
    new Uint8Array(messageBytes),
    [
      { alg: 'Ed25519', private_key: executor.privateKey, key_id: executor.executor_key_id },
      { alg: 'ML-DSA-65', private_key: pqSecret, key_id: pqKeyId },
    ],
    deterministic === true ? { deterministic: true } : {},
  );
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered = EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS.map((alg) => {
    const s = byAlg.get(alg);
    if (!s) throw new Error(`buildExecutionIntegrityV2: signing produced no ${alg} leg`);
    return s;
  });

  att.proof = {
    profile: EXECUTION_INTEGRITY_V2_VERSION,
    required_algorithms: [...EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS],
    executor_key_id: executor.executor_key_id,
    public_key: edPublic,
    pq_key_id: pqKeyId,
    pq_public_key: pqPublic,
    signatures: ordered,
  };
  return att;
}

/**
 * verifyExecutionIntegrityV2 — FAIL-CLOSED hybrid drift + attestation check.
 * Accepts the same two calling conventions as verifyExecutionIntegrity:
 *   (A) verifyExecutionIntegrityV2(attestation, receipt, opts)
 *   (B) verifyExecutionIntegrityV2({ approvedActionHash, executedAction,
 *         attestation, execution }, opts)
 * Never throws on caller input; a v2 attestation NEVER verifies on one leg alone.
 */
export async function verifyExecutionIntegrityV2(arg1?: any, arg2?: any, arg3?: any): Promise<ExecutionIntegrityResult> {
  const isObjectArg =
    arg1 && typeof arg1 === 'object' && arg1['@version'] === undefined && (
      'approvedActionHash' in arg1 || 'executedAction' in arg1 || 'attestation' in arg1 || 'execution' in arg1
    );

  let attestation: ExecutionIntegrityV2Attestation | null;
  let receipt: ExecutionIntegrityReceiptRef;
  let opts: ExecutionIntegrityV2Opts;
  if (isObjectArg) {
    const { approvedActionHash, attestation: att } = arg1;
    attestation = att ?? null;
    receipt = { action_hash: approvedActionHash };
    opts = { ...(arg2 || {}) };
  } else {
    attestation = arg1 ?? null;
    receipt = arg2 || {};
    opts = { ...(arg3 || {}) };
  }

  const executorKeys = opts.executorKeys || {};
  let reversibilityAsserted = opts.reversibilityAsserted === true;
  if (typeof opts.reversibilityAsserted === 'function') {
    try {
      reversibilityAsserted = opts.reversibilityAsserted(attestation) === true;
    } catch {
      reversibilityAsserted = false;
    }
  }

  const checks: Record<string, boolean> = {
    attestation_present: true,
    version: true,
    executed_hash_self_consistent: true,
    executed_hash_matches_approved: true,
    algorithm_set: true,
    legs_present: true,
    executor_key_pinned: true,
    executor_signature_valid: true,
    signature_binds_attestation: true,
  };
  const errors: string[] = [];
  const fail = (key: string, msg: string): void => { checks[key] = false; errors.push(msg); };
  const result = (bindingStatus: string | null): ExecutionIntegrityResult => ({
    valid: Object.values(checks).every(Boolean),
    checks: checks as unknown as ExecutionIntegrityChecks,
    errors,
    binding_status: bindingStatus,
  });

  if (!attestation) {
    if (!reversibilityAsserted) {
      fail('attestation_present',
        'no execution-integrity attestation; reversibility was not independently asserted (fail-closed)');
      return result(null);
    }
    return result(null);
  }

  if (attestation['@version'] !== EXECUTION_INTEGRITY_V2_VERSION) {
    fail('version', `unsupported version: ${attestation['@version']}`);
    return result(attestation.binding_status ?? null);
  }

  // Executed hash self-consistent (recompute from executed_action).
  let recomputed: string | null = null;
  if (attestation.executed_action) {
    try { recomputed = actionHash(attestation.executed_action as ActionObject); } catch { recomputed = null; }
    if (recomputed === null) {
      fail('executed_hash_self_consistent', 'executed_action present but not hashable');
    } else if (hexOf(recomputed) !== hexOf(attestation.executed_action_hash)) {
      fail('executed_hash_self_consistent',
        `executed_action hashes to ${recomputed} but executed_action_hash claims ${attestation.executed_action_hash}`);
    }
  }

  // Executed canonical hash == approved action_hash (drift check).
  const executedHex = hexOf(recomputed ?? attestation.executed_action_hash);
  const approvedHex = hexOf(receipt?.action_hash);
  if (!approvedHex) {
    fail('executed_hash_matches_approved', 'receipt carries no action_hash to bind against');
  } else if (executedHex !== approvedHex) {
    fail('executed_hash_matches_approved',
      `execution drift: executed canonical hash ${executedHex} != approved action_hash ${approvedHex}`);
  }
  if (attestation.binding_status === 'drift' || (attestation.binding_status === 'match' && executedHex !== approvedHex)) {
    fail('executed_hash_matches_approved',
      `binding_status "${attestation.binding_status}" contradicts the hashes (status is not trusted)`);
  }

  const proof = attestation.proof;
  if (!proof || typeof proof !== 'object' || proof.profile !== EXECUTION_INTEGRITY_V2_VERSION
    || typeof proof.executor_key_id !== 'string') {
    fail('legs_present', 'proof must use the exact EP-EXECUTION-INTEGRITY-v2 proof schema');
    return result(attestation.binding_status ?? null);
  }

  if (!executionAlgorithmSetMatches(proof.required_algorithms)) {
    fail('algorithm_set',
      `proof.required_algorithms must be exactly ${JSON.stringify([...EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
  }

  const signatures = Array.isArray(proof.signatures) ? proof.signatures as AgileSignature[] : null;
  if (!signatures || signatures.length === 0) {
    fail('legs_present', 'proof.signatures must carry one signature per required algorithm');
  } else {
    const presented = new Set<string>();
    let malformed = false;
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        fail('legs_present', 'each proof.signatures entry must be { alg, sig, key_id? }');
        malformed = true;
        break;
      }
      if (presented.has(s.alg)) {
        fail('legs_present', `duplicate signature for algorithm "${s.alg}"`);
        malformed = true;
        break;
      }
      presented.add(s.alg);
    }
    if (!malformed) {
      for (const alg of EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) fail('legs_present', `missing required ${alg} signature (leg stripped)`);
      }
      for (const alg of presented) {
        if (!(EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
          fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
        }
      }
    }
  }

  // Executor pinned, BOTH halves (identified but not trusted).
  const pin = executorKeys[proof.executor_key_id];
  const presentedEd = typeof proof.public_key === 'string' ? proof.public_key : '';
  const presentedPq = typeof proof.pq_public_key === 'string' ? proof.pq_public_key : '';
  const derivedPqKeyId = presentedPq
    && Buffer.from(presentedPq, 'base64url').length === ML_DSA_65_PUBLIC_KEY_BYTES
    && Buffer.from(presentedPq, 'base64url').toString('base64url') === presentedPq
    ? executorPqKeyIdOf(presentedPq) : '';
  if (!pin || !pin.public_key || !pin.pq_public_key) {
    fail('executor_key_pinned', `no pinned key pair for executor "${proof.executor_key_id}" (identified but not trusted)`);
  } else {
    if (pin.public_key !== presentedEd) fail('executor_key_pinned', 'presented Ed25519 executor key != pinned key (key substitution)');
    if (pin.pq_public_key !== presentedPq) fail('executor_key_pinned', 'presented ML-DSA-65 executor key != pinned key (key substitution)');
  }
  if (!derivedPqKeyId || proof.pq_key_id !== derivedPqKeyId
    || !EXECUTOR_PQ_KEY_ID.test(typeof proof.pq_key_id === 'string' ? proof.pq_key_id : '')) {
    fail('executor_key_pinned', 'pq_key_id must be the full digest of the presented ML-DSA-65 key');
  }

  // Signature set: both legs over bytes rebuilt from the presented fields and
  // the REGISTERED set, under the PINNED keys only.
  let recomputedBytes: Buffer | null = null;
  try {
    recomputedBytes = executionV2SignedPayload(attestation, EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS);
  } catch {
    recomputedBytes = null;
  }
  if (!recomputedBytes) {
    fail('signature_binds_attestation', 'attestation fields are not canonicalizable');
    fail('executor_signature_valid', 'attestation fields are not canonicalizable');
    return result(attestation.binding_status ?? null);
  }
  const verificationKeys: AgileVerificationKey[] = [
    { alg: 'Ed25519', public_key: pin?.public_key ?? '', key_id: proof.executor_key_id },
    { alg: 'ML-DSA-65', public_key: pin?.pq_public_key ?? '', key_id: derivedPqKeyId || undefined },
  ];
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(recomputedBytes),
      signatures ?? [],
      verificationKeys,
      {
        ...executionAgilityPassthrough(opts),
        policy: 'hybrid_all',
        requiredAlgorithms: [...EXECUTION_INTEGRITY_V2_REQUIRED_ALGORITHMS],
      },
    );
  } catch {
    setResult = null;
  }
  if (setResult?.verified !== true) {
    const reason = String(setResult?.reason ?? 'signature_set_unverified');
    fail('executor_signature_valid',
      `executor signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
    const failedLeg = Array.isArray(setResult?.results)
      ? setResult.results.find((r) => r?.verified !== true) ?? null
      : null;
    if (failedLeg?.reason === 'signature_invalid') {
      fail('signature_binds_attestation',
        'executor signature set does not bind the presented attestation bytes (recomputed payload mismatch)');
    }
  }

  return result(attestation.binding_status ?? null);
}

function executionAgilityPassthrough(opts: ExecutionIntegrityV2Opts): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

const executionIntegrity = {
  bindExecution,
  buildExecutionIntegrity,
  buildExecutionIntegrityV2,
  executedActionHash,
  executionV2SignedPayload,
  verifyExecutionIntegrity,
  verifyExecutionIntegrityV2,
  EXECUTION_INTEGRITY_VERSION,
  EXECUTION_INTEGRITY_V2_VERSION,
};
export default executionIntegrity;
