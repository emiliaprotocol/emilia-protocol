// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORIZATION-BUNDLE-v1 pre-execution verifier.
 *
 * This verifies portable human-approval evidence. It deliberately does not
 * issue an authorization decision, reserve capacity, consume a grant, or
 * assert execution. Native authorization formats stay outside this module and
 * are supplied as an independently verified, profile-specific expected
 * binding. The core deliberately does not privilege OAuth, AP2, WIMSE, or any
 * other authorization system.
 */
import crypto from 'node:crypto';
import { canonicalizeAeb, digestAeb, type AebDigest } from './aeb-adapter-contract.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSignature,
  type AgileSigningKey,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, unknown>;

export const AUTHORIZATION_BUNDLE_VERSION = 'EP-AUTHORIZATION-BUNDLE-v1';

export type AuthorizationBundleVerdict = 'SATISFIED' | 'REFUSE' | 'INDETERMINATE';

export interface AuthorizationBundleKeyEntry {
  approver_id: string;
  public_key: string;
  key_class: 'A' | 'B' | 'C';
  valid_from: string;
  valid_to: string;
  compromised_at?: string | null;
}

export interface AuthorizationBundleCurrentStatus {
  checked_at: string;
  expires_at: string;
  unavailable?: boolean;
  revoked_key_ids: readonly string[];
}

export interface AuthorizationBundleCurrentPolicy {
  policy_hash: AebDigest;
  decision: 'PERMIT' | 'REFUSE';
  checked_at: string;
  expires_at: string;
  unavailable?: boolean;
}

export interface AuthorizationBundleVerificationOptions {
  now: string | number | Date;
  audience: string;
  approverKeys: Record<string, AuthorizationBundleKeyEntry>;
  /** Approvers independently selected by the authorization server or policy. */
  expectedApprovers: readonly string[];
  /** Key custody classes accepted by the relying party for this action. */
  acceptedKeyClasses: readonly AuthorizationBundleKeyEntry['key_class'][];
  /** Current local policy evaluation; a bundle never freezes policy. */
  currentPolicy: AuthorizationBundleCurrentPolicy;
  /** Exact action independently derived by the relying party. */
  expectedAction: unknown;
  /**
   * Fresh authorization instance independently issued or registered by the
   * relying party or authorization server for this approval ceremony.
   * A presenter-selected value is not a trust input.
   */
  expectedAuthorizationInstance?: string;
  /**
   * Native-verified, profile-specific projection independently derived by the
   * relying party. Required when the contexts bind one. The Bundle verifier
   * compares canonical bytes; native verification belongs to the selected
   * profile implementation.
   */
  expectedAuthorizationBinding?: unknown;
  requireAuthorizationBinding?: boolean;
  /** Required when relying-party policy demands current revocation status. */
  currentStatus?: AuthorizationBundleCurrentStatus;
  requireCurrentStatus?: boolean;
  /** Class-A verification hook, normally backed by verifyWebAuthnSignoff. */
  verifyClassASignoff?: (input: {
    signoff: Obj;
    context: Obj;
    contextDigest: AebDigest;
    key: AuthorizationBundleKeyEntry;
  }) => boolean;
  /** Optional directory-proof verifier when keys are not accepted as direct pins. */
  verifyKeyProofs?: (proofs: readonly unknown[], keys: Record<string, AuthorizationBundleKeyEntry>) => boolean;
  /** Optional presentation-evidence verifier selected by relying-party policy. */
  verifyPresentationEvidence?: (evidence: readonly unknown[], contexts: readonly Obj[]) => boolean;
  requirePresentationEvidence?: boolean;
}

export interface AuthorizationBundleVerificationResult {
  verdict: AuthorizationBundleVerdict;
  evidence_satisfied: boolean;
  authorization_decision: false;
  bundle_digest: AebDigest | null;
  checks: Record<string, boolean>;
  reasons: string[];
}

const BUNDLE_KEYS = new Set([
  'bundle_version', 'bundle_id', 'action', 'action_hash', 'contexts', 'signoffs',
  'approver_key_proofs', 'presentation_evidence',
]);
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, expected: ReadonlySet<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && !/[\u0000-\u001f\u007f]/.test(value);
}

function absoluteUri(value: unknown): value is string {
  if (!nonEmptyString(value)) return false;
  try {
    return new URL(value).protocol.length > 1;
  } catch { return false; }
}

function parseInstant(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === 'number') return Number.isFinite(value) ? value : NaN;
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return NaN;
  const result = Date.parse(value);
  return Number.isFinite(result) ? result : NaN;
}

function canonicalDigest(value: unknown): AebDigest | null {
  try { return digestAeb(value); } catch { return null; }
}

function equalCanonical(left: unknown, right: unknown): boolean {
  try { return canonicalizeAeb(left) === canonicalizeAeb(right); } catch { return false; }
}

function canonicalB64url(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const normalized = value.replace(/^b64u:/, '');
  if (!B64URL_RE.test(normalized) || normalized.length % 4 === 1) return false;
  try {
    const bytes = Buffer.from(normalized, 'base64url');
    return bytes.length > 0 && bytes.toString('base64url') === normalized;
  } catch { return false; }
}

function verifyEd25519(signature: unknown, digest: AebDigest, publicKey: unknown): boolean {
  if (!canonicalB64url(signature) || !canonicalB64url(publicKey)) return false;
  try {
    const keyBytes = Buffer.from(String(publicKey).replace(/^b64u:/, ''), 'base64url');
    const key = crypto.createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
    if (key.asymmetricKeyType !== 'ed25519') return false;
    const digestBytes = Buffer.from(digest.slice('sha256:'.length), 'hex');
    return crypto.verify(
      null,
      digestBytes,
      key,
      Buffer.from(String(signature).replace(/^b64u:/, ''), 'base64url'),
    );
  } catch { return false; }
}

function validAuthorizationBinding(value: unknown): value is Obj {
  return isRecord(value)
    && Object.hasOwn(value, 'profile')
    && nonEmptyString(value.profile)
    && canonicalDigest(value) !== null;
}

function baseResult(): AuthorizationBundleVerificationResult {
  return {
    verdict: 'REFUSE',
    evidence_satisfied: false,
    authorization_decision: false,
    bundle_digest: null,
    checks: {
      closed_shape: false,
      action: false,
      contexts: false,
      signatures: false,
      approver_selection: false,
      separation_of_duties: false,
      windows: false,
      audience: false,
      authorization_instance: false,
      authorization_binding: false,
      key_proofs: false,
      presentation: false,
      current_status: false,
      current_policy: false,
    },
    reasons: [],
  };
}

/**
 * Verify an EP-AUTHORIZATION-BUNDLE-v1 as pre-execution evidence.
 * SATISFIED never means AUTHORIZED; the caller still needs a native grant or
 * PDP decision and executor-side atomic consumption.
 */
function verifyAuthorizationBundleCore(
  bundle: unknown,
  options: AuthorizationBundleVerificationOptions,
): AuthorizationBundleVerificationResult {
  options = isRecord(options) ? options as unknown as AuthorizationBundleVerificationOptions
    : {} as AuthorizationBundleVerificationOptions;
  const result = baseResult();
  const definite: string[] = [];
  const uncertain: string[] = [];
  const now = parseInstant(options?.now);
  if (!Number.isFinite(now)) definite.push('verifier_time_invalid');
  if (!absoluteUri(options?.audience)) definite.push('audience_pin_missing_or_invalid');
  const approverKeys = isRecord(options.approverKeys)
    ? options.approverKeys as Record<string, AuthorizationBundleKeyEntry>
    : {};
  if (Object.keys(approverKeys).length === 0) definite.push('approver_keys_missing');

  if (!isRecord(bundle) || !exactKeys(bundle, BUNDLE_KEYS)
      || bundle.bundle_version !== AUTHORIZATION_BUNDLE_VERSION
      || !nonEmptyString(bundle.bundle_id)
      || !isRecord(bundle.action)
      || typeof bundle.action_hash !== 'string' || !DIGEST_RE.test(bundle.action_hash)
      || !Array.isArray(bundle.contexts) || bundle.contexts.length === 0
      || !Array.isArray(bundle.signoffs) || bundle.signoffs.length === 0
      || !Array.isArray(bundle.approver_key_proofs)
      || !Array.isArray(bundle.presentation_evidence)) {
    definite.push('bundle_malformed');
    result.reasons = [...new Set(definite)].sort();
    return result;
  }
  result.checks.closed_shape = true;
  result.bundle_digest = canonicalDigest(bundle);
  if (result.bundle_digest === null) {
    definite.push('bundle_not_canonicalizable');
    result.reasons = [...new Set(definite)].sort();
    return result;
  }

  const actionDigest = canonicalDigest(bundle.action);
  const expectedActionDigest = canonicalDigest(options.expectedAction);
  if (actionDigest !== bundle.action_hash) {
    definite.push('action_hash_mismatch');
  } else if (expectedActionDigest === null) {
    uncertain.push('expected_action_unavailable');
  } else if (expectedActionDigest === actionDigest) {
    result.checks.action = true;
  } else {
    definite.push('action_mismatch');
  }

  const contexts = bundle.contexts.filter(isRecord);
  const signoffs = bundle.signoffs.filter(isRecord);
  if (contexts.length !== bundle.contexts.length || signoffs.length !== bundle.signoffs.length) {
    definite.push('context_or_signoff_malformed');
  }
  const contextByDigest = new Map<AebDigest, Obj>();
  const policyHashes = new Set<string>();
  const policyIds = new Set<string>();
  const audiences = new Set<string>();
  const authorizationInstances = new Set<string>();
  const bindingDigests = new Set<string>();
  let bindingPresence = 0;
  const approverIds: string[] = [];
  const approverIndexes = new Set<number>();
  const nonces = new Set<string>();
  const requiredApprovalCounts = new Set<number>();
  let contextsOk = contexts.length === bundle.contexts.length;
  let windowsOk = Number.isFinite(now);
  let audiencesOk = true;
  let bindingsOk = true;

  for (const context of contexts) {
    const digest = canonicalDigest(context);
    if (digest === null) {
      contextsOk = false;
      definite.push('context_not_canonicalizable');
      continue;
    }
    contextByDigest.set(digest, context);
    if (context.action_hash !== bundle.action_hash
        || typeof context.policy_hash !== 'string' || !DIGEST_RE.test(context.policy_hash)
        || !nonEmptyString(context.policy_id)
        || !nonEmptyString(context.approver)
        || context.initiator !== bundle.action.initiator
        || !Number.isInteger(context.approver_index) || Number(context.approver_index) < 1
        || !Number.isInteger(context.required_approvals) || Number(context.required_approvals) < 1
        || !canonicalB64url(context.nonce)
        || Buffer.from(String(context.nonce).replace(/^b64u:/, ''), 'base64url').length < 16) {
      contextsOk = false;
      definite.push('context_commitment_mismatch');
    }
    if (!canonicalB64url(context.authorization_instance)
        || Buffer.from(
          String(context.authorization_instance).replace(/^b64u:/, ''),
          'base64url',
        ).length < 16) {
      contextsOk = false;
      definite.push('authorization_instance_missing_or_invalid');
    } else {
      authorizationInstances.add(String(context.authorization_instance));
    }
    if (nonEmptyString(context.policy_hash)) policyHashes.add(context.policy_hash);
    if (nonEmptyString(context.policy_id)) policyIds.add(context.policy_id);
    if (nonEmptyString(context.approver)) approverIds.push(context.approver);
    if (Number.isInteger(context.approver_index)) approverIndexes.add(Number(context.approver_index));
    if (nonEmptyString(context.nonce)) nonces.add(context.nonce);
    if (Number.isInteger(context.required_approvals)) {
      requiredApprovalCounts.add(Number(context.required_approvals));
    }
    if (!absoluteUri(context.audience)) {
      audiencesOk = false;
      definite.push('context_audience_missing_or_invalid');
    } else {
      audiences.add(context.audience);
      if (context.audience !== options.audience) {
        audiencesOk = false;
        definite.push('context_audience_mismatch');
      }
    }
    const issued = parseInstant(context.issued_at);
    const expires = parseInstant(context.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires)
        || issued > now || now > expires || issued >= expires) {
      windowsOk = false;
      definite.push('context_outside_validity_window');
    }
    if (context.authorization_binding !== undefined) {
      bindingPresence += 1;
      if (!validAuthorizationBinding(context.authorization_binding)) {
        bindingsOk = false;
        definite.push('authorization_binding_malformed');
      } else {
        const bindingDigest = canonicalDigest(context.authorization_binding);
        if (bindingDigest !== null) bindingDigests.add(bindingDigest);
        if (options.expectedAuthorizationBinding === undefined
            || !validAuthorizationBinding(options.expectedAuthorizationBinding)) {
          bindingsOk = false;
          uncertain.push('native_authorization_binding_unavailable');
        } else if (!equalCanonical(context.authorization_binding, options.expectedAuthorizationBinding)) {
          bindingsOk = false;
          definite.push('authorization_binding_mismatch');
        }
      }
    }
  }
  if (bindingPresence !== 0 && bindingPresence !== contexts.length) {
    contextsOk = false;
    bindingsOk = false;
    definite.push('contexts_do_not_share_one_policy_audience_and_binding');
  }
  if (authorizationInstances.size !== 1) {
    contextsOk = false;
    definite.push('authorization_instance_mismatch');
  }
  if (!canonicalB64url(options.expectedAuthorizationInstance)
      || Buffer.from(
        String(options.expectedAuthorizationInstance).replace(/^b64u:/, ''),
        'base64url',
      ).length < 16) {
    uncertain.push('expected_authorization_instance_unavailable');
  } else if (authorizationInstances.size === 1
      && authorizationInstances.has(options.expectedAuthorizationInstance)) {
    result.checks.authorization_instance = true;
  } else {
    definite.push('authorization_instance_mismatch');
  }
  if (policyHashes.size !== 1 || policyIds.size !== 1 || audiences.size !== 1
      || bindingDigests.size > 1 || approverIndexes.size !== contexts.length
      || nonces.size !== contexts.length || requiredApprovalCounts.size !== 1) {
    contextsOk = false;
    definite.push('contexts_do_not_share_one_policy_audience_and_binding');
  }
  if (options.requireAuthorizationBinding === true && bindingDigests.size === 0) {
    bindingsOk = false;
    definite.push('authorization_binding_required');
  }
  result.checks.contexts = contextsOk;
  result.checks.windows = windowsOk;
  result.checks.audience = audiencesOk;
  result.checks.authorization_binding = bindingsOk;

  const rawExpectedApprovers = options.expectedApprovers;
  const expectedApprovers = Array.isArray(rawExpectedApprovers)
    ? rawExpectedApprovers.filter(nonEmptyString)
    : [];
  if (expectedApprovers.length === 0
      || expectedApprovers.length !== rawExpectedApprovers?.length) {
    uncertain.push('approver_selection_unavailable');
  } else {
    const expected = [...new Set(expectedApprovers)].sort();
    const presented = [...new Set(approverIds)].sort();
    if (expected.length !== expectedApprovers.length || !equalCanonical(expected, presented)) {
      definite.push('approver_selection_mismatch');
    } else {
      result.checks.approver_selection = true;
    }
  }

  const requiredValues = contexts.map((context) => context.required_approvals);
  const validRequired = requiredValues.every((value) => Number.isInteger(value) && Number(value) >= 1)
    && new Set(requiredValues).size === 1;
  const required = validRequired ? Number(requiredValues[0]) : Number.POSITIVE_INFINITY;
  if (!validRequired || required > contexts.length) {
    contextsOk = false;
    result.checks.contexts = false;
    definite.push('required_approvals_invalid');
  }

  const validApprovers: string[] = [];
  const signedContextDigests = new Set<string>();
  let signaturesOk = signoffs.length === bundle.signoffs.length;
  for (const signoff of signoffs) {
    const contextDigest = signoff.context_hash;
    if (typeof contextDigest !== 'string' || !DIGEST_RE.test(contextDigest)) {
      signaturesOk = false;
      definite.push('signoff_context_hash_invalid');
      continue;
    }
    const context = contextByDigest.get(contextDigest as AebDigest);
    if (signedContextDigests.has(contextDigest)) {
      signaturesOk = false;
      definite.push('signoff_context_coverage_failed');
      continue;
    }
    signedContextDigests.add(contextDigest);
    const keyId = signoff.approver_key_id;
    const key = nonEmptyString(keyId) ? approverKeys[keyId] : undefined;
    if (!context || !key || key.approver_id !== context.approver
        || key.key_class !== signoff.key_class) {
      signaturesOk = false;
      definite.push('signoff_context_or_key_mismatch');
      continue;
    }
    const issued = parseInstant(context.issued_at);
    const keyFrom = parseInstant(key.valid_from);
    const keyTo = parseInstant(key.valid_to);
    const signedAt = parseInstant(signoff.signed_at);
    const acceptedKeyClasses = Array.isArray(options.acceptedKeyClasses)
      ? options.acceptedKeyClasses
      : [];
    if (!acceptedKeyClasses.includes(key.key_class)) {
      signaturesOk = false;
      definite.push('key_class_not_accepted');
      continue;
    }
    if (![issued, keyFrom, keyTo, signedAt].every(Number.isFinite)
        || issued < keyFrom || issued > keyTo || now < keyFrom || now > keyTo
        || signedAt < issued || signedAt > parseInstant(context.expires_at) || signedAt > now
        || (key.compromised_at !== undefined && key.compromised_at !== null)) {
      signaturesOk = false;
      definite.push('approver_key_not_current');
      continue;
    }
    let verified = false;
    if (key.key_class === 'A') {
      if (!options.verifyClassASignoff) {
        uncertain.push('class_a_verifier_unavailable');
      } else {
        try {
          verified = options.verifyClassASignoff({
            signoff,
            context,
            contextDigest: contextDigest as AebDigest,
            key,
          }) === true;
        } catch { verified = false; }
      }
    } else {
      verified = verifyEd25519(signoff.signature, contextDigest as AebDigest, key.public_key);
    }
    if (!verified) {
      signaturesOk = false;
      if (key.key_class === 'A' && !options.verifyClassASignoff) continue;
      definite.push('signoff_signature_invalid');
      continue;
    }
    if (context.decision === 'denied') {
      definite.push('signed_denial_does_not_approve');
      continue;
    }
    if (context.decision !== undefined && context.decision !== 'approved') {
      definite.push('signed_decision_unknown');
      continue;
    }
    validApprovers.push(String(context.approver));
  }
  if (!validRequired || signoffs.length < required
      || signedContextDigests.size !== signoffs.length) {
    signaturesOk = false;
    definite.push('signoff_context_coverage_failed');
  }
  result.checks.signatures = signaturesOk;

  const initiator = bundle.action.initiator;
  const sod = validRequired
    && nonEmptyString(initiator)
    && !validApprovers.includes(initiator)
    && new Set(validApprovers).size === validApprovers.length
    && validApprovers.length >= required;
  result.checks.separation_of_duties = sod;
  if (!sod) definite.push('separation_of_duties_or_quorum_failed');

  if (bundle.approver_key_proofs.length === 0) {
    result.checks.key_proofs = Object.keys(approverKeys).length > 0;
    if (!result.checks.key_proofs) uncertain.push('approver_key_trust_unavailable');
  } else if (!options.verifyKeyProofs) {
    uncertain.push('directory_proof_verifier_unavailable');
  } else {
    try { result.checks.key_proofs = options.verifyKeyProofs(bundle.approver_key_proofs, approverKeys) === true; }
    catch { result.checks.key_proofs = false; }
    if (!result.checks.key_proofs) definite.push('directory_proof_invalid');
  }

  if (bundle.presentation_evidence.length === 0) {
    result.checks.presentation = options.requirePresentationEvidence !== true;
    if (!result.checks.presentation) definite.push('presentation_evidence_required');
  } else if (!options.verifyPresentationEvidence) {
    uncertain.push('presentation_verifier_unavailable');
  } else {
    try { result.checks.presentation = options.verifyPresentationEvidence(bundle.presentation_evidence, contexts) === true; }
    catch { result.checks.presentation = false; }
    if (!result.checks.presentation) definite.push('presentation_evidence_invalid');
  }

  if (options.requireCurrentStatus === true) {
    const status = options.currentStatus;
    const checked = parseInstant(status?.checked_at);
    const expires = parseInstant(status?.expires_at);
    if (!status || status.unavailable === true || !Number.isFinite(checked) || !Number.isFinite(expires)
        || checked > now || now >= expires) {
      uncertain.push('current_status_unavailable_or_stale');
    } else if (!Array.isArray(status.revoked_key_ids)) {
      uncertain.push('current_status_malformed');
    } else if (signoffs.some((signoff) => status.revoked_key_ids.includes(String(signoff.approver_key_id)))) {
      definite.push('approver_key_revoked');
    } else {
      result.checks.current_status = true;
    }
  } else {
    result.checks.current_status = true;
  }

  const policy = options.currentPolicy;
  const policyChecked = parseInstant(policy?.checked_at);
  const policyExpires = parseInstant(policy?.expires_at);
  if (!policy || policy.unavailable === true
      || typeof policy.policy_hash !== 'string' || !DIGEST_RE.test(policy.policy_hash)
      || !Number.isFinite(policyChecked) || !Number.isFinite(policyExpires)
      || policyChecked > now || now >= policyExpires) {
    uncertain.push('current_policy_unavailable_or_stale');
  } else if (policy.decision === 'REFUSE') {
    definite.push('current_policy_refused');
  } else if (policy.decision !== 'PERMIT' || policyHashes.size !== 1
      || !policyHashes.has(policy.policy_hash)) {
    definite.push('current_policy_mismatch');
  } else {
    result.checks.current_policy = true;
  }

  result.reasons = [...new Set([...definite, ...uncertain])].sort();
  if (definite.length > 0) return result;
  if (uncertain.length > 0 || Object.values(result.checks).some((value) => value !== true)) {
    result.verdict = 'INDETERMINATE';
    return result;
  }
  result.verdict = 'SATISFIED';
  result.evidence_satisfied = true;
  return result;
}

/**
 * Fail-closed public wrapper. Hostile proxies, accessors, and malformed option
 * objects are protocol input and must produce a verdict instead of escaping as
 * an exception across an executor boundary.
 */
export function verifyAuthorizationBundle(
  bundle: unknown,
  options: AuthorizationBundleVerificationOptions,
): AuthorizationBundleVerificationResult {
  try {
    return verifyAuthorizationBundleCore(bundle, options);
  } catch {
    const result = baseResult();
    result.reasons = ['bundle_or_verifier_input_malformed'];
    return result;
  }
}

export interface AuthorizationBundleGrantBindingState {
  bundle_digest: AebDigest;
  grant_id: string;
}

export interface AuthorizationBundleGrantBindingResult {
  outcome: 'BOUND' | 'IDEMPOTENT' | 'REFUSE';
  state: AuthorizationBundleGrantBindingState;
  reason: string | null;
}

/**
 * Deterministic compare-and-set transition for AS-side bundle-to-grant state.
 * The caller MUST execute this transition atomically in its authoritative
 * store; this pure helper does not claim distributed or cross-domain locking.
 */
export function bindAuthorizationBundleToGrant(
  current: AuthorizationBundleGrantBindingState | null,
  requested: AuthorizationBundleGrantBindingState,
): AuthorizationBundleGrantBindingResult {
  if (!requested || typeof requested !== 'object'
      || typeof requested.bundle_digest !== 'string' || !DIGEST_RE.test(requested.bundle_digest)
      || !nonEmptyString(requested.grant_id)) {
    throw new TypeError('invalid authorization bundle grant binding request');
  }
  if (current === null) {
    return { outcome: 'BOUND', state: { ...requested }, reason: null };
  }
  if (current.bundle_digest !== requested.bundle_digest) {
    return { outcome: 'REFUSE', state: { ...current }, reason: 'bundle_digest_mismatch' };
  }
  if (current.grant_id === requested.grant_id) {
    return { outcome: 'IDEMPOTENT', state: { ...current }, reason: null };
  }
  return { outcome: 'REFUSE', state: { ...current }, reason: 'bundle_already_bound_to_another_grant' };
}

// ===========================================================================
// EP-AUTHORIZATION-BUNDLE-v2 -- hybrid (Ed25519 + ML-DSA-65) Class B/C signoffs
// ===========================================================================
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to Class B/C
 * approver signoffs inside the bundle:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature per signoff changes
 *    the SHAPE of the signoff's proof, a wire-format change, so the bundle
 *    takes a new `bundle_version` (EP-AUTHORIZATION-BUNDLE-v1 -> -v2).
 *    verifyAuthorizationBundle() above is untouched: it requires
 *    `bundle.bundle_version === AUTHORIZATION_BUNDLE_VERSION` (v1) as part of
 *    its closed-shape gate, so a v2 bundle refuses on `bundle_malformed`
 *    before any signature inspection, and never throws.
 * 2. SET SHAPE. Each Class B/C signoff's flat `signature` string is replaced
 *    by `proof`, carrying `required_algorithms` plus a `signatures` array
 *    shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }).
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (signoffV2SigningBytes below), alongside the context digest
 *    each signoff already binds. Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 bundles keep verifying, unchanged, through
 *    verifyAuthorizationBundle (which stays synchronous internally, even
 *    though its public wrapper always returns a value directly). v2
 *    verification is a SEPARATE, ASYNC entry point (ML-DSA verification is
 *    async); verifyAuthorizationBundleAny() routes on `bundle_version` for
 *    callers holding a mixed bag. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure path is a reason string folded into the
 *    same `reasons` list v1 uses; nothing throws on caller input (mirrored by
 *    the same hostile-proxy try/catch wrapper v1 uses). An absent ML-DSA
 *    backend makes the affected signoff's signature check fail, which is
 *    surfaced through the existing 'signoff_signature_invalid' reason --
 *    never a skipped check and never a pass on the classical leg alone.
 *
 * SCOPE BOUNDARY (honest, not a hedge): Class A signoffs are UNCHANGED in v2.
 * verifyClassASignoff remains the sole authority for a Class A signoff exactly
 * as in v1 -- Class A is a hardware-authenticator (WebAuthn/passkey) ceremony,
 * and a PQ upgrade there is gated on FIDO Alliance / W3C WebAuthn PQC
 * extensions landing in browsers and authenticators, not on EP code (see
 * docs/protocol/pq-hybrid-program.md, priority item 2). Only Class B/C
 * signoffs -- EP-issued Ed25519 keys this module verifies directly -- gain the
 * ML-DSA-65 leg. A v2 bundle's Class B/C approver key entries carry BOTH
 * `public_key` and `pq_public_key`; a key entry missing the PQ half fails the
 * affected signoff, never a silent single-leg pass.
 *
 * HONEST BOUNDARIES carry over unchanged from v1: SATISFIED never means
 * AUTHORIZED. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * v2 does NOT retroactively protect bundles already issued under v1.
 */

export const AUTHORIZATION_BUNDLE_V2_VERSION = 'EP-AUTHORIZATION-BUNDLE-v2';
const AUTHORIZATION_BUNDLE_SIGNOFF_V2_DOMAIN = 'EP-AUTHORIZATION-BUNDLE-SIGNOFF-v2\0';

/** The registered required algorithm set, in canonical order. */
export const AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

export interface AuthorizationBundleSignoffV2Proof {
  required_algorithms: readonly string[];
  signatures: AgileSignature[];
}

/** v2 Class B/C approver key: BOTH public halves. Class A entries need not carry pq_public_key. */
export interface AuthorizationBundleKeyEntryV2 extends AuthorizationBundleKeyEntry {
  pq_public_key?: string;
}

export interface AuthorizationBundleVerificationOptionsV2
  extends Omit<AuthorizationBundleVerificationOptions, 'approverKeys'> {
  approverKeys: Record<string, AuthorizationBundleKeyEntryV2>;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}

function algorithmSetMatchesRegisteredBundleV2(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS[i]);
}

function validBundleAgileSignatureSetShape(value: unknown): value is AgileSignature[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  const presented = new Set<string>();
  for (const s of value) {
    if (!isRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') return false;
    if (presented.has(s.alg as string)) return false;
    presented.add(s.alg as string);
  }
  if (presented.size !== AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS.length) return false;
  return AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS.every((alg) => presented.has(alg));
}

/**
 * The bytes BOTH legs sign for one signoff: the context digest that signoff
 * binds, plus the committed `required_algorithms` set, under a dedicated v2
 * domain tag. This REPLACES v1's convention of signing the raw context-digest
 * bytes directly (crypto.sign over the bare 32-byte digest) -- v2 needs
 * structure to commit the algorithm set into, so it moves to the same
 * domain-separated canonical-JSON convention every other hybrid surface uses.
 * Recomputed independently by the verifier from the PRESENTED context digest
 * and the REGISTERED set.
 */
export function signoffV2SigningBytes(
  contextDigest: AebDigest,
  requiredAlgorithms: readonly string[] = AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesRegisteredBundleV2(requiredAlgorithms)) {
    throw new Error('signoffV2SigningBytes: algorithm set is not the registered EP-AUTHORIZATION-BUNDLE-v2 set');
  }
  return Buffer.from(
    `${AUTHORIZATION_BUNDLE_SIGNOFF_V2_DOMAIN}${canonicalizeAeb({
      context_hash: contextDigest,
      required_algorithms: [...requiredAlgorithms],
    })}`,
    'utf8',
  );
}

/** Mint a real hybrid Class B/C signoff proof over one context digest. Throws on issuer misuse. */
export async function signAuthorizationBundleSignoffV2(
  contextDigest: AebDigest,
  signers: AgileSigningKey[],
  options: AgilityOptions = {},
): Promise<AuthorizationBundleSignoffV2Proof> {
  const bytes = signoffV2SigningBytes(contextDigest, AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(new Uint8Array(bytes), signers, options);
  return { required_algorithms: [...AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS], signatures };
}

/** FAIL-CLOSED hybrid check for one Class B/C signoff; never verifies on one leg alone. */
async function verifySignoffHybrid(
  proof: unknown,
  contextDigest: AebDigest,
  key: { public_key?: unknown; pq_public_key?: unknown } | undefined,
  agility: AgilityOptions,
): Promise<boolean> {
  if (!isRecord(proof) || !algorithmSetMatchesRegisteredBundleV2(proof.required_algorithms)
      || !validBundleAgileSignatureSetShape(proof.signatures)) return false;
  if (typeof key?.public_key !== 'string' || typeof key?.pq_public_key !== 'string'
      || key.public_key.length === 0 || key.pq_public_key.length === 0) return false;
  let bytes: Buffer;
  try {
    bytes = signoffV2SigningBytes(contextDigest, AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS);
  } catch {
    return false;
  }
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(bytes),
      proof.signatures as AgileSignature[],
      [
        { alg: 'Ed25519', public_key: key.public_key },
        { alg: 'ML-DSA-65', public_key: key.pq_public_key },
      ],
      { ...agility, policy: 'hybrid_all', requiredAlgorithms: [...AUTHORIZATION_BUNDLE_V2_REQUIRED_ALGORITHMS] },
    );
  } catch {
    setResult = null;
  }
  return setResult?.verified === true;
}

/**
 * Verify an EP-AUTHORIZATION-BUNDLE-v2 as pre-execution evidence. Structurally
 * identical to verifyAuthorizationBundleCore (the same context/window/
 * approver-selection/presentation/policy checks, none of them crypto); the
 * ONLY hybrid, async piece is the Class B/C signoff signature check.
 * SATISFIED never means AUTHORIZED here either.
 */
async function verifyAuthorizationBundleCoreV2(
  bundle: unknown,
  options: AuthorizationBundleVerificationOptionsV2,
): Promise<AuthorizationBundleVerificationResult> {
  options = isRecord(options) ? options as unknown as AuthorizationBundleVerificationOptionsV2
    : {} as AuthorizationBundleVerificationOptionsV2;
  const agility: AgilityOptions = {};
  if (options.mldsaBackend !== undefined) agility.mldsaBackend = options.mldsaBackend;
  if (options.mldsaBackendLoader !== undefined) agility.mldsaBackendLoader = options.mldsaBackendLoader;
  const result = baseResult();
  const definite: string[] = [];
  const uncertain: string[] = [];
  const now = parseInstant(options?.now);
  if (!Number.isFinite(now)) definite.push('verifier_time_invalid');
  if (!absoluteUri(options?.audience)) definite.push('audience_pin_missing_or_invalid');
  const approverKeys = isRecord(options.approverKeys)
    ? options.approverKeys as Record<string, AuthorizationBundleKeyEntryV2>
    : {};
  if (Object.keys(approverKeys).length === 0) definite.push('approver_keys_missing');

  if (!isRecord(bundle) || !exactKeys(bundle, BUNDLE_KEYS)
      || bundle.bundle_version !== AUTHORIZATION_BUNDLE_V2_VERSION
      || !nonEmptyString(bundle.bundle_id)
      || !isRecord(bundle.action)
      || typeof bundle.action_hash !== 'string' || !DIGEST_RE.test(bundle.action_hash)
      || !Array.isArray(bundle.contexts) || bundle.contexts.length === 0
      || !Array.isArray(bundle.signoffs) || bundle.signoffs.length === 0
      || !Array.isArray(bundle.approver_key_proofs)
      || !Array.isArray(bundle.presentation_evidence)) {
    definite.push('bundle_malformed');
    result.reasons = [...new Set(definite)].sort();
    return result;
  }
  result.checks.closed_shape = true;
  result.bundle_digest = canonicalDigest(bundle);
  if (result.bundle_digest === null) {
    definite.push('bundle_not_canonicalizable');
    result.reasons = [...new Set(definite)].sort();
    return result;
  }

  const actionDigest = canonicalDigest(bundle.action);
  const expectedActionDigest = canonicalDigest(options.expectedAction);
  if (actionDigest !== bundle.action_hash) {
    definite.push('action_hash_mismatch');
  } else if (expectedActionDigest === null) {
    uncertain.push('expected_action_unavailable');
  } else if (expectedActionDigest === actionDigest) {
    result.checks.action = true;
  } else {
    definite.push('action_mismatch');
  }

  const contexts = bundle.contexts.filter(isRecord);
  const signoffs = bundle.signoffs.filter(isRecord);
  if (contexts.length !== bundle.contexts.length || signoffs.length !== bundle.signoffs.length) {
    definite.push('context_or_signoff_malformed');
  }
  const contextByDigest = new Map<AebDigest, Obj>();
  const policyHashes = new Set<string>();
  const policyIds = new Set<string>();
  const audiences = new Set<string>();
  const authorizationInstances = new Set<string>();
  const bindingDigests = new Set<string>();
  let bindingPresence = 0;
  const approverIds: string[] = [];
  const approverIndexes = new Set<number>();
  const nonces = new Set<string>();
  const requiredApprovalCounts = new Set<number>();
  let contextsOk = contexts.length === bundle.contexts.length;
  let windowsOk = Number.isFinite(now);
  let audiencesOk = true;
  let bindingsOk = true;

  for (const context of contexts) {
    const digest = canonicalDigest(context);
    if (digest === null) {
      contextsOk = false;
      definite.push('context_not_canonicalizable');
      continue;
    }
    contextByDigest.set(digest, context);
    if (context.action_hash !== bundle.action_hash
        || typeof context.policy_hash !== 'string' || !DIGEST_RE.test(context.policy_hash)
        || !nonEmptyString(context.policy_id)
        || !nonEmptyString(context.approver)
        || context.initiator !== bundle.action.initiator
        || !Number.isInteger(context.approver_index) || Number(context.approver_index) < 1
        || !Number.isInteger(context.required_approvals) || Number(context.required_approvals) < 1
        || !canonicalB64url(context.nonce)
        || Buffer.from(String(context.nonce).replace(/^b64u:/, ''), 'base64url').length < 16) {
      contextsOk = false;
      definite.push('context_commitment_mismatch');
    }
    if (!canonicalB64url(context.authorization_instance)
        || Buffer.from(
          String(context.authorization_instance).replace(/^b64u:/, ''),
          'base64url',
        ).length < 16) {
      contextsOk = false;
      definite.push('authorization_instance_missing_or_invalid');
    } else {
      authorizationInstances.add(String(context.authorization_instance));
    }
    if (nonEmptyString(context.policy_hash)) policyHashes.add(context.policy_hash);
    if (nonEmptyString(context.policy_id)) policyIds.add(context.policy_id);
    if (nonEmptyString(context.approver)) approverIds.push(context.approver);
    if (Number.isInteger(context.approver_index)) approverIndexes.add(Number(context.approver_index));
    if (nonEmptyString(context.nonce)) nonces.add(context.nonce);
    if (Number.isInteger(context.required_approvals)) {
      requiredApprovalCounts.add(Number(context.required_approvals));
    }
    if (!absoluteUri(context.audience)) {
      audiencesOk = false;
      definite.push('context_audience_missing_or_invalid');
    } else {
      audiences.add(context.audience);
      if (context.audience !== options.audience) {
        audiencesOk = false;
        definite.push('context_audience_mismatch');
      }
    }
    const issued = parseInstant(context.issued_at);
    const expires = parseInstant(context.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires)
        || issued > now || now > expires || issued >= expires) {
      windowsOk = false;
      definite.push('context_outside_validity_window');
    }
    if (context.authorization_binding !== undefined) {
      bindingPresence += 1;
      if (!validAuthorizationBinding(context.authorization_binding)) {
        bindingsOk = false;
        definite.push('authorization_binding_malformed');
      } else {
        const bindingDigest = canonicalDigest(context.authorization_binding);
        if (bindingDigest !== null) bindingDigests.add(bindingDigest);
        if (options.expectedAuthorizationBinding === undefined
            || !validAuthorizationBinding(options.expectedAuthorizationBinding)) {
          bindingsOk = false;
          uncertain.push('native_authorization_binding_unavailable');
        } else if (!equalCanonical(context.authorization_binding, options.expectedAuthorizationBinding)) {
          bindingsOk = false;
          definite.push('authorization_binding_mismatch');
        }
      }
    }
  }
  if (bindingPresence !== 0 && bindingPresence !== contexts.length) {
    contextsOk = false;
    bindingsOk = false;
    definite.push('contexts_do_not_share_one_policy_audience_and_binding');
  }
  if (authorizationInstances.size !== 1) {
    contextsOk = false;
    definite.push('authorization_instance_mismatch');
  }
  if (!canonicalB64url(options.expectedAuthorizationInstance)
      || Buffer.from(
        String(options.expectedAuthorizationInstance).replace(/^b64u:/, ''),
        'base64url',
      ).length < 16) {
    uncertain.push('expected_authorization_instance_unavailable');
  } else if (authorizationInstances.size === 1
      && authorizationInstances.has(options.expectedAuthorizationInstance)) {
    result.checks.authorization_instance = true;
  } else {
    definite.push('authorization_instance_mismatch');
  }
  if (policyHashes.size !== 1 || policyIds.size !== 1 || audiences.size !== 1
      || bindingDigests.size > 1 || approverIndexes.size !== contexts.length
      || nonces.size !== contexts.length || requiredApprovalCounts.size !== 1) {
    contextsOk = false;
    definite.push('contexts_do_not_share_one_policy_audience_and_binding');
  }
  if (options.requireAuthorizationBinding === true && bindingDigests.size === 0) {
    bindingsOk = false;
    definite.push('authorization_binding_required');
  }
  result.checks.contexts = contextsOk;
  result.checks.windows = windowsOk;
  result.checks.audience = audiencesOk;
  result.checks.authorization_binding = bindingsOk;

  const rawExpectedApprovers = options.expectedApprovers;
  const expectedApprovers = Array.isArray(rawExpectedApprovers)
    ? rawExpectedApprovers.filter(nonEmptyString)
    : [];
  if (expectedApprovers.length === 0
      || expectedApprovers.length !== rawExpectedApprovers?.length) {
    uncertain.push('approver_selection_unavailable');
  } else {
    const expected = [...new Set(expectedApprovers)].sort();
    const presented = [...new Set(approverIds)].sort();
    if (expected.length !== expectedApprovers.length || !equalCanonical(expected, presented)) {
      definite.push('approver_selection_mismatch');
    } else {
      result.checks.approver_selection = true;
    }
  }

  const requiredValues = contexts.map((context) => context.required_approvals);
  const validRequired = requiredValues.every((value) => Number.isInteger(value) && Number(value) >= 1)
    && new Set(requiredValues).size === 1;
  const required = validRequired ? Number(requiredValues[0]) : Number.POSITIVE_INFINITY;
  if (!validRequired || required > contexts.length) {
    contextsOk = false;
    result.checks.contexts = false;
    definite.push('required_approvals_invalid');
  }

  const validApprovers: string[] = [];
  const signedContextDigests = new Set<string>();
  let signaturesOk = signoffs.length === bundle.signoffs.length;
  for (const signoff of signoffs) {
    const contextDigest = signoff.context_hash;
    if (typeof contextDigest !== 'string' || !DIGEST_RE.test(contextDigest)) {
      signaturesOk = false;
      definite.push('signoff_context_hash_invalid');
      continue;
    }
    const context = contextByDigest.get(contextDigest as AebDigest);
    if (signedContextDigests.has(contextDigest)) {
      signaturesOk = false;
      definite.push('signoff_context_coverage_failed');
      continue;
    }
    signedContextDigests.add(contextDigest);
    const keyId = signoff.approver_key_id;
    const key = nonEmptyString(keyId) ? approverKeys[keyId] : undefined;
    if (!context || !key || key.approver_id !== context.approver
        || key.key_class !== signoff.key_class) {
      signaturesOk = false;
      definite.push('signoff_context_or_key_mismatch');
      continue;
    }
    const issued = parseInstant(context.issued_at);
    const keyFrom = parseInstant(key.valid_from);
    const keyTo = parseInstant(key.valid_to);
    const signedAt = parseInstant(signoff.signed_at);
    const acceptedKeyClasses = Array.isArray(options.acceptedKeyClasses)
      ? options.acceptedKeyClasses
      : [];
    if (!acceptedKeyClasses.includes(key.key_class)) {
      signaturesOk = false;
      definite.push('key_class_not_accepted');
      continue;
    }
    if (![issued, keyFrom, keyTo, signedAt].every(Number.isFinite)
        || issued < keyFrom || issued > keyTo || now < keyFrom || now > keyTo
        || signedAt < issued || signedAt > parseInstant(context.expires_at) || signedAt > now
        || (key.compromised_at !== undefined && key.compromised_at !== null)) {
      signaturesOk = false;
      definite.push('approver_key_not_current');
      continue;
    }
    let verified = false;
    if (key.key_class === 'A') {
      if (!options.verifyClassASignoff) {
        uncertain.push('class_a_verifier_unavailable');
      } else {
        try {
          verified = options.verifyClassASignoff({
            signoff,
            context,
            contextDigest: contextDigest as AebDigest,
            key,
          }) === true;
        } catch { verified = false; }
      }
    } else {
      // Class B/C: the ONLY hybrid, async signature path in this migration.
      verified = await verifySignoffHybrid(signoff.proof, contextDigest as AebDigest, key, agility);
    }
    if (!verified) {
      signaturesOk = false;
      if (key.key_class === 'A' && !options.verifyClassASignoff) continue;
      definite.push('signoff_signature_invalid');
      continue;
    }
    if (context.decision === 'denied') {
      definite.push('signed_denial_does_not_approve');
      continue;
    }
    if (context.decision !== undefined && context.decision !== 'approved') {
      definite.push('signed_decision_unknown');
      continue;
    }
    validApprovers.push(String(context.approver));
  }
  if (!validRequired || signoffs.length < required
      || signedContextDigests.size !== signoffs.length) {
    signaturesOk = false;
    definite.push('signoff_context_coverage_failed');
  }
  result.checks.signatures = signaturesOk;

  const initiator = bundle.action.initiator;
  const sod = validRequired
    && nonEmptyString(initiator)
    && !validApprovers.includes(initiator)
    && new Set(validApprovers).size === validApprovers.length
    && validApprovers.length >= required;
  result.checks.separation_of_duties = sod;
  if (!sod) definite.push('separation_of_duties_or_quorum_failed');

  if (bundle.approver_key_proofs.length === 0) {
    result.checks.key_proofs = Object.keys(approverKeys).length > 0;
    if (!result.checks.key_proofs) uncertain.push('approver_key_trust_unavailable');
  } else if (!options.verifyKeyProofs) {
    uncertain.push('directory_proof_verifier_unavailable');
  } else {
    try { result.checks.key_proofs = options.verifyKeyProofs(bundle.approver_key_proofs, approverKeys) === true; }
    catch { result.checks.key_proofs = false; }
    if (!result.checks.key_proofs) definite.push('directory_proof_invalid');
  }

  if (bundle.presentation_evidence.length === 0) {
    result.checks.presentation = options.requirePresentationEvidence !== true;
    if (!result.checks.presentation) definite.push('presentation_evidence_required');
  } else if (!options.verifyPresentationEvidence) {
    uncertain.push('presentation_verifier_unavailable');
  } else {
    try { result.checks.presentation = options.verifyPresentationEvidence(bundle.presentation_evidence, contexts) === true; }
    catch { result.checks.presentation = false; }
    if (!result.checks.presentation) definite.push('presentation_evidence_invalid');
  }

  if (options.requireCurrentStatus === true) {
    const status = options.currentStatus;
    const checked = parseInstant(status?.checked_at);
    const expires = parseInstant(status?.expires_at);
    if (!status || status.unavailable === true || !Number.isFinite(checked) || !Number.isFinite(expires)
        || checked > now || now >= expires) {
      uncertain.push('current_status_unavailable_or_stale');
    } else if (!Array.isArray(status.revoked_key_ids)) {
      uncertain.push('current_status_malformed');
    } else if (signoffs.some((signoff) => status.revoked_key_ids.includes(String(signoff.approver_key_id)))) {
      definite.push('approver_key_revoked');
    } else {
      result.checks.current_status = true;
    }
  } else {
    result.checks.current_status = true;
  }

  const policy = options.currentPolicy;
  const policyChecked = parseInstant(policy?.checked_at);
  const policyExpires = parseInstant(policy?.expires_at);
  if (!policy || policy.unavailable === true
      || typeof policy.policy_hash !== 'string' || !DIGEST_RE.test(policy.policy_hash)
      || !Number.isFinite(policyChecked) || !Number.isFinite(policyExpires)
      || policyChecked > now || now >= policyExpires) {
    uncertain.push('current_policy_unavailable_or_stale');
  } else if (policy.decision === 'REFUSE') {
    definite.push('current_policy_refused');
  } else if (policy.decision !== 'PERMIT' || policyHashes.size !== 1
      || !policyHashes.has(policy.policy_hash)) {
    definite.push('current_policy_mismatch');
  } else {
    result.checks.current_policy = true;
  }

  result.reasons = [...new Set([...definite, ...uncertain])].sort();
  if (definite.length > 0) return result;
  if (uncertain.length > 0 || Object.values(result.checks).some((value) => value !== true)) {
    result.verdict = 'INDETERMINATE';
    return result;
  }
  result.verdict = 'SATISFIED';
  result.evidence_satisfied = true;
  return result;
}

/**
 * Fail-closed public wrapper for EP-AUTHORIZATION-BUNDLE-v2. Hostile proxies,
 * accessors, and malformed option objects are protocol input and must produce
 * a verdict instead of escaping as an exception.
 */
export async function verifyAuthorizationBundleV2(
  bundle: unknown,
  options: AuthorizationBundleVerificationOptionsV2,
): Promise<AuthorizationBundleVerificationResult> {
  try {
    return await verifyAuthorizationBundleCoreV2(bundle, options);
  } catch {
    const result = baseResult();
    result.reasons = ['bundle_or_verifier_input_malformed'];
    return result;
  }
}

/** Route a bundle of EITHER version to its own verifier, on `bundle_version`. */
export async function verifyAuthorizationBundleAny(
  bundle: unknown,
  options: AuthorizationBundleVerificationOptions | AuthorizationBundleVerificationOptionsV2,
): Promise<AuthorizationBundleVerificationResult> {
  if (isRecord(bundle) && bundle.bundle_version === AUTHORIZATION_BUNDLE_V2_VERSION) {
    return verifyAuthorizationBundleV2(bundle, options as AuthorizationBundleVerificationOptionsV2);
  }
  return verifyAuthorizationBundle(bundle, options as AuthorizationBundleVerificationOptions);
}
