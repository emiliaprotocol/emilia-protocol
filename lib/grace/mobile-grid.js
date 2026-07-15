// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import cbor from 'cbor';
import { canonicalize, isCanonicalizable, verifyWebAuthnSignoff } from '../../packages/verify/index.js';
import { verifyQuorum } from '../../packages/verify/quorum.js';
import { strictJsonGate } from '../../packages/verify/strict-json.js';
import { hashCanonical } from '../../packages/mobile/index.js';
import { checkOrderWithinEnvelope, computeCompliance, runSettlementOnce } from './curtailment.js';

export const GRACE_MOBILE_ACTION_VERSION = 'EP-GRACE-CURTAILMENT-ACTION-v1';
export const GRACE_DISPATCH_VERSION = 'EP-GRACE-COSA-DISPATCH-v1';
export const GRACE_COSA_ACK_VERSION = 'EP-GRACE-COSA-ACK-v1';
export const GRACE_METER_VERSION = 'EP-GRACE-METER-STATEMENT-v1';
export const GRACE_BUNDLE_VERSION = 'EP-GRACE-PROOF-OF-CURTAILMENT-v1';
export const ACTION_STATE_SPEC_VERSION = 'draft-mih-scitt-agent-action-capsule-02';
export const ACTION_STATE_FORMAT_VERSION = '2';
export const ACTION_STATE_MEDIA_TYPE = 'application/agent-action-capsule+json';

const ACTION_MEMBERS = new Set([
  '@version', 'action_id', 'action_type', 'effect_class', 'facility',
  'target_delta_kw', 'window', 'issued_at', 'expires_at',
  'baseline_method_hash', 'control_mode', 'envelope_id', 'requested_by',
]);
const WINDOW_MEMBERS = new Set(['not_before', 'not_after']);
const HEX_DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?$/;
const ID = /^[A-Za-z0-9:_.@/-]{3,256}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function record(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function exactMembers(value, members) {
  return record(value) && Object.keys(value).every((key) => members.has(key));
}

function validInstant(value) {
  return typeof value === 'string' && INSTANT.test(value) && Number.isFinite(Date.parse(value));
}

function validId(value) {
  return typeof value === 'string' && ID.test(value);
}

function digestBytes(value) {
  if (!isCanonicalizable(value)) throw new TypeError('value is outside the EP canonicalization profile');
  return crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest();
}

export function graceDigest(value) {
  return `sha256:${digestBytes(value).toString('hex')}`;
}

function publicSpki(publicKey) {
  if (typeof publicKey !== 'string' || !/^[A-Za-z0-9_-]+$/.test(publicKey)) return null;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(publicKey, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function privateEd25519(privateKey) {
  try {
    if (privateKey?.type === 'private' && privateKey.asymmetricKeyType === 'ed25519') return privateKey;
    const key = crypto.createPrivateKey(privateKey);
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

export function signGraceArtifact(body, { privateKey, keyId } = {}) {
  if (!record(body) || !isCanonicalizable(body) || !validId(keyId)) {
    throw new TypeError('canonical artifact body and signer key ID are required');
  }
  const key = privateEd25519(privateKey);
  if (!key) throw new TypeError('an Ed25519 private key is required');
  const signed = { ...structuredClone(body), signer_key_id: keyId };
  const value = crypto.sign(null, Buffer.from(canonicalize(signed), 'utf8'), key).toString('base64url');
  return { ...signed, signature: { algorithm: 'Ed25519', value } };
}

export function verifyGraceArtifact(artifact, { publicKeySpkiB64u, keyId, version } = {}) {
  try {
    if (!record(artifact) || artifact['@version'] !== version
        || artifact.signer_key_id !== keyId || !validId(keyId)
        || !record(artifact.signature) || artifact.signature.algorithm !== 'Ed25519'
        || typeof artifact.signature.value !== 'string'
        || !/^[A-Za-z0-9_-]+$/.test(artifact.signature.value)
        || Object.keys(artifact.signature).length !== 2) return false;
    const key = publicSpki(publicKeySpkiB64u);
    if (!key) return false;
    const { signature, ...body } = artifact;
    return isCanonicalizable(body) && crypto.verify(
      null,
      Buffer.from(canonicalize(body), 'utf8'),
      key,
      Buffer.from(signature.value, 'base64url'),
    );
  } catch {
    return false;
  }
}

export function validateCurtailmentAction(action) {
  const errors = [];
  if (!exactMembers(action, ACTION_MEMBERS)) return { valid: false, errors: ['action_shape_invalid'] };
  if (!isCanonicalizable(action)) errors.push('action_not_canonicalizable');
  if (action['@version'] !== GRACE_MOBILE_ACTION_VERSION) errors.push('action_version_invalid');
  if (!validId(action.action_id)) errors.push('action_id_invalid');
  if (action.action_type !== 'grid.curtailment') errors.push('action_type_invalid');
  if (action.effect_class !== 'power_reduction') errors.push('effect_class_invalid');
  if (!validId(action.facility)) errors.push('facility_invalid');
  if (typeof action.target_delta_kw !== 'string' || !DECIMAL.test(action.target_delta_kw)
      || Number(action.target_delta_kw) <= 0) errors.push('target_delta_kw_invalid');
  if (!exactMembers(action.window, WINDOW_MEMBERS)
      || !validInstant(action.window?.not_before) || !validInstant(action.window?.not_after)
      || Date.parse(action.window?.not_before) >= Date.parse(action.window?.not_after)) {
    errors.push('window_invalid');
  }
  if (!validInstant(action.issued_at)
      || (validInstant(action.window?.not_before)
        && Date.parse(action.issued_at) >= Date.parse(action.window.not_before))) errors.push('issued_at_invalid');
  if (!validInstant(action.expires_at) || action.expires_at !== action.window?.not_after) {
    errors.push('expires_at_invalid');
  }
  if (typeof action.baseline_method_hash !== 'string'
      || !HEX_DIGEST.test(action.baseline_method_hash)) errors.push('baseline_method_hash_invalid');
  if (!['human_on_the_loop', 'human_in_the_loop'].includes(action.control_mode)) {
    errors.push('control_mode_invalid');
  }
  if (!validId(action.envelope_id)) errors.push('envelope_id_invalid');
  if (!validId(action.requested_by)) errors.push('requested_by_invalid');
  return { valid: errors.length === 0, errors };
}

export function createCurtailmentAction(input = {}) {
  const action = {
    '@version': GRACE_MOBILE_ACTION_VERSION,
    action_id: input.actionId,
    action_type: 'grid.curtailment',
    effect_class: 'power_reduction',
    facility: input.facility,
    target_delta_kw: input.targetDeltaKw,
    window: { not_before: input.notBefore, not_after: input.notAfter },
    issued_at: input.issuedAt,
    expires_at: input.notAfter,
    baseline_method_hash: input.baselineMethodHash,
    control_mode: input.controlMode || 'human_on_the_loop',
    envelope_id: input.envelopeId,
    requested_by: input.requestedBy,
  };
  const result = validateCurtailmentAction(action);
  if (!result.valid) throw new TypeError(`invalid grid.curtailment action: ${result.errors.join(', ')}`);
  return action;
}

export function buildCurtailmentPresentation(action) {
  const checked = validateCurtailmentAction(action);
  if (!checked.valid) throw new TypeError(`invalid grid.curtailment action: ${checked.errors.join(', ')}`);
  const targetMw = (Number(action.target_delta_kw) / 1000).toFixed(3).replace(/\.000$/, '');
  const minutes = Math.round((Date.parse(action.window.not_after) - Date.parse(action.window.not_before)) / 60000);
  return {
    title: `Reduce load by ${targetMw} MW`,
    summary: 'A grid coordinator requests one bounded, reversible load reduction.',
    risk: 'critical infrastructure',
    material_fields: {
      facility: action.facility,
      reduction: `${targetMw} MW`,
      starts: action.window.not_before,
      duration: `${minutes} minutes`,
      baseline_method: action.baseline_method_hash,
      control_mode: action.control_mode,
    },
    consequence: 'Approval permits this exact event only. Any changed facility, power, window, or baseline method requires a new ceremony.',
  };
}

export function actionAsEnvelopeOrder(action) {
  const checked = validateCurtailmentAction(action);
  if (!checked.valid) return { valid: false, order: null, reason: checked.errors[0] };
  return {
    valid: true,
    order: {
      mw: String(Number(action.target_delta_kw) / 1000),
      notice_minutes: (Date.parse(action.window.not_before) - Date.parse(action.issued_at)) / 60000,
      window: { start: action.window.not_before, end: action.window.not_after },
    },
    reason: null,
  };
}

function classASignoff(evidence) {
  if (!record(evidence?.context) || !record(evidence?.signoff)
      || evidence.signoff.key_class !== 'A' || !record(evidence.signoff.webauthn)
      || evidence.signoff.context_hash !== hashCanonical(evidence.context)
      || evidence.signoff.approver_key_id !== evidence.context.mobile_binding?.device_key_id) return null;
  return { context: evidence.context, webauthn: evidence.signoff.webauthn };
}

export function verifyGraceMobileAuthorization({
  action,
  presentation,
  policy,
  evidence,
  profile,
} = {}) {
  const checks = {
    action: false,
    pinned_profile: false,
    signed_semantics: false,
    approval_indices: false,
    ceremony_windows: false,
    quorum: false,
  };
  try {
    checks.action = validateCurtailmentAction(action).valid;
    if (!checks.action || !record(presentation) || !record(policy)
        || !Array.isArray(evidence) || evidence.length === 0
        || !record(profile) || !Number.isSafeInteger(profile.required)
        || profile.required < 1 || !Array.isArray(profile.approvers)
        || profile.approvers.length > 16 || profile.required > profile.approvers.length
        || !validId(profile.rp_id)
        || !Array.isArray(profile.allowed_origins) || profile.allowed_origins.length === 0
        || profile.allowed_origins.length > 16
        || !profile.allowed_origins.every((origin) => typeof origin === 'string'
          && origin.length > 0 && origin.length <= 2048)
        || new Set(profile.allowed_origins).size !== profile.allowed_origins.length
        || !Number.isSafeInteger(profile.max_challenge_age_ms)
        || profile.max_challenge_age_ms < 1 || profile.max_challenge_age_ms > 3600000
        || !Number.isSafeInteger(profile.window_sec)
        || profile.window_sec < 1 || profile.window_sec > 3600
        || typeof profile.mobile_profile_hash !== 'string'
        || !HEX_DIGEST.test(profile.mobile_profile_hash)) {
      return { valid: false, checks, authorization_digest: null };
    }
    const roster = profile.approvers;
    checks.pinned_profile = roster.length > 0 && roster.every((item) => record(item)
      && validId(item.role) && validId(item.approver) && validId(item.device_key_id)
      && typeof item.public_key_spki === 'string'
      && ['ios', 'android'].includes(item.platform)
      && validId(item.app_id) && typeof item.credential_id === 'string')
      && new Set(roster.map((item) => item.approver)).size === roster.length
      && new Set(roster.map((item) => item.device_key_id)).size === roster.length
      && new Set(roster.map((item) => item.credential_id)).size === roster.length;
    if (!checks.pinned_profile) return { valid: false, checks, authorization_digest: null };

    const actionHash = graceDigest(action);
    const presentationHash = graceDigest(presentation);
    const policyHash = graceDigest(policy);
    const rosterByApprover = new Map(roster.map((item) => [item.approver, item]));
    const approverIndexById = new Map(roster.map((item, index) => [item.approver, index + 1]));
    const members = [];
    const indices = [];
    const windows = [];
    let semantics = true;
    for (const item of evidence) {
      const signoff = classASignoff(item);
      const context = signoff?.context;
      const pinned = rosterByApprover.get(context?.approver);
      if (!signoff || !pinned
          || context.action_hash !== actionHash
          || context.display_hash !== presentationHash
          || context.policy_hash !== policyHash
          || context.decision !== 'approved'
          || context.initiator !== action.requested_by
          || context.required_approvals !== profile.required
          || context.approver_index !== approverIndexById.get(context.approver)
          || context.mobile_binding?.profile_hash !== profile.mobile_profile_hash
          || context.mobile_binding?.device_key_id !== pinned.device_key_id
          || context.mobile_binding?.platform !== pinned.platform
          || context.mobile_binding?.app_id !== pinned.app_id
          || context.mobile_binding?.credential_id !== pinned.credential_id
          || item.signoff.approver_key_id !== pinned.device_key_id) semantics = false;
      indices.push(context?.approver_index);
      const issued = Date.parse(context?.issued_at || '');
      const expires = Date.parse(context?.expires_at || '');
      windows.push(Number.isFinite(issued) && Number.isFinite(expires)
        && issued < expires
        && issued >= Date.parse(action.issued_at)
        && expires <= Date.parse(action.expires_at)
        && expires - issued <= profile.max_challenge_age_ms
        && item.signoff?.signed_at === context?.issued_at);
      if (signoff && pinned) {
        members.push({ role: pinned.role, approver_public_key: pinned.public_key_spki, signoff });
      }
    }
    checks.signed_semantics = semantics && members.length === evidence.length;
    checks.approval_indices = indices.every((value) => Number.isSafeInteger(value) && value > 0)
      && new Set(indices).size === indices.length;
    checks.ceremony_windows = windows.length === evidence.length && windows.every(Boolean);
    if (!checks.signed_semantics || !checks.approval_indices || !checks.ceremony_windows) {
      return { valid: false, checks, authorization_digest: null };
    }

    const quorum = verifyQuorum({
      '@type': 'ep.quorum',
      action_hash: actionHash,
      policy: {
        mode: 'threshold',
        required: profile.required,
        approvers: roster.map(({ role, approver }) => ({ role, approver })),
        distinct_humans: true,
        window_sec: profile.window_sec,
      },
      members,
    }, { rpId: profile.rp_id, allowedOrigins: profile.allowed_origins });
    checks.quorum = quorum.valid === true;
    const valid = Object.values(checks).every(Boolean);
    return {
      valid,
      checks,
      quorum,
      authorization_digest: valid ? graceDigest({
        action_hash: actionHash,
        policy_hash: policyHash,
        evidence: evidence.map((item) => graceDigest(item)),
      }) : null,
    };
  } catch {
    return { valid: false, checks, authorization_digest: null };
  }
}

function stripDigest(value) {
  return typeof value === 'string' && HEX_DIGEST.test(value) ? value.slice(7) : null;
}

function normalizeCapsule(value) {
  if (Array.isArray(value)) return value.map(normalizeCapsule);
  if (!record(value)) return value;
  const output = {};
  for (const [key, member] of Object.entries(value)) {
    const normalized = normalizeCapsule(member);
    if (normalized === null || normalized === undefined) continue;
    if ((Array.isArray(normalized) || record(normalized)) && Object.keys(normalized).length === 0) continue;
    output[key] = normalized;
  }
  return output;
}

export function actionStateCapsuleId(capsule) {
  if (!record(capsule)) return null;
  const canonical = Object.fromEntries(Object.entries(capsule)
    .filter(([key]) => key !== 'capsule_id' && key !== 'chain'));
  const normalized = normalizeCapsule(canonical);
  if (!isCanonicalizable(normalized)) return null;
  return digestBytes(normalized).toString('hex');
}

export function buildActionStateCapsule({
  action,
  operator,
  developer,
  timestamp,
  dispatchRequestDigest,
  meterDigest,
  authorizationDigest,
} = {}) {
  const actionCheck = validateCurtailmentAction(action);
  const requestDigest = stripDigest(dispatchRequestDigest);
  const responseDigest = stripDigest(meterDigest);
  const authorityDigest = stripDigest(authorizationDigest);
  if (!actionCheck.valid || !validId(operator) || !validId(developer)
      || !validInstant(timestamp) || !requestDigest || !responseDigest || !authorityDigest) {
    throw new TypeError('verified action, authority, dispatch, and meter inputs are required');
  }
  const capsule = {
    spec_version: ACTION_STATE_SPEC_VERSION,
    format_version: ACTION_STATE_FORMAT_VERSION,
    action_id: action.action_id,
    action_type: 'decide',
    operator,
    developer,
    timestamp,
    domain: 'action',
    provenance: 'gate',
    effect: {
      status: 'confirmed',
      type: 'power_reduction',
      request_digest: requestDigest,
      response_digest: responseDigest,
      external_ref: action.action_id,
      irreversibility_class: 'two_way',
      effect_attestation: 'gate_executed',
    },
    assurance: {
      attestation_mode: 'self_attested',
      effect_mode: 'confirmed',
      ledger_mode: 'standalone',
    },
    disposition: {
      decision: 'accept',
      approver: 'human',
      human_disposed: true,
      authority: `ep-authorization-digest:${authorityDigest}`,
      verdict_class: 'executed',
    },
    constraints: [
      { id: 'ep:grace:order_within_envelope', result: 'pass', severity: 'critical', blocking: true },
      { id: 'ep:grace:mobile_authorization', result: 'pass', severity: 'critical', blocking: true, evidence_digest: authorityDigest },
      { id: 'ep:grace:cosa_dispatch', result: 'pass', severity: 'critical', blocking: true, evidence_digest: requestDigest },
      { id: 'ep:grace:meter_confirmation', result: 'pass', severity: 'critical', blocking: true, evidence_digest: responseDigest },
    ],
  };
  const capsuleId = actionStateCapsuleId(capsule);
  if (!capsuleId) throw new TypeError('Action State Capsule could not be canonicalized');
  return {
    spec_version: capsule.spec_version,
    format_version: capsule.format_version,
    capsule_id: capsuleId,
    ...Object.fromEntries(Object.entries(capsule).filter(([key]) => !['spec_version', 'format_version'].includes(key))),
  };
}

function actionStateProtectedHeaders(capsule, keyId) {
  return new Map([
    [1, -8],
    [3, ACTION_STATE_MEDIA_TYPE],
    [4, Buffer.from(keyId, 'utf8')],
    [15, new Map([
      [1, capsule.developer],
      [2, `urn:agent-action-capsule:${capsule.operator}:${capsule.action_id}`],
      ['capsule_action_type', capsule.action_type],
      ['capsule_decision_id', capsule.action_id],
      ['capsule_statement_type', 'agent_action'],
    ])],
  ]);
}

export function createActionStateSignedStatement(capsule, { privateKey, keyId } = {}) {
  if (!record(capsule) || actionStateCapsuleId(capsule) !== capsule.capsule_id || !validId(keyId)) {
    throw new TypeError('a valid sealed Action State Capsule and key ID are required');
  }
  const key = privateEd25519(privateKey);
  if (!key) throw new TypeError('an Ed25519 private key is required');
  const payload = Buffer.from(canonicalize(capsule), 'utf8');
  const protectedBytes = cbor.encodeCanonical(actionStateProtectedHeaders(capsule, keyId));
  const sigStructure = cbor.encodeCanonical(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
  const signature = crypto.sign(null, sigStructure, key);
  const statement = cbor.encodeCanonical(new cbor.Tagged(18, [
    protectedBytes,
    new Map(),
    payload,
    signature,
  ]));
  return {
    media_type: ACTION_STATE_MEDIA_TYPE,
    anchoring: 'unregistered_signed_statement',
    cose_sign1_b64u: statement.toString('base64url'),
    statement_digest: `sha256:${crypto.createHash('sha256').update(statement).digest('hex')}`,
    capsule,
  };
}

export function verifyActionStateSignedStatement(statement, { publicKeySpkiB64u, keyId } = {}) {
  try {
    if (!record(statement) || statement.media_type !== ACTION_STATE_MEDIA_TYPE
        || statement.anchoring !== 'unregistered_signed_statement'
        || !HEX_DIGEST.test(statement.statement_digest)
        || typeof statement.cose_sign1_b64u !== 'string') return { valid: false, capsule: null };
    const bytes = Buffer.from(statement.cose_sign1_b64u, 'base64url');
    if (`sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}` !== statement.statement_digest) {
      return { valid: false, capsule: null };
    }
    const tagged = cbor.decodeFirstSync(bytes, { preferMap: true });
    if (!(tagged instanceof cbor.Tagged) || tagged.tag !== 18 || !Array.isArray(tagged.value)
        || tagged.value.length !== 4) return { valid: false, capsule: null };
    const [protectedBytes, unprotected, payload, signature] = tagged.value;
    if (!Buffer.isBuffer(protectedBytes) || !(unprotected instanceof Map) || unprotected.size !== 0
        || !Buffer.isBuffer(payload) || !Buffer.isBuffer(signature)) return { valid: false, capsule: null };
    const protectedMap = cbor.decodeFirstSync(protectedBytes, { preferMap: true });
    if (!(protectedMap instanceof Map) || protectedMap.size !== 4
        || protectedMap.get(1) !== -8 || protectedMap.get(3) !== ACTION_STATE_MEDIA_TYPE
        || !Buffer.isBuffer(protectedMap.get(4)) || protectedMap.get(4).toString('utf8') !== keyId) {
      return { valid: false, capsule: null };
    }
    const text = payload.toString('utf8');
    if (!strictJsonGate(text).ok) return { valid: false, capsule: null };
    const capsule = JSON.parse(text);
    if (!record(capsule) || actionStateCapsuleId(capsule) !== capsule.capsule_id
        || canonicalize(capsule) !== text
        || (record(statement.capsule) && canonicalize(statement.capsule) !== text)) {
      return { valid: false, capsule: null };
    }
    const claims = protectedMap.get(15);
    if (!(claims instanceof Map) || claims.size !== 5
        || claims.get(1) !== capsule.developer
        || claims.get(2) !== `urn:agent-action-capsule:${capsule.operator}:${capsule.action_id}`
        || claims.get('capsule_statement_type') !== 'agent_action'
        || claims.get('capsule_action_type') !== capsule.action_type
        || claims.get('capsule_decision_id') !== capsule.action_id) return { valid: false, capsule: null };
    const key = publicSpki(publicKeySpkiB64u);
    if (!key) return { valid: false, capsule: null };
    const sigStructure = cbor.encodeCanonical(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
    return { valid: crypto.verify(null, sigStructure, key, signature), capsule };
  } catch {
    return { valid: false, capsule: null };
  }
}

export async function runCurtailmentOnce(key, store, execute) {
  if (typeof key !== 'string' || !key || !store || store.durable !== true
      || store.ownershipFenced !== true || typeof store.reserve !== 'function'
      || typeof store.commit !== 'function' || typeof execute !== 'function') {
    return { executed: false, reason: 'execution_store_missing' };
  }
  let reserved;
  try {
    reserved = await store.reserve(key);
  } catch {
    return { executed: false, reason: 'execution_store_unavailable' };
  }
  if (reserved !== true) return { executed: false, reason: 'execution_already_consumed' };
  let committed = false;
  try {
    const result = await execute({ key });
    if ((await store.commit(key)) !== true) throw new Error('execution_consumption_commit_failed');
    committed = true;
    return { executed: true, reason: null, result };
  } catch (error) {
    if (!committed) {
      try {
        if ((await store.commit(key)) !== true) throw new Error('execution_consumption_commit_failed');
      } catch (commitError) {
        if (error && typeof error === 'object') error.execution_state_error = String(commitError?.message || commitError);
      }
    }
    throw error;
  }
}

export async function executeGraceCurtailment({
  action,
  envelope,
  spent = {},
  presentation,
  policy,
  authorizationEvidence,
  authorizationProfile,
  executionStore,
  actuator,
  actuatorTrust,
  meter,
  meterTrust,
  settlementStore,
  settle,
  operator,
  developer = 'cosa-reference-adapter/1.0',
  capsuleSigner,
  clock = () => new Date().toISOString(),
} = {}) {
  const actionResult = actionAsEnvelopeOrder(action);
  if (!actionResult.valid) return { ok: false, verdict: 'refuse_action', reason: actionResult.reason };
  let gateAt;
  try { gateAt = clock(); } catch { gateAt = null; }
  if (!validInstant(gateAt)
      || Date.parse(gateAt) < Date.parse(action.window.not_before)
      || Date.parse(gateAt) > Date.parse(action.expires_at)) {
    return { ok: false, verdict: 'refuse_action_not_active', reason: 'curtailment action is not active at the execution boundary' };
  }
  const containment = checkOrderWithinEnvelope(actionResult.order, envelope, spent);
  if (!containment.within) return { ok: false, verdict: 'refuse_outside_envelope', reason: containment.violations[0], containment };
  const authorization = verifyGraceMobileAuthorization({
    action,
    presentation,
    policy,
    evidence: authorizationEvidence,
    profile: authorizationProfile,
  });
  if (!authorization.valid) return { ok: false, verdict: 'refuse_authorization', reason: 'mobile authorization evidence did not satisfy the pinned profile', authorization };
  if (!actuator || typeof actuator.dispatch !== 'function' || typeof actuator.verify !== 'function'
      || !record(actuatorTrust) || !meter || typeof meter.observe !== 'function'
      || typeof meter.verify !== 'function' || !record(meterTrust)
      || !validId(operator) || !validId(developer)
      || !record(capsuleSigner) || !validId(capsuleSigner.keyId)
      || !privateEd25519(capsuleSigner.privateKey)
      || !settlementStore || typeof settlementStore.reserve !== 'function'
      || typeof settlementStore.commit !== 'function' || typeof settle !== 'function') {
    return { ok: false, verdict: 'refuse_adapter_unavailable', reason: 'pinned actuator and meter adapters are required' };
  }

  const actionHash = graceDigest(action);
  const requestBody = {
    '@version': GRACE_DISPATCH_VERSION,
    action,
    action_hash: actionHash,
    envelope_digest: graceDigest(envelope),
    authorization_digest: authorization.authorization_digest,
    idempotency_key: `grace:${action.action_id}:${actionHash}`,
    dispatched_by: operator,
  };
  const requestDigest = graceDigest(requestBody);
  let dispatched;
  try {
    dispatched = await runCurtailmentOnce(requestBody.idempotency_key, executionStore, () => actuator.dispatch(requestBody));
  } catch (error) {
    return {
      ok: false,
      verdict: 'execution_indeterminate',
      reason: error instanceof Error ? error.message : 'actuator result is indeterminate',
      retry_safe: false,
      request_digest: requestDigest,
    };
  }
  if (!dispatched.executed) return { ok: false, verdict: 'refuse_replay', reason: dispatched.reason };
  const acknowledgment = dispatched.result;
  const ackValid = actuator.verify(acknowledgment, actuatorTrust, {
    action_hash: actionHash,
    request_digest: requestDigest,
    event_id: action.action_id,
  });
  if (!ackValid) return { ok: false, verdict: 'refuse_actuator_ack', reason: 'actuator acknowledgment failed pinned verification', retry_safe: false };

  let meterStatement;
  try {
    meterStatement = await meter.observe({ action, acknowledgment });
  } catch {
    return { ok: false, verdict: 'effect_unconfirmed', reason: 'meter observation unavailable', retry_safe: false, acknowledgment };
  }
  const meterValid = meter.verify(meterStatement, meterTrust, {
    event_id: action.action_id,
    action_hash: actionHash,
  })
    && canonicalize(meterStatement.window) === canonicalize(action.window)
    && !Object.hasOwn(meterStatement, 'baseline_method_hash');
  if (!meterValid) return { ok: false, verdict: 'effect_unconfirmed', reason: 'meter statement failed pinned verification', retry_safe: false, acknowledgment };
  const compliance = computeCompliance(actionResult.order, {
    baseline_mw: meterStatement.baseline_mw,
    intervals_mw: meterStatement.intervals.map((item) => item.load_mw),
  });
  if (!compliance.computable) return { ok: false, verdict: 'effect_unconfirmed', reason: compliance.reason, retry_safe: false };

  const meterBody = Object.fromEntries(Object.entries(meterStatement).filter(([key]) => key !== 'signature'));
  const meterDigest = graceDigest(meterBody);
  const capsule = buildActionStateCapsule({
    action,
    operator,
    developer,
    timestamp: meterStatement.observed_at,
    dispatchRequestDigest: requestDigest,
    meterDigest,
    authorizationDigest: authorization.authorization_digest,
  });
  const actionState = createActionStateSignedStatement(capsule, capsuleSigner);
  const settlementClaim = {
    entitlement_id: action.envelope_id,
    event_id: action.action_id,
    meter_window_digest: meterDigest,
  };
  const settlement = compliance.compliant
    ? await runSettlementOnce(settlementClaim, settlementStore, settle)
    : { settled: false, reason: 'curtailment_under_delivered', key: null };
  const canonicalCompliance = {
    ordered_mw: Number(compliance.ordered_mw).toFixed(3),
    delivered_mw: Number(compliance.delivered_mw).toFixed(3),
    compliance_ratio: Number(compliance.compliance_ratio).toFixed(3),
    compliant: compliance.compliant,
  };
  const bundleBody = {
    '@version': GRACE_BUNDLE_VERSION,
    action,
    action_hash: actionHash,
    envelope_digest: graceDigest(envelope),
    baseline_method_hash: action.baseline_method_hash,
    authorization_digest: authorization.authorization_digest,
    dispatch_request_digest: requestDigest,
    actuator_ack_digest: graceDigest(Object.fromEntries(Object.entries(acknowledgment).filter(([key]) => key !== 'signature'))),
    meter_payload_digest: meterDigest,
    compliance: canonicalCompliance,
    action_state_statement_digest: actionState.statement_digest,
    settlement: {
      entitlement_key: settlement.key || null,
      status: settlement.settled ? 'settled' : 'not_settled',
      reason: settlement.reason || null,
    },
  };
  return {
    ok: true,
    verdict: settlement.settled ? 'executed_measured_settled' : 'executed_measured_not_settled',
    action_hash: actionHash,
    authorization,
    acknowledgment,
    meter_statement: meterStatement,
    compliance,
    action_state: actionState,
    settlement,
    bundle: signGraceArtifact(bundleBody, capsuleSigner),
  };
}
