// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import {
  canonicalEvidenceJson,
  createAtomicEvidenceLog,
  verifyEvidenceRecord,
} from '../../packages/gate/evidence.js';
import { normalizeMobilePresentation } from '../../packages/mobile/presentation.js';
import {
  buildDecisionPassport,
  buildMobileActionIdentity,
  deriveMobileActionContinuity,
  materialFieldDiff,
  mobileActionFingerprint,
  normalizeSystemAlignments,
  verifyMobileProviderOutcome,
} from './action-continuity.js';

const MOBILE_TOKEN = /^ep_mobile_([A-Za-z0-9_-]{43})$/;
const MOBILE_LOOKUP_ID = /^[A-Za-z0-9:_.@-]{8,256}$/;
const MOBILE_ID = /^[A-Za-z0-9:_.@-]{3,256}$/;
const MOBILE_SHA256 = /^sha256:[0-9a-f]{64}$/;
const MOBILE_B64U = /^[A-Za-z0-9_-]+$/;
const MOBILE_ATTESTATION_KEY_ID = /^[A-Za-z0-9:._+/=-]{3,512}$/;
const MOBILE_CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MOBILE_DECISION_AUDIT_MEMBERS = new Set([
  'event_type', 'challenge_id', 'action_hash', 'profile_hash', 'verdict',
  'decision', 'approver_id', 'device_key_id', 'context_hash',
]);
const MOBILE_DECISION_EVIDENCE_MEMBERS = new Set(['context', 'signoff']);
const MOBILE_DECISION_CONTEXT_MEMBERS = new Set([
  'ep_version', 'context_type', 'action_reference', 'action_caid', 'action_digest',
  'action_hash', 'policy_id', 'policy_hash',
  'initiator', 'approver', 'approver_index', 'required_approvals', 'nonce',
  'issued_at', 'expires_at', 'decision', 'display_hash', 'mobile_binding',
]);
const MOBILE_DECISION_BINDING_MEMBERS = new Set([
  'profile', 'profile_hash', 'platform', 'app_id', 'device_key_id',
  'credential_id', 'attestation_key_id',
]);
const MOBILE_DECISION_SIGNOFF_MEMBERS = new Set([
  'context_hash', 'key_class', 'approver_key_id', 'signed_at', 'webauthn',
]);
const MOBILE_WEBAUTHN_MEMBERS = new Set([
  'authenticator_data', 'client_data_json', 'signature',
]);

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function databaseError(label, error) {
  return new Error(`${label}: ${error?.message || error?.code || 'database operation failed'}`);
}

export function createMobileStateBackend(supabase) {
  if (!supabase?.from || !supabase?.rpc) throw new TypeError('Supabase client is required');
  return {
    durable: true,
    async addIfAbsent(key, value) {
      const { data, error } = await supabase.rpc('mobile_state_add_if_absent', {
        p_state_key: key,
        p_state_value: value,
      });
      if (error) throw databaseError('mobile state insert failed', error);
      return data === true;
    },
    async compareAndSet(key, expected, replacement) {
      const { data, error } = await supabase.rpc('mobile_state_compare_and_set', {
        p_state_key: key,
        p_expected: expected,
        p_replacement: replacement,
        p_now: new Date().toISOString(),
      });
      if (error) throw databaseError('mobile state compare-and-set failed', error);
      return data === true;
    },
    async has(key) {
      const { data, error } = await supabase
        .from('mobile_kv_state')
        .select('state_key')
        .eq('state_key', key)
        .maybeSingle();
      if (error) throw databaseError('mobile state lookup failed', error);
      return Boolean(data);
    },
  };
}

export function createMobileCounterStore(supabase, namespace = 'mobile') {
  if (!supabase?.rpc) throw new TypeError('Supabase client is required');
  return {
    durable: true,
    async advance(key, next) {
      if (typeof key !== 'string' || !Number.isSafeInteger(next) || next < 0) return false;
      const { data, error } = await supabase.rpc('advance_mobile_counter', {
        p_counter_key: `${namespace}:${key}`,
        p_next: next,
      });
      if (error) throw databaseError('mobile counter advance failed', error);
      return data === true;
    },
  };
}

function createMobileEvidenceBackend(supabase, entityRef) {
  if (!supabase?.rpc || !supabase?.from || typeof entityRef !== 'string' || !entityRef) {
    throw new TypeError('Supabase client and entityRef are required');
  }
  return {
    durable: true,
    async readHead(streamId) {
      if (streamId !== entityRef) throw new Error('mobile evidence stream mismatch');
      const { data, error } = await supabase
        .from('mobile_evidence_records')
        .select('record,record_hash')
        .eq('entity_ref', entityRef)
        .order('sequence_id', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (error) throw databaseError('mobile evidence head lookup failed', error);
      if (!data) return null;
      return { seq: data.record?.seq, hash: data.record_hash };
    },
    async getById(streamId, recordId) {
      if (streamId !== entityRef) throw new Error('mobile evidence stream mismatch');
      const { data, error } = await supabase
        .from('mobile_evidence_records')
        .select('record')
        .eq('entity_ref', entityRef)
        .eq('record_id', recordId)
        .maybeSingle();
      if (error) throw databaseError('mobile evidence record lookup failed', error);
      return data?.record || null;
    },
    async appendIfHead(streamId, expectedHeadHash, record) {
      if (streamId !== entityRef) throw new Error('mobile evidence stream mismatch');
      const { hash, ...body } = record;
      const { data, error } = await supabase.rpc('append_mobile_evidence_record', {
        p_entity_ref: entityRef,
        p_expected_hash: expectedHeadHash,
        p_record: record,
        p_canonical_body: canonicalEvidenceJson(body),
      });
      if (error) throw databaseError('mobile evidence append failed', error);
      return data === true;
    },
    async readAll(streamId) {
      if (streamId !== entityRef) throw new Error('mobile evidence stream mismatch');
      const { data, error } = await supabase
        .from('mobile_evidence_records')
        .select('record')
        .eq('entity_ref', entityRef)
        .order('sequence_id', { ascending: true });
      if (error) throw databaseError('mobile evidence history lookup failed', error);
      return (data || []).map((row) => row.record);
    },
  };
}

function mobileEvidenceRecordId() {
  return `mar_${crypto.randomUUID().replaceAll('-', '')}`;
}

export function createMobileAuditLog(supabase, entityRef) {
  const backend = createMobileEvidenceBackend(supabase, entityRef);
  return createAtomicEvidenceLog(backend, {
    streamId: entityRef,
    recordIdFactory: /** @type {() => `${string}-${string}-${string}-${string}-${string}`} */ (mobileEvidenceRecordId),
  });
}

export function createMobileEnrollmentDirectory(supabase, entityRef, sessionId) {
  if (!supabase?.from || !supabase?.rpc || typeof entityRef !== 'string' || !entityRef
      || typeof sessionId !== 'string' || !sessionId) {
    throw new TypeError('Supabase client, entityRef, and sessionId are required');
  }
  return {
    durable: true,
    async enrollAtomically({ enrollment, event }) {
      const { data, error } = await supabase.rpc('enroll_mobile_device', {
        p_entity_ref: entityRef,
        p_session_id: sessionId,
        p_enrollment: enrollment,
        p_event: event,
      });
      if (error) throw databaseError('mobile enrollment insert failed', error);
      return data === true;
    },
    async active() {
      const now = new Date().toISOString();
      const { data, error } = await supabase
        .from('mobile_enrollments')
        .select('device_key_id, credential_id, public_key_spki, approver_id, platform, app_id, attestation_key_id, status, valid_from, valid_to, sign_count')
        .eq('entity_ref', entityRef)
        .eq('status', 'active')
        .lte('valid_from', now)
        .gte('valid_to', now);
      if (error) throw databaseError('mobile enrollment directory unavailable', error);
      return data || [];
    },
    async platformKey(attestationKeyId, platform) {
      if (!['ios', 'android'].includes(platform)) throw new TypeError('mobile platform key lookup is malformed');
      const { data, error } = await supabase
        .from('mobile_enrollments')
        .select('platform_public_key, app_id, status, valid_from, valid_to')
        .eq('entity_ref', entityRef)
        .eq('platform', platform)
        .eq('attestation_key_id', attestationKeyId)
        .eq('status', 'active')
        .maybeSingle();
      if (error) throw databaseError('mobile platform key lookup failed', error);
      return data || null;
    },
  };
}

export async function createPairing(supabase, {
  code,
  entityRef,
  approverId,
  profileId,
  allowedApps,
  expiresAt,
  sessionExpiresAt,
}) {
  const { data, error } = await supabase.rpc('create_mobile_pairing', {
    p_code_hash: sha256Hex(code),
    p_entity_ref: entityRef,
    p_approver_id: approverId,
    p_profile_id: profileId,
    p_allowed_apps: allowedApps,
    p_expires_at: expiresAt,
    p_session_expires_at: sessionExpiresAt,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile pairing creation failed', error);
  if (data !== true) throw new Error('mobile pairing creation refused');
  return true;
}

export async function exchangePairing(supabase, { code, token, platform, appId }) {
  const { data, error } = await supabase.rpc('exchange_mobile_pairing', {
    p_code_hash: sha256Hex(code),
    p_token_hash: sha256Hex(token),
    p_platform: platform,
    p_app_id: appId,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile pairing exchange failed', error);
  return data || { ok: false, reason: 'invalid_or_expired' };
}

export async function authenticateMobileToken(supabase, authorization) {
  const match = /^Bearer\s+(.+)$/i.exec(authorization || '');
  if (!match || !MOBILE_TOKEN.test(match[1])) return null;
  const tokenHash = sha256Hex(match[1]);
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from('mobile_sessions')
    .select('session_id, entity_ref, approver_id, profile_id, platform, app_id, device_key_id, expires_at')
    .eq('token_hash', tokenHash)
    .is('revoked_at', null)
    .gt('expires_at', now)
    .maybeSingle();
  if (error) throw databaseError('mobile session lookup failed', error);
  if (!data) return null;
  const { data: touched, error: touchError } = await supabase.rpc('touch_mobile_session', {
    p_session_id: data.session_id,
    p_token_hash: tokenHash,
    p_now: now,
  });
  if (touchError) throw databaseError('mobile session update failed', touchError);
  if (touched !== true) return null;
  return data;
}

export async function revokeMobileSession(supabase, { sessionId, entityRef }) {
  if (typeof sessionId !== 'string' || !sessionId || typeof entityRef !== 'string' || !entityRef) return false;
  const { data, error } = await supabase.rpc('revoke_mobile_session', {
    p_entity_ref: entityRef,
    p_session_id: sessionId,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile session revocation failed', error);
  return data === true;
}

export async function listMobileActions(supabase, { entityRef, approverId }) {
  return listMobileActionContinuity(supabase, { entityRef, approverId, pendingOnly: true });
}

function mobileContinuitySnapshot(row) {
  const operation = mobileRecord(row.operation) ? row.operation : null;
  const effectStatus = operation?.status || 'not_consumed';
  const continuity = deriveMobileActionContinuity({
    status: row.status,
    required_approvals: Number(row.required_approvals),
    approved_count: Number(row.approved_count),
    denied_count: Number(row.denied_count),
    withdrawn_count: Number(row.withdrawn_count),
    effect_status: effectStatus,
    consumption_nonce: operation?.consumption_nonce,
    outcome_verified: ['executed', 'refused'].includes(effectStatus)
      && MOBILE_SHA256.test(operation?.provider_evidence_digest || ''),
  });
  const identity = typeof row.action_caid === 'string' && MOBILE_SHA256.test(row.action_digest || '')
    ? {
        action_caid: row.action_caid,
        action_digest: row.action_digest,
        fingerprint: mobileActionFingerprint(row.action_caid),
      }
    : null;
  const normalized = {
    ...row,
    presentation: normalizeMobilePresentation(row.presentation),
    identity,
    changes: Array.isArray(row.change_set) ? row.change_set : [],
    alignments: normalizeSystemAlignments(row.alignments),
    continuity,
    quorum: continuity.quorum,
    events: Array.isArray(row.events) ? row.events : [],
    operation,
    can_withdraw: row.status === 'approved'
      && ['open', 'authorized'].includes(row.group_state)
      && operation === null,
  };
  if (MOBILE_SHA256.test(row.action_digest || '') && typeof row.action_caid === 'string') {
    normalized.passport = buildDecisionPassport({
      ...row,
      consumption_nonce: operation?.consumption_nonce || null,
      outcome_digest: operation?.provider_evidence_digest || null,
      outcome_attestation: null,
    }, continuity);
  }
  return normalized;
}

async function listMobileActionContinuity(supabase, {
  entityRef,
  approverId,
  pendingOnly,
}) {
  if (!supabase?.rpc) throw new TypeError('Supabase client is required');
  const { data, error } = await supabase.rpc('list_mobile_action_continuity', {
    p_entity_ref: entityRef,
    p_approver_id: approverId,
    p_pending_only: pendingOnly,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action inbox unavailable', error);
  if (!Array.isArray(data)) return [];
  return data.map(mobileContinuitySnapshot);
}

export async function listMobileActionHistory(supabase, { entityRef, approverId }) {
  return listMobileActionContinuity(supabase, { entityRef, approverId, pendingOnly: false });
}

export async function resolveMobileAction(supabase, { entityRef, approverId, actionReference }) {
  let rows;
  try {
    rows = await listMobileActionContinuity(supabase, {
      entityRef,
      approverId,
      pendingOnly: false,
    });
  } catch (error) {
    throw new Error(String(error?.message || error).replace('action inbox', 'action lookup'));
  }
  const data = rows.find((row) => row.action_reference === actionReference);
  if (!data || data.status !== 'pending' || Date.parse(data.expires_at) <= Date.now()) return null;
  return data;
}

function mobileRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function mobileExactMembers(value, members) {
  return mobileRecord(value)
    && Object.keys(value).length === members.size
    && Object.keys(value).every((key) => members.has(key));
}

function mobileInstant(value) {
  if (typeof value !== 'string' || !MOBILE_CANONICAL_INSTANT.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
}

function mobileB64u(value, maxBytes) {
  if (typeof value !== 'string' || !MOBILE_B64U.test(value)
      || value.length > Math.ceil(maxBytes * 4 / 3) + 4) return false;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length > 0 && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

function mobileContextHash(context) {
  try {
    return `sha256:${crypto.createHash('sha256')
      .update(canonicalEvidenceJson(context), 'utf8')
      .digest('hex')}`;
  } catch {
    return null;
  }
}

function mobileDecisionEvidenceMatches(evidence, {
  decision,
  actionHash,
  profileHash,
  approverId,
  deviceKeyId,
  contextHash,
  platform = null,
  appId = null,
}) {
  const context = evidence?.context;
  const binding = context?.mobile_binding;
  const signoff = evidence?.signoff;
  const webauthn = signoff?.webauthn;
  const issuedAt = mobileInstant(context?.issued_at);
  const expiresAt = mobileInstant(context?.expires_at);
  const computedContextHash = mobileContextHash(context);
  return mobileExactMembers(evidence, MOBILE_DECISION_EVIDENCE_MEMBERS)
    && mobileExactMembers(context, MOBILE_DECISION_CONTEXT_MEMBERS)
    && mobileExactMembers(binding, MOBILE_DECISION_BINDING_MEMBERS)
    && mobileExactMembers(signoff, MOBILE_DECISION_SIGNOFF_MEMBERS)
    && mobileExactMembers(webauthn, MOBILE_WEBAUTHN_MEMBERS)
    && context.ep_version === '1.0'
    && context.context_type === 'ep.signoff.v1'
    && MOBILE_LOOKUP_ID.test(context.action_reference || '')
    && /^caid:1:emilia\.mobile\.authorized-action\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/
      .test(context.action_caid || '')
    && MOBILE_SHA256.test(context.action_digest || '')
    && evidence.context.action_hash === actionHash
    && (context.policy_id === null
      || (typeof context.policy_id === 'string' && context.policy_id.length >= 1
        && context.policy_id.length <= 256))
    && (context.policy_hash === null || MOBILE_SHA256.test(context.policy_hash || ''))
    && MOBILE_ID.test(context.initiator || '')
    && MOBILE_ID.test(context.approver || '')
    && Number.isSafeInteger(context.approver_index)
    && context.approver_index >= 1
    && context.approver_index <= 1024
    && Number.isSafeInteger(context.required_approvals)
    && context.required_approvals >= 1
    && context.required_approvals <= 1024
    && MOBILE_ID.test(context.nonce || '')
    && issuedAt !== null
    && expiresAt !== null
    && issuedAt < expiresAt
    && context.decision === decision
    && MOBILE_SHA256.test(context.display_hash || '')
    && evidence.context.approver === approverId
    && binding.profile === 'EP-MOBILE-CHALLENGE-v2'
    && binding.profile_hash === profileHash
    && ['ios', 'android'].includes(binding.platform)
    && (platform === null || binding.platform === platform)
    && MOBILE_ID.test(binding.app_id || '')
    && (appId === null || binding.app_id === appId)
    && binding.device_key_id === deviceKeyId
    && MOBILE_ID.test(binding.device_key_id || '')
    && mobileB64u(binding.credential_id, 2048)
    && MOBILE_ATTESTATION_KEY_ID.test(binding.attestation_key_id || '')
    && evidence.signoff.key_class === 'A'
    && evidence.signoff.context_hash === contextHash
    && evidence.signoff.context_hash === computedContextHash
    && evidence.signoff.approver_key_id === deviceKeyId
    && evidence.signoff.signed_at === context.issued_at
    && mobileB64u(webauthn.authenticator_data, 4096)
    && mobileB64u(webauthn.client_data_json, 64 * 1024)
    && mobileB64u(webauthn.signature, 4096);
}

function mobileDecisionAuditMatches(entry, {
  challengeId,
  actionHash,
  decision,
  verdict,
}) {
  return mobileExactMembers(entry, MOBILE_DECISION_AUDIT_MEMBERS)
    && entry.event_type === 'mobile.ceremony.decision'
    && entry.challenge_id === challengeId
    && entry.action_hash === actionHash
    && MOBILE_SHA256.test(entry.profile_hash || '')
    && entry.verdict === verdict
    && entry.verdict === 'verified'
    && entry.decision === decision
    && MOBILE_ID.test(entry.approver_id || '')
    && MOBILE_ID.test(entry.device_key_id || '')
    && MOBILE_SHA256.test(entry.context_hash || '');
}

function recoveredMobileResult({ challenge, action, evidenceRecord, session }) {
  const evidence = action?.decision_evidence;
  if (!mobileRecord(challenge) || !mobileRecord(action) || !mobileRecord(evidence)) return null;

  const challengeCreatedAt = mobileInstant(challenge.created_at);
  const challengeExpiresAt = mobileInstant(challenge.expires_at);
  const consumedAt = mobileInstant(challenge.consumed_at);
  const decidedAt = mobileInstant(action.decided_at);
  if (challengeCreatedAt === null || challengeExpiresAt === null
      || consumedAt === null || decidedAt === null
      || challengeCreatedAt > consumedAt || consumedAt !== decidedAt
      || decidedAt > challengeExpiresAt) return null;

  if (!['approved', 'denied'].includes(challenge.decision)
      || challenge.entity_ref !== session.entityRef
      || challenge.session_id !== session.sessionId
      || challenge.approver_id !== session.approverId
      || challenge.challenge_id !== session.challengeId
      || !MOBILE_SHA256.test(challenge.action_hash || '')
      || action.entity_ref !== session.entityRef
      || action.approver_id !== session.approverId
      || action.action_reference !== challenge.action_reference
      || action.status !== challenge.decision
      || action.decision_challenge_id !== challenge.challenge_id
      || action.decision_verdict !== 'verified') return null;

  const context = evidence.context;
  const binding = context?.mobile_binding;
  const contextHash = mobileContextHash(context);
  const profileHash = binding?.profile_hash;
  const issuedAt = mobileInstant(context?.issued_at);
  const contextExpiresAt = mobileInstant(context?.expires_at);
  if (!MOBILE_SHA256.test(profileHash || '') || !MOBILE_SHA256.test(contextHash || '')
      || issuedAt === null || contextExpiresAt === null
      || issuedAt > challengeCreatedAt || contextExpiresAt !== challengeExpiresAt
      || !mobileDecisionEvidenceMatches(evidence, {
        decision: challenge.decision,
        actionHash: challenge.action_hash,
        profileHash,
        approverId: challenge.approver_id,
        deviceKeyId: session.deviceKeyId,
        contextHash,
        platform: session.platform,
        appId: session.appId,
      })) return null;

  const expectedEntry = {
    event_type: 'mobile.ceremony.decision',
    challenge_id: challenge.challenge_id,
    action_hash: challenge.action_hash,
    profile_hash: profileHash,
    verdict: 'verified',
    decision: challenge.decision,
    approver_id: challenge.approver_id,
    device_key_id: session.deviceKeyId,
    context_hash: contextHash,
    session_id: challenge.session_id,
    decision_evidence: evidence,
  };
  if (!verifyEvidenceRecord(evidenceRecord, { atomicRequired: true, expectedEntry })) return null;

  const recovered = {
    valid: true,
    verdict: 'verified',
    decision: challenge.decision,
    reason: null,
    context_hash: contextHash,
    decision_evidence: structuredClone(evidence),
  };
  if (challenge.decision === 'approved') {
    recovered.class_a = structuredClone(evidence);
  }
  return recovered;
}

export async function lookupMobileCeremonyResult(supabase, {
  entityRef,
  sessionId,
  approverId,
  platform,
  appId,
  deviceKeyId,
  challengeId,
}) {
  if (!supabase?.from || typeof entityRef !== 'string' || !entityRef
      || typeof sessionId !== 'string' || !sessionId
      || typeof approverId !== 'string' || !approverId
      || !['ios', 'android'].includes(platform)
      || typeof appId !== 'string' || !appId
      || typeof deviceKeyId !== 'string' || !deviceKeyId
      || typeof challengeId !== 'string' || !MOBILE_LOOKUP_ID.test(challengeId)) return null;

  const { data: challenge, error: challengeError } = await supabase
    .from('mobile_action_challenges')
    .select('challenge_id, session_id, action_reference, entity_ref, approver_id, decision, action_hash, expires_at, consumed_at, created_at')
    .eq('entity_ref', entityRef)
    .eq('session_id', sessionId)
    .eq('approver_id', approverId)
    .eq('challenge_id', challengeId)
    .maybeSingle();
  if (challengeError) throw databaseError('mobile ceremony result lookup failed', challengeError);
  if (!challenge || challenge.consumed_at === null) return null;

  const { data: action, error: actionError } = await supabase
    .from('mobile_actions')
    .select('action_reference, entity_ref, approver_id, status, decision_challenge_id, decision_verdict, decision_evidence, decided_at')
    .eq('entity_ref', entityRef)
    .eq('approver_id', approverId)
    .eq('action_reference', challenge.action_reference)
    .eq('decision_challenge_id', challengeId)
    .maybeSingle();
  if (actionError) throw databaseError('mobile ceremony result lookup failed', actionError);
  if (!action) return null;

  const { data: evidence, error: evidenceError } = await supabase
    .from('mobile_evidence_records')
    .select('record')
    .eq('entity_ref', entityRef)
    .eq('record->>session_id', sessionId)
    .eq('record->>challenge_id', challengeId)
    .maybeSingle();
  if (evidenceError) throw databaseError('mobile ceremony result lookup failed', evidenceError);
  if (!evidence?.record) return null;

  return recoveredMobileResult({
    challenge,
    action,
    evidenceRecord: evidence.record,
    session: {
      entityRef,
      sessionId,
      approverId,
      platform,
      appId,
      deviceKeyId,
      challengeId,
    },
  });
}

export async function registerMobileActionChallenge(supabase, {
  entityRef,
  sessionId,
  actionReference,
  approverId,
  challengeId,
  actionHash,
  decision,
  expiresAt,
}) {
  const { data, error } = await supabase.rpc('register_mobile_action_challenge', {
    p_entity_ref: entityRef,
    p_session_id: sessionId,
    p_action_reference: actionReference,
    p_approver_id: approverId,
    p_challenge_id: challengeId,
    p_action_hash: actionHash,
    p_decision: decision,
    p_expires_at: expiresAt,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action challenge registration failed', error);
  return data === true;
}

export async function commitMobileActionDecision(supabase, {
  entityRef,
  sessionId,
  challengeId,
  actionHash,
  decision,
  verdict,
  decisionEvidence,
  auditEntry,
}) {
  if (!auditEntry || typeof auditEntry !== 'object' || Array.isArray(auditEntry)) {
    throw new TypeError('mobile action decision audit entry is required');
  }
  if (!decisionEvidence || typeof decisionEvidence !== 'object' || Array.isArray(decisionEvidence)) {
    throw new TypeError('typed mobile decision evidence is required');
  }
  const resultEvidence = structuredClone(decisionEvidence);
  const suppliedEntry = structuredClone(auditEntry);
  if (!mobileDecisionAuditMatches(suppliedEntry, {
    challengeId,
    actionHash,
    decision,
    verdict,
  })) {
    throw new TypeError('mobile action decision audit entry is malformed');
  }
  if (!mobileDecisionEvidenceMatches(resultEvidence, {
    decision,
    actionHash,
    profileHash: suppliedEntry.profile_hash,
    approverId: suppliedEntry.approver_id,
    deviceKeyId: suppliedEntry.device_key_id,
    contextHash: suppliedEntry.context_hash,
  })) {
    throw new TypeError(`stored ${decision || 'unknown'} mobile decision evidence is malformed`);
  }
  const snapshot = {
    ...suppliedEntry,
    session_id: sessionId,
    decision_evidence: resultEvidence,
  };
  const backend = createMobileEvidenceBackend(supabase, entityRef);
  const recordId = mobileEvidenceRecordId();

  for (let attempt = 0; attempt < 32; attempt++) {
    const head = await backend.readHead(entityRef);
    const body = {
      seq: head === null ? 0 : head.seq + 1,
      prev_hash: head === null ? 'genesis' : head.hash,
      record_id: recordId,
      ...snapshot,
    };
    const record = {
      ...body,
      hash: crypto.createHash('sha256').update(canonicalEvidenceJson(body)).digest('hex'),
    };
    if (!verifyEvidenceRecord(record, { atomicRequired: true, expectedEntry: snapshot })) {
      throw new Error('mobile action decision produced a malformed evidence record');
    }

    const { data, error } = await supabase.rpc('commit_mobile_action_decision', {
      p_entity_ref: entityRef,
      p_session_id: sessionId,
      p_challenge_id: challengeId,
      p_action_hash: actionHash,
      p_decision: decision,
      p_verdict: verdict,
      p_decision_evidence: resultEvidence,
      p_expected_hash: head?.hash ?? null,
      p_record: record,
      p_canonical_body: canonicalEvidenceJson(body),
      p_now: new Date().toISOString(),
    });
    if (error) {
      const recovered = await backend.getById(entityRef, recordId);
      if (recovered && canonicalEvidenceJson(recovered) === canonicalEvidenceJson(record)
          && verifyEvidenceRecord(recovered, { atomicRequired: true, expectedEntry: snapshot })) {
        return { committed: true, audit_record: recovered };
      }
      throw databaseError('mobile action decision commit failed', error);
    }
    if (data?.ok === true) {
      const persisted = await backend.getById(entityRef, recordId);
      if (!persisted || canonicalEvidenceJson(persisted) !== canonicalEvidenceJson(record)
          || !verifyEvidenceRecord(persisted, { atomicRequired: true, expectedEntry: snapshot })) {
        throw new Error('atomic mobile decision was not observable after commit');
      }
      return { committed: true, audit_record: persisted };
    }
    if (data?.reason === 'head_changed') continue;
    if (['action_conflict', 'session_inactive'].includes(data?.reason)) return false;
    throw new Error(`mobile action decision refused: ${data?.reason || 'unknown'}`);
  }
  throw new Error('mobile action decision evidence contention limit');
}

export async function createDemoAction(supabase, row) {
  const presentation = normalizeMobilePresentation(row.presentation, { allowUnversioned: true });
  const identity = buildMobileActionIdentity({
    actionReference: row.action_reference,
    action: row.action,
  });
  const groupId = `mag_${crypto.randomBytes(16).toString('hex')}`;
  const { data, error } = await supabase.rpc('create_mobile_demo_action_v2', {
    p_group_id: groupId,
    p_action_reference: row.action_reference,
    p_entity_ref: row.entity_ref,
    p_approver_id: row.approver_id,
    p_initiator_id: row.initiator_id,
    p_action: row.action,
    p_presentation: presentation,
    p_policy: row.policy,
    p_policy_id: row.policy_id,
    p_action_caid: identity.action_caid,
    p_action_digest: identity.action_digest,
    p_expires_at: row.expires_at,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile demo action creation failed', error);
  if (data !== true) throw new Error('mobile demo action creation refused');
  return row.action_reference;
}

export async function createGraceMobileActionGroup(supabase, {
  assignments,
  entityRef,
  initiatorId,
  action,
  presentation,
  policy,
  policyId,
  expiresAt,
}) {
  if (!Array.isArray(assignments) || assignments.length === 0) {
    throw new TypeError('at least one mobile approval assignment is required');
  }
  const snapshot = structuredClone(assignments);
  const normalizedPresentation = normalizeMobilePresentation(presentation, { allowUnversioned: true });
  const identity = buildMobileActionIdentity({
    actionReference: snapshot[0].action_reference,
    action,
  });
  const groupId = `mag_${crypto.randomBytes(16).toString('hex')}`;
  const { data, error } = await supabase.rpc('create_grace_mobile_action_group_v2', {
    p_group_id: groupId,
    p_assignments: snapshot,
    p_entity_ref: entityRef,
    p_initiator_id: initiatorId,
    p_action: structuredClone(action),
    p_presentation: normalizedPresentation,
    p_policy: structuredClone(policy),
    p_policy_id: policyId,
    p_action_caid: identity.action_caid,
    p_action_digest: identity.action_digest,
    p_expires_at: expiresAt,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('GRACE mobile action group creation failed', error);
  if (data !== true) throw new Error('GRACE mobile action group creation refused');
  return snapshot;
}

export async function supersedeMobileAction(supabase, {
  entityRef,
  currentActionReference,
  assignments,
  initiatorId,
  action,
  presentation,
  policy,
  policyId,
  expiresAt,
}) {
  if (!Array.isArray(assignments) || assignments.length === 0) {
    throw new TypeError('at least one successor approval assignment is required');
  }
  const normalizedPresentation = normalizeMobilePresentation(presentation, { allowUnversioned: true });
  const { data: current, error: currentError } = await supabase
    .from('mobile_actions')
    .select('presentation')
    .eq('entity_ref', entityRef)
    .eq('action_reference', currentActionReference)
    .maybeSingle();
  if (currentError) throw databaseError('mobile action supersession failed', currentError);
  if (!current?.presentation) throw new Error('mobile action supersession refused: not_found');
  const currentPresentation = normalizeMobilePresentation(current.presentation);
  const identity = buildMobileActionIdentity({
    actionReference: assignments[0].action_reference,
    action,
  });
  const changes = materialFieldDiff(
    normalizedPresentation.material_fields,
    currentPresentation.material_fields,
  );
  const { data, error } = await supabase.rpc('supersede_mobile_action', {
    p_entity_ref: entityRef,
    p_current_action_reference: currentActionReference,
    p_assignments: structuredClone(assignments),
    p_initiator_id: initiatorId,
    p_action: structuredClone(action),
    p_presentation: normalizedPresentation,
    p_policy: structuredClone(policy),
    p_policy_id: policyId,
    p_action_caid: identity.action_caid,
    p_action_digest: identity.action_digest,
    p_change_set: changes,
    p_expires_at: expiresAt,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action supersession failed', error);
  if (data?.ok !== true) throw new Error(`mobile action supersession refused: ${data?.reason || 'unknown'}`);
  return { ...data, identity, changes };
}

export async function withdrawMobileAction(supabase, {
  entityRef,
  sessionId,
  actionReference,
}) {
  const { data, error } = await supabase.rpc('withdraw_mobile_action', {
    p_entity_ref: entityRef,
    p_session_id: sessionId,
    p_action_reference: actionReference,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile approval withdrawal failed', error);
  return data || { ok: false, reason: 'unknown' };
}

export async function consumeMobileAction(supabase, {
  entityRef,
  actionReference,
  operationId,
  consumptionNonce,
  executorId,
}) {
  const { data, error } = await supabase.rpc('consume_mobile_action', {
    p_entity_ref: entityRef,
    p_action_reference: actionReference,
    p_operation_id: operationId,
    p_consumption_nonce: consumptionNonce,
    p_executor_id: executorId,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action consumption failed', error);
  return data || { ok: false, reason: 'unknown' };
}

export async function markMobileActionIndeterminate(supabase, {
  entityRef,
  operationId,
}) {
  const { data, error } = await supabase.rpc('mark_mobile_action_indeterminate', {
    p_entity_ref: entityRef,
    p_operation_id: operationId,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action indeterminate transition failed', error);
  return data || { ok: false, reason: 'unknown' };
}

export async function resolveMobileOperation(supabase, { entityRef, operationId, actionReference = null }) {
  const { data, error } = await supabase
    .from('mobile_action_operations')
    .select('operation_id, group_id, revision, action_caid, consumption_nonce, executor_id, executor_key_id, status, consumed_at')
    .eq('entity_ref', entityRef)
    .eq('operation_id', operationId)
    .maybeSingle();
  if (error) throw databaseError('mobile action operation lookup failed', error);
  if (!data) return null;
  const { data: revision, error: revisionError } = await supabase
    .from('mobile_action_revisions')
    .select('action_digest')
    .eq('entity_ref', entityRef)
    .eq('group_id', data.group_id)
    .eq('revision', data.revision)
    .maybeSingle();
  if (revisionError) throw databaseError('mobile action operation lookup failed', revisionError);
  if (!revision) return null;
  if (actionReference !== null) {
    const { data: action, error: actionError } = await supabase
      .from('mobile_actions')
      .select('action_reference')
      .eq('entity_ref', entityRef)
      .eq('group_id', data.group_id)
      .eq('revision', data.revision)
      .eq('action_reference', actionReference)
      .maybeSingle();
    if (actionError) throw databaseError('mobile action operation lookup failed', actionError);
    if (!action) return null;
  }
  return { ...data, action_digest: revision.action_digest };
}

export async function resolveMobileExecutorKey(supabase, { entityRef, executorId, executorKeyId = null }) {
  let query = supabase
    .from('mobile_executor_keys')
    .select('executor_id, key_id, public_key')
    .eq('entity_ref', entityRef)
    .eq('executor_id', executorId)
    .eq('status', 'active');
  if (executorKeyId !== null) query = query.eq('key_id', executorKeyId);
  const { data, error } = await query.maybeSingle();
  if (error) throw databaseError('mobile executor key lookup failed', error);
  return data || null;
}

export async function reconcileMobileActionOperation(supabase, {
  entityRef,
  operation,
  evidence,
}) {
  const executorId = operation?.executor_id;
  const executorKeyId = operation?.executor_key_id;
  const pin = await resolveMobileExecutorKey(supabase, {
    entityRef,
    executorId,
    executorKeyId,
  });
  const verified = verifyMobileProviderOutcome(evidence, {
    expected: {
      operation_id: operation?.operation_id,
      action_caid: operation?.action_caid,
      action_digest: operation?.action_digest,
      consumption_nonce: operation?.consumption_nonce,
      executor_id: executorId,
      executor_key_id: executorKeyId,
    },
    executorKeys: pin ? { [pin.executor_id]: pin } : {},
    notBefore: operation?.consumed_at,
  });
  if (!verified.valid) return { ok: false, reason: verified.reason };
  const { data, error } = await supabase.rpc('reconcile_mobile_action_operation', {
    p_entity_ref: entityRef,
    p_operation_id: operation.operation_id,
    p_executor_id: executorId,
    p_executor_key_id: executorKeyId,
    p_outcome: verified.outcome,
    p_provider_reference: evidence.provider_reference,
    p_evidence_digest: verified.evidence_digest,
    p_provider_evidence: structuredClone(evidence),
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action reconciliation failed', error);
  return data || { ok: false, reason: 'unknown' };
}

export async function registerMobileExecutorKey(supabase, {
  entityRef,
  executorId,
  keyId,
  publicKey,
}) {
  const { data, error } = await supabase.rpc('register_mobile_executor_key', {
    p_entity_ref: entityRef,
    p_executor_id: executorId,
    p_key_id: keyId,
    p_public_key: publicKey,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile executor key registration failed', error);
  return data === true;
}

export async function recordMobileActionAlignment(supabase, {
  entityRef,
  actionReference,
  alignment,
}) {
  const [normalized] = normalizeSystemAlignments([alignment]);
  if (!normalized) throw new TypeError('mobile action alignment is malformed');
  const { data, error } = await supabase.rpc('record_mobile_action_alignment', {
    p_entity_ref: entityRef,
    p_action_reference: actionReference,
    p_system_name: normalized.system,
    p_verdict: normalized.verdict,
    p_profile_id: normalized.profile_id,
    p_profile_hash: normalized.profile_hash,
    p_native_verified: normalized.native_verified,
    p_evidence_digest: normalized.evidence_digest,
    p_reason: normalized.reason,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile action alignment recording failed', error);
  return data === true;
}
