// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import {
  canonicalEvidenceJson,
  createAtomicEvidenceLog,
  verifyEvidenceRecord,
} from '../../packages/gate/evidence.js';

const MOBILE_TOKEN = /^ep_mobile_([A-Za-z0-9_-]{43})$/;

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
    recordIdFactory: mobileEvidenceRecordId,
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
        .select('device_key_id, credential_id, public_key_spki, approver_id, platform, app_id, attestation_key_id, status, valid_from, valid_to')
        .eq('entity_ref', entityRef)
        .eq('status', 'active')
        .lte('valid_from', now)
        .gte('valid_to', now);
      if (error) throw databaseError('mobile enrollment directory unavailable', error);
      return data || [];
    },
    async appAttestKey(attestationKeyId) {
      const { data, error } = await supabase
        .from('mobile_enrollments')
        .select('platform_public_key, app_id, status, valid_from, valid_to')
        .eq('entity_ref', entityRef)
        .eq('platform', 'ios')
        .eq('attestation_key_id', attestationKeyId)
        .maybeSingle();
      if (error) throw databaseError('App Attest key lookup failed', error);
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
  const now = new Date().toISOString();
  const { data, error } = await supabase
    .from('mobile_actions')
    .select('action_reference, action, presentation, policy_id, status, expires_at, created_at')
    .eq('entity_ref', entityRef)
    .eq('approver_id', approverId)
    .eq('status', 'pending')
    .gt('expires_at', now)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) throw databaseError('mobile action inbox unavailable', error);
  return data || [];
}

export async function resolveMobileAction(supabase, { entityRef, approverId, actionReference }) {
  const { data, error } = await supabase
    .from('mobile_actions')
    .select('action_reference, action, presentation, policy, policy_id, initiator_id, approver_id, status, expires_at')
    .eq('entity_ref', entityRef)
    .eq('approver_id', approverId)
    .eq('action_reference', actionReference)
    .maybeSingle();
  if (error) throw databaseError('mobile action lookup unavailable', error);
  if (!data || data.status !== 'pending' || Date.parse(data.expires_at) <= Date.now()) return null;
  return data;
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
  auditEntry,
}) {
  if (!auditEntry || typeof auditEntry !== 'object' || Array.isArray(auditEntry)) {
    throw new TypeError('mobile action decision audit entry is required');
  }
  const suppliedEntry = structuredClone(auditEntry);
  if (['seq', 'prev_hash', 'record_id', 'hash', 'session_id'].some((field) => Object.hasOwn(suppliedEntry, field))) {
    throw new TypeError('mobile action decision audit entry contains a reserved evidence field');
  }
  const snapshot = { ...suppliedEntry, session_id: sessionId };
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
  const { data, error } = await supabase.rpc('create_mobile_demo_action', {
    p_action_reference: row.action_reference,
    p_entity_ref: row.entity_ref,
    p_approver_id: row.approver_id,
    p_initiator_id: row.initiator_id,
    p_action: row.action,
    p_presentation: row.presentation,
    p_policy: row.policy,
    p_policy_id: row.policy_id,
    p_expires_at: row.expires_at,
    p_now: new Date().toISOString(),
  });
  if (error) throw databaseError('mobile demo action creation failed', error);
  if (data !== true) throw new Error('mobile demo action creation refused');
  return row.action_reference;
}
