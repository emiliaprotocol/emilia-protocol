// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import { lookupMobileCeremonyResult } from '@/lib/mobile/store.js';
import { canonicalEvidenceJson } from '@/packages/gate/evidence.js';

const SESSION = Object.freeze({
  entityRef: 'entity-1',
  sessionId: '00000000-0000-0000-0000-000000000001',
  approverId: 'ep:approver:supervisor',
  platform: 'ios',
  appId: 'ai.emiliaprotocol.approver',
  deviceKeyId: 'ep:key:mobile-device-1',
});
const CHALLENGE_ID = 'mob_0123456789abcdef0123456789abcdef';
const ACTION_HASH = `sha256:${'a'.repeat(64)}`;
const PROFILE_HASH = `sha256:${'b'.repeat(64)}`;

function hashCanonical(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalEvidenceJson(value)).digest('hex')}`;
}

function committedRows() {
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash: ACTION_HASH,
    policy_id: 'policy-1',
    policy_hash: null,
    initiator: 'ep:agent:treasury',
    approver: SESSION.approverId,
    approver_index: 1,
    required_approvals: 1,
    nonce: 'sig_0123456789abcdef0123456789abcdef',
    issued_at: '2026-07-16T20:00:00.000Z',
    expires_at: '2026-07-16T20:05:00.000Z',
    decision: 'approved',
    display_hash: `sha256:${'c'.repeat(64)}`,
    mobile_binding: {
      profile: 'EP-MOBILE-CHALLENGE-v1',
      profile_hash: PROFILE_HASH,
      platform: SESSION.platform,
      app_id: SESSION.appId,
      device_key_id: SESSION.deviceKeyId,
      credential_id: 'Y3JlZGVudGlhbC0x',
      attestation_key_id: 'apple-key-1',
    },
  };
  const contextHash = hashCanonical(context);
  const decisionEvidence = {
    context,
    signoff: {
      context_hash: contextHash,
      key_class: 'A',
      approver_key_id: SESSION.deviceKeyId,
      signed_at: context.issued_at,
      webauthn: {
        authenticator_data: 'YXV0aC1kYXRh',
        client_data_json: 'Y2xpZW50LWRhdGE',
        signature: 'c2lnbmF0dXJl',
      },
    },
  };
  const entry = {
    event_type: 'mobile.ceremony.decision',
    challenge_id: CHALLENGE_ID,
    action_hash: ACTION_HASH,
    profile_hash: PROFILE_HASH,
    verdict: 'verified',
    decision: 'approved',
    approver_id: SESSION.approverId,
    device_key_id: SESSION.deviceKeyId,
    context_hash: contextHash,
    session_id: SESSION.sessionId,
  };
  const body = {
    seq: 4,
    prev_hash: 'd'.repeat(64),
    record_id: `mar_${'e'.repeat(32)}`,
    ...entry,
  };
  const record = {
    ...body,
    hash: crypto.createHash('sha256').update(canonicalEvidenceJson(body)).digest('hex'),
  };
  return {
    mobile_action_challenges: [{
      challenge_id: CHALLENGE_ID,
      session_id: SESSION.sessionId,
      action_reference: 'mobact_0123456789abcdef0123456789abcdef',
      entity_ref: SESSION.entityRef,
      approver_id: SESSION.approverId,
      decision: 'approved',
      action_hash: ACTION_HASH,
      expires_at: context.expires_at,
      consumed_at: '2026-07-16T20:01:00.000Z',
      created_at: context.issued_at,
    }],
    mobile_actions: [{
      action_reference: 'mobact_0123456789abcdef0123456789abcdef',
      entity_ref: SESSION.entityRef,
      approver_id: SESSION.approverId,
      status: 'approved',
      decision_challenge_id: CHALLENGE_ID,
      decision_verdict: 'verified',
      decision_evidence: decisionEvidence,
      decided_at: '2026-07-16T20:01:00.000Z',
    }],
    mobile_evidence_records: [{ entity_ref: SESSION.entityRef, record }],
  };
}

function valueAt(row, field) {
  const jsonText = /^record->>([A-Za-z0-9_]+)$/.exec(field);
  return jsonText ? row.record?.[jsonText[1]] : row[field];
}

function database(rows) {
  const queries = [];
  const from = vi.fn((table) => {
    const filters = [];
    const query = {
      select: vi.fn(() => query),
      eq: vi.fn((field, value) => {
        filters.push([field, value]);
        return query;
      }),
      maybeSingle: vi.fn(async () => {
        const matches = (rows[table] || []).filter((row) => (
          filters.every(([field, value]) => valueAt(row, field) === value)
        ));
        return { data: matches.length === 1 ? structuredClone(matches[0]) : null, error: null };
      }),
    };
    queries.push({ table, filters, query });
    return query;
  });
  return { from, queries };
}

describe('mobile ceremony committed-result lookup', () => {
  it('recovers the exact verified result only from a matching atomic commit', async () => {
    const db = database(committedRows());
    await expect(lookupMobileCeremonyResult(db, {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toEqual({
      valid: true,
      verdict: 'verified',
      decision: 'approved',
      reason: null,
      context_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    });
    expect(db.queries.map(({ table }) => table)).toEqual([
      'mobile_action_challenges',
      'mobile_actions',
      'mobile_evidence_records',
    ]);
    expect(db.queries[0].filters).toEqual(expect.arrayContaining([
      ['entity_ref', SESSION.entityRef],
      ['session_id', SESSION.sessionId],
      ['approver_id', SESSION.approverId],
      ['challenge_id', CHALLENGE_ID],
    ]));
  });

  it.each([
    ['session', { sessionId: '00000000-0000-0000-0000-000000000002' }],
    ['approver', { approverId: 'ep:approver:attacker' }],
  ])('closes a wrong %s scope without probing later tables', async (_label, mismatch) => {
    const db = database(committedRows());
    await expect(lookupMobileCeremonyResult(db, {
      ...SESSION,
      ...mismatch,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();
    expect(db.from).toHaveBeenCalledTimes(1);
  });

  it('closes malformed decision evidence and a stale commit timestamp', async () => {
    const malformedRows = committedRows();
    malformedRows.mobile_actions[0].decision_evidence.signoff.context_hash = `sha256:${'f'.repeat(64)}`;
    await expect(lookupMobileCeremonyResult(database(malformedRows), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();

    const staleRows = committedRows();
    staleRows.mobile_actions[0].decided_at = '2026-07-16T20:06:00.000Z';
    staleRows.mobile_action_challenges[0].consumed_at = '2026-07-16T20:06:00.000Z';
    await expect(lookupMobileCeremonyResult(database(staleRows), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();
  });

  it('returns the same closed result for an unknown challenge ID', async () => {
    const db = database(committedRows());
    await expect(lookupMobileCeremonyResult(db, {
      ...SESSION,
      challengeId: 'mob_ffffffffffffffffffffffffffffffff',
    })).resolves.toBeNull();
    expect(db.from).toHaveBeenCalledTimes(1);
  });
});
