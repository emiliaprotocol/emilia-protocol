// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  lookupMobileCeremonyResult,
} from '@/lib/mobile/store.js';
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

function committedRows(decision = 'approved') {
  const context = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_reference: 'mobact_0123456789abcdef0123456789abcdef',
    action_caid: `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
    action_digest: `sha256:${'c'.repeat(64)}`,
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
    decision,
    display_hash: `sha256:${'c'.repeat(64)}`,
    mobile_binding: {
      profile: 'EP-MOBILE-CHALLENGE-v2',
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
    decision,
    approver_id: SESSION.approverId,
    device_key_id: SESSION.deviceKeyId,
    context_hash: contextHash,
    session_id: SESSION.sessionId,
    decision_evidence: structuredClone(decisionEvidence),
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
      decision,
      action_hash: ACTION_HASH,
      expires_at: context.expires_at,
      consumed_at: '2026-07-16T20:01:00.000Z',
      created_at: context.issued_at,
    }],
    mobile_actions: [{
      action_reference: 'mobact_0123456789abcdef0123456789abcdef',
      entity_ref: SESSION.entityRef,
      approver_id: SESSION.approverId,
      status: decision,
      decision_challenge_id: CHALLENGE_ID,
      decision_verdict: 'verified',
      decision_evidence: structuredClone(decisionEvidence),
      decided_at: '2026-07-16T20:01:00.000Z',
    }],
    mobile_evidence_records: [{ entity_ref: SESSION.entityRef, record }],
  };
}

function valueAt(row, field) {
  const jsonText = /^record->>([A-Za-z0-9_]+)$/.exec(field);
  return jsonText ? row.record?.[jsonText[1]] : row[field];
}

function database(rows, errors = {}) {
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
        if (errors[table]) return { data: null, error: errors[table] };
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
    const rows = committedRows();
    const db = database(rows);
    await expect(lookupMobileCeremonyResult(db, {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toEqual({
      valid: true,
      verdict: 'verified',
      decision: 'approved',
      reason: null,
      context_hash: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      decision_evidence: rows.mobile_actions[0].decision_evidence,
      class_a: rows.mobile_actions[0].decision_evidence,
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

  it('recovers the original signed denial envelope without class_a authorization evidence', async () => {
    const rows = committedRows('denied');
    const result = await lookupMobileCeremonyResult(database(rows), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    });
    expect(result).toEqual({
      valid: true,
      verdict: 'verified',
      decision: 'denied',
      reason: null,
      context_hash: rows.mobile_actions[0].decision_evidence.signoff.context_hash,
      decision_evidence: rows.mobile_actions[0].decision_evidence,
    });
    expect(Object.hasOwn(result, 'class_a')).toBe(false);
    expect(Object.hasOwn(result, 'authorization')).toBe(false);
    expect(result.decision_evidence.signoff.webauthn.signature).toBe('c2lnbmF0dXJl');
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

  it.each(['approved', 'denied'])('refuses altered %s context and signoff bytes', async (decision) => {
    const mutations = [
      ['decision', (evidence) => { evidence.context.decision = decision === 'approved' ? 'denied' : 'approved'; }],
      ['approver', (evidence) => { evidence.context.approver = 'ep:approver:attacker'; }],
      ['device', (evidence) => { evidence.context.mobile_binding.device_key_id = 'ep:key:mobile-attacker'; }],
      ['profile', (evidence) => { evidence.context.mobile_binding.profile_hash = `sha256:${'f'.repeat(64)}`; }],
      ['action', (evidence) => { evidence.context.action_hash = `sha256:${'e'.repeat(64)}`; }],
      ['context hash', (evidence) => { evidence.signoff.context_hash = `sha256:${'f'.repeat(64)}`; }],
      ['WebAuthn signature', (evidence) => { evidence.signoff.webauthn.signature = 'dGFtcGVyZWQ'; }],
    ];
    for (const [label, mutate] of mutations) {
      const rows = committedRows(decision);
      mutate(rows.mobile_actions[0].decision_evidence);
      await expect(lookupMobileCeremonyResult(database(rows), {
        ...SESSION,
        challengeId: CHALLENGE_ID,
      }), label).resolves.toBeNull();
    }
  });

  it('closes a stale commit timestamp', async () => {
    const staleRows = committedRows();
    staleRows.mobile_actions[0].decided_at = '2026-07-16T20:06:00.000Z';
    staleRows.mobile_action_challenges[0].consumed_at = '2026-07-16T20:06:00.000Z';
    await expect(lookupMobileCeremonyResult(database(staleRows), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();
  });

  it('returns the same closed result for an unknown challenge ID', async () => {
    const rows = committedRows();
    const db = database(rows);
    await expect(lookupMobileCeremonyResult(db, {
      ...SESSION,
      challengeId: 'mob_ffffffffffffffffffffffffffffffff',
    })).resolves.toBeNull();
    expect(db.from).toHaveBeenCalledTimes(1);

    await expect(lookupMobileCeremonyResult(null, {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();

    for (const table of [
      'mobile_action_challenges',
      'mobile_actions',
      'mobile_evidence_records',
    ]) {
      await expect(lookupMobileCeremonyResult(database(rows, {
        [table]: { code: '08006', message: 'unavailable' },
      }), {
        ...SESSION,
        challengeId: CHALLENGE_ID,
      })).rejects.toThrow(/mobile ceremony result lookup failed/);
    }

    const noAction = committedRows();
    noAction.mobile_actions = [];
    await expect(lookupMobileCeremonyResult(database(noAction), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();

    const noEvidence = committedRows();
    noEvidence.mobile_evidence_records = [];
    await expect(lookupMobileCeremonyResult(database(noEvidence), {
      ...SESSION,
      challengeId: CHALLENGE_ID,
    })).resolves.toBeNull();
  });
});
