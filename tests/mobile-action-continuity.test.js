// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

import {
  buildMobileProviderOutcome,
  buildDecisionPassport,
  buildMobileActionIdentity,
  deriveMobileActionContinuity,
  materialFieldDiff,
  normalizeSystemAlignments,
  verifyMobileProviderOutcome,
  _internals,
} from '@/lib/mobile/action-continuity.js';
import { mobileActionView } from '@/lib/mobile/action-view.js';
import {
  consumeMobileAction,
  listMobileActionHistory,
  markMobileActionIndeterminate,
  reconcileMobileActionOperation,
  recordMobileActionAlignment,
  registerMobileExecutorKey,
  resolveMobileExecutorKey,
  resolveMobileOperation,
  supersedeMobileAction,
  withdrawMobileAction,
} from '@/lib/mobile/store.js';

const action = {
  '@type': 'treasury.disbursement.release',
  action_id: 'payment-42',
  amount_minor: 25000000,
  beneficiary_id: 'vendor:grid-restoration-42',
  currency: 'USD',
};

const ACTION_REFERENCE = 'mobact_11111111111111111111111111111111';

function providerFixture({ outcome = 'executed' } = {}) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const identity = buildMobileActionIdentity({ actionReference: ACTION_REFERENCE, action });
  const consumedAt = new Date(Date.now() - 60_000).toISOString();
  const observedAt = new Date(Date.now() - 30_000).toISOString();
  const evidence = buildMobileProviderOutcome({
    operationId: 'mobile-operation-42',
    actionCaid: identity.action_caid,
    actionDigest: identity.action_digest,
    consumptionNonce: 'consume-42',
    executorId: 'provider:treasury-production',
    outcome,
    observedAt,
    providerReference: 'provider-effect-42',
    privateKey: pair.privateKey,
  });
  return {
    evidence,
    identity,
    operation: {
      operation_id: 'mobile-operation-42',
      action_caid: identity.action_caid,
      action_digest: identity.action_digest,
      consumption_nonce: 'consume-42',
      executor_id: 'provider:treasury-production',
      executor_key_id: evidence.proof.key_id,
      consumed_at: consumedAt,
    },
    pin: {
      executor_id: 'provider:treasury-production',
      key_id: evidence.proof.key_id,
      public_key: evidence.proof.public_key,
    },
  };
}

function queryClient({ rows = {}, rpcResult = { data: true, error: null } } = {}) {
  const filters = [];
  const supabase = {
    rpc: vi.fn(async (...args) => (
      typeof rpcResult === 'function' ? rpcResult(...args) : rpcResult
    )),
    from: vi.fn((table) => {
      const builder = {};
      builder.select = vi.fn(() => builder);
      builder.eq = vi.fn((field, value) => {
        filters.push({ table, field, value });
        return builder;
      });
      builder.maybeSingle = vi.fn(async () => {
        const result = rows[table];
        return typeof result === 'function'
          ? result(filters.filter((entry) => entry.table === table))
          : (result || { data: null, error: null });
      });
      return builder;
    }),
  };
  return { filters, supabase };
}

describe('mobile CAID and Action Evidence Boundary continuity', () => {
  it('pins the exact public CAID action-type definition used by the mobile kernel', () => {
    const registry = JSON.parse(fs.readFileSync(
      new URL('../caid/registry/action-types.json', import.meta.url),
      'utf8',
    ));
    expect(registry.types.find(
      (entry) => entry.action_type === 'emilia.mobile.authorized-action.1',
    )).toEqual(_internals.MOBILE_ACTION_CAID_DEFINITION);
  });

  it('computes one stable CAID from the exact authoritative action bytes', () => {
    const first = buildMobileActionIdentity({
      actionReference: 'mobact_11111111111111111111111111111111',
      action,
    });
    const reordered = buildMobileActionIdentity({
      actionReference: 'mobact_11111111111111111111111111111111',
      action: {
        currency: 'USD',
        beneficiary_id: 'vendor:grid-restoration-42',
        amount_minor: 25000000,
        action_id: 'payment-42',
        '@type': 'treasury.disbursement.release',
      },
    });
    const changed = buildMobileActionIdentity({
      actionReference: 'mobact_11111111111111111111111111111111',
      action: { ...action, amount_minor: 25000001 },
    });

    expect(first).toEqual(reordered);
    expect(first.action_caid).toMatch(
      /^caid:1:emilia\.mobile\.authorized-action\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/,
    );
    expect(first.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(first.fingerprint).toMatch(/^[0-9A-F]{4}(?:-[0-9A-F]{4}){3}$/);
    expect(changed.action_caid).not.toBe(first.action_caid);
    expect(changed.action_digest).not.toBe(first.action_digest);
  });

  it('reports material changes without hiding added or removed fields', () => {
    expect(materialFieldDiff(
      { amount: '$250,000', beneficiary: 'Vendor B', memo: 'Emergency' },
      { amount: '$200,000', beneficiary: 'Vendor A', old_code: 'A1' },
    )).toEqual([
      { field: 'amount', change: 'changed', before: '$200,000', after: '$250,000' },
      { field: 'beneficiary', change: 'changed', before: 'Vendor A', after: 'Vendor B' },
      { field: 'memo', change: 'added', before: null, after: 'Emergency' },
      { field: 'old_code', change: 'removed', before: 'A1', after: null },
    ]);
    expect(materialFieldDiff(null, [])).toEqual([]);
    expect(() => _internals.canonicalDigest({ undefined_is_not_json: undefined }))
      .toThrow(/not canonicalizable/i);
  });

  it('projects safe mobile defaults without inventing presentation or passport claims', () => {
    expect(mobileActionView({})).toEqual({
      action_reference: undefined,
      title: 'Approval required',
      summary: 'Review the exact action before deciding.',
      risk: 'consequential',
      material_fields: {},
      expires_at: undefined,
      created_at: undefined,
      status: undefined,
      revision: undefined,
      identity: null,
      supersedes_action_caid: null,
      changes: [],
      continuity: null,
      quorum: null,
      alignments: [],
      events: [],
      can_withdraw: false,
    });
    expect(mobileActionView({ passport: { passport_digest: 'sha256:test' } }, {
      includePassport: true,
    })).toMatchObject({ passport: { passport_digest: 'sha256:test' } });
    expect(mobileActionView({}, { includePassport: true }).passport).toBeNull();
  });

  it('keeps authorization, consumption, uncertainty, and execution separate', () => {
    const base = {
      status: 'approved',
      required_approvals: 2,
      approved_count: 2,
      denied_count: 0,
      withdrawn_count: 0,
      effect_status: 'not_consumed',
    };
    expect(deriveMobileActionContinuity(base).state).toBe('AUTHORIZED');
    expect(deriveMobileActionContinuity({
      ...base,
      denied_count: 1,
      withdrawn_count: 1,
    }).state).toBe('AUTHORIZED');
    expect(deriveMobileActionContinuity({ ...base, approved_count: 1 }).state).toBe('QUORUM_PENDING');
    expect(deriveMobileActionContinuity({
      ...base,
      effect_status: 'consumed',
      consumption_nonce: 'consume-42',
    }).state).toBe('CONSUMED');
    expect(deriveMobileActionContinuity({
      ...base,
      effect_status: 'indeterminate',
      consumption_nonce: 'consume-42',
    })).toMatchObject({ state: 'INDETERMINATE', retry_safe: false });
    expect(() => deriveMobileActionContinuity({
      ...base,
      effect_status: 'executed',
      outcome_verified: false,
    })).toThrow(/authenticated provider evidence/i);
    expect(deriveMobileActionContinuity({
      ...base,
      effect_status: 'executed',
      outcome_verified: true,
    }).state).toBe('EXECUTED');
  });

  it('fails closed on unpinned cross-system correlations', () => {
    const normalized = normalizeSystemAlignments([
      {
        system: 'AgentROA',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        profile_id: 'ep:map:agentroa:v1',
        profile_hash: `sha256:${'a'.repeat(64)}`,
        native_verified: true,
        evidence_digest: `sha256:${'c'.repeat(64)}`,
      },
      {
        system: 'Unpinned',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        profile_id: 'ep:map:missing',
        profile_hash: null,
        native_verified: true,
      },
      {
        system: 'Unsigned',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        profile_id: 'ep:map:unsigned',
        profile_hash: `sha256:${'b'.repeat(64)}`,
        native_verified: false,
      },
    ]);
    expect(normalized).toEqual([
      expect.objectContaining({
        system: 'AgentROA',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        evidence_digest: `sha256:${'c'.repeat(64)}`,
      }),
      expect.objectContaining({ system: 'Unpinned', verdict: 'INDETERMINATE' }),
      expect.objectContaining({ system: 'Unsigned', verdict: 'INDETERMINATE' }),
    ]);
  });

  it('exports a bounded decision passport with evidence digests, not secret evidence bytes', () => {
    const passport = buildDecisionPassport({
      action_reference: 'mobact_11111111111111111111111111111111',
      action_caid: 'caid:1:emilia.mobile.authorized-action.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      action_digest: `sha256:${'a'.repeat(64)}`,
      decision_challenge_id: 'challenge-42',
      decision_verdict: 'verified',
      decision_evidence: { signoff: { webauthn: { signature: 'secret' } } },
      decided_at: '2026-07-20T20:00:00.000Z',
      effect_status: 'indeterminate',
      consumption_nonce: 'consume-42',
      outcome_attestation: null,
      outcome_digest: null,
      created_at: '2026-07-20T19:00:00.000Z',
    }, {
      state: 'INDETERMINATE',
      retry_safe: false,
      quorum: { approved: 2, required: 2 },
    });

    expect(passport['@version']).toBe('EP-MOBILE-DECISION-PASSPORT-v1');
    expect(passport.decision.evidence_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(passport.lifecycle).toMatchObject({ state: 'INDETERMINATE', retry_safe: false });
    expect(JSON.stringify(passport)).not.toContain('secret');
    expect(JSON.stringify(passport)).not.toContain('webauthn');
  });

  it('accepts terminal execution only under a pinned provider key and exact operation binding', () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const identity = buildMobileActionIdentity({
      actionReference: 'mobact_11111111111111111111111111111111',
      action,
    });
    const evidence = buildMobileProviderOutcome({
      operationId: 'mobile-operation-42',
      actionCaid: identity.action_caid,
      actionDigest: identity.action_digest,
      consumptionNonce: 'consume-42',
      executorId: 'provider:treasury-production',
      outcome: 'executed',
      observedAt: '2026-07-20T20:05:00.000Z',
      providerReference: 'provider-effect-42',
      privateKey: pair.privateKey,
    });
    const expected = {
      operation_id: 'mobile-operation-42',
      action_caid: identity.action_caid,
      action_digest: identity.action_digest,
      consumption_nonce: 'consume-42',
      executor_id: 'provider:treasury-production',
      executor_key_id: evidence.proof.key_id,
    };
    expect(verifyMobileProviderOutcome(evidence, {
      expected,
      executorKeys: { 'provider:treasury-production': { public_key: publicKey } },
      notBefore: '2026-07-20T20:04:00.000Z',
      now: '2026-07-20T20:06:00.000Z',
    })).toMatchObject({ valid: true, outcome: 'executed' });
    expect(verifyMobileProviderOutcome(evidence, {
      expected,
      executorKeys: { 'provider:treasury-production': { public_key: publicKey } },
      notBefore: '2026-07-20T20:05:01.000Z',
      now: '2026-07-20T20:06:00.000Z',
    })).toMatchObject({ valid: false, reason: 'provider_outcome_time_invalid' });
    expect(verifyMobileProviderOutcome(evidence, {
      expected,
      executorKeys: {},
      now: '2026-07-20T20:06:00.000Z',
    })).toMatchObject({ valid: false, reason: 'executor_key_not_pinned' });
    expect(verifyMobileProviderOutcome(evidence, {
      expected: { ...expected, operation_id: 'mobile-operation-other' },
      executorKeys: { 'provider:treasury-production': { public_key: publicKey } },
      now: '2026-07-20T20:06:00.000Z',
    })).toMatchObject({ valid: false, reason: 'provider_outcome_binding_mismatch' });
  });

  it('normalizes hostile alignment input without inferring equivalence', () => {
    expect(normalizeSystemAlignments(null)).toEqual([]);
    expect(normalizeSystemAlignments([
      null,
      [],
      { system: '' },
      { system: 'x'.repeat(129) },
      {
        system: 'UnknownVerdict',
        verdict: 'SAME_ENOUGH',
        profile_id: 42,
        profile_hash: 'sha256:not-a-digest',
        native_verified: false,
        evidence_digest: 'sha256:bad',
        reason: 'Source semantics are not pinned',
      },
      {
        system: 'NativeMismatch',
        verdict: 'NOT_EQUIVALENT',
        profile_id: 'ep:map:native:v1',
        profile_hash: `sha256:${'d'.repeat(64)}`,
        native_verified: true,
        evidence_digest: `sha256:${'e'.repeat(64)}`,
        reason: 'Compared under the pinned profile',
      },
    ])).toEqual([
      {
        system: 'UnknownVerdict',
        verdict: 'INDETERMINATE',
        profile_id: null,
        profile_hash: null,
        native_verified: false,
        evidence_digest: null,
        reason: 'Source semantics are not pinned',
      },
      {
        system: 'NativeMismatch',
        verdict: 'NOT_EQUIVALENT',
        profile_id: 'ep:map:native:v1',
        profile_hash: `sha256:${'d'.repeat(64)}`,
        native_verified: true,
        evidence_digest: `sha256:${'e'.repeat(64)}`,
        reason: 'Compared under the pinned profile',
      },
    ]);
  });

  it('covers every non-execution lifecycle without trusting malformed counters', () => {
    expect(deriveMobileActionContinuity({
      required_approvals: 0,
      approved_count: -1,
      denied_count: -1,
      withdrawn_count: -1,
      effect_status: 'future-state',
    })).toEqual({
      state: 'AWAITING_DECISION',
      retry_safe: true,
      quorum: { approved: 0, required: 1, denied: 0, withdrawn: 0 },
    });
    expect(deriveMobileActionContinuity({ effect_status: 'refused' }).state).toBe('REFUSED');
    expect(deriveMobileActionContinuity({ status: 'denied' }).state).toBe('DENIED');
    expect(deriveMobileActionContinuity({ denied_count: 1 }).state).toBe('DENIED');
    expect(deriveMobileActionContinuity({ status: 'withdrawn' }).state).toBe('WITHDRAWN');
    expect(deriveMobileActionContinuity({ withdrawn_count: 1 }).state).toBe('WITHDRAWN');
    expect(deriveMobileActionContinuity({ status: 'expired' }).state).toBe('EXPIRED');
    expect(deriveMobileActionContinuity({ status: 'cancelled' }).state).toBe('CANCELLED');
  });

  it('rejects unbound passport rows and bounds every optional export field', () => {
    const validRow = {
      action_reference: ACTION_REFERENCE,
      action_caid: `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`,
      action_digest: `sha256:${'a'.repeat(64)}`,
    };
    for (const row of [
      null,
      { ...validRow, action_reference: 'bad' },
      { ...validRow, action_caid: 'caid:bad' },
      { ...validRow, action_digest: 'sha256:bad' },
    ]) {
      expect(() => buildDecisionPassport(row)).toThrow(/CAID-bound mobile action row/i);
    }

    const passport = buildDecisionPassport({
      ...validRow,
      decision_challenge_id: '',
      decision_verdict: 'x'.repeat(65),
      decision_evidence: null,
      decided_at: 42,
      consumption_nonce: '',
      outcome_digest: 'sha256:bad',
      created_at: null,
    }, {
      state: '',
      retry_safe: 'yes',
      quorum: [],
    });
    expect(passport).toMatchObject({
      decision: {
        challenge_id: null,
        verdict: null,
        decided_at: null,
        evidence_digest: null,
      },
      lifecycle: {
        state: 'AWAITING_DECISION',
        retry_safe: false,
        quorum: null,
        consumption_nonce: null,
        outcome_digest: null,
      },
      created_at: null,
    });
    expect(Object.isFrozen(passport)).toBe(true);
  });

  it('requires every provider-outcome field before signing', () => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const identity = buildMobileActionIdentity({ actionReference: ACTION_REFERENCE, action });
    const valid = {
      operationId: 'mobile-operation-42',
      actionCaid: identity.action_caid,
      actionDigest: identity.action_digest,
      consumptionNonce: 'consume-42',
      executorId: 'provider:treasury-production',
      outcome: 'refused',
      observedAt: new Date().toISOString(),
      providerReference: 'provider-effect-42',
      privateKey: pair.privateKey,
    };
    const invalid = [
      ['operationId', ''],
      ['actionCaid', 'caid:bad'],
      ['actionDigest', 'sha256:bad'],
      ['consumptionNonce', ''],
      ['executorId', ''],
      ['outcome', 'pending'],
      ['observedAt', 'x'.repeat(65)],
      ['observedAt', 'not-an-instant'],
      ['providerReference', ''],
      ['privateKey', null],
    ];
    for (const [field, value] of invalid) {
      expect(() => buildMobileProviderOutcome({ ...valid, [field]: value }))
        .toThrow(/complete, CAID-bound provider outcome/i);
    }
    expect(buildMobileProviderOutcome(valid)).toMatchObject({
      outcome: 'refused',
      proof: { algorithm: 'Ed25519' },
    });
  });

  it('rejects each malformed provider-outcome envelope before trust lookup', () => {
    const { evidence, operation } = providerFixture();
    const replaceMember = (target, removed, added) => {
      const copy = structuredClone(target);
      delete copy[removed];
      copy[added] = 'hostile';
      return copy;
    };
    const mutate = (path, value) => {
      const copy = structuredClone(evidence);
      if (path.length === 1) copy[path[0]] = value;
      else copy[path[0]][path[1]] = value;
      return copy;
    };
    const malformed = [
      null,
      [],
      { ...evidence, extra: true },
      replaceMember(evidence, 'provider_reference', 'unexpected'),
      mutate(['@version'], 'EP-MOBILE-PROVIDER-OUTCOME-v2'),
      mutate(['operation_id'], ''),
      mutate(['action_caid'], 'caid:bad'),
      mutate(['action_digest'], 'sha256:bad'),
      mutate(['consumption_nonce'], ''),
      mutate(['executor_id'], ''),
      mutate(['outcome'], 'pending'),
      mutate(['observed_at'], ''),
      mutate(['provider_reference'], ''),
      mutate(['proof'], { ...evidence.proof, extra: true }),
      mutate(['proof'], replaceMember(evidence.proof, 'signature_b64u', 'unexpected')),
      mutate(['proof', 'algorithm'], 'ECDSA'),
      mutate(['proof', 'key_id'], 'ep:executor-key:sha256:bad'),
      mutate(['proof', 'public_key'], '*'),
      mutate(['proof', 'signature_b64u'], '*'),
    ];
    for (const candidate of malformed) {
      expect(verifyMobileProviderOutcome(candidate, {
        expected: operation,
        executorKeys: {},
      })).toMatchObject({ valid: false, reason: 'malformed_provider_outcome' });
    }
  });

  it('rejects invalid clocks, key metadata, algorithms, and signatures', () => {
    const { evidence, operation, pin } = providerFixture();
    const expectedOptions = {
      expected: operation,
      executorKeys: { [pin.executor_id]: pin },
    };
    expect(verifyMobileProviderOutcome(
      { ...evidence, observed_at: 'not-an-instant' },
      expectedOptions,
    )).toMatchObject({ valid: false, reason: 'provider_outcome_time_invalid' });
    expect(verifyMobileProviderOutcome(evidence, {
      ...expectedOptions,
      notBefore: 'not-an-instant',
    })).toMatchObject({ valid: false, reason: 'provider_outcome_time_invalid' });
    expect(verifyMobileProviderOutcome(evidence, {
      ...expectedOptions,
      now: 'not-an-instant',
    })).toMatchObject({ valid: false, reason: 'provider_outcome_time_invalid' });
    expect(verifyMobileProviderOutcome(evidence, {
      ...expectedOptions,
      now: new Date(Date.parse(evidence.observed_at) - 1).toISOString(),
    })).toMatchObject({ valid: false, reason: 'provider_outcome_time_invalid' });
    expect(verifyMobileProviderOutcome(evidence, {
      expected: operation,
      executorKeys: null,
    })).toMatchObject({ valid: false, reason: 'executor_key_not_pinned' });
    expect(verifyMobileProviderOutcome(evidence, {
      expected: operation,
      executorKeys: {
        [pin.executor_id]: { ...pin, key_id: `ep:executor-key:sha256:${'0'.repeat(64)}` },
      },
    })).toMatchObject({ valid: false, reason: 'executor_key_not_pinned' });

    const badSignature = structuredClone(evidence);
    badSignature.proof.signature_b64u = `${
      evidence.proof.signature_b64u[0] === 'A' ? 'B' : 'A'
    }${evidence.proof.signature_b64u.slice(1)}`;
    expect(verifyMobileProviderOutcome(badSignature, expectedOptions))
      .toMatchObject({ valid: false, reason: 'provider_outcome_signature_invalid' });

    const invalidDer = structuredClone(evidence);
    invalidDer.proof.public_key = 'AAAA';
    invalidDer.proof.key_id = _internals.publicKeyId(invalidDer.proof.public_key);
    expect(verifyMobileProviderOutcome(invalidDer, {
      expected: { ...operation, executor_key_id: invalidDer.proof.key_id },
      executorKeys: {
        [pin.executor_id]: {
          executor_id: pin.executor_id,
          key_id: invalidDer.proof.key_id,
          public_key: invalidDer.proof.public_key,
        },
      },
    })).toMatchObject({ valid: false, reason: 'provider_outcome_signature_invalid' });

    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPublicKey = rsa.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const wrongAlgorithm = structuredClone(evidence);
    wrongAlgorithm.proof.public_key = rsaPublicKey;
    wrongAlgorithm.proof.key_id = _internals.publicKeyId(rsaPublicKey);
    expect(verifyMobileProviderOutcome(wrongAlgorithm, {
      expected: { ...operation, executor_key_id: wrongAlgorithm.proof.key_id },
      executorKeys: {
        [pin.executor_id]: {
          executor_id: pin.executor_id,
          key_id: wrongAlgorithm.proof.key_id,
          public_key: rsaPublicKey,
        },
      },
    })).toMatchObject({ valid: false, reason: 'provider_outcome_signature_invalid' });

    const pinWithoutRedundantKeyId = {
      [pin.executor_id]: { public_key: pin.public_key },
    };
    expect(verifyMobileProviderOutcome(evidence, {
      expected: operation,
      executorKeys: pinWithoutRedundantKeyId,
    })).toMatchObject({ valid: true, outcome: 'executed' });

    const missingSignature = structuredClone(evidence);
    missingSignature.proof.signature_b64u = null;
    expect(verifyMobileProviderOutcome(missingSignature, expectedOptions))
      .toMatchObject({ valid: false, reason: 'malformed_provider_outcome' });
  });
});

describe('mobile action-continuity store contracts', () => {
  const presentation = {
    '@version': 'EP-MOBILE-PRESENTATION-v1',
    title: 'Release funds',
    summary: 'Release exact funds.',
    risk: 'high',
    consequence: 'Funds move.',
    material_fields: { amount: '11.00' },
  };

  it('normalizes complete and legacy history rows without upgrading uncertain evidence', async () => {
    const actionCaid = `caid:1:emilia.mobile.authorized-action.1:jcs-sha256:${'A'.repeat(43)}`;
    const actionDigest = `sha256:${'a'.repeat(64)}`;
    const base = {
      action_reference: ACTION_REFERENCE,
      action,
      presentation,
      policy: { policy_id: 'policy-1', required_approvals: 1 },
      policy_id: 'policy-1',
      status: 'approved',
      expires_at: '2099-01-01T00:00:00.000Z',
      created_at: '2026-07-20T00:00:00.000Z',
      group_id: `mag_${'1'.repeat(32)}`,
      revision: 1,
      group_state: 'authorized',
      required_approvals: 1,
      approved_count: 1,
      denied_count: 0,
      withdrawn_count: 0,
    };
    const rows = [
      {
        ...base,
        status: 'pending',
        action_caid: null,
        action_digest: null,
        change_set: null,
        alignments: null,
        events: null,
        operation: null,
      },
      {
        ...base,
        action_caid: actionCaid,
        action_digest: actionDigest,
        change_set: [{ field: 'amount', change: 'changed' }],
        alignments: [],
        events: [{ event_type: 'executed' }],
        operation: {
          status: 'executed',
          consumption_nonce: 'consume-history-1',
          provider_evidence_digest: `sha256:${'b'.repeat(64)}`,
        },
      },
      {
        ...base,
        action_reference: 'mobact_22222222222222222222222222222222',
        action_caid: actionCaid,
        action_digest: actionDigest,
        change_set: [],
        alignments: [],
        events: [],
        operation: {
          status: 'refused',
          consumption_nonce: null,
          provider_evidence_digest: 'sha256:invalid',
        },
      },
      {
        ...base,
        action_reference: 'mobact_33333333333333333333333333333333',
        action_caid: actionCaid,
        action_digest: actionDigest,
        change_set: [],
        alignments: [],
        events: [],
        operation: {},
      },
    ];
    const client = queryClient({
      rpcResult: { data: rows, error: null },
    }).supabase;
    const history = await listMobileActionHistory(client, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
    });
    expect(history).toHaveLength(4);
    expect(history[0]).toMatchObject({
      identity: null,
      changes: [],
      events: [],
      operation: null,
      can_withdraw: false,
      continuity: { state: 'AUTHORIZED' },
    });
    expect(history[0]).not.toHaveProperty('passport');
    expect(history[1]).toMatchObject({
      continuity: { state: 'EXECUTED', retry_safe: false },
      identity: { fingerprint: expect.stringMatching(/^[0-9A-F-]{19}$/) },
      can_withdraw: false,
      passport: {
        lifecycle: {
          consumption_nonce: 'consume-history-1',
          outcome_digest: `sha256:${'b'.repeat(64)}`,
        },
      },
    });
    expect(history[2].continuity.state).toBe('REFUSED');
    expect(history[3]).toMatchObject({
      operation: {},
      continuity: { state: 'AUTHORIZED' },
      can_withdraw: false,
    });
    await expect(listMobileActionHistory({}, {
      entityRef: 'entity-1',
      approverId: 'approver-1',
    })).rejects.toThrow(/Supabase client/);
  });

  it('supersedes from the persisted presentation and returns only computed identity and diff', async () => {
    const rpcResult = { data: { ok: true, group_id: 'group-2', revision: 2 }, error: null };
    const { supabase } = queryClient({
      rows: {
        mobile_actions: {
          data: {
            presentation: {
              ...presentation,
              material_fields: { amount: '10.00', old_code: 'A1' },
            },
          },
          error: null,
        },
      },
      rpcResult,
    });
    const assignments = [{
      action_reference: 'mobact_22222222222222222222222222222222',
      approver_id: 'approver-1',
    }];
    const result = await supersedeMobileAction(supabase, {
      entityRef: 'entity-1',
      currentActionReference: ACTION_REFERENCE,
      assignments,
      initiatorId: 'agent-1',
      action,
      presentation,
      policy: { policy_id: 'policy-1', required_approvals: 1 },
      policyId: 'policy-1',
      expiresAt: '2099-01-01T00:00:00.000Z',
    });
    expect(result).toMatchObject({
      ok: true,
      group_id: 'group-2',
      revision: 2,
      identity: {
        action_caid: expect.stringMatching(/^caid:1:/),
        action_digest: expect.stringMatching(/^sha256:/),
      },
      changes: [
        { field: 'amount', change: 'changed', before: '10.00', after: '11.00' },
        { field: 'old_code', change: 'removed', before: 'A1', after: null },
      ],
    });
    expect(supabase.rpc).toHaveBeenCalledWith('supersede_mobile_action', expect.objectContaining({
      p_current_action_reference: ACTION_REFERENCE,
      p_action_caid: result.identity.action_caid,
      p_action_digest: result.identity.action_digest,
      p_change_set: result.changes,
    }));
  });

  it('fails supersession closed for missing assignments, source rows, database errors, and RPC refusals', async () => {
    await expect(supersedeMobileAction({}, { assignments: [] }))
      .rejects.toThrow(/successor approval assignment/i);

    const base = {
      entityRef: 'entity-1',
      currentActionReference: ACTION_REFERENCE,
      assignments: [{ action_reference: ACTION_REFERENCE, approver_id: 'approver-1' }],
      initiatorId: 'agent-1',
      action,
      presentation,
      policy: { required_approvals: 1 },
      policyId: 'policy-1',
      expiresAt: '2099-01-01T00:00:00.000Z',
    };
    const currentError = queryClient({
      rows: { mobile_actions: { data: null, error: { code: 'P0001' } } },
    }).supabase;
    await expect(supersedeMobileAction(currentError, base))
      .rejects.toThrow(/mobile action supersession failed: P0001/);

    const missing = queryClient({
      rows: { mobile_actions: { data: null, error: null } },
    }).supabase;
    await expect(supersedeMobileAction(missing, base))
      .rejects.toThrow(/not_found/);

    const rpcError = queryClient({
      rows: { mobile_actions: { data: { presentation }, error: null } },
      rpcResult: { data: null, error: {} },
    }).supabase;
    await expect(supersedeMobileAction(rpcError, base))
      .rejects.toThrow(/database operation failed/);

    const refused = queryClient({
      rows: { mobile_actions: { data: { presentation }, error: null } },
      rpcResult: { data: { ok: false }, error: null },
    }).supabase;
    await expect(supersedeMobileAction(refused, base))
      .rejects.toThrow(/refused: unknown/);
  });

  it('preserves atomic transition refusals and surfaces database failures', async () => {
    const calls = [
      {
        name: 'withdraw_mobile_action',
        invoke: (supabase) => withdrawMobileAction(supabase, {
          entityRef: 'entity-1',
          sessionId: 'session-1',
          actionReference: ACTION_REFERENCE,
        }),
      },
      {
        name: 'consume_mobile_action',
        invoke: (supabase) => consumeMobileAction(supabase, {
          entityRef: 'entity-1',
          actionReference: ACTION_REFERENCE,
          operationId: 'operation-42',
          consumptionNonce: 'consume-42',
          executorId: 'provider-1',
        }),
      },
      {
        name: 'mark_mobile_action_indeterminate',
        invoke: (supabase) => markMobileActionIndeterminate(supabase, {
          entityRef: 'entity-1',
          operationId: 'operation-42',
        }),
      },
    ];
    for (const contract of calls) {
      const successful = queryClient({
        rpcResult: { data: { ok: true, state: 'accepted' }, error: null },
      }).supabase;
      await expect(contract.invoke(successful)).resolves.toMatchObject({ ok: true });
      expect(successful.rpc).toHaveBeenCalledWith(contract.name, expect.objectContaining({
        p_entity_ref: 'entity-1',
        p_now: expect.stringMatching(/Z$/),
      }));

      const refused = queryClient({ rpcResult: { data: null, error: null } }).supabase;
      await expect(contract.invoke(refused)).resolves.toEqual({ ok: false, reason: 'unknown' });

      const failed = queryClient({
        rpcResult: { data: null, error: { message: 'database offline' } },
      }).supabase;
      await expect(contract.invoke(failed)).rejects.toThrow(/database offline/);
    }
  });

  it('binds operation lookup to revision and optional action reference', async () => {
    const operation = {
      operation_id: 'operation-42',
      group_id: 'group-1',
      revision: 2,
      action_caid: 'caid:test',
      consumption_nonce: 'consume-42',
      executor_id: 'provider-1',
      executor_key_id: 'key-1',
      status: 'consumed',
      consumed_at: '2026-07-20T20:00:00.000Z',
    };
    const rows = {
      mobile_action_operations: { data: operation, error: null },
      mobile_action_revisions: { data: { action_digest: `sha256:${'a'.repeat(64)}` }, error: null },
      mobile_actions: { data: { action_reference: ACTION_REFERENCE }, error: null },
    };
    const withoutReference = queryClient({ rows }).supabase;
    await expect(resolveMobileOperation(withoutReference, {
      entityRef: 'entity-1',
      operationId: 'operation-42',
    })).resolves.toEqual({ ...operation, action_digest: `sha256:${'a'.repeat(64)}` });
    expect(withoutReference.from).toHaveBeenCalledTimes(2);

    const withReference = queryClient({ rows }).supabase;
    await expect(resolveMobileOperation(withReference, {
      entityRef: 'entity-1',
      operationId: 'operation-42',
      actionReference: ACTION_REFERENCE,
    })).resolves.toEqual({ ...operation, action_digest: `sha256:${'a'.repeat(64)}` });
    expect(withReference.from).toHaveBeenCalledTimes(3);
  });

  it('refuses incomplete operation joins and reports each lookup failure', async () => {
    const baseRows = {
      mobile_action_operations: {
        data: { operation_id: 'operation-42', group_id: 'group-1', revision: 1 },
        error: null,
      },
      mobile_action_revisions: { data: { action_digest: `sha256:${'a'.repeat(64)}` }, error: null },
      mobile_actions: { data: { action_reference: ACTION_REFERENCE }, error: null },
    };
    const cases = [
      {
        rows: { ...baseRows, mobile_action_operations: { data: null, error: { message: 'op failed' } } },
        error: /op failed/,
      },
      {
        rows: { ...baseRows, mobile_action_operations: { data: null, error: null } },
        value: null,
      },
      {
        rows: { ...baseRows, mobile_action_revisions: { data: null, error: { message: 'revision failed' } } },
        error: /revision failed/,
      },
      {
        rows: { ...baseRows, mobile_action_revisions: { data: null, error: null } },
        value: null,
      },
      {
        rows: { ...baseRows, mobile_actions: { data: null, error: { message: 'action failed' } } },
        actionReference: ACTION_REFERENCE,
        error: /action failed/,
      },
      {
        rows: { ...baseRows, mobile_actions: { data: null, error: null } },
        actionReference: ACTION_REFERENCE,
        value: null,
      },
    ];
    for (const testCase of cases) {
      const { supabase } = queryClient({ rows: testCase.rows });
      const result = resolveMobileOperation(supabase, {
        entityRef: 'entity-1',
        operationId: 'operation-42',
        actionReference: testCase.actionReference,
      });
      if (testCase.error) await expect(result).rejects.toThrow(testCase.error);
      else await expect(result).resolves.toBe(testCase.value);
    }
  });

  it('resolves only active executor pins and preserves null lookups', async () => {
    const pin = { executor_id: 'provider-1', key_id: 'key-1', public_key: 'AAAA' };
    const found = queryClient({
      rows: { mobile_executor_keys: { data: pin, error: null } },
    }).supabase;
    await expect(resolveMobileExecutorKey(found, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
      executorKeyId: 'key-1',
    })).resolves.toEqual(pin);
    expect(found.from).toHaveBeenCalledWith('mobile_executor_keys');

    const missing = queryClient({
      rows: { mobile_executor_keys: { data: null, error: null } },
    }).supabase;
    await expect(resolveMobileExecutorKey(missing, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
    })).resolves.toBeNull();

    const failed = queryClient({
      rows: { mobile_executor_keys: { data: null, error: { message: 'lookup failed' } } },
    }).supabase;
    await expect(resolveMobileExecutorKey(failed, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
    })).rejects.toThrow(/lookup failed/);
  });

  it('reconciles only an exact signed provider outcome and preserves terminal refusals', async () => {
    const { evidence, operation, pin } = providerFixture();
    const successful = queryClient({
      rows: { mobile_executor_keys: { data: pin, error: null } },
      rpcResult: { data: { ok: true, state: 'executed' }, error: null },
    }).supabase;
    await expect(reconcileMobileActionOperation(successful, {
      entityRef: 'entity-1',
      operation,
      evidence,
    })).resolves.toEqual({ ok: true, state: 'executed' });
    expect(successful.rpc).toHaveBeenCalledWith(
      'reconcile_mobile_action_operation',
      expect.objectContaining({
        p_operation_id: operation.operation_id,
        p_executor_id: operation.executor_id,
        p_executor_key_id: operation.executor_key_id,
        p_outcome: 'executed',
        p_provider_reference: evidence.provider_reference,
        p_evidence_digest: expect.stringMatching(/^sha256:/),
        p_provider_evidence: evidence,
      }),
    );

    const noPin = queryClient({
      rows: { mobile_executor_keys: { data: null, error: null } },
    }).supabase;
    await expect(reconcileMobileActionOperation(noPin, {
      entityRef: 'entity-1',
      operation,
      evidence,
    })).resolves.toEqual({ ok: false, reason: 'executor_key_not_pinned' });
    expect(noPin.rpc).not.toHaveBeenCalled();

    const failed = queryClient({
      rows: { mobile_executor_keys: { data: pin, error: null } },
      rpcResult: { data: null, error: { message: 'reconcile failed' } },
    }).supabase;
    await expect(reconcileMobileActionOperation(failed, {
      entityRef: 'entity-1',
      operation,
      evidence,
    })).rejects.toThrow(/reconcile failed/);

    const refused = queryClient({
      rows: { mobile_executor_keys: { data: pin, error: null } },
      rpcResult: { data: null, error: null },
    }).supabase;
    await expect(reconcileMobileActionOperation(refused, {
      entityRef: 'entity-1',
      operation,
      evidence,
    })).resolves.toEqual({ ok: false, reason: 'unknown' });
  });

  it('registers executor pins and records only normalized alignments', async () => {
    const registered = queryClient({ rpcResult: { data: true, error: null } }).supabase;
    await expect(registerMobileExecutorKey(registered, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
      keyId: 'key-1',
      publicKey: 'AAAA',
    })).resolves.toBe(true);
    const refusedKey = queryClient({ rpcResult: { data: false, error: null } }).supabase;
    await expect(registerMobileExecutorKey(refusedKey, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
      keyId: 'key-1',
      publicKey: 'AAAA',
    })).resolves.toBe(false);
    const failedKey = queryClient({
      rpcResult: { data: null, error: { message: 'key insert failed' } },
    }).supabase;
    await expect(registerMobileExecutorKey(failedKey, {
      entityRef: 'entity-1',
      executorId: 'provider-1',
      keyId: 'key-1',
      publicKey: 'AAAA',
    })).rejects.toThrow(/key insert failed/);

    await expect(recordMobileActionAlignment({}, {
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      alignment: null,
    })).rejects.toThrow(/alignment is malformed/);
    const recorded = queryClient({ rpcResult: { data: true, error: null } }).supabase;
    await expect(recordMobileActionAlignment(recorded, {
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      alignment: {
        system: 'AgentROA',
        verdict: 'EQUIVALENT_UNDER_PROFILE',
        profile_id: 'ep:map:agentroa:v1',
        profile_hash: `sha256:${'a'.repeat(64)}`,
        native_verified: true,
        evidence_digest: `sha256:${'b'.repeat(64)}`,
      },
    })).resolves.toBe(true);
    expect(recorded.rpc).toHaveBeenCalledWith('record_mobile_action_alignment', expect.objectContaining({
      p_verdict: 'EQUIVALENT_UNDER_PROFILE',
      p_native_verified: true,
    }));
    const refused = queryClient({ rpcResult: { data: false, error: null } }).supabase;
    await expect(recordMobileActionAlignment(refused, {
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      alignment: { system: 'Unknown', verdict: 'INDETERMINATE' },
    })).resolves.toBe(false);
    const failed = queryClient({
      rpcResult: { data: null, error: { message: 'alignment failed' } },
    }).supabase;
    await expect(recordMobileActionAlignment(failed, {
      entityRef: 'entity-1',
      actionReference: ACTION_REFERENCE,
      alignment: { system: 'Unknown', verdict: 'INDETERMINATE' },
    })).rejects.toThrow(/alignment failed/);
  });
});
