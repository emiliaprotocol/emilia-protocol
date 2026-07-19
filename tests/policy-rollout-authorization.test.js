// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import { hashCanonicalAction } from '../lib/guard-policies.js';
import {
  buildPolicyRolloutAfterState,
  buildPolicyRolloutBeforeState,
  buildPolicyRolloutQuorumPolicy,
  buildPolicyRolloutReceiptRequest,
  verifyPolicyRolloutAuthorization,
  verifyPolicyRolloutEvidenceShape,
} from '../lib/cloud/policy-rollout-authorization.js';

const NOW = Date.parse('2026-07-19T20:00:00.000Z');
const receiptId = `tr_${'a'.repeat(32)}`;
const policyId = '11111111-1111-4111-8111-111111111111';
const tenantId = '33333333-3333-4333-8333-333333333333';
const rules = { threshold: 0.9, deny: ['compromised'] };
const beforeState = buildPolicyRolloutBeforeState([]);
const afterState = buildPolicyRolloutAfterState({
  policyId,
  policyKey: 'strict',
  version: 2,
  policyRules: rules,
  policyMode: 'mutual',
  policyStatus: 'active',
  environment: 'production',
  strategy: 'immediate',
  metadata: { ticket: 'CAB-42' },
});
const request = buildPolicyRolloutReceiptRequest({
  tenantId,
  executingKeyId: 'key-abc123',
  policyId,
  policyKey: 'strict',
  version: 2,
  policyRules: rules,
  policyMode: 'mutual',
  policyStatus: 'active',
  environment: 'production',
  strategy: 'immediate',
  metadata: { ticket: 'CAB-42' },
  beforeState,
  afterState,
});
const canonicalAction = {
  organization_id: tenantId,
  actor_id: 'initiator-1',
  action_type: 'policy_rollout',
  target_resource_id: 'policy:strict',
  policy_id: 'policy_default_policy_rollout',
  policy_hash: 'c'.repeat(64),
  before_state_hash: hashCanonicalAction(beforeState),
  after_state_hash: hashCanonicalAction(afterState),
  authority: { verdict: 'authorized' },
  nonce: 'nonce_1',
  expires_at: '2026-07-19T20:15:00.000Z',
  requested_at: '2026-07-19T20:00:00.000Z',
  executing_key_id: request.executing_key_id,
  rollout_policy_id: request.rollout_policy_id,
  rollout_policy_key: request.rollout_policy_key,
  rollout_policy_version: request.rollout_policy_version,
  rollout_policy_rules: request.rollout_policy_rules,
  rollout_policy_mode: request.rollout_policy_mode,
  rollout_policy_status: request.rollout_policy_status,
  rollout_environment: request.rollout_environment,
  rollout_strategy: request.rollout_strategy,
  rollout_canary_pct: request.rollout_canary_pct,
  rollout_metadata: request.rollout_metadata,
  rollout_before_state: request.before_state,
  rollout_after_state: request.after_state,
};
const actionHash = hashCanonicalAction(canonicalAction);

function validEvents() {
  return [
    {
      event_type: 'guard.trust_receipt.created',
      actor_id: 'ep:cloud-key:key-abc123',
      after_state: {
        organization_id: tenantId,
        action_type: 'policy_rollout',
        target_resource_id: 'policy:strict',
        decision: 'allow_with_signoff',
        signoff_required: true,
        required_assurance: 'A',
        quorum_policy: null,
        expires_at: '2026-07-19T20:15:00.000Z',
        action_hash: actionHash,
        before_state_hash: hashCanonicalAction(beforeState),
        after_state_hash: hashCanonicalAction(afterState),
        canonical_action: structuredClone(canonicalAction),
      },
    },
    {
      event_type: 'guard.signoff.requested',
      actor_id: 'ep:cloud-key:key-abc123',
      after_state: {
        signoff_id: 'sig_1',
        approver_id: 'approver-1',
        action_hash: actionHash,
      },
    },
    {
      event_type: 'guard.signoff.approved',
      actor_id: 'approver-1',
      after_state: {
        signoff_id: 'sig_1',
        approver_id: 'approver-1',
        role: 'policy_admin',
        key_class: 'A',
        context: { action_hash: actionHash },
        webauthn: { credential_id: 'cred-1' },
      },
    },
  ];
}

function expected(overrides = {}) {
  return {
    tenantId,
    executingKeyId: 'key-abc123',
    policyId,
    policyKey: 'strict',
    version: 2,
    policyRules: rules,
    policyMode: 'mutual',
    policyStatus: 'active',
    environment: 'production',
    strategy: 'immediate',
    canaryPct: undefined,
    metadata: { ticket: 'CAB-42' },
    beforeState,
    afterState,
    receiptId,
    now: NOW,
    ...overrides,
  };
}

function credentialClient(overrides = {}) {
  return {
    from(table) {
      expect(table).toBe('approver_credentials');
      const builder = {
        select: () => builder,
        eq: () => builder,
        is: () => builder,
        limit: () => Promise.resolve({
          data: [{
            credential_id: 'cred-1',
            approver_id: 'approver-1',
            public_key_spki: 'spki',
            key_class: 'A',
            valid_from: '2026-01-01T00:00:00.000Z',
            valid_to: '2027-01-01T00:00:00.000Z',
            revoked_at: null,
            ...overrides,
          }],
          error: null,
        }),
      };
      return builder;
    },
  };
}

function quorumCredentialClient(rows) {
  return {
    from(table) {
      expect(table).toBe('approver_credentials');
      const builder = {
        select: () => builder,
        eq: () => builder,
        in: () => Promise.resolve({ data: rows, error: null }),
      };
      return builder;
    },
  };
}

describe('policy rollout Accountable Signoff evidence', () => {
  it('materializes only a concrete org-pinned mandatory quorum', () => {
    const result = buildPolicyRolloutQuorumPolicy({
      quorum_required: true,
      min_required: 2,
      max_window_sec: 600,
      require_distinct_humans: true,
      allowed_modes: ['threshold'],
      allowed_approvers: [
        { role: 'change_control', approver: 'approver-1' },
        { role: 'security', approver: 'approver-2' },
      ],
    });
    expect(result.policy).toEqual({
      mode: 'threshold',
      required: 2,
      window_sec: 600,
      distinct_humans: true,
      approvers: [
        { role: 'change_control', approver: 'approver-1' },
        { role: 'security', approver: 'approver-2' },
      ],
    });
    expect(buildPolicyRolloutQuorumPolicy({
      quorum_required: true,
      min_required: 2,
      allowed_approvers: null,
    })).toMatchObject({ ok: false, code: 'policy_rollout_quorum_roster_required' });
    expect(buildPolicyRolloutQuorumPolicy({
      quorum_required: true,
      min_required: 2,
      require_distinct_humans: false,
      allowed_modes: ['threshold'],
      allowed_approvers: [
        { role: 'change_control', approver: 'approver-1' },
        { role: 'security', approver: 'approver-2' },
      ],
    }).policy.distinct_humans).toBe(true);
  });

  it('uses a real canonical action hash and accepts exact, pending Class-A evidence', () => {
    const result = verifyPolicyRolloutEvidenceShape(validEvents(), expected());
    expect(result.ok).toBe(true);
    expect(result.actionHash).toBe(hashCanonicalAction(result.action));
  });

  it('requires creator continuity with the executing tenant rollout key', () => {
    const events = validEvents();
    events[0].actor_id = 'initiator-1';
    expect(verifyPolicyRolloutEvidenceShape(events, expected())).toMatchObject({
      ok: false,
      code: 'rollout_authorization_creator_mismatch',
    });
  });

  it.each([
    ['tenant', (value) => ({ tenantId: `${value}x` }), 'tenant_mismatch'],
    ['executing key', (value) => ({ executingKeyId: `${value}x` }), 'creator_mismatch'],
    ['policy ID', (value) => ({ policyId: `${value}x` }), 'action_mismatch'],
    ['policy key', (value) => ({ policyKey: `${value}x` }), 'target_mismatch'],
    ['version', (value) => ({ version: value + 1 }), 'action_mismatch'],
    ['rules', () => ({ policyRules: { threshold: 0.1 } }), 'action_mismatch'],
    ['mode', () => ({ policyMode: 'one_sided' }), 'action_mismatch'],
    ['status', () => ({ policyStatus: 'deprecated' }), 'action_mismatch'],
    ['environment', (value) => ({ environment: `${value}x` }), 'action_mismatch'],
    ['strategy', () => ({ strategy: 'canary', canaryPct: 10 }), 'action_mismatch'],
    ['metadata', () => ({ metadata: { ticket: 'CAB-99' } }), 'action_mismatch'],
    ['before state', () => ({ beforeState: { active_rollouts: [{ rollout_id: 'other' }] } }), 'stale'],
  ])('refuses %s substitution', (_name, change, codeSuffix) => {
    const base = expected();
    const key = _name === 'tenant' ? base.tenantId
      : _name === 'executing key' ? base.executingKeyId
        : _name === 'policy ID' ? base.policyId
          : _name === 'policy key' ? base.policyKey
            : _name === 'version' ? base.version
              : _name === 'environment' ? base.environment
                : null;
    const result = verifyPolicyRolloutEvidenceShape(validEvents(), {
      ...base,
      ...change(key),
    });
    expect(result.ok).toBe(false);
    expect(result.code).toContain(codeSuffix);
  });

  it('refuses expiry, prior consumption, rejection, and non-Class-A approval', () => {
    expect(verifyPolicyRolloutEvidenceShape(validEvents(), expected({ now: NOW + 16 * 60 * 1000 })))
      .toMatchObject({ ok: false, code: 'rollout_authorization_expired' });

    const consumed = validEvents();
    consumed.push({ event_type: 'guard.trust_receipt.consumed', actor_id: 'key:x', after_state: {} });
    expect(verifyPolicyRolloutEvidenceShape(consumed, expected()))
      .toMatchObject({ ok: false, code: 'rollout_authorization_replayed' });

    const rejected = validEvents();
    rejected.push({
      event_type: 'guard.signoff.rejected',
      actor_id: 'approver-1',
      after_state: { signoff_id: 'sig_1', approver_id: 'approver-1' },
    });
    expect(verifyPolicyRolloutEvidenceShape(rejected, expected()))
      .toMatchObject({ ok: false, code: 'signoff_rejected' });

    const weak = validEvents();
    weak[2].after_state.key_class = 'C';
    expect(verifyPolicyRolloutEvidenceShape(weak, expected()))
      .toMatchObject({ ok: false, code: 'rollout_authorization_assurance_insufficient' });
  });

  it('re-verifies WebAuthn UV and explicit policy-rollout authority immediately before RPC', async () => {
    const derive = vi.fn(() => ({ verified: true, reason: 'user_verified' }));
    const resolve = vi.fn(async () => ({
      authorized: true,
      reason: 'ok',
      authority_id: 'auth-1',
      assurance_class: 'A',
      role: 'policy_admin',
    }));

    const result = await verifyPolicyRolloutAuthorization({
      supabase: credentialClient(),
      events: validEvents(),
      expected: expected(),
      dependencies: {
        deriveSignoffUserVerification: derive,
        resolveGuardAuthority: resolve,
        getRpConfig: () => ({ rpID: 'example.test', origin: 'https://example.test' }),
      },
    });

    expect(result.ok).toBe(true);
    expect(derive).toHaveBeenCalledWith(expect.objectContaining({
      approverPublicKeySpki: 'spki',
      expectedActionHash: actionHash,
    }));
    expect(resolve).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      actionType: 'policy_rollout',
      requireExplicitScope: true,
      allowedRoles: ['policy_admin', 'control_plane_approver'],
    }));
    expect(result.authority).toMatchObject({
      action_scope: 'policy_rollout',
      role: 'policy_admin',
      user_verification: 'verified',
    });
  });

  it('re-verifies every quorum credential, signature, and scoped authority', async () => {
    const quorumPolicy = {
      mode: 'threshold',
      required: 2,
      distinct_humans: true,
      window_sec: 600,
      approvers: [
        { role: 'change_control', approver: 'approver-1' },
        { role: 'security', approver: 'approver-2' },
      ],
    };
    const events = validEvents();
    events[0].after_state.quorum_policy = quorumPolicy;
    events[1].after_state.quorum = {
      role: 'change_control',
      approver_id: 'approver-1',
      mode: 'threshold',
      required: 2,
    };
    delete events[1].after_state.approver_id;
    events[2].after_state.context = {
      action_hash: actionHash,
      approver: 'approver-1',
      issued_at: '2026-07-19T20:01:00.000Z',
    };
    events.push(
      {
        event_type: 'guard.signoff.requested',
        actor_id: 'ep:cloud-key:key-abc123',
        after_state: {
          signoff_id: 'sig_2',
          action_hash: actionHash,
          quorum: {
            role: 'security',
            approver_id: 'approver-2',
            mode: 'threshold',
            required: 2,
          },
        },
      },
      {
        event_type: 'guard.signoff.approved',
        actor_id: 'approver-2',
        after_state: {
          signoff_id: 'sig_2',
          approver_id: 'approver-2',
          key_class: 'A',
          context: {
            action_hash: actionHash,
            approver: 'approver-2',
            issued_at: '2026-07-19T20:02:00.000Z',
          },
          webauthn: { credential_id: 'cred-2' },
        },
      },
    );
    const resolve = vi.fn(async (_client, { approverId }) => ({
      authorized: true,
      reason: 'ok',
      authority_id: approverId === 'approver-1' ? 'auth-1' : 'auth-2',
      assurance_class: 'A',
      role: 'policy_admin',
    }));
    const gate = vi.fn(() => ({ satisfied: true, checks: {} }));

    const result = await verifyPolicyRolloutAuthorization({
      supabase: quorumCredentialClient([
        {
          credential_id: 'cred-1',
          approver_id: 'approver-1',
          public_key_spki: 'spki-1',
          key_class: 'A',
          valid_from: '2026-01-01T00:00:00.000Z',
          valid_to: '2027-01-01T00:00:00.000Z',
          revoked_at: null,
        },
        {
          credential_id: 'cred-2',
          approver_id: 'approver-2',
          public_key_spki: 'spki-2',
          key_class: 'A',
          valid_from: '2026-01-01T00:00:00.000Z',
          valid_to: '2027-01-01T00:00:00.000Z',
          revoked_at: null,
        },
      ]),
      events,
      expected: expected({ quorumPolicy }),
      dependencies: {
        quorumGate: gate,
        resolveGuardAuthority: resolve,
        getRpConfig: () => ({ rpID: 'example.test', origin: 'https://example.test' }),
      },
    });

    expect(result.ok).toBe(true);
    expect(gate).toHaveBeenCalledOnce();
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(result.authorityIds).toEqual(['auth-1', 'auth-2']);
    expect(result.authority).toMatchObject({ quorum: true });
  });

  it('fails closed when UV or scoped authority cannot be re-verified', async () => {
    const uvFailure = await verifyPolicyRolloutAuthorization({
      supabase: credentialClient(),
      events: validEvents(),
      expected: expected(),
      dependencies: {
        deriveSignoffUserVerification: () => ({ verified: false, reason: 'assertion_invalid' }),
        getRpConfig: () => ({ rpID: 'example.test', origin: 'https://example.test' }),
      },
    });
    expect(uvFailure).toMatchObject({
      ok: false,
      code: 'rollout_authorization_assurance_insufficient',
    });

    const authorityFailure = await verifyPolicyRolloutAuthorization({
      supabase: credentialClient(),
      events: validEvents(),
      expected: expected(),
      dependencies: {
        deriveSignoffUserVerification: () => ({ verified: true, reason: 'user_verified' }),
        resolveGuardAuthority: async () => ({ authorized: false, reason: 'wrong_scope' }),
        getRpConfig: () => ({ rpID: 'example.test', origin: 'https://example.test' }),
      },
    });
    expect(authorityFailure).toMatchObject({ ok: false, code: 'authority_invalid' });
  });

  it.each([
    ['wrong owner', { approver_id: 'approver-2' }],
    ['wrong class', { key_class: 'C' }],
    ['not yet valid', { valid_from: '2026-08-01T00:00:00.000Z' }],
    ['expired', { valid_to: '2026-07-01T00:00:00.000Z' }],
  ])('fails closed when the credential is %s', async (_name, credential) => {
    const result = await verifyPolicyRolloutAuthorization({
      supabase: credentialClient(credential),
      events: validEvents(),
      expected: expected(),
      dependencies: {
        deriveSignoffUserVerification: () => ({ verified: true }),
        resolveGuardAuthority: async () => ({
          authorized: true,
          authority_id: 'auth-1',
          assurance_class: 'A',
          role: 'policy_admin',
          reason: 'ok',
        }),
        getRpConfig: () => ({ rpID: 'example.test', origin: 'https://example.test' }),
      },
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'rollout_authorization_assurance_insufficient',
    });
  });
});
