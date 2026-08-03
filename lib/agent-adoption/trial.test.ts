// SPDX-License-Identifier: Apache-2.0
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  provision: vi.fn(),
  submit: vi.fn(),
}));

vi.mock('@/lib/arena/service', () => ({
  provisionArenaSession: mocks.provision,
  submitArenaAttempt: mocks.submit,
}));

const { provisionBoundAgentTrial, submitBoundAgentTrial, AgentAdoptionTrialError } =
  await import('./trial');

const NOW = Date.parse('2026-08-02T17:00:00.000Z');
const ADOPTION_ID = '00000000-0000-4000-8000-000000000001';
const BOND_ID = '00000000-0000-4000-8000-000000000002';
const BOND_DIGEST = `sha256:${'a'.repeat(64)}`;

function authorization() {
  return {
    sessionId: ADOPTION_ID,
    sessionToken: `eaa1_${'b'.repeat(64)}`,
    session: {
      adoption_id: ADOPTION_ID,
      agent_label: 'Atlas',
      status: 'active',
      bond_count: 1,
      latest_bond_id: BOND_ID,
      latest_bond_digest: BOND_DIGEST,
      bond_digest: BOND_DIGEST,
      operating_bond: {
        candidate: {
          label: 'Atlas',
          source_kind: 'local',
          job_template_id: 'job_document_route_v1',
          allowance_template_id: 'allowance_cautious_v1',
        },
        allowance: { total: 200, max_per_action: 40 },
        constraints: { allowed_targets: ['documents.demo'] },
      },
    },
  } as any;
}

describe('Agent Adoption no-egress trial adapter', () => {
  beforeEach(() => vi.resetAllMocks());

  it('provisions an Arena profile from the exact asserted bond and hides the Arena token', async () => {
    mocks.provision.mockResolvedValue({
      session_id: `arena_session_${'1'.repeat(32)}`,
      token: `ep_arena_${'2'.repeat(64)}`,
      allowance: { expires_at: '2026-08-03T17:00:00.000Z' },
    });
    const result = await provisionBoundAgentTrial({ authorization: authorization(), now: NOW });
    expect(mocks.provision).toHaveBeenCalledWith(expect.objectContaining({
      agentName: 'Atlas',
      profile: {
        totalAmount: 200,
        maxAmountPerAction: 40,
        allowedTargets: ['documents.demo'],
      },
    }));
    expect(result.trial_token).toMatch(/^epenc:v1:/);
    expect(JSON.stringify(result)).not.toContain('ep_arena_');
    expect(JSON.stringify(result)).not.toContain('arena_session_');
  });

  it('rejects a trial token replayed under another adoption or bond', async () => {
    mocks.provision.mockResolvedValue({
      session_id: `arena_session_${'1'.repeat(32)}`,
      token: `ep_arena_${'2'.repeat(64)}`,
      allowance: { expires_at: '2026-08-03T17:00:00.000Z' },
    });
    const trial = await provisionBoundAgentTrial({ authorization: authorization(), now: NOW });
    const other = authorization();
    other.sessionId = '00000000-0000-4000-8000-000000000009';
    other.session.adoption_id = other.sessionId;
    await expect(submitBoundAgentTrial({
      authorization: other,
      input: { attempt_template_id: 'attempt_in_bounds_v1', trial_token: trial.trial_token },
      now: NOW,
    })).rejects.toBeInstanceOf(AgentAdoptionTrialError);
    expect(mocks.submit).not.toHaveBeenCalled();
  });

  it('maps only a fixed template into the Arena request and never accepts a caller verdict', async () => {
    mocks.provision.mockResolvedValue({
      session_id: `arena_session_${'1'.repeat(32)}`,
      token: `ep_arena_${'2'.repeat(64)}`,
      allowance: { expires_at: '2026-08-03T17:00:00.000Z' },
    });
    mocks.submit.mockResolvedValue({
      attempt_id: `arena_attempt_${'3'.repeat(32)}`,
      decision: 'refuse',
      reason: 'allowance_per_action_limit_exceeded',
      action: { target: 'documents.demo', amount: 900 },
      action_digest: `sha256:${'4'.repeat(64)}`,
      refusal_digest: `sha256:${'5'.repeat(64)}`,
    });
    const trial = await provisionBoundAgentTrial({ authorization: authorization(), now: NOW });
    const result = await submitBoundAgentTrial({
      authorization: authorization(),
      input: { attempt_template_id: 'attempt_over_limit_v1', trial_token: trial.trial_token },
      now: NOW,
    });
    expect(result).toMatchObject({
      decision: 'refuse',
      reason_code: 'per_action_limit_exceeded',
      synthetic_credits: 900,
    });
    const called = mocks.submit.mock.calls[0][0];
    expect(called.input).toMatchObject({
      target: 'documents.demo',
      amount: 900,
      purpose: 'synthetic-adoption-over-limit',
    });
    expect(called.input).not.toHaveProperty('decision');
  });

  it('fails closed on extra attempt fields and unknown Arena reasons', async () => {
    mocks.provision.mockResolvedValue({
      session_id: `arena_session_${'1'.repeat(32)}`,
      token: `ep_arena_${'2'.repeat(64)}`,
      allowance: { expires_at: '2026-08-03T17:00:00.000Z' },
    });
    const trial = await provisionBoundAgentTrial({ authorization: authorization(), now: NOW });
    await expect(submitBoundAgentTrial({
      authorization: authorization(),
      input: {
        attempt_template_id: 'attempt_in_bounds_v1',
        trial_token: trial.trial_token,
        decision: 'permit',
      },
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_adoption_attempt_invalid' });
    mocks.submit.mockResolvedValue({
      attempt_id: `arena_attempt_${'3'.repeat(32)}`,
      decision: 'refuse', reason: 'new_unknown_reason',
      action: { target: 'documents.demo', amount: 30 },
      action_digest: `sha256:${'4'.repeat(64)}`,
      refusal_digest: `sha256:${'5'.repeat(64)}`,
    });
    await expect(submitBoundAgentTrial({
      authorization: authorization(),
      input: { attempt_template_id: 'attempt_in_bounds_v1', trial_token: trial.trial_token },
      now: NOW,
    })).rejects.toMatchObject({ code: 'agent_adoption_trial_decision_invalid' });
  });
});
