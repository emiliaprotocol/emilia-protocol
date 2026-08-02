// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import {
  ARENA_ALLOWANCE_VERSION,
  ARENA_CLAIM_BOUNDARY,
  buildArenaRefusalInput,
  createArenaAllowance,
  deriveArenaActionBinding,
  evaluateArenaAttempt,
} from './core';

const NOW = Date.parse('2026-08-02T12:00:00.000Z');

function allowance() {
  return createArenaAllowance({
    sessionId: 'arena-session-001',
    agentName: 'Night Shift',
    totalAmount: 1_000,
    maxAmountPerAction: 250,
    allowedTargets: ['compute.batch', 'vendor.demo'],
    issuedAt: '2026-08-02T11:59:00.000Z',
    expiresAt: '2026-08-03T11:59:00.000Z',
  });
}

function action(overrides: Record<string, unknown> = {}) {
  return {
    operation_id: 'operation-001',
    action_type: 'arena.resource.allocate.1',
    target: 'vendor.demo',
    amount: 80,
    currency: 'CREDITS',
    purpose: 'synthetic-vendor-payment',
    ...overrides,
  };
}

describe('EMILIA Arena allowance profile', () => {
  it('creates one closed, time-bounded synthetic allowance', () => {
    const profile = allowance();
    expect(profile['@version']).toBe(ARENA_ALLOWANCE_VERSION);
    expect(profile.claim_boundary).toBe(ARENA_CLAIM_BOUNDARY);
    expect(profile.allowed_targets).toEqual(['compute.batch', 'vendor.demo']);
    expect(Object.isFrozen(profile)).toBe(true);
  });

  it('allows an in-envelope action and decrements the synthetic balance', () => {
    expect(evaluateArenaAttempt({
      allowance: allowance(),
      action: action(),
      remainingAmount: 1_000,
      operationSeen: false,
      now: NOW,
    })).toEqual({
      decision: 'allow',
      reason: null,
      remaining_amount: 920,
    });
  });

  it.each([
    [{ amount: 251 }, 1_000, false, 'allowance_per_action_limit_exceeded'],
    [{ amount: 80 }, 60, false, 'allowance_aggregate_limit_exceeded'],
    [{ target: 'production.database' }, 1_000, false, 'allowance_target_not_allowed'],
    [{ currency: 'USD' }, 1_000, false, 'allowance_currency_mismatch'],
    [{}, 1_000, true, 'allowance_operation_replay'],
  ])('refuses a hostile or out-of-envelope attempt', (overrides, remaining, operationSeen, reason) => {
    expect(evaluateArenaAttempt({
      allowance: allowance(),
      action: action(overrides),
      remainingAmount: remaining,
      operationSeen,
      now: NOW,
    })).toMatchObject({ decision: 'refuse', reason, remaining_amount: remaining });
  });

  it('fails closed after expiry and on malformed action objects', () => {
    expect(evaluateArenaAttempt({
      allowance: allowance(), action: action(), remainingAmount: 1_000,
      operationSeen: false, now: Date.parse('2026-08-04T00:00:00.000Z'),
    }).reason).toBe('allowance_expired');
    expect(evaluateArenaAttempt({
      allowance: allowance(), action: { ...action(), hidden: true }, remainingAmount: 1_000,
      operationSeen: false, now: NOW,
    }).reason).toBe('allowance_action_shape_invalid');
  });

  it('derives a stable CAID and exact-action digest from the same canonical bytes', () => {
    const first = deriveArenaActionBinding(action());
    const second = deriveArenaActionBinding({ ...action() });
    expect(first).toEqual(second);
    expect(first.caid).toMatch(/^caid:1:arena\.resource\.allocate\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
    expect(first.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('maps an allowance refusal into the standard exact-action refusal input', () => {
    const profile = allowance();
    const candidate = action({ amount: 900 });
    const binding = deriveArenaActionBinding(candidate);
    const refusal = buildArenaRefusalInput({
      allowance: profile,
      action: candidate,
      binding,
      reason: 'allowance_per_action_limit_exceeded',
      refusalId: 'arena-refusal-001',
      relyingPartyId: 'arena:emilia:public',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      refusedAt: '2026-08-02T12:00:00.000Z',
      expiresAt: '2026-08-09T12:00:00.000Z',
    });
    expect(refusal.caid).toBe(binding.caid);
    expect(refusal.action_digest).toBe(binding.action_digest);
    expect(refusal.failed_requirement_ids).toEqual(['allowance-per-action-limit']);
    expect(refusal.refusal_class).toBe('authorization_refused');
    expect(refusal.claim_boundary).toBe('technical_refusal_not_legal_or_benefit_determination');
  });
});
