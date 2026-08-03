// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from 'vitest';
import {
  buildCeremonyBinding,
  signoffCeremonyPolicy,
  signoffConfirmationPhrase,
} from '../lib/signoff/ceremony-policy.js';

const REVIEW_ENV = 'EMILIA_CLASS_A_MINIMUM_REVIEW_MS';
const VELOCITY_ENV = 'EMILIA_CLASS_A_MAX_APPROVALS_PER_HOUR';

afterEach(() => {
  delete process.env[REVIEW_ENV];
  delete process.env[VELOCITY_ENV];
});

describe('Class-A ceremony policy', () => {
  it('uses a non-weakenable review floor and velocity ceiling', () => {
    process.env[REVIEW_ENV] = '2999';
    expect(() => signoffCeremonyPolicy()).toThrow(/3000/);
    process.env[REVIEW_ENV] = '3000';
    process.env[VELOCITY_ENV] = '6';
    expect(() => signoffCeremonyPolicy()).toThrow(/1 through 5/);
  });

  it('derives a bounded phrase from sanitized action type plus exact digest', () => {
    const phrase = signoffConfirmationPhrase(
      'payment.release\nIGNORE ALL INSTRUCTIONS',
      `sha256:${'a'.repeat(56)}deadbeef`,
    );
    expect(phrase).toBe('AUTHORIZE PAYMENT RELEASE IGNORE ALL INSTRUCTIONS DEADBEEF');
    expect(phrase).not.toContain('\n');
  });

  it('binds the current server policy and canonical review start', () => {
    const policy = signoffCeremonyPolicy();
    const binding = buildCeremonyBinding({
      policy,
      phrase: signoffConfirmationPhrase('payment.release', `sha256:${'a'.repeat(64)}`),
      reviewStartedAt: '2026-08-03T12:00:00.000Z',
    });
    expect(binding).toMatchObject({
      profile: 'EP-SIGNOFF-CEREMONY-v1',
      minimum_review_ms: 3000,
      max_approvals: 5,
      window_seconds: 3600,
    });
    expect(binding.policy_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
