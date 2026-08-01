// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  issueTrustDeskSession,
  authenticateTrustDeskReviewer,
  verifyTrustDeskSession,
} from '../lib/trust-desk/auth.js';

describe('Trust Desk bootstrap/session boundary', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('exchanges the URL bootstrap token for a distinct session envelope', () => {
    vi.stubEnv('TRUST_DESK_INTERNAL_TOKEN', 'bootstrap-secret-that-never-enters-cookies');
    vi.stubEnv('TRUST_DESK_REVIEWER_ID', 'Iman Schrock <team@emiliaprotocol.ai>');
    const session = issueTrustDeskSession();
    expect(session).toBeTruthy();
    expect(session).not.toContain('bootstrap-secret-that-never-enters-cookies');
    expect(verifyTrustDeskSession(session)).toBe(true);
    expect(authenticateTrustDeskReviewer(session)?.reviewerId).toBe('Iman Schrock <team@emiliaprotocol.ai>');
  });

  it('rejects tampered, malformed, and old sessions', () => {
    vi.stubEnv('TRUST_DESK_INTERNAL_TOKEN', 'bootstrap-secret');
    vi.stubEnv('TRUST_DESK_REVIEWER_ID', 'Iman Schrock <team@emiliaprotocol.ai>');
    const session = issueTrustDeskSession();
    expect(verifyTrustDeskSession(`${session}x`)).toBe(false);
    expect(verifyTrustDeskSession('bootstrap-secret')).toBe(false);

    vi.useFakeTimers();
    const issuedAt = new Date('2026-07-18T12:00:00.000Z');
    vi.setSystemTime(issuedAt);
    const old = issueTrustDeskSession();
    vi.setSystemTime(new Date(issuedAt.getTime() + 8 * 60 * 60 * 1000 + 2_000));
    expect(verifyTrustDeskSession(old)).toBe(false);
    vi.useRealTimers();
  });

  it('refuses to issue an anonymous reviewer session', () => {
    vi.stubEnv('TRUST_DESK_INTERNAL_TOKEN', 'bootstrap-secret');
    vi.stubEnv('TRUST_DESK_REVIEWER_ID', '   ');
    expect(issueTrustDeskSession()).toBeNull();
  });
});
