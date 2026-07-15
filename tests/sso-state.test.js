/**
 * SSO transient-state token — HMAC sign/verify, tamper, and expiry.
 *
 * This token carries the login round-trip's state/nonce/PKCE-verifier from the
 * redirect to the callback. A forged or stale token MUST NOT verify — that is
 * the CSRF / association guarantee for the callback.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import crypto from 'node:crypto';
import { signState, verifyState } from '../lib/sso/state.js';

function signedRawState(raw) {
  const body = Buffer.from(raw, 'utf8').toString('base64url');
  const mac = crypto.createHmac('sha256', 'test-secret-for-sso-state').update(body).digest('base64url');
  return `${body}.${mac}`;
}

beforeAll(() => {
  process.env.SSO_STATE_SECRET = 'test-secret-for-sso-state';
});

describe('SSO state token', () => {
  it('round-trips a payload', () => {
    const token = signState({ tenant: 'ep_entity_acme', state: 's1', nonce: 'n1', codeVerifier: 'v1' });
    const payload = verifyState(token);
    expect(payload).toBeTruthy();
    expect(payload.tenant).toBe('ep_entity_acme');
    expect(payload.state).toBe('s1');
    expect(payload.nonce).toBe('n1');
  });

  it('rejects a tampered body', () => {
    const token = signState({ tenant: 't', state: 's1' });
    const [body, mac] = token.split('.');
    const forgedBody = Buffer.from(JSON.stringify({ tenant: 'attacker', state: 's1', iat: Date.now() })).toString('base64url');
    expect(verifyState(`${forgedBody}.${mac}`)).toBeNull();
    expect(verifyState(`${body}.deadbeef`)).toBeNull();
  });

  it('rejects a malformed token', () => {
    expect(verifyState('')).toBeNull();
    expect(verifyState('no-dot')).toBeNull();
    expect(verifyState(undefined)).toBeNull();
    expect(verifyState(`${signState({ tenant: 't' })}.extra`)).toBeNull();
  });

  it('rejects valid-MAC ambiguous JSON and a far-future issued-at', () => {
    const now = Date.now();
    expect(verifyState(signedRawState(`{"tenant":"safe","tenant":"attacker","iat":${now}}`))).toBeNull();
    expect(verifyState(signedRawState(`{"tenant":"t","iat":${now + 120_000}}`))).toBeNull();
  });

  it('rejects an expired token', () => {
    const token = signState({ tenant: 't' });
    // maxAge of 0 → anything older than now fails (iat is in the past by construction).
    expect(verifyState(token, -1)).toBeNull();
  });

  it('a token signed under a different secret does not verify', () => {
    const token = signState({ tenant: 't' });
    process.env.SSO_STATE_SECRET = 'a-different-secret';
    expect(verifyState(token)).toBeNull();
    process.env.SSO_STATE_SECRET = 'test-secret-for-sso-state'; // restore
  });
});
