/**
 * EP SSO session — mint/verify, tamper rejection, cookie parsing.
 * The session is what "logged in via SSO" means: a signed assertion of the
 * verified identity + directory verdict. It never grants signing authority.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { mintSession, verifySession, readSessionFromRequest, SESSION_COOKIE } from '../lib/sso/session.js';

beforeAll(() => {
  process.env.SSO_SESSION_SECRET = 'test-session-secret';
});

const identity = {
  tenant: 'ep_entity_acme',
  subject: 'approver@example.com',
  email: 'approver@example.com',
  protocol: 'oidc',
  directory: { matched: true, active: true, user_id: 'u1' },
};

describe('EP session', () => {
  it('mints and verifies a session with the identity + directory verdict', async () => {
    const token = await mintSession(identity);
    const claims = await verifySession(token);
    expect(claims.sub).toBe('approver@example.com');
    expect(claims.tenant).toBe('ep_entity_acme');
    expect(claims.protocol).toBe('oidc');
    expect(claims.directory).toEqual({ matched: true, active: true, user_id: 'u1' });
    expect(claims.exp - claims.iat).toBe(8 * 60 * 60); // 8h
  });

  it('rejects a tampered token', async () => {
    const token = await mintSession(identity);
    const [h, p, s] = token.split('.');
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    payload.tenant = 'ep_entity_attacker';
    const forged = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
    expect(await verifySession(forged)).toBeNull();
  });

  it('rejects a token minted under a different secret', async () => {
    const token = await mintSession(identity);
    process.env.SSO_SESSION_SECRET = 'rotated-secret';
    expect(await verifySession(token)).toBeNull();
    process.env.SSO_SESSION_SECRET = 'test-session-secret';
  });

  it('rejects absent/garbage tokens', async () => {
    expect(await verifySession(null)).toBeNull();
    expect(await verifySession('not.a.jwt')).toBeNull();
  });

  it('requires tenant and subject to mint', async () => {
    await expect(mintSession({ subject: 'x' })).rejects.toThrow(/tenant/);
  });

  it('readSessionFromRequest parses the cookie header', async () => {
    const token = await mintSession(identity);
    const req = new Request('https://x/api/sso/session', {
      headers: { cookie: `other=1; ${SESSION_COOKIE}=${encodeURIComponent(token)}; z=2` },
    });
    const claims = await readSessionFromRequest(req);
    expect(claims.sub).toBe('approver@example.com');

    const bare = new Request('https://x/api/sso/session');
    expect(await readSessionFromRequest(bare)).toBeNull();
  });
});
