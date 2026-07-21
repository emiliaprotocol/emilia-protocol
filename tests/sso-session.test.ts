/**
 * EP SSO session — mint/verify, tamper rejection, cookie parsing.
 * The session is what "logged in via SSO" means: a signed assertion of the
 * verified identity + directory verdict. It never grants signing authority.
 */

import { describe, it, expect, beforeAll, vi } from 'vitest';

vi.mock('@/lib/supabase', () => ({
  getServiceClient: () => ({
    from() {
      const chain = {
        select() { return chain; },
        eq() { return chain; },
        async maybeSingle() { return { data: null, error: null }; },
      };
      return chain;
    },
  }),
}));

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

  it('requires an explicit secret in production', async () => {
    const saved = {
      nodeEnv: process.env.NODE_ENV,
      sessionSecret: process.env.SSO_SESSION_SECRET,
      serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      serviceKey: process.env.SUPABASE_SERVICE_KEY,
    };
    try {
      process.env.NODE_ENV = 'production';
      delete process.env.SSO_SESSION_SECRET;
      delete process.env.SUPABASE_SERVICE_ROLE_KEY;
      delete process.env.SUPABASE_SERVICE_KEY;

      await expect(mintSession(identity)).rejects.toThrow(/SSO_SESSION_SECRET is required/);
    } finally {
      if (saved.nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = saved.nodeEnv;
      if (saved.sessionSecret === undefined) delete process.env.SSO_SESSION_SECRET;
      else process.env.SSO_SESSION_SECRET = saved.sessionSecret;
      if (saved.serviceRoleKey === undefined) delete process.env.SUPABASE_SERVICE_ROLE_KEY;
      else process.env.SUPABASE_SERVICE_ROLE_KEY = saved.serviceRoleKey;
      if (saved.serviceKey === undefined) delete process.env.SUPABASE_SERVICE_KEY;
      else process.env.SUPABASE_SERVICE_KEY = saved.serviceKey;
    }
  });

  it('does not use the source-predictable development fallback', async () => {
    const saved = {
      nodeEnv: process.env.NODE_ENV,
      sessionSecret: process.env.SSO_SESSION_SECRET,
      serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      serviceKey: process.env.SUPABASE_SERVICE_KEY,
    };
    try {
      process.env.NODE_ENV = 'development';
      delete process.env.SSO_SESSION_SECRET;
      delete process.env.SUPABASE_SERVICE_ROLE_KEY;
      delete process.env.SUPABASE_SERVICE_KEY;

      const token = await mintSession(identity);
      process.env.SSO_SESSION_SECRET = 'ep-sso-dev';
      expect(await verifySession(token)).toBeNull();
      delete process.env.SSO_SESSION_SECRET;
      expect(await verifySession(token)).toMatchObject({ sub: identity.subject });
    } finally {
      if (saved.nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = saved.nodeEnv;
      if (saved.sessionSecret === undefined) delete process.env.SSO_SESSION_SECRET;
      else process.env.SSO_SESSION_SECRET = saved.sessionSecret;
      if (saved.serviceRoleKey === undefined) delete process.env.SUPABASE_SERVICE_ROLE_KEY;
      else process.env.SUPABASE_SERVICE_ROLE_KEY = saved.serviceRoleKey;
      if (saved.serviceKey === undefined) delete process.env.SUPABASE_SERVICE_KEY;
      else process.env.SUPABASE_SERVICE_KEY = saved.serviceKey;
    }
  });
});
