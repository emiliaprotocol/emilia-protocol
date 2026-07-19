/**
 * OIDC Relying Party — validation tests against a FIXTURE provider.
 *
 * A fixture RSA keypair stands in for the IdP's signing key; its public half is
 * published as a JWKS exactly as a real provider would. We sign genuine ID
 * tokens and prove the RP accepts a valid one and rejects every tampered
 * variant — wrong audience, wrong issuer, expired, bad nonce, and a token signed
 * by a key the provider does not publish.
 *
 * This is the whole security-critical core of OIDC SSO, exercised without a live
 * IdP. The live round-trip needs the provider's client_id/secret.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as jose from 'jose';
import {
  buildAuthorizeUrl, pkceChallenge, randomUrlToken, validateIdToken, discover, exchangeCode,
  assertSafeDiscoveryEndpoints,
} from '../lib/sso/oidc.js';

const ISSUER = 'https://idp.example.com';
const CLIENT_ID = 'ep-client-123';

let privateKey, jwks, otherPrivateKey;

beforeAll(async () => {
  const kp = await jose.generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = await jose.exportJWK(kp.publicKey);
  jwk.kid = 'fixture-key-1';
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  jwks = { keys: [jwk] };

  // A second key NOT published in the JWKS — used to forge a token.
  const other = await jose.generateKeyPair('RS256');
  otherPrivateKey = other.privateKey;
});

async function signIdToken(claims = {}, { key = privateKey, kid = 'fixture-key-1', expiresIn = '1h' } = {}) {
  return new jose.SignJWT({ email: 'approver@example.com', ...claims })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(claims.iss || ISSUER)
    .setAudience(claims.aud || CLIENT_ID)
    .setSubject(claims.sub || 'user-abc')
    .setExpirationTime(expiresIn)
    .sign(key);
}

describe('OIDC ID-token validation', () => {
  it('accepts a valid token and returns claims', async () => {
    const token = await signIdToken({ nonce: 'n1' });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks, nonce: 'n1' });
    expect(r.valid).toBe(true);
    expect(r.subject).toBe('user-abc');
    expect(r.email).toBe('approver@example.com');
  });

  it('rejects a token with no sub claim (OIDC requires it; would mint an undefined-subject session)', async () => {
    // jose verifies sig/iss/aud/exp but not sub presence, so a signed token
    // lacking sub used to validate and flow subject:undefined into mintSession.
    const token = await new jose.SignJWT({ email: 'approver@example.com', nonce: 'n1' })
      .setProtectedHeader({ alg: 'RS256', kid: 'fixture-key-1' })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setExpirationTime('1h')
      .sign(privateKey); // deliberately no setSubject
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks, nonce: 'n1' });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/sub/i);
  });

  it('rejects a wrong audience', async () => {
    const token = await signIdToken({ aud: 'some-other-client' });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks });
    expect(r.valid).toBe(false);
  });

  it('rejects a wrong issuer', async () => {
    const token = await signIdToken({ iss: 'https://evil.example.com' });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks });
    expect(r.valid).toBe(false);
  });

  it('rejects an expired token', async () => {
    const token = await signIdToken({}, { expiresIn: '-5m' });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks });
    expect(r.valid).toBe(false);
  });

  it('rejects a nonce mismatch', async () => {
    const token = await signIdToken({ nonce: 'real-nonce' });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks, nonce: 'attacker-nonce' });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/Nonce/);
  });

  it('rejects a token signed by a key not in the provider JWKS (forgery)', async () => {
    const token = await signIdToken({ nonce: 'n1' }, { key: otherPrivateKey });
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, jwks, nonce: 'n1' });
    expect(r.valid).toBe(false);
  });

  it('requires jwks or jwksUri', async () => {
    const token = await signIdToken();
    const r = await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID });
    expect(r.valid).toBe(false);
    expect(r.error).toMatch(/jwks/);
  });
});

describe('OIDC authorize request (PKCE)', () => {
  it('builds an authorize URL with PKCE + state + nonce', () => {
    const verifier = randomUrlToken();
    const url = new URL(buildAuthorizeUrl({
      authorizationEndpoint: `${ISSUER}/authorize`,
      clientId: CLIENT_ID,
      redirectUri: 'https://www.emiliaprotocol.ai/api/sso/oidc/callback',
      state: 'state123',
      nonce: 'nonce123',
      codeChallenge: pkceChallenge(verifier),
    }));
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBe('state123');
    expect(url.searchParams.get('nonce')).toBe('nonce123');
  });

  it('pkceChallenge is the S256 of the verifier', () => {
    // Known RFC 7636 Appendix B vector.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(pkceChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});

describe('OIDC discovery + token exchange (injected fetch)', () => {
  it('discover reads the well-known document', async () => {
    const fetchImpl = async (url) => {
      expect(url).toBe(`${ISSUER}/.well-known/openid-configuration`);
      return { ok: true, json: async () => ({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks` }) };
    };
    const doc = await discover(ISSUER, fetchImpl);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
  });

  it('discover throws when endpoints are missing', async () => {
    const fetchImpl = async () => ({ ok: true, json: async () => ({ issuer: ISSUER }) });
    await expect(discover(ISSUER, fetchImpl)).rejects.toThrow(/missing required endpoints/);
  });

  it('exchangeCode posts the auth-code grant', async () => {
    const fetchImpl = async (url, init) => {
      expect(url).toBe(`${ISSUER}/token`);
      expect(init.body).toContain('grant_type=authorization_code');
      expect(init.body).toContain('code_verifier=verifier123');
      return { ok: true, json: async () => ({ id_token: 'idt', access_token: 'at' }) };
    };
    const tokens = await exchangeCode({
      tokenEndpoint: `${ISSUER}/token`, clientId: CLIENT_ID, clientSecret: 'secret',
      code: 'authcode', redirectUri: 'https://x/cb', codeVerifier: 'verifier123', fetchImpl,
    });
    expect(tokens.id_token).toBe('idt');
  });

  it('discover refuses server-followed redirects (SSRF)', async () => {
    let sawRedirectOption;
    const fetchImpl = async (url, init) => {
      sawRedirectOption = init?.redirect;
      return { ok: true, json: async () => ({ issuer: ISSUER, authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token`, jwks_uri: `${ISSUER}/jwks` }) };
    };
    await discover(ISSUER, fetchImpl);
    expect(sawRedirectOption).toBe('error');
  });

  it('exchangeCode refuses redirects on the secret-bearing POST (SSRF)', async () => {
    let sawRedirectOption;
    const fetchImpl = async (url, init) => {
      sawRedirectOption = init?.redirect;
      return { ok: true, json: async () => ({ id_token: 'idt' }) };
    };
    await exchangeCode({
      tokenEndpoint: `${ISSUER}/token`, clientId: CLIENT_ID, clientSecret: 'secret',
      code: 'c', redirectUri: 'https://x/cb', codeVerifier: 'v', fetchImpl,
    });
    expect(sawRedirectOption).toBe('error');
  });
});

describe('OIDC discovery-endpoint SSRF gate (assertSafeDiscoveryEndpoints)', () => {
  // Injected DNS: a hostile issuer can return real-looking https endpoints that
  // resolve to cloud-metadata / loopback. The gate must refuse them even though
  // the issuer host itself was already validated.
  // Host-aware injected DNS: every host resolves public EXCEPT the ones named in
  // `poison`, which resolve to the given attacker/internal address.
  const lookupMap = (poison = {}) => async (hostname) => {
    const addr = poison[hostname] || '142.250.80.1';
    return [{ address: addr, family: addr.includes(':') ? 6 : 4 }];
  };

  it('accepts public https endpoints on sibling hosts (e.g. Google-style)', async () => {
    const doc = {
      authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      token_endpoint: 'https://oauth2.googleapis.com/token',
      jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
    };
    const r = await assertSafeDiscoveryEndpoints(doc, { lookup: lookupMap() });
    expect(r.valid).toBe(true);
  });

  it('refuses a token_endpoint that resolves to the cloud metadata IP', async () => {
    const doc = {
      authorization_endpoint: 'https://idp.example.com/authorize',
      token_endpoint: 'https://attacker.example.com/token',
      jwks_uri: 'https://idp.example.com/jwks',
    };
    const r = await assertSafeDiscoveryEndpoints(doc, {
      lookup: lookupMap({ 'attacker.example.com': '169.254.169.254' }),
    });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('token_endpoint');
  });

  it('refuses a non-https jwks_uri', async () => {
    const doc = {
      authorization_endpoint: 'https://idp.example.com/authorize',
      token_endpoint: 'https://idp.example.com/token',
      jwks_uri: 'http://idp.example.com/jwks',
    };
    const r = await assertSafeDiscoveryEndpoints(doc, { lookup: lookupMap() });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('jwks_uri');
  });

  it('refuses a jwks_uri that resolves to loopback (IPv6)', async () => {
    const doc = {
      authorization_endpoint: 'https://idp.example.com/authorize',
      token_endpoint: 'https://idp.example.com/token',
      jwks_uri: 'https://internal.example.com/jwks',
    };
    const r = await assertSafeDiscoveryEndpoints(doc, {
      lookup: lookupMap({ 'internal.example.com': '::1' }),
    });
    expect(r.valid).toBe(false);
    expect(r.field).toBe('jwks_uri');
  });
});
