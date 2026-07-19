// SPDX-License-Identifier: Apache-2.0
// Unit coverage for the Class A signoff libs — the pure logic in
// lib/webauthn.js (rp config, hashing, COSE→SPKI guards) and the Supabase
// loaders in lib/webauthn-signoff.js (exercised here with a chainable mock,
// not a live DB; the real DB path is covered by the e2e journey).

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { Encoder } from 'cbor-x';
import {
  getRpConfig,
  contextHashHex,
  coseToSpkiP256,
  buildAuthorizationContext,
} from '../lib/webauthn.js';
import { loadSignoffForSigning, loadApproverCredentials } from '../lib/webauthn-signoff.js';

// ── A chainable Supabase stub. Each from() collects the chain; awaiting it
// calls resolve(calls) with what was asked, so a test controls the result.
function makeSupabase(resolve) {
  function builder(table) {
    const calls = { table, eq: {}, in: {}, is: {}, limit: null };
    const b = {
      select() { return b; },
      eq(k, v) { calls.eq[k] = v; return b; },
      in(k, v) { calls.in[k] = v; return b; },
      is(k, v) { calls.is[k] = v; return b; },
      order() { return b; },
      limit(n) { calls.limit = n; return b; },
      then(onF, onR) { return Promise.resolve(resolve(calls)).then(onF, onR); },
    };
    return b;
  }
  return { from: (t) => builder(t) };
}

function coseKey({ kty = 2, alg = -7, crv = 1, x, y } = {}) {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = kp.publicKey.export({ format: 'jwk' });
  const m = new Map([[1, kty], [3, alg], [-1, crv]]);
  m.set(-2, x !== undefined ? x : Buffer.from(jwk.x, 'base64url'));
  m.set(-3, y !== undefined ? y : Buffer.from(jwk.y, 'base64url'));
  return new Encoder({ mapsAsObjects: false }).encode(m);
}

describe('lib/webauthn — getRpConfig', () => {
  const saved = {};
  beforeEach(() => {
    for (const k of ['WEBAUTHN_RP_ID', 'WEBAUTHN_ORIGIN', 'NODE_ENV']) saved[k] = process.env[k];
  });
  afterEach(() => {
    for (const k of ['WEBAUTHN_RP_ID', 'WEBAUTHN_ORIGIN', 'NODE_ENV']) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  });

  it('uses localhost in development', () => {
    delete process.env.WEBAUTHN_RP_ID; delete process.env.WEBAUTHN_ORIGIN;
    process.env.NODE_ENV = 'development';
    const c = getRpConfig();
    expect(c.rpID).toBe('localhost');
    expect(c.origin).toBe('http://localhost:3000');
    expect(c.rpName).toBe('EMILIA Protocol');
  });

  it('uses the production domain otherwise', () => {
    delete process.env.WEBAUTHN_RP_ID; delete process.env.WEBAUTHN_ORIGIN;
    process.env.NODE_ENV = 'production';
    const c = getRpConfig();
    expect(c.rpID).toBe('emiliaprotocol.ai');
    expect(c.origin).toBe('https://www.emiliaprotocol.ai');
  });

  it('honors explicit env overrides', () => {
    process.env.WEBAUTHN_RP_ID = 'rp.example';
    process.env.WEBAUTHN_ORIGIN = 'https://rp.example';
    const c = getRpConfig();
    expect(c.rpID).toBe('rp.example');
    expect(c.origin).toBe('https://rp.example');
  });
});

describe('lib/webauthn — hashing + COSE conversion', () => {
  it('contextHashHex is a 64-char hex digest, stable for equal contexts', () => {
    const ctx = buildAuthorizationContext({
      actionHash: 'a'.repeat(64), policyId: 'p', policyHash: 'h',
      initiatorId: 'i', approverId: 'ap', signoffId: 'sig_' + 'c'.repeat(32),
      issuedAt: '2026-06-09T00:00:00Z', expiresAt: '2026-06-09T00:05:00Z',
    });
    const h = contextHashHex(ctx);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(contextHashHex({ ...ctx })).toBe(h);
  });

  it('coseToSpkiP256 round-trips a valid EC2/ES256/P-256 key', () => {
    const spki = coseToSpkiP256(coseKey());
    // Must be loadable by node:crypto — the offline-verify contract.
    expect(() => crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' })).not.toThrow();
  });

  it('rejects a non-CBOR-map COSE input', () => {
    const notMap = new Encoder({ mapsAsObjects: false }).encode([1, 2, 3]);
    expect(() => coseToSpkiP256(notMap)).toThrow(/CBOR map/);
  });

  it('rejects wrong kty / alg / crv', () => {
    expect(() => coseToSpkiP256(coseKey({ kty: 1 }))).toThrow(/kty/);
    expect(() => coseToSpkiP256(coseKey({ alg: -8 }))).toThrow(/alg/);
    expect(() => coseToSpkiP256(coseKey({ crv: 6 }))).toThrow(/crv/);
  });

  it('rejects malformed x / y coordinates', () => {
    expect(() => coseToSpkiP256(coseKey({ x: Buffer.alloc(8) }))).toThrow(/x coordinate/);
    expect(() => coseToSpkiP256(coseKey({ y: Buffer.alloc(8) }))).toThrow(/y coordinate/);
  });
});

describe('lib/webauthn-signoff — loadSignoffForSigning', () => {
  const REQ = {
    target_id: 'tr_' + 'a'.repeat(32),
    after_state: { signoff_id: 'sig_' + 'b'.repeat(32), initiator_id: 'ent_init', action_hash: 'a'.repeat(64), expires_at: '2030-01-01T00:00:00Z' },
  };
  const CREATED = { event_type: 'guard.trust_receipt.created', after_state: { policy_id: 'p', policy_hash: 'h' } };

  it('returns an error response when the request load fails', async () => {
    const sb = makeSupabase(() => ({ data: null, error: { message: 'boom' } }));
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.error).toBeTruthy();
    expect(r.receiptId).toBeUndefined();
  });

  it('404s when no signoff request matches', async () => {
    const sb = makeSupabase((c) => (c.eq['event_type'] === 'guard.signoff.requested' ? { data: [], error: null } : { data: [], error: null }));
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.error).toBeTruthy();
  });

  it('errors when the receipt events load fails', async () => {
    const sb = makeSupabase((c) => {
      if (c.eq['event_type'] === 'guard.signoff.requested') return { data: [REQ], error: null };
      return { data: null, error: { message: 'events boom' } };
    });
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.error).toBeTruthy();
  });

  it('errors when the creation event is missing', async () => {
    const sb = makeSupabase((c) => {
      if (c.eq['event_type'] === 'guard.signoff.requested') return { data: [REQ], error: null };
      return { data: [], error: null }; // no created event
    });
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.error).toBeTruthy();
  });

  it('loads cleanly with alreadyDecided=false', async () => {
    const sb = makeSupabase((c) => {
      if (c.eq['event_type'] === 'guard.signoff.requested') return { data: [REQ], error: null };
      return { data: [CREATED], error: null };
    });
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.error).toBeUndefined();
    expect(r.receiptId).toBe(REQ.target_id);
    expect(r.initiatorId).toBe('ent_init');
    expect(r.actionHash).toBe('a'.repeat(64));
    expect(r.alreadyDecided).toBe(false);
    expect(r.createdState.policy_id).toBe('p');
  });

  it('flags alreadyDecided=true when a matching decision exists', async () => {
    const decided = { event_type: 'guard.signoff.approved', after_state: { signoff_id: REQ.after_state.signoff_id } };
    const sb = makeSupabase((c) => {
      if (c.eq['event_type'] === 'guard.signoff.requested') return { data: [REQ], error: null };
      return { data: [CREATED, decided], error: null };
    });
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.alreadyDecided).toBe(true);
  });

  it('treats a matching rejection as equally terminal', async () => {
    const denied = { event_type: 'guard.signoff.rejected', after_state: { signoff_id: REQ.after_state.signoff_id } };
    const sb = makeSupabase((c) => {
      if (c.eq['event_type'] === 'guard.signoff.requested') return { data: [REQ], error: null };
      return { data: [CREATED, denied], error: null };
    });
    const r = await loadSignoffForSigning(sb, REQ.after_state.signoff_id);
    expect(r.alreadyDecided).toBe(true);
  });
});

describe('lib/webauthn-signoff — loadApproverCredentials', () => {
  it('returns an error response on DB failure', async () => {
    const sb = makeSupabase(() => ({ data: null, error: { message: 'db' } }));
    const r = await loadApproverCredentials(sb, 'ep:approver:x');
    expect(r.error).toBeTruthy();
  });

  it('drops expired credentials and keeps active ones', async () => {
    const sb = makeSupabase(() => ({
      data: [
        { credential_id: 'c_active', approver_id: 'ep:approver:x', enrollment_basis: 'operator_attested', valid_to: null },
        { credential_id: 'c_future', approver_id: 'ep:approver:x', enrollment_basis: 'operator_attested', valid_to: '2999-01-01T00:00:00Z' },
        { credential_id: 'c_expired', approver_id: 'ep:approver:x', enrollment_basis: 'operator_attested', valid_to: '2000-01-01T00:00:00Z' },
      ],
      error: null,
    }));
    const r = await loadApproverCredentials(sb, 'ep:approver:x');
    expect(r.error).toBeUndefined();
    const ids = r.credentials.map((c) => c.credential_id);
    expect(ids).toContain('c_active');
    expect(ids).toContain('c_future');
    expect(ids).not.toContain('c_expired');
  });

  it('does NOT let a case-variant satisfy an operator-attested identity, but honors the normalized alias for a directory credential', async () => {
    // Both rows carry the same case-folded id `alice@corp`; the signoff targets
    // the distinct-cased `Alice@corp`. The DB .in() returns both forms; the JS
    // filter must accept the directory row (stored normalized) and reject the
    // operator-attested one (whose raw id only case-folds to the target).
    const sb = makeSupabase(() => ({
      data: [
        { credential_id: 'c_operator_lower', approver_id: 'alice@corp', enrollment_basis: 'operator_attested', valid_to: null },
        { credential_id: 'c_directory_lower', approver_id: 'alice@corp', enrollment_basis: 'directory', valid_to: null },
      ],
      error: null,
    }));
    const r = await loadApproverCredentials(sb, 'Alice@corp');
    expect(r.error).toBeUndefined();
    const ids = r.credentials.map((c) => c.credential_id);
    expect(ids).not.toContain('c_operator_lower'); // cross-identity path closed
    expect(ids).toContain('c_directory_lower');    // directory alias honored
  });

  it('matches an operator-attested credential only on the exact raw approver_id', async () => {
    const sb = makeSupabase(() => ({
      data: [
        { credential_id: 'c_exact', approver_id: 'Alice@corp', enrollment_basis: 'operator_attested', valid_to: null },
      ],
      error: null,
    }));
    const r = await loadApproverCredentials(sb, 'Alice@corp');
    expect(r.credentials.map((c) => c.credential_id)).toContain('c_exact');
  });
});

describe('lib/webauthn — WYSIWYS display_hash binding', () => {
  const baseArgs = {
    actionHash: 'sha256:abc',
    policyId: 'p1',
    policyHash: 'sha256:pol',
    initiatorId: 'init',
    approverId: 'appr',
    signoffId: 'sig_000000000000000000000000000000aa',
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-01T00:05:00.000Z',
  };

  it('omits display_hash when none is provided (back-compat: byte-identical context)', () => {
    expect(buildAuthorizationContext(baseArgs).display_hash).toBeUndefined();
  });

  it('binds display_hash into the signed context and changes the challenge', () => {
    const withoutHash = contextHashHex(buildAuthorizationContext(baseArgs));
    const withDisplay = buildAuthorizationContext({ ...baseArgs, displayHash: 'sha256:display' });
    expect(withDisplay.display_hash).toBe('sha256:display');
    // The challenge IS the context hash — binding the display changes what the human signs.
    expect(contextHashHex(withDisplay)).not.toBe(withoutHash);
  });
});
