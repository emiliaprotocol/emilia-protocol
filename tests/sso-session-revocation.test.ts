// SPDX-License-Identifier: Apache-2.0
//
// Server-side session revocation (Pentest-1, Report C): logout must invalidate a
// session server-side, and a subject-wide cutoff must kill all existing sessions.
// The supabase service client is mocked with an in-memory store so the revocation
// paths are exercised without a database.

import { describe, it, expect, beforeEach, vi } from 'vitest';

const store = vi.hoisted(() => ({ revokedJtis: new Set(), cutoffs: new Map(), revocationStoreDown: false }));

vi.mock('@/lib/supabase', () => ({
  getServiceClient: () => ({
    from(table: string): any {
      const filters: any = {};
      const chain: any = {
        select() { return chain; },
        eq(col, val) { filters[col] = val; return chain; },
        async maybeSingle() {
          if (store.revocationStoreDown) {
            return { data: null, error: { message: 'revocation store unavailable' } };
          }
          if (table === 'revoked_sessions') {
            return { data: store.revokedJtis.has(filters.jti) ? { jti: filters.jti } : null, error: null };
          }
          if (table === 'session_cutoffs') {
            const nb = store.cutoffs.get(`${filters.subject}|${filters.tenant}`);
            return { data: nb ? { not_before: nb } : null, error: null };
          }
          return { data: null, error: null };
        },
        async upsert(row) {
          if (table === 'revoked_sessions') store.revokedJtis.add(row.jti);
          if (table === 'session_cutoffs') store.cutoffs.set(`${row.subject}|${row.tenant}`, row.not_before);
          return { error: null };
        },
      };
      return chain;
    },
  }),
}));

const { mintSession, verifySession, revokeSession, revokeAllSessionsForSubject } =
  await import('../lib/sso/session.js');

const identity = {
  tenant: 'acme',
  subject: 'user@acme.com',
  email: 'user@acme.com',
  protocol: 'oidc',
  directory: { matched: true, active: true },
};

describe('SSO session revocation', () => {
  beforeEach(() => {
    store.revokedJtis.clear();
    store.cutoffs.clear();
    store.revocationStoreDown = false;
  });

  it('mints a session carrying a jti, valid before revocation', async () => {
    const token = await mintSession(identity);
    const claims = await verifySession(token);
    expect(claims).not.toBeNull();
    expect(typeof claims.jti).toBe('string');
  });

  it('revokeSession(jti) makes that exact session stop verifying (logout is not cosmetic)', async () => {
    const token = await mintSession(identity);
    const claims = await verifySession(token);

    await revokeSession(claims.jti, { subject: claims.sub, tenant: claims.tenant });

    expect(await verifySession(token)).toBeNull();      // revoked
    const other = await mintSession(identity);          // a fresh session
    expect(await verifySession(other)).not.toBeNull();  // unaffected (different jti)
  });

  it('subject cutoff (logout-all-devices) rejects tokens issued before not_before', async () => {
    const token = await mintSession(identity);
    // Cutoff just after this token's issuance → it must be rejected.
    store.cutoffs.set(`${identity.subject}|${identity.tenant}`, new Date(Date.now() + 5000).toISOString());
    expect(await verifySession(token)).toBeNull();
  });

  it('revokeAllSessionsForSubject records a cutoff for the subject/tenant', async () => {
    const ok = await revokeAllSessionsForSubject(identity.subject, identity.tenant);
    expect(ok).toBe(true);
    expect(store.cutoffs.has(`${identity.subject}|${identity.tenant}`)).toBe(true);
  });

  it('fails closed when revocation state cannot be verified', async () => {
    const token = await mintSession(identity);
    store.revocationStoreDown = true;
    expect(await verifySession(token)).toBeNull();
  });
});
