/**
 * /api/discovery/keys — operator signing-key publication.
 *
 * The discovery document (served at /.well-known/ep-keys.json via next.config.js
 * rewrite) must advertise the operator commit signing key (ep-signing-key-1,
 * key_class C) that signs /evidence EP-RECEIPT-v1 documents, so a verifier
 * following a receipt's discovery link can pin the signer. Only the PUBLIC SPKI
 * is ever published; the seed must never leak; and an ephemeral dev key must not
 * be advertised when no real key is configured.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

const mockGetGuardedClient = vi.fn();
vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));
vi.mock('@/lib/logger.js', () => ({ logger: { warn() {}, error() {}, info() {} } }));
vi.mock('../lib/logger.js', () => ({ logger: { warn() {}, error() {}, info() {} } }));

import { GET } from '../app/api/discovery/keys/route.js';
import { _resetForTesting } from '../lib/guard-evidence-receipt.js';

// Minimal Supabase stub: every chain resolves to empty so the route's entity
// query path is a clean no-op (operator_signing_keys is computed before it).
function stubClient() {
  const chain = {
    select: () => chain,
    eq: () => chain,
    order: () => chain,
    limit: () => Promise.resolve({ data: [], error: null }),
  };
  return { from: () => chain };
}

const ORIG_KEY = process.env.EP_COMMIT_SIGNING_KEY;

describe('GET /api/discovery/keys — operator signing key', () => {
  beforeEach(() => {
    mockGetGuardedClient.mockReturnValue(stubClient());
    _resetForTesting();
  });
  afterEach(() => {
    if (ORIG_KEY === undefined) delete process.env.EP_COMMIT_SIGNING_KEY;
    else process.env.EP_COMMIT_SIGNING_KEY = ORIG_KEY;
    _resetForTesting();
  });

  it('publishes ep-signing-key-1 (public SPKI, key_class C) when a key is configured', async () => {
    const seed = crypto.randomBytes(32).toString('base64');
    process.env.EP_COMMIT_SIGNING_KEY = seed;
    _resetForTesting();

    const res = await GET();
    const body = await res.json();

    const k = body.operator_signing_keys?.['ep-signing-key-1'];
    expect(k).toBeTruthy();
    expect(k.key_class).toBe('C');
    expect(k.algorithm).toBe('Ed25519');
    expect(k.key_id).toBe('ep-signing-key-1');
    expect(typeof k.public_key).toBe('string');
    expect(k.public_key.length).toBeGreaterThan(20);

    // The published key must be the PUBLIC half — the seed must never leak.
    expect(JSON.stringify(body)).not.toContain(seed);
    // It must equal the SPKI the evidence path serves (same derivation).
    const { getEvidenceSigningKeypair } = await import('../lib/guard-evidence-receipt.js');
    expect(k.public_key).toBe(getEvidenceSigningKeypair().publicKeySpkiB64u);
  });

  it('advertises no operator signing key when none is configured (no ephemeral key)', async () => {
    delete process.env.EP_COMMIT_SIGNING_KEY;
    _resetForTesting();

    const res = await GET();
    const body = await res.json();
    expect(body.operator_signing_keys).toEqual({});
  });
});
