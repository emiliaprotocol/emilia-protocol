// SPDX-License-Identifier: Apache-2.0
//
// /api/v1/guarded — the parts of the fail-closed story the route CLAIMED but
// did not do:
//
//   1. A failed commit released the reservation, so the very next request with
//      the same receipt was allowed. The comment on that branch said "the
//      reservation already blocks replay"; the release() call made that false.
//   2. `action` came straight off an unvalidated query parameter and was echoed
//      into the WWW-Authenticate challenge header and into the consumption key.
//   3. The store was constructed with ttlSeconds: 900 and a comment about
//      operator reaping, but the Supabase backend writes no expiry column and
//      nothing reaps: the advertised retention did not exist.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';
import { createEg1Harness } from '../packages/gate/eg1-conformance.js';

const ACTION = 'payment.release';
const harness = createEg1Harness({ action: { action_type: ACTION }, idPrefix: 'guarded_fc' });

function guardedRequest(doc, { action = ACTION, raw = false } = {}) {
  const query = raw ? action : encodeURIComponent(action);
  return {
    url: `https://www.emiliaprotocol.ai/api/v1/guarded?action=${query}`,
    method: 'POST',
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => ({ emilia_receipt: doc }),
  };
}

describe('/api/v1/guarded fail-closed consumption and action validation', () => {
  let POST;
  let consumption;

  beforeEach(async () => {
    process.env.EP_TRUSTED_ISSUER_KEYS = harness.publicKey;
    process.env.EP_PINNED_APPROVER_KEYS = JSON.stringify(harness.approverKeys);
    process.env.EP_WEBAUTHN_RP_ID = harness.rpId;
    process.env.EP_WEBAUTHN_ALLOWED_ORIGINS = harness.allowedOrigins.join(',');
    delete process.env.NODE_ENV;
    consumption = await import('../lib/http/guarded-consumption.js');
    consumption.__resetGuardedConsumptionStoreForTests();
    ({ POST } = await import('../app/api/v1/guarded/route.js'));
  });

  afterEach(() => {
    delete process.env.EP_TRUSTED_ISSUER_KEYS;
    delete process.env.EP_PINNED_APPROVER_KEYS;
    delete process.env.EP_WEBAUTHN_RP_ID;
    delete process.env.EP_WEBAUTHN_ALLOWED_ORIGINS;
    vi.restoreAllMocks();
  });

  it('keeps the reservation when the commit fails, so the retry is a refused replay', async () => {
    const store = await consumption.getGuardedConsumptionStore();
    const realCommit = store.commit.bind(store);
    const releases = vi.fn();
    const realRelease = store.release.bind(store);
    store.release = async (key) => { releases(key); return realRelease(key); };
    store.commit = async () => { throw new Error('durable commit boom'); };

    const doc = harness.mint({ outcome: 'allow_with_signoff' });
    const failed = await POST(guardedRequest(doc));
    expect(failed.status).toBe(503);
    expect((await failed.json()).rejected?.reason).toBe('consumption_commit_failed');
    // The reservation must survive: releasing it re-opens exactly the replay
    // window the reservation exists to close.
    expect(releases).not.toHaveBeenCalled();

    store.commit = realCommit;
    const retry = await POST(guardedRequest(doc));
    expect(retry.status).toBe(409);
    expect((await retry.json()).rejected?.reason).toBe('receipt_replayed');
  });

  it('refuses an action that is not a closed action identifier', async () => {
    const doc = harness.mint({ outcome: 'allow_with_signoff' });
    for (const action of [
      'payment.release" realm="anything',
      'a'.repeat(129),
      'Payment.Release',
      '../../etc/passwd',
      '',
    ]) {
      const res = await POST(guardedRequest(doc, { action }));
      expect(res.status).toBe(400);
      expect((await res.json()).rejected?.reason).toBe('action_invalid');
    }
  });

  it('accepts the closed action identifiers the manifest actually names', async () => {
    for (const action of ['payment.release', 'gov.disbursement_release', 'large_payment_release']) {
      const scoped = createEg1Harness({ action: { action_type: action }, idPrefix: 'guarded_ok' });
      process.env.EP_TRUSTED_ISSUER_KEYS = scoped.publicKey;
      process.env.EP_PINNED_APPROVER_KEYS = JSON.stringify(scoped.approverKeys);
      process.env.EP_WEBAUTHN_RP_ID = scoped.rpId;
      process.env.EP_WEBAUTHN_ALLOWED_ORIGINS = scoped.allowedOrigins.join(',');
      const res = await POST(guardedRequest(scoped.mint({ outcome: 'allow_with_signoff' }), { action }));
      expect([200, 428]).toContain(res.status);
      expect((await res.json()).rejected?.reason).not.toBe('action_invalid');
    }
  });

  it('never puts caller-controlled text into the WWW-Authenticate challenge', async () => {
    const res = await POST(guardedRequest(null, { action: 'payment.release%22%20realm%3D%22x', raw: true }));
    expect(res.status).toBe(400);
    expect(res.headers.get('www-authenticate')).toBeNull();
  });

  it('advertises the consumption it actually keeps: permanent, with no retention', async () => {
    process.env.NODE_ENV = 'production';
    consumption.__resetGuardedConsumptionStoreForTests();
    vi.doMock('@/lib/supabase', () => ({ getServiceClient: () => ({ from: () => ({}) }) }));
    const fresh = await import('../lib/http/guarded-consumption.js?permanence');
    const store = await fresh.getGuardedConsumptionStore();
    // The Supabase backend inserts only (consume_key, state): no expiry column
    // is written and nothing reaps, so a non-null retention would be a claim
    // the storage layer does not honor.
    expect(store.permanentConsumption).toBe(true);
    expect(store.retentionSeconds).toBeNull();
    delete process.env.NODE_ENV;
  });
});
