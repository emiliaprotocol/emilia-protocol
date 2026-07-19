// SPDX-License-Identifier: Apache-2.0
// Smoke tests for the hosted Rx Reliance API routes. The reliance kernel itself
// is exhaustively covered in ncpdp-rx-reliance.test.js; these assert the route
// wiring: auth gate, body validation, and fail-closed behavior on a malformed
// packet (a bad packet returns a 200 with a do_not_rely verdict, never a pass).
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@/lib/supabase', () => ({ authenticateRequest: vi.fn() }));
const { authenticateRequest } = await import('@/lib/supabase');
const { POST: evaluatePOST } = await import('@/app/api/v1/rx-reliance/evaluate/route.js');
const { POST: profilesPOST } = await import('@/app/api/v1/rx-reliance/profiles/route.js');

const req = (body) => new Request('https://x/api', { method: 'POST', headers: { authorization: 'Bearer ep_live_test', 'content-type': 'application/json' }, body: JSON.stringify(body) });

beforeEach(() => {
  authenticateRequest.mockReset();
  authenticateRequest.mockResolvedValue({ entity: { entity_id: 'e' }, permissions: [] });
  delete process.env.EP_RX_PRIVACY_KEY_B64U;
  delete process.env.EP_RX_PRIVACY_KEY_ID;
});

describe('POST /api/v1/rx-reliance/evaluate', () => {
  it('401 without a valid API key', async () => {
    authenticateRequest.mockResolvedValue({ error: 'no key', status: 401 });
    expect((await evaluatePOST(req({ challenge: {}, packet: {} }))).status).toBe(401);
  });
  it('400 when challenge or packet is missing', async () => {
    expect((await evaluatePOST(req({ packet: {} }))).status).toBe(400);
    expect((await evaluatePOST(req({ challenge: {} }))).status).toBe(400);
  });
  it('fail-closed: a malformed packet returns 200 with a do_not_rely verdict', async () => {
    const res = await evaluatePOST(req({ challenge: { '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', required: {} }, packet: { '@type': 'EP-RX-RELIANCE-PACKET-v1' } }));
    expect(res.status).toBe(200);
    const j = await res.json();
    expect(j.rely).toBe(false);
    expect(j.verdict.startsWith('rx_do_not_rely')).toBe(true);
  });
  it('refuses appeal export when the deployment privacy key is unavailable', async () => {
    const res = await evaluatePOST(req({
      challenge: { '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', required: {} },
      packet: { '@type': 'EP-RX-RELIANCE-PACKET-v1' },
      appeal_bundle: true,
    }));
    expect(res.status).toBe(503);
    expect((await res.json()).type).toMatch(/rx_privacy_key_unavailable/);
  });
  it('refuses a non-canonical or undersized deployment privacy key', async () => {
    process.env.EP_RX_PRIVACY_KEY_B64U = Buffer.alloc(16).toString('base64url');
    process.env.EP_RX_PRIVACY_KEY_ID = 'rx-privacy-test';
    const res = await evaluatePOST(req({
      challenge: { '@type': 'EP-RX-EVIDENCE-CHALLENGE-v1', required: {} },
      packet: { '@type': 'EP-RX-RELIANCE-PACKET-v1' },
      appeal_bundle: true,
    }));
    expect(res.status).toBe(503);
  });
});

describe('POST /api/v1/rx-reliance/profiles', () => {
  it('401 without a valid API key', async () => {
    authenticateRequest.mockResolvedValue({ error: 'no key', status: 401 });
    expect((await profilesPOST(req({ profile: {} }))).status).toBe(401);
  });
  it('400 when profile is missing', async () => {
    expect((await profilesPOST(req({}))).status).toBe(400);
  });
  it('returns a content-addressed profile_hash and validity', async () => {
    const good = await (await profilesPOST(req({ profile: { '@type': 'EP-RELIANCE-PROFILE-v1', required_assurance: 'class_a', required_evidence: [] } }))).json();
    expect(good.valid).toBe(true);
    expect(good.profile_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const bad = await (await profilesPOST(req({ profile: { required_assurance: 'nope' } }))).json();
    expect(bad.valid).toBe(false);
    expect(Array.isArray(bad.issues)).toBe(true);
  });
});
