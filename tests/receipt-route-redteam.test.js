// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

const mockAuthenticateRequest = vi.fn();
const mockGetGuardedClient = vi.fn();

vi.mock('@/lib/supabase', () => ({
  authenticateRequest: (...args) => mockAuthenticateRequest(...args),
  authEntityId: (auth) => auth?.entity?.entity_id || auth?.entity?.id || '',
}));

vi.mock('@/lib/write-guard', () => ({
  getGuardedClient: (...args) => mockGetGuardedClient(...args),
}));

vi.mock('@/lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { POST } = await import('../app/api/receipt/route.js');
const { verifyReceipt } = await import('../packages/verify/index.js');

function jsonReq(body) {
  return new Request('https://www.emiliaprotocol.ai/api/receipt', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ep_live_test' },
    body: JSON.stringify(body),
  });
}

function entityLookup(row) {
  const chain = {
    select: vi.fn(() => chain),
    eq: vi.fn(() => chain),
    single: vi.fn(async () => ({ data: row, error: null })),
  };
  return { from: vi.fn(() => chain) };
}

describe('POST /api/receipt red-team regressions', () => {
  it('signs the full nested payload, not a shallow/top-level projection', async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    const publicKeyB64u = Buffer.from(publicKey).toString('base64url');
    const privateKeyB64u = Buffer.from(privateKey).toString('base64url');

    mockAuthenticateRequest.mockResolvedValue({
      entity: { id: 'uuid-issuer', entity_id: 'issuer_agent' },
      permissions: {},
    });
    mockGetGuardedClient.mockReturnValue(entityLookup({
      entity_id: 'issuer_agent',
      private_key_encrypted: privateKeyB64u,
      public_key: publicKeyB64u,
    }));

    const res = await POST(jsonReq({
      subject: 'payment_instruction_7',
      action_type: 'payment.release',
      outcome: 'allow',
      context: {
        amount_cents: 8200000,
        beneficiary: { name: 'Acme Vendor', account_hash: 'sha256:abc' },
      },
    }));
    const doc = await res.json();

    expect(res.status).toBe(201);
    expect(verifyReceipt(doc, publicKeyB64u).valid).toBe(true);

    const tampered = JSON.parse(JSON.stringify(doc));
    tampered.payload.claim.context.beneficiary.account_hash = 'sha256:attacker';
    expect(verifyReceipt(tampered, publicKeyB64u).valid).toBe(false);
  });
});
