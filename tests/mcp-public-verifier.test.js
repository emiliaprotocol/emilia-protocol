// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  verifyReceiptTool,
  verifySignoffTool,
} from '../app/api/mcp/[transport]/route.js';

function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function receiptFixture() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const payload = { receipt_id: 'mcp-public-1', claim: { action_type: 'payment.release' } };
  const signature = crypto.sign(null, Buffer.from(canonicalize(payload)), privateKey).toString('base64url');
  const key = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  return {
    key,
    document: {
      '@version': 'EP-RECEIPT-v1',
      payload,
      issuer_public_key: key,
      signature: { algorithm: 'Ed25519', value: signature },
    },
  };
}

function signoffFixture({ crossOrigin } = {}) {
  const rpId = 'emiliaprotocol.ai';
  const origin = 'https://www.emiliaprotocol.ai';
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    context_type: 'ep.signoff.v1',
    action_hash: `sha256:${'a'.repeat(64)}`,
    approver: 'ep:approver:alice',
    initiator: 'ep:agent:7',
  };
  const challenge = crypto.createHash('sha256').update(canonicalize(context)).digest('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge,
    origin,
    ...(crossOrigin === undefined ? {} : { crossOrigin }),
  }));
  const authenticatorData = Buffer.concat([
    crypto.createHash('sha256').update(rpId).digest(),
    Buffer.from([0x05]),
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([authenticatorData, crypto.createHash('sha256').update(clientData).digest()]);
  return {
    rpId,
    origin,
    key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    signoff: {
      context,
      approver_public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      webauthn: {
        authenticator_data: authenticatorData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: crypto.sign('sha256', signed, privateKey).toString('base64url'),
      },
    },
  };
}

describe('public MCP verifier trust boundaries', () => {
  it('refuses an artifact-embedded issuer key and labels explicit-key verification as integrity only', async () => {
    const fixture = receiptFixture();
    const selfAnchored = await verifyReceiptTool({ document: fixture.document });
    expect(selfAnchored.valid).toBe(false);
    expect(selfAnchored.error).toMatch(/cannot establish.*trust/i);

    const explicit = await verifyReceiptTool({ document: fixture.document, public_key: fixture.key });
    expect(explicit.valid).toBe(true);
    expect(explicit.accepted).toBeNull();
    expect(explicit.scope).toBe('cryptographic_integrity');
  });

  it('requires a caller key, RP ID, and exact origin allowlist for a signoff', async () => {
    const fixture = signoffFixture();
    expect((await verifySignoffTool({ signoff: fixture.signoff })).valid).toBe(false);
    expect((await verifySignoffTool({
      signoff: fixture.signoff,
      approver_public_key: fixture.key,
    })).valid).toBe(false);

    const verified = await verifySignoffTool({
      signoff: fixture.signoff,
      approver_public_key: fixture.key,
      rp_id: fixture.rpId,
      allowed_origins: [fixture.origin],
    });
    expect(verified.valid).toBe(true);
    expect(verified.accepted).toBeNull();
    expect(verified.limitation).toMatch(/does not prove legal identity/i);
  });

  it('refuses a cross-origin ceremony even when its origin string is allowlisted', async () => {
    const fixture = signoffFixture({ crossOrigin: true });
    const verified = await verifySignoffTool({
      signoff: fixture.signoff,
      approver_public_key: fixture.key,
      rp_id: fixture.rpId,
      allowed_origins: [fixture.origin],
    });
    expect(verified.valid).toBe(false);
  });
});
