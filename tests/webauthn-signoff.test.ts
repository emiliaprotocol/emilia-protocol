// SPDX-License-Identifier: Apache-2.0
// Class A signoff — offline verification + helper tests.
//
// Builds a REAL WebAuthn-shaped assertion with a locally generated P-256
// key (authenticatorData bytes + clientDataJSON + DER ECDSA signature, per
// WebAuthn L2 §6), so the offline verifier is exercised end-to-end with no
// physical authenticator. If these pass, a genuine device assertion of the
// same shape verifies too — the math is identical.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { verifyWebAuthnSignoff } from '../packages/verify/index.js';
import {
  canonicalize,
  buildAuthorizationContext,
  contextHashBytes,
  coseToSpkiP256,
} from '../lib/webauthn.js';
import { canonicalize as sharedCanonicalize } from '../lib/canonical-json.js';
import { Encoder } from 'cbor-x';

const RP_ID = 'emiliaprotocol.ai';

function makeContext(overrides: any = {}): any {
  return buildAuthorizationContext({
    actionHash: 'a'.repeat(64),
    policyId: 'policy_default_large_payment_release',
    policyHash: 'b'.repeat(64),
    initiatorId: 'ent_agent_recon_7',
    approverId: 'ep:approver:jchen-controller',
    signoffId: `sig_${'c'.repeat(32)}`,
    issuedAt: '2026-06-09T17:21:05.000Z',
    expiresAt: '2026-06-09T17:26:05.000Z',
    decision: 'approved',
    ...overrides,
  });
}

/** Build a real assertion over the context with a local P-256 key. */
function makeAssertion(context: any, { flags = 0x05, counter = 9, rpId = RP_ID, type = 'webauthn.get' }: { flags?: number; counter?: number; rpId?: string; type?: string } = {}): any {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

  const challenge = contextHashBytes(context).toString('base64url');
  const clientData = Buffer.from(JSON.stringify({
    type,
    challenge,
    origin: 'https://www.emiliaprotocol.ai',
    crossOrigin: false,
  }), 'utf8');

  const authData = Buffer.concat([
    crypto.createHash('sha256').update(rpId, 'utf8').digest(), // rpIdHash
    Buffer.from([flags]),                                      // UP|UV = 0x05
    (() => { const b = Buffer.alloc(4); b.writeUInt32BE(counter); return b; })(),
  ]);

  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signedData, privateKey); // DER ECDSA

  return {
    signoff: {
      context,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature: signature.toString('base64url'),
      },
    },
    spkiB64u: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    privateKey,
    publicKey,
  };
}

describe('verifyWebAuthnSignoff — offline Class A verification', () => {
  it('verifies a valid assertion end-to-end (challenge binding, flags, signature)', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context);
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.checks.challenge_binding).toBe(true);
    expect(result.checks.client_data_type).toBe(true);
    expect(result.checks.user_present).toBe(true);
    expect(result.checks.user_verified).toBe(true);
    expect(result.checks.rp_id_hash).toBe(true);
    expect(result.checks.signature).toBe(true);
    expect(result.valid).toBe(true);
  });

  it('FAILS when the context is tampered (action hash changed after signing)', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context);
    signoff.context = { ...context, action_hash: 'f'.repeat(64) }; // the forge
    const result = verifyWebAuthnSignoff(signoff, spkiB64u);
    expect(result.checks.challenge_binding).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('verifies a device-signed denial as the co-equal terminal outcome', () => {
    const context = makeContext({ decision: 'denied' });
    const { signoff, spkiB64u } = makeAssertion(context);
    expect(verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID }).valid).toBe(true);
    expect(signoff.context.decision).toBe('denied');
  });

  it('FAILS when a signed denial is relabeled as approval after signing', () => {
    const context = makeContext({ decision: 'denied' });
    const { signoff, spkiB64u } = makeAssertion(context);
    signoff.context = { ...context, decision: 'approved' };
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.checks.challenge_binding).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('FAILS when the nonce is tampered (replay against a different attempt)', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context);
    signoff.context = { ...context, nonce: `sig_${'d'.repeat(32)}` };
    expect(verifyWebAuthnSignoff(signoff, spkiB64u).valid).toBe(false);
  });

  it('FAILS when user verification bit is unset (no biometric/PIN)', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context, { flags: 0x01 }); // UP only
    const result = verifyWebAuthnSignoff(signoff, spkiB64u);
    expect(result.checks.user_verified).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('FAILS when ceremony type is registration, not assertion', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context, { type: 'webauthn.create' });
    const result = verifyWebAuthnSignoff(signoff, spkiB64u);
    expect(result.checks.client_data_type).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('FAILS against the wrong approver key', () => {
    const context = makeContext();
    const { signoff } = makeAssertion(context);
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const wrongKey = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = verifyWebAuthnSignoff(signoff, wrongKey);
    expect(result.checks.signature).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('FAILS rp scope check for a different relying party', () => {
    const context = makeContext();
    const { signoff, spkiB64u } = makeAssertion(context, { rpId: 'evil.example' });
    const result = verifyWebAuthnSignoff(signoff, spkiB64u, { rpId: RP_ID });
    expect(result.checks.rp_id_hash).toBe(false);
    expect(result.valid).toBe(false);
  });
});

describe('authEntityId — actor identity is a string, never the entity row', () => {
  it('derives the same id from a row object and a string mock (SoD comparability)', async () => {
    const { authEntityId } = await import('../lib/supabase.js');
    const row = { id: 'uuid-1', entity_id: 'agent-recon-7', api_key_hash: 'x', private_key_encrypted: 'y' };
    // The bug this guards against: `auth.entity === initiatorId` compared an
    // OBJECT to a string — always false — so self-approval never 403'd.
    expect(authEntityId({ entity: row })).toBe('agent-recon-7');
    expect(authEntityId({ entity: 'agent-recon-7' })).toBe('agent-recon-7');
    expect(authEntityId({ entity: row })).toBe(authEntityId({ entity: 'agent-recon-7' }));
    expect(typeof authEntityId({ entity: row })).toBe('string');
  });
});

describe('lib/webauthn helpers', () => {
  it('rejects non-canonical signed decision values', () => {
    expect(() => makeContext({ decision: 'rejected' })).toThrow(/approved, denied/);
  });

  it('challenge is single-use by construction: nonce inside the hashed context', () => {
    const a = makeContext({ signoffId: `sig_${'1'.repeat(32)}` });
    const b = makeContext({ signoffId: `sig_${'2'.repeat(32)}` });
    expect(contextHashBytes(a).equals(contextHashBytes(b))).toBe(false);
  });

  it('approval and denial produce different device challenges for the same action', () => {
    const approved = makeContext({ decision: 'approved' });
    const denied = makeContext({ decision: 'denied' });
    expect(contextHashBytes(approved).equals(contextHashBytes(denied))).toBe(false);
  });

  it('canonicalize is key-order independent at every depth', () => {
    // The signer (lib/webauthn) and verifier (packages/verify) each
    // canonicalize the context; the end-to-end test above proves they agree
    // byte-for-byte. This pins the key-order independence both rely on.
    const ctx1 = { b: 2, a: 1, nested: { y: [1, 2], x: 'z' } };
    const ctx2 = { nested: { x: 'z', y: [1, 2] }, a: 1, b: 2 };
    expect(canonicalize(ctx1)).toBe(canonicalize(ctx2));
  });

  it('uses the shared canonicalizer and refuses out-of-profile values', () => {
    const context = makeContext();
    expect(canonicalize(context)).toBe(sharedCanonicalize(context));
    expect(() => canonicalize({ omitted: undefined })).toThrow(/canonicalization profile/);
  });

  it('coseToSpkiP256 converts a COSE EC2 key and the result verifies signatures', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = new Map([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(jwk.x, 'base64url')],
      [-3, Buffer.from(jwk.y, 'base64url')],
    ]);
    const coseBytes = new Encoder({ mapsAsObjects: false }).encode(cose);
    const spki = coseToSpkiP256(coseBytes);

    const data = Buffer.from('exact action bytes');
    const sig = crypto.sign('sha256', data, privateKey);
    const rebuilt = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    expect(crypto.verify('sha256', data, rebuilt, sig)).toBe(true);
  });

  it('coseToSpkiP256 rejects non-ES256 keys', () => {
    const cose = new Map([[1, 1], [3, -8], [-1, 6], [-2, Buffer.alloc(32)]]); // OKP/EdDSA
    const coseBytes = new Encoder({ mapsAsObjects: false }).encode(cose);
    expect(() => coseToSpkiP256(coseBytes)).toThrow(/kty|alg/);
  });
});
