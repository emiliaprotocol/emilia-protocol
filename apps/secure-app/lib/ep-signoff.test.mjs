/**
 * Secure App signoff core — round-trip proof.
 *
 * Proves the Class-A signoff this app produces verifies offline under the
 * protocol's own verifier (@emilia-protocol/verify), with no special-casing:
 * the app computes the challenge, a software authenticator (standing in for the
 * device secure enclave) signs it WebAuthn-style, and verifyWebAuthnSignoff
 * accepts it — and rejects a tampered context.
 *
 *   node --test apps/secure-app/lib/ep-signoff.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize, challengeFromContext, buildAttestation } from './ep-signoff.ts';
import { verifyWebAuthnSignoff } from '../../../packages/verify/index.js';

const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';

// A software authenticator: signs the app's challenge exactly as a WebAuthn
// platform authenticator would (authData = rpIdHash|flags|signCount, signature
// over authData||SHA-256(clientDataJSON)). On a real device this is the OS
// secure enclave; here it is a P-256 key in node crypto.
function softwareAuthenticator() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubSpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

  function assert_(challenge) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }), 'utf8');
    const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
    const flags = Buffer.from([0x05]); // UP | UV
    const signCount = Buffer.from([0, 0, 0, 0]);
    const authData = Buffer.concat([rpIdHash, flags, signCount]);
    const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
    const signature = crypto.sign('sha256', signedData, privateKey); // DER ECDSA
    return {
      authenticator_data: authData.toString('base64url'),
      client_data_json: clientDataJSON.toString('base64url'),
      signature: signature.toString('base64url'),
    };
  }
  return { pubSpkiB64u, assert_ };
}

const sampleContext = () => ({
  '@version': 'EP-CONTEXT-v1',
  action: { type: 'fin/payment-release', amount: 1_400_000, currency: 'USD' },
  approver: 'approver@example.com',
  nonce: 'a1b2c3d4',
  not_after: '2026-06-11T13:00:00Z',
});

test('canonicalize matches the verifier (recursive key sort)', () => {
  expect_eq(canonicalize({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
});

test('the app produces a Class-A signoff that verifies offline', async () => {
  const auth = softwareAuthenticator();
  const context = sampleContext();

  const challenge = await challengeFromContext(context);
  const webauthn = auth.assert_(challenge);
  const attestation = buildAttestation({ context, webauthn, approverId: 'approver@example.com' });

  // The attestation the app would POST to the gate, verified by EP's own verifier.
  const result = verifyWebAuthnSignoff({ context: attestation.context, webauthn: attestation.webauthn }, auth.pubSpkiB64u, { rpId: RP_ID });
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.challenge_binding, true);
  assert.equal(result.checks.user_present, true);
  assert.equal(result.checks.user_verified, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.rp_id_hash, true);
});

test('a tampered context fails the challenge binding', async () => {
  const auth = softwareAuthenticator();
  const context = sampleContext();
  const challenge = await challengeFromContext(context);
  const webauthn = auth.assert_(challenge);

  // Relying party flips the amount AFTER the device signed.
  const tampered = { ...context, action: { ...context.action, amount: 1 } };
  const result = verifyWebAuthnSignoff({ context: tampered, webauthn }, auth.pubSpkiB64u, { rpId: RP_ID });
  assert.equal(result.valid, false);
  assert.equal(result.checks.challenge_binding, false);
});

test('a signoff from a different key does not verify', async () => {
  const signer = softwareAuthenticator();
  const other = softwareAuthenticator();
  const context = sampleContext();
  const challenge = await challengeFromContext(context);
  const webauthn = signer.assert_(challenge);

  const result = verifyWebAuthnSignoff({ context, webauthn }, other.pubSpkiB64u, { rpId: RP_ID });
  assert.equal(result.valid, false);
});

function expect_eq(a, b) { assert.equal(a, b); }
