/**
 * Secure App security-boundary regression tests.
 *
 *   node --test apps/secure-app/lib/ep-signoff.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { canonicalize, challengeFromContext, buildAttestation } from './ep-signoff.js';
import {
  assertSoftwareSignerAllowed,
  authenticateForPolicy,
  authorizationHeadersForSession,
  createPairedSessionVault,
  normalizeSigningPolicy,
  validatePairedSession,
} from './security-boundary.mjs';
import { verifyWebAuthnSignoff } from '../../../packages/verify/index.js';

const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';
const NOW = Date.parse('2026-07-29T12:00:00Z');

function authenticatorFixture({ flags = 0x05 } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubSpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

  function assert_(challenge) {
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }), 'utf8');
    const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
    const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.alloc(4)]);
    const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
    const signature = crypto.sign('sha256', signedData, privateKey);
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
  not_after: '2026-12-11T13:00:00Z',
});

const pairedSession = () => ({
  accessToken: `ep_mobile_${'A'.repeat(43)}`,
  expiresAt: '2026-07-30T12:00:00Z',
  approverId: 'ep:approver:case-supervisor',
  profileId: 'agency.high-assurance.mobile.v1',
  platform: 'ios',
  appId: 'ai.emiliaprotocol.secure',
});

test('canonicalize matches the verifier recursive key sort', () => {
  assert.equal(canonicalize({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
});

test('client evidence binds the context but never assigns its own assurance class', async () => {
  const authenticator = authenticatorFixture();
  const context = sampleContext();
  const webauthn = authenticator.assert_(await challengeFromContext(context));
  const attestation = buildAttestation({
    context,
    webauthn,
    approverId: 'approver@example.com',
    keyClass: 'A', // hostile caller input must not become evidence
  });

  assert.deepEqual(Object.keys(attestation).sort(), ['@version', 'approver_id', 'context', 'webauthn']);
  assert.equal(Object.hasOwn(attestation, 'key_class'), false);

  const result = verifyWebAuthnSignoff(
    { context: attestation.context, webauthn: attestation.webauthn },
    authenticator.pubSpkiB64u,
    { rpId: RP_ID }
  );
  assert.equal(result.valid, true, JSON.stringify(result));
  assert.equal(result.checks.challenge_binding, true);
  assert.equal(result.checks.signature, true);
});

test('an exportable software signature cannot synthesize WebAuthn user presence or verification', async () => {
  const software = authenticatorFixture({ flags: 0x00 });
  const context = sampleContext();
  const webauthn = software.assert_(await challengeFromContext(context));
  const result = verifyWebAuthnSignoff({ context, webauthn }, software.pubSpkiB64u, { rpId: RP_ID });

  assert.equal(result.valid, false);
  assert.equal(result.checks.challenge_binding, true);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.user_present, false);
  assert.equal(result.checks.user_verified, false);
});

test('a tampered context fails challenge binding', async () => {
  const authenticator = authenticatorFixture();
  const context = sampleContext();
  const webauthn = authenticator.assert_(await challengeFromContext(context));
  const tampered = { ...context, action: { ...context.action, amount: 1 } };
  const result = verifyWebAuthnSignoff({ context: tampered, webauthn }, authenticator.pubSpkiB64u, { rpId: RP_ID });
  assert.equal(result.valid, false);
  assert.equal(result.checks.challenge_binding, false);
});

test('a signoff from a different key does not verify', async () => {
  const signer = authenticatorFixture();
  const other = authenticatorFixture();
  const context = sampleContext();
  const webauthn = signer.assert_(await challengeFromContext(context));
  const result = verifyWebAuthnSignoff({ context, webauthn }, other.pubSpkiB64u, { rpId: RP_ID });
  assert.equal(result.valid, false);
});

test('software mode requires an explicit policy and refuses hardware provenance requirements', () => {
  assert.throws(() => normalizeSigningPolicy(undefined), /explicitly choose/);
  assert.throws(
    () => assertSoftwareSignerAllowed({
      requiredKeyProvenance: 'hardware_attested_required',
      userVerification: 'biometric_only',
    }),
    /hardware_provenance_required/
  );
  assert.deepEqual(
    assertSoftwareSignerAllowed({
      requiredKeyProvenance: 'software_allowed',
      userVerification: 'biometric_only',
    }),
    { requiredKeyProvenance: 'software_allowed', userVerification: 'biometric_only' }
  );
});

test('biometric-only policy disables passcode fallback and requires enrolled hardware', async () => {
  let options = null;
  const localAuthentication = {
    hasHardwareAsync: async () => true,
    isEnrolledAsync: async () => true,
    getEnrolledLevelAsync: async () => 3,
    authenticateAsync: async (input) => { options = input; return { success: true }; },
  };
  const result = await authenticateForPolicy(localAuthentication, {
    requiredKeyProvenance: 'software_allowed',
    userVerification: 'biometric_only',
  });
  assert.deepEqual(result, { ok: true, method: 'biometric', policy: 'biometric_only' });
  assert.equal(options.disableDeviceFallback, true);
  assert.equal(options.fallbackLabel, '');
  assert.equal(options.biometricsSecurityLevel, 'strong');

  const refused = await authenticateForPolicy({
    ...localAuthentication,
    isEnrolledAsync: async () => false,
  }, {
    requiredKeyProvenance: 'software_allowed',
    userVerification: 'biometric_only',
  });
  assert.deepEqual(refused, { ok: false, reason: 'no_biometric_enrolled' });
});

test('passcode-capable policy uses device-owner authentication without claiming which factor succeeded', async () => {
  let options = null;
  const result = await authenticateForPolicy({
    hasHardwareAsync: async () => false,
    isEnrolledAsync: async () => false,
    getEnrolledLevelAsync: async () => 1,
    authenticateAsync: async (input) => { options = input; return { success: true }; },
  }, {
    requiredKeyProvenance: 'software_allowed',
    userVerification: 'biometric_or_device_passcode',
  });
  assert.deepEqual(result, {
    ok: true,
    method: 'device_owner_authentication',
    policy: 'biometric_or_device_passcode',
  });
  assert.equal(options.disableDeviceFallback, false);
  assert.equal(options.fallbackLabel, 'Use device passcode');
});

test('paired sessions fail closed when missing, malformed, expired, or client-extended', () => {
  assert.equal(validatePairedSession(null, NOW), null);
  assert.equal(validatePairedSession({ ...pairedSession(), accessToken: 'public-build-token' }, NOW), null);
  assert.equal(validatePairedSession({ ...pairedSession(), expiresAt: '2026-07-29T11:59:59Z' }, NOW), null);
  assert.equal(validatePairedSession({ ...pairedSession(), key_class: 'A' }, NOW), null);
  assert.throws(() => authorizationHeadersForSession(null, NOW), /paired_mobile_session_required/);
  assert.deepEqual(authorizationHeadersForSession(pairedSession(), NOW), {
    authorization: `Bearer ep_mobile_${'A'.repeat(43)}`,
  });
});

test('session vault stores only valid runtime sessions and clears corrupt or expired records', async () => {
  const records = new Map();
  let clock = NOW;
  const secureStore = {
    getItemAsync: async (key) => records.get(key) ?? null,
    setItemAsync: async (key, value) => { records.set(key, value); },
    deleteItemAsync: async (key) => { records.delete(key); },
  };
  const vault = createPairedSessionVault({ secureStore, now: () => clock });
  await vault.save(pairedSession());
  assert.deepEqual(await vault.load(), pairedSession());

  clock = Date.parse('2026-07-31T00:00:00Z');
  assert.equal(await vault.load(), null);
  assert.equal(records.size, 0);

  records.set('ep_secure_app_mobile_session_v1', '{not-json');
  assert.equal(await vault.load(), null);
  assert.equal(records.size, 0);
});

test('owned source has no bundled bearer credential or live software-key submit path', async () => {
  const paths = [
    new URL('../App.tsx', import.meta.url),
    new URL('../README.md', import.meta.url),
    new URL('./ep-client.ts', import.meta.url),
    new URL('./secure-key.ts', import.meta.url),
    new URL('./ep-signoff.ts', import.meta.url),
  ];
  const source = (await Promise.all(paths.map((path) => readFile(path, 'utf8')))).join('\n');
  assert.doesNotMatch(source, /EXPO_PUBLIC_EP_TOKEN/);
  assert.doesNotMatch(source, /\/api\/v1\/signoffs/);
  assert.doesNotMatch(source, /key_class\s*:\s*['"]A['"]/);
  assert.doesNotMatch(source, /authData\[32\]\s*=\s*0x05/);
  assert.match(source, /hardware_attested_required/);
  assert.match(source, /WHEN_UNLOCKED_THIS_DEVICE_ONLY/);
});
