// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
  AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
  AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
  AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
  aebNativeAuthorizationReplayKey,
  deriveAebNativeAuthorizationReplayUnit,
  issueAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationHandoff,
} from './aeb.js';

const ACTION = Object.freeze({
  action_type: 'payment.release.1',
  transfer_id: 'transfer-1',
  amount: '500.00',
  currency: 'USD',
});
const PROVIDER = Object.freeze({
  tenant_id: 'tenant:acme',
  provider_id: 'provider:bank',
  provider_account_id: 'account:one',
  environment: 'sandbox',
});
const NOW = '2026-09-24T12:00:10.000Z';

function fixture(overrides = {}) {
  const pair = crypto.generateKeyPairSync('ed25519');
  const gatewayId = overrides.gateway_id ?? 'gateway:authzen-bridge';
  const keyId = 'gateway-key:one';
  const source = {
    system: overrides.system ?? 'authzen',
    profile: overrides.profile ?? 'authzen:exact-action-result:1',
    issuer: overrides.issuer ?? 'https://authz.example',
    authorization_id: overrides.authorization_id ?? 'native-authz:123',
  };
  const pins = {
    '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
    relying_party_id: 'rp:payments',
    audience: 'https://gate.example/payments',
    executor_id: 'executor:gate-1',
    provider: PROVIDER,
    max_handoff_age_seconds: 120,
    max_status_age_seconds: 30,
    clock_skew_seconds: 2,
    gateway_keys: [{
      '@version': AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
      gateway_id: gatewayId,
      key_id: keyId,
      algorithm: 'Ed25519',
      public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    accepted_sources: [{
      '@version': AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
      gateway_id: gatewayId,
      system: source.system,
      profile: source.profile,
      issuer: source.issuer,
    }],
  };
  const input = {
    gateway_id: gatewayId,
    native_authorization: source,
    relying_party_id: pins.relying_party_id,
    audience: pins.audience,
    executor_id: pins.executor_id,
    provider: PROVIDER,
    action: ACTION,
    issued_at: '2026-09-24T12:00:00.000Z',
    not_before: '2026-09-24T12:00:00.000Z',
    expires_at: '2026-09-24T12:01:00.000Z',
    revocation_id: 'revocation:native-authz:123',
  };
  const status = {
    '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
    gateway_id: gatewayId,
    native_authorization: {
      ...source,
      replay_unit: deriveAebNativeAuthorizationReplayUnit(source),
    },
    revocation_id: input.revocation_id,
    checked_at: '2026-09-24T12:00:09.000Z',
    valid_until: '2026-09-24T12:00:30.000Z',
    revoked: false,
  };
  const signer = { key_id: keyId, private_key: pair.privateKey };
  return { pair, pins, input, status, signer };
}

function verify(f, handoff, action = ACTION, overrides = {}) {
  return verifyAebNativeAuthorizationHandoff(handoff, {
    pins: overrides.pins ?? f.pins,
    expected_action: action,
    status: overrides.status ?? f.status,
    now: overrides.now ?? NOW,
  });
}

test('a pinned gateway can hand an exact native PERMIT directly to AEB', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const result = verify(f, handoff);
  assert.equal(result.valid, true, JSON.stringify(result.reasons));
  assert.equal(result.execution_authorizing, true);
  assert.equal(result.handoff.decision, 'PERMIT');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.handoff), true);
  assert.match(result.replay_key, /^aeb-native:sha256:[0-9a-f]{64}$/);
});

test('the replay unit is stable across wrappers and excludes operation identifiers', () => {
  const f = fixture();
  const first = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const second = issueAebNativeAuthorizationHandoff({
    ...f.input,
    issued_at: '2026-09-24T12:00:01.000Z',
  }, f.signer);
  assert.equal(first.native_authorization.replay_unit, second.native_authorization.replay_unit);
  assert.equal(aebNativeAuthorizationReplayKey(first), aebNativeAuthorizationReplayKey(second));
  assert.equal(
    first.native_authorization.replay_unit,
    deriveAebNativeAuthorizationReplayUnit(f.input.native_authorization),
  );
});

test('action substitution is refused even when the handoff signature is valid', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const result = verify(f, handoff, { ...ACTION, amount: '5000.00' });
  assert.equal(result.valid, false);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.exact_action, false);
  assert.deepEqual(result.reasons, ['native_handoff_exact_action_mismatch']);
});

test('signed audience, executor, and provider mutations remain outside relying-party pins', () => {
  for (const [name, change, failedCheck] of [
    ['audience', { audience: 'https://other.example/payments' }, 'audience'],
    ['executor', { executor_id: 'executor:other' }, 'executor'],
    ['provider', { provider: { ...PROVIDER, provider_account_id: 'account:other' } }, 'provider'],
  ]) {
    const f = fixture();
    const handoff = issueAebNativeAuthorizationHandoff({ ...f.input, ...change }, f.signer);
    const result = verify(f, handoff);
    assert.equal(result.valid, false, name);
    assert.equal(result.checks.signature, true, name);
    assert.equal(result.checks[failedCheck], false, name);
  }
});

test('a gateway cannot switch to an unpinned native source profile', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff({
    ...f.input,
    native_authorization: { ...f.input.native_authorization, profile: 'authzen:other:1' },
  }, f.signer);
  const result = verify(f, handoff);
  assert.equal(result.valid, false);
  assert.equal(result.checks.signature, true);
  assert.equal(result.checks.source_pinned, false);
});

test('AIMS and COAZ results use the same direct path under explicit source pins', () => {
  for (const system of ['aims', 'coaz']) {
    const f = fixture({
      system,
      profile: `${system}:exact-action-result:1`,
      issuer: `https://${system}.example`,
    });
    const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
    const result = verify(f, handoff);
    assert.equal(result.valid, true, `${system}: ${JSON.stringify(result.reasons)}`);
    assert.equal(result.handoff.native_authorization.system, system);
  }
});

test('stale and revoked handoffs fail closed', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const stale = verify(f, handoff, ACTION, { now: '2026-09-24T12:02:01.000Z' });
  assert.equal(stale.valid, false);
  assert.equal(stale.checks.freshness, false);

  const revoked = verify(f, handoff, ACTION, {
    status: { ...f.status, revoked: true },
  });
  assert.equal(revoked.valid, false);
  assert.equal(revoked.checks.revocation, false);
  assert.ok(revoked.reasons.includes('native_handoff_revoked'));
});

test('status for a colliding revocation identifier cannot authorize another gateway or source', () => {
  const first = fixture({ authorization_id: 'native-authz:shared' });
  const handoff = issueAebNativeAuthorizationHandoff(first.input, first.signer);

  const wrongGateway = verify(first, handoff, ACTION, {
    status: {
      ...first.status,
      gateway_id: 'gateway:other',
    },
  });
  assert.equal(wrongGateway.valid, false);
  assert.equal(wrongGateway.checks.revocation, false);

  const wrongSource = verify(first, handoff, ACTION, {
    status: {
      ...first.status,
      native_authorization: {
        ...first.status.native_authorization,
        authorization_id: 'native-authz:different',
        replay_unit: deriveAebNativeAuthorizationReplayUnit({
          ...first.input.native_authorization,
          authorization_id: 'native-authz:different',
        }),
      },
    },
  });
  assert.equal(wrongSource.valid, false);
  assert.equal(wrongSource.checks.revocation, false);
});

test('unknown members and signature tampering are refused', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const extra = { ...handoff, authorization_hint: 'allow' };
  assert.equal(verify(f, extra).checks.schema, false);

  const tampered = structuredClone(handoff);
  tampered.signature.value = `${tampered.signature.value[0] === 'A' ? 'B' : 'A'}${tampered.signature.value.slice(1)}`;
  const result = verify(f, tampered);
  assert.equal(result.valid, false);
  assert.equal(result.checks.signature, false);
});

test('an unknown runtime verification mode fails closed', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const result = verifyAebNativeAuthorizationHandoff(handoff, {
    pins: f.pins,
    expected_action: ACTION,
    status: f.status,
    now: NOW,
    mode: 'garbage',
  });
  assert.equal(result.valid, false);
  assert.equal(result.execution_authorizing, false);
  assert.equal(result.mode, 'execution');
  assert.ok(result.reasons.includes('native_handoff_mode_invalid'));
});
