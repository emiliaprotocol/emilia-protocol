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

function withSources(f, sources) {
  return { ...f.pins, accepted_sources: sources };
}

function sourcePin(f, overrides = {}) {
  return { ...f.pins.accepted_sources[0], ...overrides };
}

test('one native grant relabelled under a second pinned profile or system keeps one replay identity', () => {
  // Regression for the C2 probe: the v1 replay unit hashed system and profile,
  // so the relabelled grant derived a second replay key and spent twice.
  for (const relabel of [
    { profile: 'authzen:exact-action-result:2' },
    { system: 'coaz', profile: 'coaz:exact-action-result:1' },
  ]) {
    const f = fixture();
    const pins = withSources(f, [f.pins.accepted_sources[0], sourcePin(f, relabel)]);
    const original = issueAebNativeAuthorizationHandoff(f.input, f.signer);
    const relabelled = issueAebNativeAuthorizationHandoff({
      ...f.input,
      native_authorization: { ...f.input.native_authorization, ...relabel },
    }, f.signer);
    const first = verify(f, original, ACTION, { pins });
    const second = verifyAebNativeAuthorizationHandoff(relabelled, {
      pins,
      expected_action: ACTION,
      status: { ...f.status, native_authorization: relabelled.native_authorization },
      now: NOW,
    });
    assert.equal(first.valid, true, JSON.stringify(first.reasons));
    assert.equal(second.valid, true, JSON.stringify(second.reasons));
    assert.equal(original.native_authorization.replay_unit, relabelled.native_authorization.replay_unit);
    assert.equal(first.native_replay_unit, second.native_replay_unit);
    assert.equal(first.replay_key, second.replay_key);
    assert.equal(aebNativeAuthorizationReplayKey(original), aebNativeAuthorizationReplayKey(relabelled));
  }
});

test('the replay unit is derived from the authority namespace, issuer, and authorization ID only', () => {
  const f = fixture();
  const base = f.input.native_authorization;
  const unit = deriveAebNativeAuthorizationReplayUnit(base);
  assert.equal(unit, deriveAebNativeAuthorizationReplayUnit({ ...base, system: 'oauth', profile: 'oauth:other:1' }));
  assert.equal(unit, deriveAebNativeAuthorizationReplayUnit(base, { authority_namespace: base.issuer }));
  assert.notEqual(unit, deriveAebNativeAuthorizationReplayUnit({ ...base, issuer: 'https://other.example' }));
  assert.notEqual(unit, deriveAebNativeAuthorizationReplayUnit({ ...base, authorization_id: 'native-authz:124' }));
  assert.notEqual(unit, deriveAebNativeAuthorizationReplayUnit(base, { authority_namespace: 'namespace:grants' }));
  assert.throws(
    () => deriveAebNativeAuthorizationReplayUnit(base, { authority_namespace: '' }),
    /valid native authority namespace required/,
  );
});

test('a pinned authority namespace scopes the replay identity; mixed or duplicate pins are refused', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const relabelled = issueAebNativeAuthorizationHandoff({
    ...f.input,
    native_authorization: { ...f.input.native_authorization, profile: 'authzen:exact-action-result:2' },
  }, f.signer);
  const relabelledStatus = { ...f.status, native_authorization: relabelled.native_authorization };

  const shared = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:shared' }),
    sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:shared' }),
  ]);
  const sharedFirst = verify(f, handoff, ACTION, { pins: shared });
  const sharedSecond = verify(f, relabelled, ACTION, { pins: shared, status: relabelledStatus });
  assert.equal(sharedFirst.valid, true, JSON.stringify(sharedFirst.reasons));
  assert.equal(sharedFirst.replay_key, sharedSecond.replay_key);
  assert.equal(sharedFirst.replay_key, aebNativeAuthorizationReplayKey({
    ...handoff,
    authority_namespace: 'namespace:shared',
  }));
  assert.notEqual(sharedFirst.native_replay_unit, handoff.native_authorization.replay_unit);

  const distinct = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:decisions' }),
    sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:grants' }),
  ]);
  const distinctFirst = verify(f, handoff, ACTION, { pins: distinct });
  const distinctSecond = verify(f, relabelled, ACTION, { pins: distinct, status: relabelledStatus });
  assert.equal(distinctFirst.valid, true);
  assert.equal(distinctSecond.valid, true);
  assert.notEqual(distinctFirst.replay_key, distinctSecond.replay_key);

  for (const [name, sources] of [
    ['mixed', [
      sourcePin(f),
      sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:grants' }),
    ]],
    ['duplicate-identity', [
      sourcePin(f, { authority_namespace: 'namespace:decisions' }),
      sourcePin(f, { authority_namespace: 'namespace:grants' }),
    ]],
    ['invalid-namespace', [sourcePin(f, { authority_namespace: '' })]],
  ]) {
    const result = verify(f, handoff, ACTION, { pins: withSources(f, sources) });
    assert.equal(result.valid, false, name);
    assert.equal(result.checks.schema, false, name);
    assert.equal(result.replay_key, null, name);
    assert.ok(result.reasons.includes('native_handoff_schema_invalid'), name);
  }
});

test('an unpinned source establishes no replay identity', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff({
    ...f.input,
    native_authorization: { ...f.input.native_authorization, profile: 'authzen:other:1' },
  }, f.signer);
  const result = verify(f, handoff);
  assert.equal(result.checks.source_pinned, false);
  assert.equal(result.native_replay_unit, null);
  assert.equal(result.replay_key, null);
});

test('hostile in-process inputs refuse with a reason instead of throwing', () => {
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const base = { pins: f.pins, expected_action: ACTION, status: f.status, now: NOW };
  const sparseKeys = [f.pins.gateway_keys[0]];
  sparseKeys.length = 2;
  const sparseSources = [f.pins.accepted_sources[0]];
  sparseSources.length = 2;
  const trapHandoff = new Proxy(structuredClone(handoff), {
    get(target, key) {
      if (key === 'signature') throw new Error('trap');
      return target[key];
    },
    getOwnPropertyDescriptor(target, key) {
      if (key === 'signature') throw new Error('trap');
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  const modeGetter = Object.defineProperty({ ...base }, 'mode', {
    get() { throw new Error('mode getter'); },
    enumerable: true,
  });
  const pinsGetter = Object.defineProperty({ ...base }, 'pins', {
    get() { return f.pins; },
    enumerable: true,
  });
  const protoPins = JSON.parse(`{"__proto__":{"a":1},${JSON.stringify(f.pins).slice(1)}`);
  // Faithful to descriptor reads, hostile on [[Get]]: still refused.
  const getTrapHandoff = new Proxy(structuredClone(handoff), {
    get(target, key) {
      if (key === 'signature') throw new Error('trap');
      return target[key];
    },
  });
  const proxyOptions = new Proxy({ ...base }, {});
  const proxyAction = new Proxy({ ...ACTION }, {});
  const cases = {
    getTrapHandoff: [getTrapHandoff, base, 'native_handoff_schema_invalid'],
    proxyOptions: [handoff, proxyOptions, 'native_handoff_options_invalid'],
    proxyAction: [handoff, { ...base, expected_action: proxyAction }, 'native_handoff_expected_action_invalid'],
    sparseGatewayKeys: [handoff, { ...base, pins: { ...f.pins, gateway_keys: sparseKeys } }, 'native_handoff_schema_invalid'],
    sparseSources: [handoff, { ...base, pins: { ...f.pins, accepted_sources: sparseSources } }, 'native_handoff_schema_invalid'],
    trapHandoff: [trapHandoff, base, 'native_handoff_schema_invalid'],
    modeGetter: [handoff, modeGetter, 'native_handoff_options_invalid'],
    pinsGetter: [handoff, pinsGetter, 'native_handoff_options_invalid'],
    protoPins: [handoff, { ...base, pins: protoPins }, 'native_handoff_schema_invalid'],
    nullOptions: [handoff, null, 'native_handoff_schema_invalid'],
  };
  for (const [name, [value, options, reason]] of Object.entries(cases)) {
    let result;
    assert.doesNotThrow(() => { result = verifyAebNativeAuthorizationHandoff(value, options); }, name);
    assert.equal(result.valid, false, name);
    assert.equal(result.execution_authorizing, false, name);
    assert.ok(result.reasons.includes(reason), `${name}: ${JSON.stringify(result.reasons)}`);
  }
});
