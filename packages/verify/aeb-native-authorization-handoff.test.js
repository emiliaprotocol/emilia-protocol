// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import {
  AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
  AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION,
  AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
  AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN,
  AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
  AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
  aebNativeAuthorizationReplayIdentityKey,
  aebNativeAuthorizationReplayKey,
  deriveAebNativeAuthorizationReplayIdentity,
  deriveAebNativeAuthorizationReplayUnit,
  issueAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationHandoff,
  verifyAebNativeAuthorizationPins,
} from './aeb.js';
import {
  AEB_ISSUER_COMPARISON_MAX_LENGTH,
  aebIssuerComparisonForm,
} from './dist/aeb-issuer-comparison.js';

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
  assert.match(result.replay_identity_key, /^aeb-native:sha256:[0-9a-f]{64}$/);
  assert.notEqual(result.replay_identity_key, result.replay_key);
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
    // The signed wire replay_unit and the 4.1.0 replay_key keep the
    // label-bearing derivation for compatibility, so they differ; the
    // label-free enforcement identity and its key do not.
    assert.notEqual(original.native_authorization.replay_unit, relabelled.native_authorization.replay_unit);
    assert.notEqual(first.native_replay_unit, second.native_replay_unit);
    assert.notEqual(first.replay_key, second.replay_key);
    assert.equal(first.native_replay_identity, second.native_replay_identity);
    assert.equal(first.replay_identity_key, second.replay_identity_key);
    assert.equal(
      aebNativeAuthorizationReplayIdentityKey(original),
      aebNativeAuthorizationReplayIdentityKey(relabelled),
    );
    assert.equal(first.replay_identity_key, aebNativeAuthorizationReplayIdentityKey(original));
  }
});

test('the replay identity is (authority namespace, authorization ID); the wire unit stays the 4.1.0 digest', () => {
  const f = fixture();
  const base = f.input.native_authorization;
  const identity = deriveAebNativeAuthorizationReplayIdentity(base);
  assert.equal(identity, deriveAebNativeAuthorizationReplayIdentity({ ...base, system: 'oauth', profile: 'oauth:other:1' }));
  assert.equal(identity, deriveAebNativeAuthorizationReplayIdentity(base, { authority_namespace: base.issuer }));
  assert.notEqual(identity, deriveAebNativeAuthorizationReplayIdentity({ ...base, issuer: 'https://other.example' }));
  assert.notEqual(identity, deriveAebNativeAuthorizationReplayIdentity({ ...base, authorization_id: 'native-authz:124' }));
  // A declared namespace replaces the issuer string: two spellings of one
  // issuer under one declared namespace derive one identity.
  const declared = deriveAebNativeAuthorizationReplayIdentity(base, { authority_namespace: 'namespace:grants' });
  assert.notEqual(identity, declared);
  assert.equal(declared, deriveAebNativeAuthorizationReplayIdentity(
    { ...base, issuer: `${base.issuer}/` },
    { authority_namespace: 'namespace:grants' },
  ));
  assert.throws(
    () => deriveAebNativeAuthorizationReplayIdentity(base, { authority_namespace: '' }),
    /valid native authority namespace required/,
  );
  // Wire unit: the verify 4.1.0 digest over all four labels, recomputed here
  // independently of the module under test.
  const wire = deriveAebNativeAuthorizationReplayUnit(base);
  const canonical = JSON.stringify({
    authorization_id: base.authorization_id,
    issuer: base.issuer,
    profile: base.profile,
    system: base.system,
  });
  assert.equal(AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN, 'AEB-NATIVE-AUTHORIZATION-REPLAY-v1');
  assert.equal(wire, `sha256:${crypto.createHash('sha256')
    .update(`${AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN}\0${canonical}`, 'utf8').digest('hex')}`);
  assert.notEqual(wire, deriveAebNativeAuthorizationReplayUnit({ ...base, profile: 'authzen:exact-action-result:2' }));
  assert.notEqual(wire, identity);
  // Both replay keys, recomputed independently: the 4.1.0 key over the wire
  // unit keeps REPLAY-KEY-v1, and the identity key uses REPLAY-KEY-v2.
  assert.equal(AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN, 'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1');
  assert.equal(AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN, 'AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2');
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const keyOver = (domain, unit) => `aeb-native:sha256:${crypto.createHash('sha256')
    .update(`${domain}\0${JSON.stringify({ relying_party_id: 'rp:payments', replay_unit: unit })}`, 'utf8')
    .digest('hex')}`;
  assert.equal(aebNativeAuthorizationReplayKey(handoff), keyOver(AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN, wire));
  assert.equal(
    aebNativeAuthorizationReplayIdentityKey(handoff),
    keyOver(AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_KEY_DOMAIN, identity),
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
  assert.equal(sharedFirst.replay_identity_key, sharedSecond.replay_identity_key);
  assert.equal(sharedFirst.replay_identity_key, aebNativeAuthorizationReplayIdentityKey({
    ...handoff,
    authority_namespace: 'namespace:shared',
  }));
  assert.notEqual(sharedFirst.native_replay_identity, handoff.native_authorization.replay_unit);
  assert.equal(sharedFirst.native_replay_unit, handoff.native_authorization.replay_unit);

  // R7: one exact issuer under two declared namespaces would give one grant
  // two replay identities, so the pin set is refused like aliased spellings.
  const distinct = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:decisions' }),
    sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:grants' }),
  ]);
  assert.deepEqual(verifyAebNativeAuthorizationPins(distinct).reasons, ['native_pins_issuer_namespace_conflict']);
  for (const [candidate, status] of [[handoff, f.status], [relabelled, relabelledStatus]]) {
    const refused = verify(f, candidate, ACTION, { pins: distinct, status });
    assert.equal(refused.valid, false);
    assert.equal(refused.replay_identity_key, null);
    assert.ok(refused.reasons.includes('native_handoff_schema_invalid'));
  }

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
    assert.equal(result.native_replay_identity, null, name);
    assert.equal(result.replay_identity_key, null, name);
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
  assert.equal(result.native_replay_identity, null);
  assert.equal(result.replay_identity_key, null);
  // The 4.1.0 fields are reported exactly as 4.1.0 reported them.
  assert.equal(result.native_replay_unit, handoff.native_authorization.replay_unit);
  assert.equal(result.replay_key, aebNativeAuthorizationReplayKey(handoff));
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

// ---------------------------------------------------------------------------
// Wire compatibility with @emilia-protocol/verify 4.1.0 and issuer aliasing.
// ---------------------------------------------------------------------------

// Issued by verify 4.1.0 (git tag verify-v4.1.0, dist/aeb-native-authorization-
// handoff.js) from COMPAT_INPUT with the Ed25519 key whose PKCS#8 seed is 32
// bytes of 0x07. Ed25519 signatures are deterministic, so the same input and
// key must reproduce these exact bytes.
const COMPAT_4_1_0_HANDOFF = Object.freeze({
  '@version': 'AEB-NATIVE-AUTHORIZATION-HANDOFF-v1',
  action_digest: 'sha256:da47a2da5c5f8e385353521f008e832fdfb52e466872f422a58b41970563ad0a',
  audience: 'https://gate.example/payments',
  decision: 'PERMIT',
  executor_id: 'executor:gate-1',
  expires_at: '2026-08-09T12:01:00.000Z',
  gateway_id: 'gateway:authzen',
  issued_at: '2026-08-09T12:00:00.000Z',
  native_authorization: {
    authorization_id: 'native-authz:authzen:123',
    issuer: 'https://authzen.example',
    profile: 'authzen:exact-action-result:1',
    replay_unit: 'sha256:b803b5d2619ebb90e2322aba7e2354f56ebe3287b95f78ab91af44e3e613c45a',
    system: 'authzen',
  },
  not_before: '2026-08-09T12:00:00.000Z',
  provider: {
    environment: 'sandbox',
    provider_account_id: 'account:one',
    provider_id: 'provider:bank',
    tenant_id: 'tenant:acme',
  },
  relying_party_id: 'rp:payments',
  revocation_id: 'revocation:authzen:123',
  signature: {
    alg: 'Ed25519',
    key_id: 'gateway-key:authzen:one',
    value: '9JVw3k8ls5lWHChX7GgIsqosdHwn8p7GjWFouvM-nJzEE66GCkf0Rg19RPwKexmDK0GwLCZMnwpg-o3E_R-3Ag',
  },
});
// verify 4.1.0's replay_key for the vector (REPLAY-KEY-v1 over the wire unit).
const COMPAT_4_1_0_REPLAY_KEY = 'aeb-native:sha256:2f64c162dd220199523fbef58b8614fc77d6ea6e39e19bc18842f6c7960b93a7';

function compatFixture() {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const provider = {
    tenant_id: 'tenant:acme',
    provider_id: 'provider:bank',
    provider_account_id: 'account:one',
    environment: 'sandbox',
  };
  const action = {
    action_type: 'payment.release.1',
    transfer_id: 'transfer-1',
    amount: '500.00',
    currency: 'USD',
  };
  const input = {
    gateway_id: 'gateway:authzen',
    native_authorization: {
      system: 'authzen',
      profile: 'authzen:exact-action-result:1',
      issuer: 'https://authzen.example',
      authorization_id: 'native-authz:authzen:123',
    },
    relying_party_id: 'rp:payments',
    audience: 'https://gate.example/payments',
    executor_id: 'executor:gate-1',
    provider,
    action,
    issued_at: '2026-08-09T12:00:00.000Z',
    not_before: '2026-08-09T12:00:00.000Z',
    expires_at: '2026-08-09T12:01:00.000Z',
    revocation_id: 'revocation:authzen:123',
  };
  const pins = {
    '@version': AEB_NATIVE_AUTHORIZATION_PINS_VERSION,
    relying_party_id: 'rp:payments',
    audience: 'https://gate.example/payments',
    executor_id: 'executor:gate-1',
    provider,
    max_handoff_age_seconds: 120,
    max_status_age_seconds: 30,
    clock_skew_seconds: 2,
    gateway_keys: [{
      '@version': AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION,
      gateway_id: 'gateway:authzen',
      key_id: 'gateway-key:authzen:one',
      algorithm: 'Ed25519',
      public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    }],
    accepted_sources: [{
      '@version': AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION,
      gateway_id: 'gateway:authzen',
      system: 'authzen',
      profile: 'authzen:exact-action-result:1',
      issuer: 'https://authzen.example',
    }],
  };
  const statusFor = (handoff) => ({
    '@version': AEB_NATIVE_AUTHORIZATION_STATUS_VERSION,
    gateway_id: handoff.gateway_id,
    native_authorization: handoff.native_authorization,
    revocation_id: handoff.revocation_id,
    checked_at: '2026-08-09T12:00:00.000Z',
    valid_until: '2026-08-09T12:00:30.000Z',
    revoked: false,
  });
  return {
    input,
    pins,
    action,
    statusFor,
    signer: { key_id: 'gateway-key:authzen:one', private_key: privateKey },
    now: '2026-08-09T12:00:01.000Z',
  };
}

test('a handoff issued by verify 4.1.0 verifies here and this package issues the same bytes', () => {
  // Regression for the wire split: the branch that relabel-hardened the
  // replay identity also changed the signed replay_unit under the same
  // HANDOFF-v1 label, so 4.1.0 and this package refused each other as
  // native_handoff_schema_invalid.
  const c = compatFixture();
  assert.equal(COMPAT_4_1_0_HANDOFF['@version'], AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION);
  const reissued = issueAebNativeAuthorizationHandoff(c.input, c.signer);
  assert.deepEqual(JSON.parse(JSON.stringify(reissued)), COMPAT_4_1_0_HANDOFF);
  assert.equal(JSON.stringify(reissued), JSON.stringify(COMPAT_4_1_0_HANDOFF));

  const verified = verifyAebNativeAuthorizationHandoff(structuredClone(COMPAT_4_1_0_HANDOFF), {
    pins: c.pins,
    expected_action: c.action,
    status: c.statusFor(COMPAT_4_1_0_HANDOFF),
    now: c.now,
  });
  assert.equal(verified.valid, true, JSON.stringify(verified.reasons));
  assert.equal(verified.execution_authorizing, true);
  // The 4.1.0 exports keep their 4.1.0 values: replay_key and
  // aebNativeAuthorizationReplayKey() equal the key 4.1.0 derived, and
  // native_replay_unit is the signed wire unit. The label-free identity key is
  // a separate, additive field.
  assert.equal(verified.replay_key, COMPAT_4_1_0_REPLAY_KEY);
  assert.equal(aebNativeAuthorizationReplayKey(COMPAT_4_1_0_HANDOFF), COMPAT_4_1_0_REPLAY_KEY);
  assert.equal(verified.native_replay_unit, COMPAT_4_1_0_HANDOFF.native_authorization.replay_unit);
  assert.equal(
    verified.native_replay_identity,
    deriveAebNativeAuthorizationReplayIdentity(c.input.native_authorization),
  );
  assert.notEqual(verified.replay_identity_key, COMPAT_4_1_0_REPLAY_KEY);
  assert.equal(verified.replay_identity_key, aebNativeAuthorizationReplayIdentityKey(COMPAT_4_1_0_HANDOFF));
});

test('pins that spell one issuer two ways are refused unless they declare one shared namespace', () => {
  // Regression for C5/C6: a trailing slash (or case, or a default port) on a
  // second pin let one authorization ID be spent once per spelling, and a
  // shared declared namespace did not merge them because the issuer was
  // still hashed.
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const aliasSpellings = [
    'https://authz.example/',
    'HTTPS://AUTHZ.EXAMPLE',
    'https://authz.example:443',
    'https://Authz.Example:443/',
    // R7 aliases the round-2 verifier found accepted: a trailing-dot host and
    // a special scheme written without its slashes.
    'https://authz.example.',
    'https://authz.example./',
    'https:authz.example',
    // Keep alias normalization linear even at the identifier-size boundary.
    // CodeQL flagged the former trailing-run regular expressions as
    // polynomial-time on attacker-controlled pin data.
    `https://AUTHZ.EXAMPLE${'.'.repeat(400)}${'/'.repeat(80)}`,
  ];
  for (const alias of aliasSpellings) {
    const aliased = withSources(f, [sourcePin(f), sourcePin(f, { issuer: alias })]);
    const pinCheck = verifyAebNativeAuthorizationPins(aliased);
    assert.equal(pinCheck.valid, false, alias);
    assert.deepEqual(pinCheck.reasons, ['native_pins_issuer_alias_without_shared_namespace'], alias);
    // Verify 4.1.0 accepted this pin set, so handoff verification still does,
    // but it derives no label-free identity from it.
    const compatible = verify(f, handoff, ACTION, { pins: aliased });
    assert.equal(compatible.valid, true, alias);
    assert.equal(compatible.native_replay_identity, null, alias);
    assert.equal(compatible.replay_identity_key, null, alias);
    assert.equal(compatible.replay_key, aebNativeAuthorizationReplayKey(handoff), alias);

    const distinct = withSources(f, [
      sourcePin(f, { authority_namespace: 'namespace:one' }),
      sourcePin(f, { issuer: alias, authority_namespace: 'namespace:two' }),
    ]);
    assert.deepEqual(
      verifyAebNativeAuthorizationPins(distinct).reasons,
      ['native_pins_issuer_alias_without_shared_namespace'],
      alias,
    );
    const halfDeclared = withSources(f, [
      sourcePin(f, { authority_namespace: 'namespace:one' }),
      sourcePin(f, { issuer: alias }),
    ]);
    assert.equal(verifyAebNativeAuthorizationPins(halfDeclared).valid, false, alias);
  }

  // One declared namespace for both spellings: accepted, and both spellings
  // of one authorization ID derive one replay key.
  const alias = 'https://authz.example/';
  const shared = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:authz' }),
    sourcePin(f, { issuer: alias, authority_namespace: 'namespace:authz' }),
  ]);
  assert.deepEqual(verifyAebNativeAuthorizationPins(shared), { valid: true, reasons: [] });
  const aliasHandoff = issueAebNativeAuthorizationHandoff({
    ...f.input,
    native_authorization: { ...f.input.native_authorization, issuer: alias },
  }, f.signer);
  const first = verify(f, handoff, ACTION, { pins: shared });
  const second = verify(f, aliasHandoff, ACTION, {
    pins: shared,
    status: { ...f.status, native_authorization: aliasHandoff.native_authorization },
  });
  assert.equal(first.valid, true, JSON.stringify(first.reasons));
  assert.equal(second.valid, true, JSON.stringify(second.reasons));
  assert.equal(first.replay_identity_key, second.replay_identity_key);
  assert.notEqual(first.replay_key, second.replay_key);

  // A namespace-declaring alias set without one shared namespace is refused
  // outright: verify 4.1.0 never accepted a declared namespace.
  const split = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:one' }),
    sourcePin(f, { issuer: alias, authority_namespace: 'namespace:two' }),
  ]);
  assert.equal(verify(f, handoff, ACTION, { pins: split }).valid, false);

  // URN scheme and namespace identifier compare case-insensitively (RFC 8141).
  const urn = fixture({ issuer: 'urn:example:issuer' });
  for (const alias of ['URN:example:issuer', 'urn:EXAMPLE:issuer']) {
    assert.deepEqual(
      verifyAebNativeAuthorizationPins(withSources(urn, [sourcePin(urn), sourcePin(urn, { issuer: alias })])).reasons,
      ['native_pins_issuer_alias_without_shared_namespace'],
      alias,
    );
  }
  assert.equal(
    verifyAebNativeAuthorizationPins(withSources(urn, [sourcePin(urn), sourcePin(urn, { issuer: 'urn:example:ISSUER' })])).valid,
    true,
  );

  // Different hosts, paths, or non-default ports are not aliases.
  for (const other of ['https://authz.example/v2', 'https://authz.example:8443', 'http://authz.example', 'https://other.example']) {
    assert.equal(
      verifyAebNativeAuthorizationPins(withSources(f, [sourcePin(f), sourcePin(f, { issuer: other })])).valid,
      true,
      other,
    );
  }
});

test('changing a declared authority namespace changes the replay key, so it is a key rotation', () => {
  // C8: a grant burned under one namespace is a new key under another. The
  // documented operator rule is to drain in-flight and burned grants before
  // changing a pin's namespace; this pins the behavior that rule relies on.
  const f = fixture();
  const handoff = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const before = verify(f, handoff, ACTION, {
    pins: withSources(f, [sourcePin(f, { authority_namespace: 'namespace:before' })]),
  });
  const after = verify(f, handoff, ACTION, {
    pins: withSources(f, [sourcePin(f, { authority_namespace: 'namespace:after' })]),
  });
  const defaulted = verify(f, handoff);
  assert.equal(before.valid && after.valid && defaulted.valid, true);
  assert.equal(
    new Set([before.replay_identity_key, after.replay_identity_key, defaulted.replay_identity_key]).size,
    3,
  );
  // The 4.1.0 key does not depend on the namespace, so a consumer that fences
  // both keys still refuses a grant burned before the rotation.
  assert.equal(new Set([before.replay_key, after.replay_key, defaulted.replay_key]).size, 1);
});

test('the pin-set validator names each refusal and never throws', () => {
  const f = fixture();
  assert.deepEqual(verifyAebNativeAuthorizationPins(f.pins), { valid: true, reasons: [] });
  const cyclic = { ...f.pins };
  cyclic.self = cyclic;
  const cases = {
    null: [null, 'native_pins_schema_invalid'],
    proxy: [new Proxy({ ...f.pins }, {}), 'native_pins_schema_invalid'],
    cyclic: [cyclic, 'native_pins_schema_invalid'],
    emptySources: [withSources(f, []), 'native_pins_schema_invalid'],
    duplicateKey: [{ ...f.pins, gateway_keys: [f.pins.gateway_keys[0], f.pins.gateway_keys[0]] }, 'native_pins_duplicate_gateway_key'],
    duplicateSource: [withSources(f, [sourcePin(f), sourcePin(f)]), 'native_pins_duplicate_source'],
    unpinnedGateway: [withSources(f, [sourcePin(f, { gateway_id: 'gateway:other' })]), 'native_pins_source_gateway_unpinned'],
    mixed: [withSources(f, [
      sourcePin(f),
      sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:x' }),
    ]), 'native_pins_namespace_declaration_mixed'],
    namespaceConflict: [withSources(f, [
      sourcePin(f, { authority_namespace: 'namespace:x' }),
      sourcePin(f, { profile: 'authzen:exact-action-result:2', authority_namespace: 'namespace:y' }),
    ]), 'native_pins_issuer_namespace_conflict'],
    alias: [withSources(f, [sourcePin(f), sourcePin(f, { issuer: 'https://authz.example/' })]),
      'native_pins_issuer_alias_without_shared_namespace'],
  };
  for (const [name, [pins, reason]] of Object.entries(cases)) {
    let result;
    assert.doesNotThrow(() => { result = verifyAebNativeAuthorizationPins(pins); }, name);
    assert.equal(result.valid, false, name);
    assert.deepEqual(result.reasons, [reason], name);
    assert.equal(Object.isFrozen(result), true, name);
  }
});

test('S3: legacy_replay_keys holds the 4.1.0 key of every pinned label in the grant\'s namespace group', () => {
  const f = fixture();
  const labelB = { profile: 'authzen:exact-action-result:2' };
  const labelC = { system: 'coaz', profile: 'coaz:exact-action-result:1' };
  const otherIssuer = { issuer: 'https://other-authz.example', profile: 'authzen:exact-action-result:9' };
  const pins = withSources(f, [
    f.pins.accepted_sources[0],
    sourcePin(f, labelB),
    sourcePin(f, labelC),
    sourcePin(f, otherIssuer),
  ]);
  const handoffA = issueAebNativeAuthorizationHandoff(f.input, f.signer);
  const keyFor = (label) => aebNativeAuthorizationReplayKey(issueAebNativeAuthorizationHandoff({
    ...f.input,
    native_authorization: { ...f.input.native_authorization, ...label },
  }, f.signer));
  const result = verify(f, handoffA, ACTION, { pins });
  assert.equal(result.valid, true, JSON.stringify(result.reasons));
  const expected = [keyFor({}), keyFor(labelB), keyFor(labelC)].sort();
  assert.deepEqual(result.legacy_replay_keys, expected);
  assert.ok(result.legacy_replay_keys.includes(result.replay_key));
  // A pin for another issuer (another default namespace) is not in the group.
  assert.ok(!result.legacy_replay_keys.includes(keyFor(otherIssuer)));
  assert.equal(Object.isFrozen(result.legacy_replay_keys), true);

  // A declared namespace groups by the namespace, across issuer spellings.
  const declared = withSources(f, [
    sourcePin(f, { authority_namespace: 'namespace:authz' }),
    sourcePin(f, { ...labelB, issuer: 'https://authz.example/', authority_namespace: 'namespace:authz' }),
    sourcePin(f, { ...otherIssuer, authority_namespace: 'namespace:other' }),
  ]);
  const grouped = verify(f, handoffA, ACTION, { pins: declared });
  assert.equal(grouped.valid, true, JSON.stringify(grouped.reasons));
  assert.deepEqual(grouped.legacy_replay_keys, [
    keyFor({}),
    keyFor({ ...labelB, issuer: 'https://authz.example/' }),
  ].sort());

  // No identity, no legacy set.
  const unpinned = verify(f, handoffA, ACTION, { pins: withSources(f, [sourcePin(f, labelB)]) });
  assert.equal(unpinned.native_replay_identity, null);
  assert.equal(unpinned.legacy_replay_keys, null);
});

test('S6: did:web host case and spiffe trust-domain case are issuer aliases', () => {
  const f = fixture();
  for (const [first, second] of [
    ['did:web:authz.example', 'did:web:AUTHZ.example'],
    ['did:web:authz.example:users:pay', 'did:web:Authz.Example.:users:pay'],
    ['DID:web:authz.example', 'did:WEB:authz.example'],
    ['did:web:authz.example:users:pay', `did:web:AUTHZ.EXAMPLE${'.'.repeat(400)}:users:pay`],
    ['spiffe://authz.example/ns/pay', 'spiffe://AUTHZ.EXAMPLE/ns/pay'],
    ['spiffe://authz.example/ns/pay', 'SPIFFE://authz.example./ns/pay/'],
    [
      'spiffe://authz.example/ns/pay',
      `SPIFFE://AUTHZ.EXAMPLE${'.'.repeat(350)}/ns/pay${'/'.repeat(100)}`,
    ],
  ]) {
    const aliased = withSources(f, [sourcePin(f, { issuer: first }), sourcePin(f, { issuer: second })]);
    assert.deepEqual(
      verifyAebNativeAuthorizationPins(aliased).reasons,
      ['native_pins_issuer_alias_without_shared_namespace'],
      `${first} ${second}`,
    );
  }
  // Paths stay case-sensitive, and other DID methods keep their identifier.
  for (const [first, second] of [
    ['did:web:authz.example:users:pay', 'did:web:authz.example:Users:Pay'],
    ['spiffe://authz.example/ns/pay', 'spiffe://authz.example/NS/pay'],
    ['did:key:z6MkAbc', 'did:key:z6Mkabc'],
  ]) {
    const distinct = withSources(f, [sourcePin(f, { issuer: first }), sourcePin(f, { issuer: second })]);
    assert.deepEqual(verifyAebNativeAuthorizationPins(distinct), { valid: true, reasons: [] }, `${first} ${second}`);
  }
});

// T5: issuer normalization is linear. The reference below is the round-four
// regular-expression implementation, kept only to prove that the linear
// rewrite gives the same comparison form for every issuer the pin grammar
// admits (S6 alias behavior unchanged).
function referenceIssuerComparisonForm(issuer) {
  const ports = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(issuer);
  if (!scheme) return issuer;
  const protocol = `${scheme[1].toLowerCase()}:`;
  const rest = issuer.slice(scheme[0].length);
  if (protocol === 'urn:') {
    const nid = /^([A-Za-z0-9][A-Za-z0-9-]{0,31}):/.exec(rest);
    return nid ? `urn:${nid[1].toLowerCase()}:${rest.slice(nid[0].length)}` : `urn:${rest}`;
  }
  if (protocol === 'did:') {
    const method = /^([A-Za-z0-9]+):/.exec(rest);
    if (!method) return `did:${rest}`;
    const methodName = method[1].toLowerCase();
    const id = rest.slice(method[0].length);
    if (methodName !== 'web') return `did:${methodName}:${id}`;
    const [host, ...path] = id.split(':');
    const normalizedHost = host.toLowerCase().replace(/\.+$/, '');
    return `did:web:${normalizedHost}${path.length > 0 ? `:${path.join(':')}` : ''}`;
  }
  if (protocol === 'spiffe:') {
    const authority = /^\/\/([^/?#]*)(.*)$/.exec(rest);
    if (!authority) return `spiffe:${rest}`;
    const trustDomain = authority[1].toLowerCase().replace(/\.+$/, '');
    return `spiffe://${trustDomain}${authority[2].replace(/\/+$/, '')}`;
  }
  if (!Object.hasOwn(ports, protocol)) return `${protocol}${rest}`;
  let url;
  try { url = new URL(issuer); } catch { return `${protocol}${rest}`; }
  const port = url.port !== '' && url.port !== ports[url.protocol] ? `:${url.port}` : '';
  const userinfo = url.username !== '' || url.password !== ''
    ? `${url.username}${url.password !== '' ? `:${url.password}` : ''}@`
    : '';
  const host = url.hostname.toLowerCase().replace(/\.+$/, '');
  const path = url.pathname.replace(/\/+$/, '');
  return `${url.protocol}//${userinfo}${host}${port}${path}${url.search}${url.hash}`;
}

test('T5: issuer normalization gives the round-four comparison form for every grammar issuer', () => {
  const alphabet = 'aAzZ09_.:@/#-';
  const prefixes = [
    '', 'did:web:', 'DID:WEB:', 'did:key:', 'did:', 'did:Web:', 'spiffe://', 'SPIFFE://', 'spiffe:',
    'urn:', 'URN:Example:', 'urn:x-y:', 'https://', 'HTTPS://', 'http:', 'ws://', 'wss://h:443',
    'ftp://h:21/', 'https://u:p@h.', 'mailto:', 'x+y.z-w:',
  ];
  let seed = 0x5eed;
  const next = () => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return seed;
  };
  let compared = 0;
  for (const prefix of prefixes) {
    for (let round = 0; round < 400; round += 1) {
      const length = next() % 40;
      let tail = '';
      for (let index = 0; index < length; index += 1) tail += alphabet[next() % alphabet.length];
      const issuer = `${prefix}${tail}`;
      if (!/^[A-Za-z0-9][A-Za-z0-9_.:@/#-]{0,511}$/.test(issuer)) continue;
      assert.equal(aebIssuerComparisonForm(issuer), referenceIssuerComparisonForm(issuer), issuer);
      compared += 1;
    }
  }
  for (const issuer of [
    'did:web:Authz.Example.:users:pay', 'did:web:authz.example...', 'spiffe://AUTHZ.EXAMPLE./ns/pay//',
    'spiffe://a#frag/', 'spiffe://', 'spiffe:/x', 'urn:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456:x',
    'urn:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345:x', 'https://Authz.Example.:443/a//', 'https://h/p/#x',
    `did:web:${'.'.repeat(503)}x`, `spiffe://a${'/'.repeat(501)}`, `https://h/${'/'.repeat(502)}`,
  ]) {
    assert.equal(aebIssuerComparisonForm(issuer), referenceIssuerComparisonForm(issuer), issuer);
    compared += 1;
  }
  assert.ok(compared > 5000, `compared ${compared}`);
});

test('T5: adversarial issuers are normalized in bounded time (no polynomial backtracking)', () => {
  const huge = 200_000;
  const adversarial = [
    `did:web:${'.'.repeat(huge)}x`,
    `did:web:a${'.'.repeat(huge)}:p`,
    `spiffe://a${'.'.repeat(huge)}x/`,
    `spiffe://a${'/'.repeat(huge)}x`,
    `spiffe://${'"'.repeat(huge)}\n`,
    `spiffe://${'"'.repeat(huge)}`,
    `https://h/${'/'.repeat(huge)}x`,
    // Grammar-length inputs take the full linear path.
    `did:web:${'.'.repeat(AEB_ISSUER_COMPARISON_MAX_LENGTH - 9)}x`,
    `spiffe://a${'/'.repeat(AEB_ISSUER_COMPARISON_MAX_LENGTH - 11)}x`,
    `spiffe://${'.'.repeat(AEB_ISSUER_COMPARISON_MAX_LENGTH - 10)}x`,
  ];
  for (const issuer of adversarial) {
    const started = process.hrtime.bigint();
    for (let repeat = 0; repeat < 20; repeat += 1) aebIssuerComparisonForm(issuer);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 250, `${issuer.slice(0, 24)}... (${issuer.length} chars) took ${elapsedMs.toFixed(1)} ms for 20 runs`);
  }
  // Longer than the pin grammar admits: returned unchanged, never parsed.
  const tooLong = `did:web:${'.'.repeat(AEB_ISSUER_COMPARISON_MAX_LENGTH)}`;
  assert.equal(aebIssuerComparisonForm(tooLong), tooLong);
  // The pin grammar refuses such issuers before normalization is reached.
  const f = fixture();
  const pins = withSources(f, [sourcePin(f, { issuer: `spiffe://${'"'.repeat(64)}` })]);
  const started = process.hrtime.bigint();
  const result = verifyAebNativeAuthorizationPins(pins);
  assert.equal(result.valid, false);
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 250);
});
