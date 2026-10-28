// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalize } from './execution-binding.js';
import { deriveProviderReplayKey, deriveProviderReplayKeyV2, providerCarriageContractDigestV2, matchesProviderReplayKeyV2,
  PROVIDER_REPLAY_KEY_V2_VERSION, PROVIDER_SLOT_SPECS } from './provider-replay-key.js';
const auth = `sha256:${'1'.repeat(64)}`;
const slot = { ...PROVIDER_SLOT_SPECS['stripe.idempotency-key'], slot_id: 'stripe.idempotency-key.v2', prefix: 'ep2_' };
const commitment = 'sha256:9dc14bb6776332a3bb7ba41d3939e117fdd1074c811ffd03f51b335c44428416';
const input = (changes = {}) => ({ authorization_digest: auth, caid: 'stripe.payout.create',
  provider_env: 'stripe:acct_a:test', retry_epoch_digest: auth, slot_spec: slot,
  carriage_contract_digest: commitment, ...changes });

test('v2 pins complete carriage contract and preserves v1 independently', () => {
  assert.equal(providerCarriageContractDigestV2(slot).digest, commitment);
  const first = deriveProviderReplayKeyV2(input());
  assert.equal(first.ok, true);
  assert.deepEqual(deriveProviderReplayKeyV2(input()), first);
  assert.match(first.key, /^ep2_[A-Za-z0-9]{43}$/);
  const old = deriveProviderReplayKey({ authorization_digest: auth, caid: 'stripe.payout.create',
    provider_env: 'stripe:acct_a:test', attempt_group: '1', slot_spec: PROVIDER_SLOT_SPECS['stripe.idempotency-key'] });
  assert.notEqual(first.key, old.key);
  assert.deepEqual(matchesProviderReplayKeyV2({ version: PROVIDER_REPLAY_KEY_V2_VERSION, key: first.key }, input()), { ok: true });
  assert.equal(matchesProviderReplayKeyV2({ version: old.derivation.version, key: old.key }, input()).reason,
    'replay_key_version_mismatch');
  assert.equal(matchesProviderReplayKeyV2({ version: PROVIDER_REPLAY_KEY_V2_VERSION, key: old.key }, input()).reason,
    'replay_key_mismatch');
  for (const change of [{ charset: slot.charset.split('').reverse().join('') }, { prefix: 'ep3_' },
    { encoded_length: 42 }, { max_length: 254 }, { min_entropy_bits: 127 },
    { charset_applies_to_prefix: true, prefix: 'EP2' }, { forbid_leading: ['x'] },
    { forbid_trailing: ['x'] }, { forbid_substrings: ['xx'] }]) {
    assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: { ...slot, ...change } })).reason,
      'carriage_contract_mismatch');
  }
  assert.notEqual(deriveProviderReplayKeyV2(input({ authorization_digest: `sha256:${'2'.repeat(64)}` })).key, first.key);
  assert.notEqual(deriveProviderReplayKeyV2(input({ provider_env: 'stripe:acct_a:live' })).key, first.key);
  assert.notEqual(deriveProviderReplayKeyV2(input({ retry_epoch_digest: `sha256:${'2'.repeat(64)}` })).key, first.key);
  assert.equal(deriveProviderReplayKeyV2(input({ retry_epoch_digest: 'unverified-string' })).reason,
    'retry_epoch_digest_invalid');
});

function digits(integer, charset, length) {
  const radix = BigInt(charset.length);
  const out = [];
  for (let i = 0; i < length; i++) { out.unshift(charset[Number(integer % radix)]); integer /= radix; }
  return out.join('');
}
function blocks(args) {
  const { authorization_digest, caid, provider_env, retry_epoch_digest, carriage_contract_digest } = args;
  const preimage = canonicalize({ '@version': PROVIDER_REPLAY_KEY_V2_VERSION,
    authorization_digest, caid, provider_env, retry_epoch_digest, carriage_contract_digest });
  return (counter) => BigInt(`0x${crypto.createHmac('sha256', PROVIDER_REPLAY_KEY_V2_VERSION)
    .update(canonicalize({ preimage, counter })).digest('hex')}`);
}

for (const [name, charset, length, epochVector] of [
  ['ternary', 'abc', 161, 0], ['decimal', '0123456789', 77, 0],
  ['base62', PROVIDER_SLOT_SPECS['stripe.idempotency-key'].charset, 42, 12],
]) test(`v2 ${name} deterministic stream rejects boundary blocks instead of modulo reduction`, () => {
  const spec = { slot_id: `test.${name}.v2`, charset, encoded_length: length,
    max_length: length, min_entropy_bits: 1 };
  const digest = providerCarriageContractDigestV2(spec).digest;
  const capacity = BigInt(charset.length) ** BigInt(length);
  const limit = (1n << 256n) - (1n << 256n) % capacity;
  const args = input({ slot_spec: spec, carriage_contract_digest: digest,
    retry_epoch_digest: `sha256:${epochVector.toString(16).padStart(64, '0')}` });
  const draw = blocks(args);
  assert.ok(draw(0) >= limit, 'fixture must require rejection');
  let counter = 1;
  while (draw(counter) >= limit) counter++;
  const result = deriveProviderReplayKeyV2(args);
  assert.equal(result.ok, true);
  assert.equal(result.key, digits(draw(counter) % capacity, spec.charset, spec.encoded_length));
  assert.notEqual(result.key, digits(draw(0) % capacity, spec.charset, spec.encoded_length));
  assert.deepEqual(deriveProviderReplayKeyV2(args), result);
  assert.equal(result.entropy_bits, capacity.toString(2).length - 1);
});

test('v2 power-of-two and oversized capacities retain all 256 source bits', () => {
  for (const spec of [{ slot_id: 'test.binary.v2', charset: '01', encoded_length: 256, max_length: 256, min_entropy_bits: 256 },
    { slot_id: 'test.hex.v2', charset: '0123456789abcdef', encoded_length: 64, max_length: 64, min_entropy_bits: 256 },
    slot]) {
    const args = input({ slot_spec: spec, carriage_contract_digest: providerCarriageContractDigestV2(spec).digest });
    const result = deriveProviderReplayKeyV2(args);
    assert.equal(result.ok, true);
    assert.equal(result.entropy_bits, 256);
    assert.equal(result.key, `${spec.prefix ?? ''}${digits(blocks(args)(0), spec.charset, spec.encoded_length)}`);
  }
});

test('v2 refuses content constraints that reduce output entropy without a valid-space proof', () => {
  const restricted = { ...slot, forbid_substrings: ['A'] };
  const result = deriveProviderReplayKeyV2(input({ slot_spec: restricted,
    carriage_contract_digest: providerCarriageContractDigestV2(restricted).digest }));
  assert.equal(result.reason, 'slot_content_constraints_unsupported');
  const unreachable = { ...slot, forbid_substrings: ['/'] };
  assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: unreachable,
    carriage_contract_digest: providerCarriageContractDigestV2(unreachable).digest })).ok, true);
});

test('v2 rejects getters, proxies, unknown fields and mutable constraint accessors without invoking them', () => {
  let reads = 0;
  const switching = { ...slot };
  Object.defineProperty(switching, 'encoded_length', { enumerable: true,
    get() { reads++; return reads < 3 ? 43 : 42; } });
  assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: switching })).reason, 'slot_spec_invalid');
  assert.equal(providerCarriageContractDigestV2(switching).reason, 'slot_spec_invalid');
  assert.equal(reads, 0);
  const proxied = new Proxy(slot, { get() { throw new Error('must not execute'); } });
  assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: proxied })).reason, 'slot_spec_invalid');
  assert.equal(deriveProviderReplayKeyV2(new Proxy(input(), {})).reason, 'derivation_input_invalid');
  assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: { ...slot, future_rule: 'unbound' } })).reason,
    'slot_spec_invalid');
  const list = ['/'];
  Object.defineProperty(list, '0', { enumerable: true, get() { reads++; return '/'; } });
  assert.equal(deriveProviderReplayKeyV2(input({ slot_spec: { ...slot, forbid_substrings: list } })).reason,
    'slot_spec_invalid');
  assert.equal(reads, 0);
  const mutating = input();
  Object.defineProperty(mutating, 'slot_spec', { enumerable: true, get() { reads++; return slot; } });
  assert.equal(deriveProviderReplayKeyV2(mutating).reason, 'derivation_input_invalid');
  assert.equal(reads, 0);
});

test('v2 verifier rejects hostile candidate records without reading their getters or proxy traps', () => {
  let reads = 0;
  const candidate = { version: PROVIDER_REPLAY_KEY_V2_VERSION };
  Object.defineProperty(candidate, 'key', { enumerable: true,
    get() { reads++; return reads === 1 ? 'foreign' : deriveProviderReplayKeyV2(input()).key; } });
  assert.equal(matchesProviderReplayKeyV2(candidate, input()).reason, 'replay_key_version_mismatch');
  assert.equal(reads, 0);
  for (const record of [null, new Proxy({}, { get() { throw new Error('must not execute'); } }),
    { version: PROVIDER_REPLAY_KEY_V2_VERSION, key: 'foreign', unbound: true }]) {
    assert.equal(matchesProviderReplayKeyV2(record, input()).reason, 'replay_key_version_mismatch');
  }
});
