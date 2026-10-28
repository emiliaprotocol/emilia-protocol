// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { membershipRoot, checkpointDigest, evaluateReplayRecovery } from './recovery.mjs';
const zero = `sha256:${'0'.repeat(64)}`;
function fixture() {
  const expected = { stream: 'issuer/native', namespace_epoch: 'epoch-1', anchor_id: 'external-pinned' };
  const checkpoint = { version: 'EP-REPLAY-CHECKPOINT-v1', stream: expected.stream,
    namespace_epoch: expected.namespace_epoch, covered_through: 5,
    root_digest: membershipRoot(['native-1']), previous_checkpoint_digest: zero };
  const snapshot = { checkpoint, consumed_identities: ['native-1'] };
  // Test double only: this does not authenticate an independent deployed anchor.
  const head = { ...expected, covered_through: 5, checkpoint_digest: checkpointDigest(checkpoint) };
  return { snapshot, expected, identity: 'native-1', head, readVerifiedLatest: async () => head };
}
test('consumed identity survives deletion of all operational dispatch evidence', async () => {
  const r = await evaluateReplayRecovery(fixture());
  assert.equal(r.membership, 'CONSUMED'); assert.equal(r.dispatch_permitted, false);
});
test('complete current snapshot distinguishes truly absent identity without granting dispatch', async () => {
  const r = await evaluateReplayRecovery({ ...fixture(), identity: 'native-2' });
  assert.equal(r.status, 'REPLAY_HISTORY_COMPLETE'); assert.equal(r.membership, 'ABSENT');
  assert.equal(r.dispatch_permitted, false);
});
for (const [name, mutate] of [
  ['missing checkpoint', f => { delete f.snapshot.checkpoint; }],
  ['deleted membership', f => { f.snapshot.consumed_identities = []; }],
  ['root tampering', f => { f.snapshot.checkpoint.root_digest = zero; }],
  ['primary rollback', f => { f.snapshot.checkpoint.covered_through = 4; }],
  ['local ahead of anchor', f => { f.head.covered_through = 4; }],
  ['continuity gap', f => { f.readVerifiedLatest = async () => { throw Error('continuity gap'); }; }],
  ['previous checkpoint substitution', f => { f.snapshot.checkpoint.previous_checkpoint_digest = membershipRoot([]); }],
  ['epoch rotation without reconstruction', f => { f.snapshot.checkpoint.namespace_epoch = 'epoch-2'; }],
  ['untrusted anchor', f => { f.head.anchor_id = 'presenter-selected'; }],
  ['contradictory root', f => { f.head.checkpoint_digest = zero; }],
  ['duplicate identity', f => { f.snapshot.consumed_identities.push('native-1'); }],
  ['anchor missing', f => { f.readVerifiedLatest = async () => null; }],
  ['anchor unavailable', f => { f.readVerifiedLatest = async () => { throw Error('offline'); }; }],
]) test(`${name} is uncertain`, async () => {
  const f = fixture(); mutate(f);
  const r = await evaluateReplayRecovery(f);
  assert.equal(r.status, 'REPLAY_HISTORY_UNCERTAIN'); assert.equal(r.membership, undefined);
});
test('caller mutation during anchor read cannot swap the verified membership', async () => {
  const f = fixture();
  f.readVerifiedLatest = async () => { f.snapshot.consumed_identities.length = 0; return f.head; };
  assert.equal((await evaluateReplayRecovery(f)).membership, 'CONSUMED');
});

const { consumeRecoveredIdentity } = await import('./recovery.mjs');
const action = membershipRoot(['exact-action']);
const receiptFor = r => ({ identity: r.identity, action_digest: r.action_digest,
  stream: r.stream, namespace_epoch: r.namespace_epoch,
  previous_checkpoint_digest: r.expected_checkpoint_digest, sequence: r.expected_covered_through + 1 });
test('uncertain or consumed recovery never calls live consume', async () => {
  let calls = 0;
  const deps = { atomicConsume: async () => { calls++; } };
  await consumeRecoveredIdentity({ ...fixture(), action_digest: action }, deps);
  const f = fixture(); f.head = null; f.readVerifiedLatest = async () => null;
  await consumeRecoveredIdentity({ ...f, action_digest: action }, deps);
  assert.equal(calls, 0);
});
test('absent history requires atomic consume and exact-action receipt', async () => {
  const r = await consumeRecoveredIdentity({ ...fixture(), identity: 'new', action_digest: action }, {
    atomicConsume: async request => receiptFor(request),
  });
  assert.equal(r.status, 'REPLAY_CONSUMED_NOW');
});
test('concurrent attempts close race at authoritative atomic consume', async () => {
  let burned = false;
  const deps = { atomicConsume: async r => {
    if (burned) return null;
    burned = true; return receiptFor(r);
  } };
  const input = { ...fixture(), identity: 'new', action_digest: action };
  const results = await Promise.all([consumeRecoveredIdentity(input, deps), consumeRecoveredIdentity(input, deps)]);
  assert.deepEqual(results.map(x => x.status).sort(), ['REPLAY_CONSUMED_NOW', 'REPLAY_CONSUMED_OR_HEAD_CHANGED']);
});
for (const field of ['identity', 'action_digest', 'namespace_epoch', 'previous_checkpoint_digest', 'sequence']) {
  test(`consume receipt ${field} substitution refuses`, async () => {
    const r = await consumeRecoveredIdentity({ ...fixture(), identity: 'new', action_digest: action }, {
      atomicConsume: async request => ({ ...receiptFor(request), [field]: 'substituted' }),
    });
    assert.equal(r.status, 'REPLAY_HISTORY_UNCERTAIN');
  });
}
test('lost consume acknowledgement fails closed and is not retried', async () => {
  let calls = 0;
  const r = await consumeRecoveredIdentity({ ...fixture(), identity: 'new', action_digest: action }, {
    atomicConsume: async () => { calls++; throw Error('committed but response lost'); },
  });
  assert.equal(r.status, 'REPLAY_HISTORY_UNCERTAIN'); assert.equal(calls, 1);
});

for (const [name, value] of [
  ['array digest', [action]],
  ['coercible object digest', { toString: () => action }],
]) test(`${name} is rejected before consume`, async () => {
  let calls = 0;
  const r = await consumeRecoveredIdentity({ ...fixture(), identity: 'new', action_digest: value }, {
    atomicConsume: async request => { calls++; return receiptFor(request); },
  });
  assert.equal(r.status, 'REPLAY_HISTORY_UNCERTAIN'); assert.equal(calls, 0);
});
for (const [name, input] of [
  ['null input', null],
  ['undefined input', undefined],
  ['uncloneable expected', { ...fixture(), action_digest: action, expected: { callback() {} } }],
  ['throwing input getter', { get identity() { throw Error('getter'); } }],
]) test(`${name} resolves uncertain`, async () => {
  let calls = 0;
  const r = await consumeRecoveredIdentity(input, {
    atomicConsume: async () => { calls++; },
  });
  assert.equal(r.status, 'REPLAY_HISTORY_UNCERTAIN'); assert.equal(calls, 0);
});
test('malformed dependency and direct null recovery resolve uncertain', async () => {
  assert.equal((await consumeRecoveredIdentity(null, null)).status, 'REPLAY_HISTORY_UNCERTAIN');
  assert.equal((await evaluateReplayRecovery(null)).status, 'REPLAY_HISTORY_UNCERTAIN');
});
test('checkpoint digest rejects coercible array and object previous digests', () => {
  for (const value of [[zero], { toString: () => zero }]) {
    assert.throws(() => checkpointDigest({ ...fixture().snapshot.checkpoint, previous_checkpoint_digest: value }), /invalid_checkpoint/);
  }
});
