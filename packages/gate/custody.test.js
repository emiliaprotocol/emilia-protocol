// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createGate, createEg1Harness,
  createKeyRegistry, classifyRetention, buildRetentionExport,
  createDurableConsumptionStore, createMemoryBackend,
} from './index.js';
import { EG1_DEFAULT_SELECTOR } from './eg1-conformance.js';

const SEL = EG1_DEFAULT_SELECTOR;

// ── Key registry: rotation + revocation ──────────────────────────────────────

test('key registry: a revoked issuer key is refused (fail closed)', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  const registry = createKeyRegistry([{ kid: 'issuer-1', key: h.publicKey }]);
  const gate = createGate({
    manifest: DEFAULT_GATE_MANIFEST, keyRegistry: registry, approverKeys: h.approverKeys,
    rpId: h.rpId, allowedOrigins: h.allowedOrigins, allowEphemeralStore: true,
  });

  const ok = await gate.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(ok.ok, true, 'valid key works before revocation');

  registry.revoke('issuer-1');
  const after = await gate.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(after.ok, false, 'revoked key is refused');
  assert.match(after.authorization.reason, /receipt_rejected/);
});

test('key registry: a receipt signed by a not-yet-valid / expired key is refused (rotation window)', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  // Key only valid in the far future.
  const future = Date.now() + 10 * 24 * 60 * 60 * 1000;
  const registry = createKeyRegistry([{ kid: 'k', key: h.publicKey, not_before: new Date(future).toISOString() }]);
  const gate = createGate({
    manifest: DEFAULT_GATE_MANIFEST, keyRegistry: registry, approverKeys: h.approverKeys,
    rpId: h.rpId, allowedOrigins: h.allowedOrigins, allowEphemeralStore: true,
  });
  const out = await gate.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(out.ok, false, 'a receipt issued before the key window is refused');
});

test('key registry: rotation overlap — both keys valid in the window', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  const other = createEg1Harness();
  const registry = createKeyRegistry([
    { kid: 'old', key: h.publicKey },
    { kid: 'new', key: other.publicKey },
  ]);
  // Two gate instances share the same registry (two pods, same trust config,
  // independent consumption stores) — both issuer keys verify during overlap.
  const gateA = createGate({
    manifest: DEFAULT_GATE_MANIFEST, keyRegistry: registry, approverKeys: h.approverKeys,
    rpId: h.rpId, allowedOrigins: h.allowedOrigins, allowEphemeralStore: true,
  });
  const gateB = createGate({
    manifest: DEFAULT_GATE_MANIFEST, keyRegistry: registry, approverKeys: other.approverKeys,
    rpId: other.rpId, allowedOrigins: other.allowedOrigins, allowEphemeralStore: true,
  });
  const a = await gateA.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => 1);
  const b = await gateB.run({ selector: SEL, receipt: other.mint({ outcome: 'allow_with_signoff' }), observedAction: other.action }, async () => 2);
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  // status() reflects revocation
  registry.revoke('old');
  assert.equal(registry.status().find((s) => s.kid === 'old').revoked, true);
  assert.throws(() => registry.revoke('does-not-exist'));
});

test('key registry: supplied invalid or non-RFC3339 dates throw instead of becoming unwindowed', () => {
  const h = createEg1Harness();
  for (const not_after of ['not-a-date', '01/02/2030', 1893456000000, null, undefined]) {
    assert.throws(
      () => createKeyRegistry([{ kid: 'eternal-if-normalized', key: h.publicKey, not_after }]),
      /not_after.*RFC3339/,
    );
  }
  const registry = createKeyRegistry();
  assert.throws(
    () => registry.add({ kid: 'bad-rotation', key: h.publicKey, not_before: 'tomorrow' }),
    /not_before.*RFC3339/,
  );
});

test('key registry: invalid receipt evaluation times fail closed for every key', () => {
  const h = createEg1Harness();
  const registry = createKeyRegistry([{ kid: 'unwindowed', key: h.publicKey }]);
  assert.deepEqual(registry.keysValidAt('not-a-date'), []);
  assert.deepEqual(registry.keysValidAt(1893456000000), []);
  assert.deepEqual(registry.keysValidAt(undefined), []);
});

test('flat trustedKeys still works (back-compat)', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  const gate = createGate({
    manifest: DEFAULT_GATE_MANIFEST, trustedKeys: [h.publicKey], approverKeys: h.approverKeys,
    rpId: h.rpId, allowedOrigins: h.allowedOrigins, allowEphemeralStore: true,
  });
  const out = await gate.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(out.ok, true);
});

// ── Durable consumption store: replay across a shared backend ─────────────────

test('durable store: a receipt consumed on one gate cannot be replayed on another', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  const backend = createMemoryBackend(); // a single SHARED backend == two pods sharing Redis
  backend.durable = true; // capability stand-in for the test's shared durable service
  const gateA = createGate({ manifest: DEFAULT_GATE_MANIFEST, trustedKeys: [h.publicKey], approverKeys: h.approverKeys, rpId: h.rpId, allowedOrigins: h.allowedOrigins, store: createDurableConsumptionStore(backend) });
  const gateB = createGate({ manifest: DEFAULT_GATE_MANIFEST, trustedKeys: [h.publicKey], approverKeys: h.approverKeys, rpId: h.rpId, allowedOrigins: h.allowedOrigins, store: createDurableConsumptionStore(backend) });
  const receipt = h.mint({ outcome: 'allow_with_signoff' });

  const a = await gateA.run({ selector: SEL, receipt, observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(a.ok, true, 'first use on pod A succeeds');
  const b = await gateB.run({ selector: SEL, receipt, observedAction: h.action }, async () => ({ ran: true }));
  assert.equal(b.ok, false, 'replay on pod B is refused via the shared store');
  assert.match(b.authorization.reason, /replay/);
});

test('durable store: proven pre-effect cancellation may release the reservation', async () => {
  const backend = createMemoryBackend();
  const store = createDurableConsumptionStore(backend);
  assert.equal(await store.reserve('r1'), true);
  await store.release('r1');
  assert.equal(await store.reserve('r1'), true, 'released id can be reserved again');
  await store.commit('r1');
  assert.equal(await store.reserve('r1'), false, 'committed id cannot be reserved');
});

test('durable store: rejects a backend without atomic addIfAbsent', () => {
  assert.throws(() => createDurableConsumptionStore({ set() {}, delete() {}, has() {} }), /addIfAbsent/);
});

// ── Retention classification ─────────────────────────────────────────────────

test('retention: classifies hot / cold / expired and honors legal hold', () => {
  const now = Date.parse('2026-06-29T00:00:00Z');
  const day = 24 * 60 * 60 * 1000;
  const entries = [
    { hash: 'a', at: new Date(now - 10 * day).toISOString() },       // hot
    { hash: 'b', at: new Date(now - 500 * day).toISOString() },      // cold
    { hash: 'c', at: new Date(now - 3000 * day).toISOString() },     // expired
    { hash: 'd', at: new Date(now - 3000 * day).toISOString() },     // expired but held
    { hash: 'e', at: 'not-a-date' },                                 // unknown
  ];
  const cls = classifyRetention(entries, { hotDays: 365, coldDays: 2190, now, legalHold: ['d'] });
  assert.deepEqual(cls.hot.map((x) => x.hash), ['a']);
  assert.deepEqual(cls.cold.map((x) => x.hash), ['b']);
  assert.deepEqual(cls.expired.map((x) => x.hash), ['c']);
  assert.deepEqual(cls.legal_hold.map((x) => x.hash), ['d']);
  assert.deepEqual(cls.unknown.map((x) => x.hash), ['e']);
  assert.equal(cls.summary.total, 5);
});

test('retention: export manifest carries the evidence head + counts', () => {
  const now = Date.parse('2026-06-29T00:00:00Z');
  const entries = [{ hash: 'a', at: new Date(now).toISOString(), kind: 'decision' }, { hash: 'z', at: new Date(now).toISOString(), kind: 'execution' }];
  const exp = buildRetentionExport(entries, { now });
  assert.equal(exp['@version'], 'EP-GATE-RETENTION-EXPORT-v1');
  assert.equal(exp.evidence_head, 'z');
  assert.equal(exp.counts.total, 2);
  assert.equal(exp.entries.length, 2);
});

test('gate.retention() classifies the live evidence log', async () => {
  const h = createEg1Harness();
  const { DEFAULT_GATE_MANIFEST } = await import('./action-packs.js');
  const gate = createGate({
    manifest: DEFAULT_GATE_MANIFEST, trustedKeys: [h.publicKey], approverKeys: h.approverKeys,
    rpId: h.rpId, allowedOrigins: h.allowedOrigins, allowEphemeralStore: true,
  });
  await gate.run({ selector: SEL, receipt: h.mint({ outcome: 'allow_with_signoff' }), observedAction: h.action }, async () => ({ ran: true }));
  const r = gate.retention();
  assert.ok(r.summary.total >= 1);
  const exp = gate.retentionExport();
  assert.ok(exp.evidence_head);
  void crypto;
});
