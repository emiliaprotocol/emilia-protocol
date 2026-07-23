// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  BREAKGLASS_VERSION,
  runBreakGlass,
  verifyBreakGlass,
} from '../packages/gate/breakglass.js';
import { canonicalize } from '../packages/gate/execution-binding.js';
import { createKeyRegistry } from '../packages/gate/key-registry.js';
import { createEvidenceLog } from '../packages/gate/evidence.js';
import {
  MemoryConsumptionStore,
  createDurableConsumptionStore,
  createMemoryBackend,
  isSecureConsumptionStore,
} from '../packages/gate/store.js';
import { createGate } from '../packages/gate/index.js';
import { createRuntimeMonitor } from '../packages/gate/runtime-monitor.js';
import {
  CAPABILITY_SCOPE_PROFILE,
  capabilityActionDigest,
  mintCapabilityReceipt,
} from '../packages/gate/capability-receipt.js';
import { createEg1Harness } from '../packages/gate/eg1-conformance.js';

function signer(kid, principalId = `principal:${kid}`) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    kid,
    principal_id: principalId,
    privateKey,
    key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

const alice = signer('alice');
const bob = signer('bob');
const carol = signer('carol');
const now = Date.parse('2026-07-04T01:00:00.000Z');
const fields = {
  scope: { action_types: ['db.restore'] },
  window: {
    not_before: '2026-07-04T00:00:00.000Z',
    expires_at: '2026-07-04T04:00:00.000Z',
  },
  reason: 'restore production',
  incident_ref: 'INC-1',
  threshold: 2,
};

function policy(entries = [alice, bob, carol]) {
  return {
    minimum_threshold: 2,
    roster: entries.map((entry) => ({
      kid: entry.kid,
      principal_id: entry.principal_id,
      key: entry.key,
    })),
  };
}

function grant(signers, overrides = {}) {
  const values = { ...fields, ...overrides };
  const core = {
    scope: { action_types: values.scope.action_types.slice() },
    window: { ...values.window },
    reason: values.reason,
    incident_ref: values.incident_ref,
    threshold: values.threshold,
  };
  const grant_id = `bg_${crypto.createHash('sha256').update(canonicalize(core)).digest('hex')}`;
  const payload = { grant_id, ...core };
  const bytes = Buffer.from(canonicalize(payload), 'utf8');
  return {
    '@version': BREAKGLASS_VERSION,
    payload,
    signatures: signers.map((entry) => ({
      kid: entry.kid,
      algorithm: 'Ed25519',
      value: crypto.sign(null, bytes, entry.privateKey).toString('base64url'),
    })),
  };
}

function verify(value, pinned = policy()) {
  return verifyBreakGlass(value, {
    policy: pinned,
    actionType: 'db.restore',
    now,
  });
}

function secureStore(options = {}) {
  const backend = createMemoryBackend();
  backend.durable = true;
  return createDurableConsumptionStore(backend, options);
}

describe('Gate core security remediation mutation oracles', () => {
  it('uses the pinned break-glass minimum and roster, never presenter policy', () => {
    expect(verify(grant([alice], { threshold: 1 }))).toMatchObject({
      valid: false,
      reason: 'policy_threshold_unmet',
      required_threshold: 2,
    });
    expect(verify(grant([alice, carol]), policy([alice, bob]))).toMatchObject({
      valid: false,
      reason: 'signer_not_in_roster',
      kid: 'carol',
    });
    expect(verify(grant([alice, bob]))).toMatchObject({
      valid: true,
      policy_minimum_threshold: 2,
      signer_principal_ids: ['principal:alice', 'principal:bob'],
    });
  });

  it('fails closed on malformed pinned policies and malformed signed quorums', () => {
    const value = grant([alice, bob]);
    const verifyWith = (pinned) => verifyBreakGlass(value, {
      policy: pinned,
      actionType: 'db.restore',
      now,
    });
    expect(verifyWith(undefined)).toMatchObject({ valid: false, reason: 'missing_policy' });

    const aliceEntry = policy([alice]).roster[0];
    const bobEntry = policy([bob]).roster[0];
    const malformed = [
      { minimum_threshold: 1, roster: [aliceEntry, bobEntry] },
      { minimum_threshold: 2.5, roster: [aliceEntry, bobEntry] },
      { minimum_threshold: 2, roster: {} },
      { minimum_threshold: 2, roster: [aliceEntry] },
      { minimum_threshold: 2, roster: [null, bobEntry] },
      { minimum_threshold: 2, roster: [[], bobEntry] },
      { minimum_threshold: 2, roster: [aliceEntry, { ...bobEntry, kid: aliceEntry.kid }] },
      { minimum_threshold: 2, roster: [aliceEntry, { ...bobEntry, principal_id: '' }] },
      { minimum_threshold: 2, roster: [aliceEntry, { ...bobEntry, key: 'not-a-key' }] },
      { minimum_threshold: 2, roster: [aliceEntry, { ...bobEntry, principal_id: aliceEntry.principal_id }] },
      { minimum_threshold: 2, roster: [aliceEntry, { ...bobEntry, key: aliceEntry.key }] },
    ];
    for (const pinned of malformed) {
      expect(verifyWith(pinned)).toMatchObject({ valid: false, reason: 'invalid_policy' });
    }

    expect(verify(grant([alice, alice]))).toMatchObject({
      valid: false,
      reason: 'duplicate_signer',
      kid: 'alice',
    });
    expect(verify(grant([alice, bob], { threshold: 3 }))).toMatchObject({
      valid: false,
      reason: 'threshold_unmet',
      threshold: 3,
      signatures: 2,
    });
    const tampered = grant([alice, bob]);
    tampered.signatures[1].value = tampered.signatures[1].value.slice(0, -2) + 'xx';
    expect(verify(tampered)).toMatchObject({ valid: false, reason: 'bad_signature', kid: 'bob' });
  });

  it('counts neither principal aliases nor duplicate SPKI keys', () => {
    const aliceSecond = signer('alice-second', alice.principal_id);
    expect(verify(
      grant([alice, aliceSecond]),
      policy([alice, aliceSecond, bob]),
    )).toMatchObject({
      valid: false,
      reason: 'duplicate_signer_principal',
      principal_id: alice.principal_id,
    });

    const keyAlias = { ...alice, kid: 'alice-key-alias', principal_id: 'principal:alias' };
    expect(verify(
      grant([alice, keyAlias]),
      policy([alice, keyAlias, bob]),
    )).toMatchObject({
      valid: false,
      reason: 'duplicate_signer_key',
      spki_fingerprint: `sha256:${crypto.createHash('sha256').update(Buffer.from(alice.key, 'base64url')).digest('hex')}`,
    });
  });

  it('runs a break-glass effect only after permanent consumption and strict evidence', async () => {
    const events = [];
    const baseStore = secureStore();
    const store = {
      ...baseStore,
      async consume(key) {
        events.push('consume');
        return baseStore.consume(key);
      },
    };
    const baseEvidence = createEvidenceLog({ strict: true });
    const evidence = {
      ...baseEvidence,
      async record(entry) {
        events.push('evidence');
        return baseEvidence.record(entry);
      },
    };
    const result = await runBreakGlass({
      grant: grant([alice, bob]), policy: policy(), actionType: 'db.restore', store, evidence, now,
    }, async () => {
      events.push('effect');
      return 'done';
    });
    expect(result).toMatchObject({ ok: true, reason: 'breakglass_executed', result: 'done' });
    expect(events).toEqual(['consume', 'evidence', 'effect']);
  });

  it('burns the grant and invokes no effect when strict evidence fails', async () => {
    const store = secureStore();
    let effects = 0;
    const value = grant([alice, bob]);
    const result = await runBreakGlass({
      grant: value,
      policy: policy(),
      actionType: 'db.restore',
      store,
      evidence: createEvidenceLog({
        strict: true,
        sink: async () => { throw new Error('offline'); },
      }),
      now,
    }, async () => { effects += 1; });
    expect(result).toMatchObject({ ok: false, reason: 'evidence_record_failed' });
    expect(effects).toBe(0);
    expect(await store.consume(`breakglass:${value.payload.grant_id}`)).toBe(false);
  });

  it('refuses replay, non-strict evidence, and malformed evidence acknowledgements', async () => {
    const value = grant([alice, bob]);
    const store = secureStore();
    let effects = 0;
    const args = { grant: value, policy: policy(), actionType: 'db.restore', store, now };

    const nonStrict = await runBreakGlass({
      ...args,
      evidence: createEvidenceLog({ strict: false }),
    }, async () => { effects += 1; });
    expect(nonStrict).toMatchObject({ ok: false, reason: 'strict_evidence_required' });

    const malformedAck = await runBreakGlass({
      ...args,
      evidence: { strict: true, record: async () => ({}) },
    }, async () => { effects += 1; });
    expect(malformedAck).toMatchObject({ ok: false, reason: 'evidence_record_failed' });

    const replay = await runBreakGlass({
      ...args,
      evidence: createEvidenceLog({ strict: true }),
    }, async () => { effects += 1; });
    expect(replay).toMatchObject({ ok: false, reason: 'already_consumed' });
    expect(effects).toBe(0);
  });

  it('returns closed runner results for failed verification and missing evidence APIs', async () => {
    let effects = 0;
    const invalid = await runBreakGlass({
      grant: grant([alice], { threshold: 1 }),
      policy: policy(),
      actionType: 'db.restore',
      store: secureStore(),
      evidence: createEvidenceLog({ strict: true }),
      now,
    }, async () => { effects += 1; });
    expect(invalid).toMatchObject({
      ok: false,
      reason: 'policy_threshold_unmet',
      consumption: null,
      evidence: null,
    });

    const noRecord = await runBreakGlass({
      grant: grant([alice, bob]),
      policy: policy(),
      actionType: 'db.restore',
      store: secureStore(),
      evidence: { strict: true },
      now,
    }, async () => { effects += 1; });
    expect(noRecord).toMatchObject({ ok: false, reason: 'strict_evidence_required' });

    const noEvidence = await runBreakGlass({
      grant: grant([alice, bob]),
      policy: policy(),
      actionType: 'db.restore',
      store: secureStore(),
      evidence: null,
      now,
    }, async () => { effects += 1; });
    expect(noEvidence).toMatchObject({ ok: false, reason: 'strict_evidence_required' });
    expect(effects).toBe(0);
  });

  it('requires every secure consumption capability in runBreakGlass and createGate', async () => {
    const value = grant([alice, bob]);
    for (const capability of ['durable', 'ownershipFenced', 'permanentConsumption']) {
      const insecure = { ...secureStore(), [capability]: false };
      const result = await runBreakGlass({
        grant: value,
        policy: policy(),
        actionType: 'db.restore',
        store: insecure,
        evidence: createEvidenceLog({ strict: true }),
        now,
      }, async () => 'forbidden');
      expect(result.ok, capability).toBe(false);
      expect(result.reason, capability).toBe('secure_consumption_store_required');
      expect(() => createGate({ store: insecure }), capability).toThrow(/durable.*ownership-fenced.*permanent/i);
    }
    expect(() => createGate({ store: secureStore() })).not.toThrow();
    expect(() => createGate({ store: new MemoryConsumptionStore() })).toThrow(/durable.*ownership-fenced.*permanent/i);
    expect(() => createGate({ allowEphemeralStore: true })).not.toThrow();

    for (const method of ['consume', 'reserve', 'commit']) {
      const malformed = { ...secureStore(), [method]: undefined };
      expect(() => createGate({ store: malformed }), method).toThrow(new RegExp(`implement ${method}`));

      const result = await runBreakGlass({
        grant: value,
        policy: policy(),
        actionType: 'db.restore',
        store: malformed,
        evidence: createEvidenceLog({ strict: true }),
        now,
      }, async () => 'forbidden');
      expect(result.ok, method).toBe(false);
      expect(result.reason, method).toBe('secure_consumption_store_required');
    }
    expect(isSecureConsumptionStore(null)).toBe(false);
    expect(isSecureConsumptionStore(() => {})).toBe(false);
    expect(isSecureConsumptionStore(1)).toBe(false);
    expect(isSecureConsumptionStore(secureStore())).toBe(true);
    expect(() => createGate({ store: null })).toThrow(/durable.*ownership-fenced.*permanent/i);
    expect(() => createGate({ store: () => {} })).toThrow(/implement consume/);
  });

  it('throws on invalid registry windows and closes invalid evaluation times', () => {
    const entry = { kid: 'issuer', key: alice.key };
    for (const invalid of ['not-a-date', '01/02/2030', 1893456000000, null, undefined]) {
      expect(() => createKeyRegistry([{ ...entry, not_after: invalid }])).toThrow(/not_after.*RFC3339/);
    }
    const registry = createKeyRegistry([entry]);
    expect(registry.keysValidAt('not-a-date')).toEqual([]);
    expect(registry.keysValidAt(1893456000000)).toEqual([]);
    expect(registry.keysValidAt(undefined)).toEqual([]);
    expect(registry.keysValidAt('2026-07-04T01:00:00.000Z')).toEqual([alice.key]);
  });

  it('enforces strict registry bounds at both inclusive window edges', () => {
    const entry = {
      kid: 'windowed',
      key: alice.key,
      not_before: '2026-07-04T01:00:00.000Z',
      not_after: '2026-07-04T02:00:00.000Z',
    };
    const registry = createKeyRegistry([entry]);
    expect(registry.keysValidAt('2026-07-04T00:59:59.999Z')).toEqual([]);
    expect(registry.keysValidAt(entry.not_before)).toEqual([alice.key]);
    expect(registry.keysValidAt(entry.not_after)).toEqual([alice.key]);
    expect(registry.keysValidAt('2026-07-04T02:00:00.001Z')).toEqual([]);
    expect(registry.status()[0].active).toBe(false);

    const unwindowed = createKeyRegistry([{ key: alice.key }]);
    expect(unwindowed.status()[0]).toMatchObject({
      kid: alice.key.slice(0, 16),
      active: true,
      revoked: false,
    });

    const onlyBefore = createKeyRegistry([{ kid: 'before', key: alice.key, not_before: entry.not_before }]);
    expect(onlyBefore.keysValidAt('2026-07-04T00:59:59.999Z')).toEqual([]);
    expect(onlyBefore.keysValidAt(entry.not_before)).toEqual([alice.key]);
    const onlyAfter = createKeyRegistry([{ kid: 'after', key: alice.key, not_after: entry.not_after }]);
    expect(onlyAfter.keysValidAt(entry.not_after)).toEqual([alice.key]);
    expect(onlyAfter.keysValidAt('2026-07-04T02:00:00.001Z')).toEqual([]);

    expect(() => createKeyRegistry([{
      kid: 'instant', key: alice.key, not_before: entry.not_before, not_after: entry.not_before,
    }])).not.toThrow();
    const revoked = createKeyRegistry([{ kid: 'revoked', key: alice.key, revoked_at: entry.not_before }]);
    expect(revoked.keysValidAt(entry.not_before)).toEqual([]);
    expect(registry.status('not-a-date')[0].active).toBe(false);

    expect(() => createKeyRegistry([{ ...entry, not_before: '2026-07-04' }])).toThrow(/not_before.*RFC3339/);
    expect(() => createKeyRegistry([{ ...entry, revoked_at: '2026-7-04T00:00:00Z' }])).toThrow(/revoked_at.*RFC3339/);
    expect(() => createKeyRegistry([{ ...entry, not_before: '2026-07-04T03:00:00Z' }])).toThrow(/must not precede/);
    expect(() => registry.add({ kid: 'bad', key: alice.key, not_after: '2026-07-04T02:00:00Zjunk' })).toThrow(/RFC3339/);
    expect(() => registry.revoke('windowed', 'tomorrow')).toThrow(/revoked_at.*RFC3339/);
  });
});

const fingerprintOf = (key) => `sha256:${crypto.createHash('sha256').update(Buffer.from(key, 'base64url')).digest('hex')}`;

describe('Gate fail-closed type-confusion and ordering oracles', () => {
  it('refuses a pinned roster entry that is not a plain object, however well-formed its fields', () => {
    // A deserialized model instance carries kid/principal_id/key but is NOT a
    // plain object. Accepting it would let a presenter-supplied prototype decide
    // roster membership; the policy must refuse before any signature is checked.
    class RosterRecord {
      kid: string;

      principal_id: string;

      key: string;

      constructor(entry) {
        this.kid = entry.kid;
        this.principal_id = entry.principal_id;
        this.key = entry.key;
      }
    }
    const aliceEntry = policy([alice]).roster[0];
    const bobEntry = policy([bob]).roster[0];
    const exotic = [
      new RosterRecord(bobEntry),
      Object.assign(Object.create({ inherited: true }), bobEntry),
      Object.assign([], bobEntry),
    ];
    for (const entry of exotic) {
      expect(verifyBreakGlass(grant([alice, bob]), {
        policy: { minimum_threshold: 2, roster: [aliceEntry, entry] },
        actionType: 'db.restore',
        now,
      })).toMatchObject({ valid: false, reason: 'invalid_policy' });
    }
  });

  it('refuses a pinned roster entry with no kid, never falling through to an unkeyed slot', () => {
    const aliceEntry = policy([alice]).roster[0];
    const bobEntry = policy([bob]).roster[0];
    const unkeyed = [
      { principal_id: bob.principal_id, key: bob.key },
      { ...bobEntry, kid: '' },
      { ...bobEntry, kid: 7 },
    ];
    for (const entry of unkeyed) {
      expect(verifyBreakGlass(grant([alice, bob]), {
        policy: { minimum_threshold: 2, roster: [aliceEntry, entry] },
        actionType: 'db.restore',
        now,
      })).toMatchObject({ valid: false, reason: 'invalid_policy' });
    }
  });

  it('refuses a callable signature entry that carries a genuine kid and signature value', () => {
    // typeof s === 'function' is not an object. A callable that answers .kid,
    // .algorithm and .value would otherwise verify like a real signature.
    const doc = grant([alice, bob]);
    const authentic = doc.signatures[1];
    doc.signatures[1] = Object.assign(function signature() {}, {
      kid: authentic.kid,
      algorithm: authentic.algorithm,
      value: authentic.value,
    }) as any;
    expect(verify(doc)).toMatchObject({ valid: false, reason: 'grant_malformed' });
  });

  it('refuses a signature whose value is not a string before any verification is attempted', () => {
    for (const value of [42, ['a'], { v: 'a' }, null]) {
      const doc = grant([alice, bob]);
      doc.signatures[1].value = value as any;
      // grant_malformed, never bad_signature: a non-string value must be
      // rejected by shape, not by a failed Buffer.from() deep in the verifier.
      expect(verify(doc)).toMatchObject({ valid: false, reason: 'grant_malformed' });
    }
    const missingKid = grant([alice, bob]);
    delete (missingKid.signatures[1] as any).kid;
    expect(verify(missingKid)).toMatchObject({ valid: false, reason: 'grant_malformed' });
  });

  it('names the actual duplicated principal, not the first signer in the list', () => {
    const aliceSecond = signer('alice-second', alice.principal_id);
    const roster = policy([bob, alice, aliceSecond]);
    const result = verify(grant([bob, alice, aliceSecond]), roster);
    expect(result).toMatchObject({ valid: false, reason: 'duplicate_signer_principal' });
    // bob is a legitimate distinct human: reporting him would misattribute the
    // separation-of-duties violation and hide the aliased principal.
    expect((result as any).principal_id).toBe(alice.principal_id);
    expect((result as any).principal_id).not.toBe(bob.principal_id);
  });

  it('names the actual duplicated SPKI key, not the first signer in the list', () => {
    const keyAlias = { ...alice, kid: 'alice-key-alias', principal_id: 'principal:alias' };
    const roster = policy([bob, alice, keyAlias]);
    const result = verify(grant([bob, alice, keyAlias]), roster);
    expect(result).toMatchObject({ valid: false, reason: 'duplicate_signer_key' });
    expect((result as any).spki_fingerprint).toBe(fingerprintOf(alice.key));
    expect((result as any).spki_fingerprint).not.toBe(fingerprintOf(bob.key));
  });

  it('refuses a callable masquerading as a fully capable consumption store', async () => {
    // Every capability flag and method answers correctly; only the type betrays
    // it. A function is not a durable store and must never fence replay.
    const callable = Object.assign(async () => true, {
      durable: true,
      ownershipFenced: true,
      permanentConsumption: true,
      consume: async () => true,
      reserve: async () => true,
      commit: async () => true,
    });
    expect(isSecureConsumptionStore(callable)).toBe(false);
    expect(() => createGate({ store: callable as any })).toThrow(/durable.*ownership-fenced.*permanent/i);
    let effects = 0;
    const result = await runBreakGlass({
      grant: grant([alice, bob]),
      policy: policy(),
      actionType: 'db.restore',
      store: callable as any,
      evidence: createEvidenceLog({ strict: true }),
      now,
    }, async () => { effects += 1; });
    expect(result).toMatchObject({ ok: false, reason: 'secure_consumption_store_required' });
    expect(effects).toBe(0);
  });

  it('refuses a durable reservation with a named error when the platform CSPRNG is absent', async () => {
    const store = secureStore();
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    try {
      Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });
      // A missing crypto object must produce the named fail-closed refusal, not
      // a TypeError from dereferencing it.
      await expect(store.reserve('no-csprng')).rejects.toThrow(
        'secure crypto.randomUUID() is required for durable reservation fencing',
      );
    } finally {
      if (original) Object.defineProperty(globalThis, 'crypto', original);
    }
    expect(await store.reserve('csprng-restored')).toBe(true);
  });

  it('accepts a registry entry bounded only by not_after, including one already expired', () => {
    const legacy = createKeyRegistry([{ kid: 'legacy', key: alice.key, not_after: '1969-06-01T00:00:00.000Z' }]);
    expect(legacy.keysValidAt('1969-06-01T00:00:00.000Z')).toEqual([alice.key]);
    expect(legacy.keysValidAt('1969-06-01T00:00:00.001Z')).toEqual([]);
    expect(legacy.keysValidAt('2026-07-04T01:00:00.000Z')).toEqual([]);
  });

  it('treats an unwindowed registry key as valid at every instant, including before the epoch', () => {
    const unwindowed = createKeyRegistry([{ kid: 'unwindowed', key: alice.key }]);
    expect(unwindowed.keysValidAt('1969-06-01T00:00:00.000Z')).toEqual([alice.key]);
    expect(unwindowed.keysValidAt('2026-07-04T01:00:00.000Z')).toEqual([alice.key]);
  });
});

describe('Gate construction guards fail closed without a runtime monitor', () => {
  const guardedManifest = {
    '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
    actions: [{
      id: 'release',
      action_type: 'payment.release',
      receipt_required: true,
      risk: 'critical',
      assurance_class: 'class_a',
      match: { protocol: 'mcp', tool: 'release_payment' },
    }],
  };
  const unguardedManifest = {
    '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
    actions: [{
      id: 'read',
      action_type: 'ledger.read',
      receipt_required: false,
      risk: 'low',
      match: { protocol: 'mcp', tool: 'read_ledger' },
    }],
  };

  it('checks cleanly with no runtime monitor at all', async () => {
    const gate = createGate({ allowEphemeralStore: true, runtimeMonitor: null });
    const out = await gate.check({ selector: { action_type: 'payment.release' } });
    expect(out).toMatchObject({ allow: false, reason: 'receipt_required' });
    const withReceipt = await gate.check({ selector: { action_type: 'payment.release' }, receipt: {} });
    expect(withReceipt.allow).toBe(false);
    expect(String(withReceipt.reason)).toMatch(/^receipt_rejected:/);
  });

  it('refuses a receipt object with no payload instead of dereferencing it', async () => {
    const gate = createGate({ allowEphemeralStore: true });
    for (const receipt of [{}, { payload: null }, { payload: undefined }]) {
      const out = await gate.check({ selector: { action_type: 'payment.release' }, receipt });
      expect(out.allow).toBe(false);
      expect(String(out.reason)).toMatch(/^receipt_rejected:/);
    }
  });

  it('checks a selector-only action with no manifest requirement', async () => {
    const gate = createGate({ allowEphemeralStore: true });
    const out = await gate.check({ selector: { action_type: 'payment.release' } });
    expect(out).toMatchObject({ allow: false, reason: 'receipt_required', requirement: null });
  });

  it('reports the true guarded flag to the runtime monitor', async () => {
    const decisions: any[] = [];
    const spy = (manifest) => {
      const base = createRuntimeMonitor({});
      const monitor = {
        ...base,
        recordDecision(cycleId, details) {
          decisions.push(details);
          return base.recordDecision(cycleId, details);
        },
      };
      return createGate({ manifest, allowEphemeralStore: true, runtimeMonitor: monitor as any });
    };

    const unguarded = await spy(unguardedManifest).check({ selector: { protocol: 'mcp', tool: 'read_ledger' } });
    expect(unguarded).toMatchObject({ allow: true, reason: 'not_guarded' });
    expect(decisions.at(-1).guarded).toBe(false);

    const guarded = await spy(guardedManifest).check({ selector: { protocol: 'mcp', tool: 'release_payment' } });
    expect(guarded).toMatchObject({ allow: false, reason: 'receipt_required' });
    expect(decisions.at(-1).guarded).toBe(true);
  });

  it('enforces a runtime-monitor tier floor above the declared tier', async () => {
    const base = createRuntimeMonitor({});
    const monitor = { ...base, minimumAssuranceTier: () => 'class_a' };
    const gate = createGate({ allowEphemeralStore: true, runtimeMonitor: monitor as any });
    const out = await gate.check({ selector: { action_type: 'payment.release', assurance_class: 'software' } });
    expect(out).toMatchObject({ allow: false, reason: 'receipt_required' });
    // The refusal must challenge for the RAISED tier; echoing the declared
    // 'software' tier would let the caller satisfy the weaker requirement.
    expect(String(out.header)).toContain('class_a');
    expect(String(out.header)).not.toContain('software');
    expect(JSON.stringify(out.challenge)).toContain('class_a');
  });

  it('builds a strict evidence log unless the operator explicitly opts out', () => {
    expect(createGate({ allowEphemeralStore: true }).evidence.strict).toBe(true);
    expect(createGate({ allowEphemeralStore: true, strictEvidence: true }).evidence.strict).toBe(true);
    expect(createGate({ allowEphemeralStore: true, strictEvidence: false }).evidence.strict).toBe(false);
  });

  it('consults the per-action pinned quorum policy, and refuses when none is pinned', async () => {
    const harness = createEg1Harness({});
    const receipt = harness.mint({ outcome: 'allow' });
    const gateWith = (quorumPolicies) => createGate({
      trustedKeys: [harness.publicKey],
      allowEphemeralStore: true,
      approverKeys: harness.approverKeys,
      rpId: harness.rpId,
      allowedOrigins: harness.allowedOrigins,
      quorumPolicy: null,
      quorumPolicies: quorumPolicies as any,
    });
    const ask = (gate) => gate.check({
      selector: { action_type: 'payment.release', assurance_class: 'quorum' },
      receipt,
      observedAction: harness.action,
    });

    // Pinned for THIS action: the policy is found, so the refusal is about the
    // receipt's tier, not a missing policy.
    const pinned = await ask(gateWith({ 'payment.release': harness.quorumPolicy }));
    expect(pinned).toMatchObject({ allow: false, reason: 'assurance_too_low' });

    // Nothing pinned for this action: fail closed on the policy itself.
    const other = await ask(gateWith({ 'ledger.read': harness.quorumPolicy }));
    expect(other).toMatchObject({ allow: false, reason: 'quorum_policy_required' });

    // A quorumPolicies registry that is not an object must never be indexed for
    // a policy, even when it answers the action key.
    const callableRegistry = Object.assign(() => {}, { 'payment.release': harness.quorumPolicy });
    const callable = await ask(gateWith(callableRegistry));
    expect(callable).toMatchObject({ allow: false, reason: 'quorum_policy_required' });
  });

  it('pins the configured capability issuer keys into the capability executor', async () => {
    const harness = createEg1Harness({});
    const baseReceipt = harness.mint({ outcome: 'allow', extra: { capability_only: true } });
    const issuer = crypto.generateKeyPairSync('ed25519');
    const issuerPublicKey = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const decoy = crypto.generateKeyPairSync('ed25519').publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    const minted = mintCapabilityReceipt(baseReceipt, {
      issuerPrivateKey: issuer.privateKey,
      budget: { amount: 100000, currency: 'USD' },
      expiry: new Date(Date.now() + 3_600_000).toISOString(),
      scope: {
        profile: CAPABILITY_SCOPE_PROFILE,
        action_digests: [capabilityActionDigest(harness.action)],
        operation_id_field: 'payment_instruction_id',
      },
    });
    const capabilityStore = {
      registerCapability: async () => ({ ok: true }),
      reserveSpend: async () => ({ ok: true, reservation_id: 'res_1' }),
      commitSpend: async () => ({ ok: true }),
      reconcileSpend: async () => ({ ok: true }),
    };
    const gateWith = (capabilityTrustedIssuerKeys) => createGate({
      trustedKeys: [harness.publicKey],
      allowEphemeralStore: true,
      capabilityStore: capabilityStore as any,
      capabilityTrustedIssuerKeys,
      approverKeys: harness.approverKeys,
      rpId: harness.rpId,
      allowedOrigins: harness.allowedOrigins,
    });
    const call = (gate) => gate.run({
      selector: { action_type: 'payment.release' },
      capability: {
        capabilityReceipt: minted.capabilityReceipt,
        action: harness.action,
        operationId: String((harness.action as any).payment_instruction_id),
        secret: minted.secret,
      },
    }, async () => 'ran');

    // An issuer outside the pinned set is refused as untrusted...
    const unpinned = await call(gateWith([decoy]));
    expect(unpinned.ok).toBe(false);
    expect(unpinned.capability.reason).toBe('capability_issuer_not_trusted');

    // ...and the pinned issuer must actually reach the executor, so the refusal
    // moves past the issuer-trust gate.
    const pinnedRun = await call(gateWith([issuerPublicKey, decoy]));
    expect(pinnedRun.ok).toBe(false);
    expect(pinnedRun.capability.reason).not.toBe('capability_issuer_not_trusted');
  });

  it('checks cleanly when quorumPolicies is null, an array, or a primitive', async () => {
    for (const quorumPolicies of [null, [], ['x'], 'quorum', 7, true]) {
      const gate = createGate({ allowEphemeralStore: true, quorumPolicies: quorumPolicies as any });
      const out = await gate.check({ selector: { action_type: 'payment.release' } });
      expect(out, String(quorumPolicies)).toMatchObject({ allow: false, reason: 'receipt_required' });
    }
  });
});
