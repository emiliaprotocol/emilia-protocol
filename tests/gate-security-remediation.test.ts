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
