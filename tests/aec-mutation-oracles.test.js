// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { __aecSecurityInternals, actionDigest } from '../packages/verify/evidence-chain.js';
import { __aecExecutionSecurityInternals } from '../packages/gate/aec-execution.js';
import {
  __atomicEvidenceSecurityInternals,
  createAtomicEvidenceLog,
  createMemoryAtomicEvidenceBackend,
} from '../packages/gate/evidence.js';

const HEX = 'ab'.repeat(32);
const OTHER_HEX = 'cd'.repeat(32);
const at = '2026-07-11T12:00:00.000Z';
const context = {
  issued_at: '2026-07-11T11:55:00.000Z',
  expires_at: '2026-07-11T12:05:00.000Z',
};
const directoryEntry = {
  status: 'active',
  valid_from: '2026-07-11T11:00:00.000Z',
  valid_to: '2026-07-11T13:00:00.000Z',
  revoked_at: null,
};
const encodeClientData = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

describe('AEC verifier mutation oracles', () => {
  const {
    normDigest, strictInstantMs, freshAt, freshRegistrySnapshot,
    activeDirectoryEntry, allowedOriginSet, webauthnOrigin,
    validUnicodeString, boundedJson, tokenizeRequirement, evalRequirement,
  } = __aecSecurityInternals;

  it('computes a fixed SHA-256 digest over canonical action bytes', () => {
    expect(actionDigest({ x: 1 })).toBe('5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22');
  });

  it('normalizes only exact SHA-256 digest forms', () => {
    expect(normDigest(HEX)).toBe(HEX);
    expect(normDigest(`SHA256:${HEX.toUpperCase()}`)).toBe(HEX);
    for (const value of [null, 1, '', 'sha256:', `sha512:${HEX}`, HEX.slice(1), `${HEX}0`, 'g'.repeat(64)]) {
      expect(normDigest(value)).toBeNull();
    }
    expect(normDigest(OTHER_HEX)).toBe(OTHER_HEX);
  });

  it('parses strict calendar instants and rejects normalization aliases', () => {
    for (const value of [
      '2024-02-29T23:59:59Z',
      '2026-01-01T00:00:00.123456789+23:59',
      '0001-01-01T00:00:00Z',
    ]) expect(Number.isFinite(strictInstantMs(value))).toBe(true);
    for (const value of [
      null, 0, '', '2026-01-01', '2026-02-29T00:00:00Z',
      '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z',
      '2026-01-01T00:00:60Z', '2026-01-01T00:00:00+24:00',
      '2026-01-01T00:00:00+00:60',
    ]) expect(Number.isNaN(strictInstantMs(value))).toBe(true);
  });

  it('enforces evidence freshness at every boundary', () => {
    expect(freshAt(context, at, 300)).toBe(true);
    expect(freshAt(context, '2026-07-11T11:55:00.000Z', 0)).toBe(true);
    expect(freshAt(context, '2026-07-11T12:05:00.000Z', 600)).toBe(true);
    expect(freshAt(context, '2026-07-11T11:54:59.999Z', 600)).toBe(false);
    expect(freshAt(context, '2026-07-11T12:05:00.001Z', 601)).toBe(false);
    expect(freshAt(context, at, 299)).toBe(false);
    expect(freshAt(context, at, -1)).toBe(false);
    expect(freshAt(context, at, 300.5)).toBe(false);
    expect(freshAt({}, at, 300)).toBe(false);
    expect(freshAt(context, 'invalid', 300)).toBe(false);
  });

  it('enforces registry freshness without future or stale checkpoints', () => {
    const profile = { registry_checked_at: '2026-07-11T11:55:00.000Z', max_registry_age_sec: 300 };
    expect(freshRegistrySnapshot(profile, at)).toBe(true);
    expect(freshRegistrySnapshot({ ...profile, max_registry_age_sec: 299 }, at)).toBe(false);
    expect(freshRegistrySnapshot({ ...profile, registry_checked_at: '2026-07-11T12:00:00.001Z' }, at)).toBe(false);
    expect(freshRegistrySnapshot({ ...profile, max_registry_age_sec: -1 }, at)).toBe(false);
    expect(freshRegistrySnapshot({ ...profile, max_registry_age_sec: 300.5 }, at)).toBe(false);
    expect(freshRegistrySnapshot({}, at)).toBe(false);
  });

  it('admits only active directory entries in-window and before revocation', () => {
    expect(activeDirectoryEntry(directoryEntry, at)).toBe(true);
    expect(activeDirectoryEntry({ ...directoryEntry, revoked_at: '2026-07-11T12:00:00.001Z' }, at)).toBe(true);
    expect(activeDirectoryEntry({ ...directoryEntry, revoked_at: at }, at)).toBe(false);
    expect(activeDirectoryEntry({ ...directoryEntry, status: 'inactive' }, at)).toBe(false);
    expect(activeDirectoryEntry({ ...directoryEntry, valid_from: '2026-07-11T12:00:00.001Z' }, at)).toBe(false);
    expect(activeDirectoryEntry({ ...directoryEntry, valid_to: '2026-07-11T11:59:59.999Z' }, at)).toBe(false);
    expect(activeDirectoryEntry(null, at)).toBe(false);
    expect(activeDirectoryEntry(directoryEntry, 'invalid')).toBe(false);
  });

  it('requires a bounded non-empty origin allowlist', () => {
    expect(allowedOriginSet({ allowed_origins: ['https://one.example', 'https://two.example'] }))
      .toEqual(new Set(['https://one.example', 'https://two.example']));
    for (const origins of [undefined, null, [], Array(17).fill('https://x.example'), [1], [''], ['x'.repeat(2049)]]) {
      expect(allowedOriginSet({ allowed_origins: origins })).toBeNull();
    }
  });

  it('extracts origin only from canonical base64url JSON client data', () => {
    const good = encodeClientData({ type: 'webauthn.get', challenge: 'x', origin: 'https://rp.example' });
    expect(webauthnOrigin({ client_data_json: good })).toBe('https://rp.example');
    for (const client_data_json of [
      undefined, '', `${good}=`, '***', Buffer.from('{').toString('base64url'),
      encodeClientData([]), encodeClientData({ origin: 1 }),
    ]) expect(webauthnOrigin({ client_data_json })).toBeNull();
    expect(webauthnOrigin(null)).toBeNull();
  });

  it('rejects invalid Unicode and every non-canonical JSON value class', () => {
    expect(validUnicodeString('ok\ud83d\ude00')).toBe(true);
    expect(validUnicodeString('\ud800')).toBe(false);
    expect(validUnicodeString('\udc00')).toBe(false);
    expect(boundedJson({ ok: true, n: Number.MAX_SAFE_INTEGER, values: [null, 'x'] })).toBe(true);
    for (const value of [
      { n: Number.MAX_SAFE_INTEGER + 1 }, { n: 1.5 }, { value: undefined },
      { value: () => true }, { text: '\ud800' }, { '\ud800': true },
    ]) expect(boundedJson(value)).toBe(false);
  });

  it('enforces JSON depth, alias, node, and byte limits exactly', () => {
    let atLimit = true;
    for (let i = 0; i < 64; i++) atLimit = [atLimit];
    expect(boundedJson(atLimit)).toBe(true);
    expect(boundedJson([atLimit])).toBe(false);
    const shared = { value: true };
    expect(boundedJson({ a: shared, b: shared })).toBe(false);
    const cyclic = {};
    cyclic.self = cyclic;
    expect(boundedJson(cyclic)).toBe(false);
    expect(boundedJson(Array(49_999).fill(null))).toBe(true);
    expect(boundedJson(Array(50_000).fill(null))).toBe(false);
    expect(boundedJson({ text: 'a'.repeat(1024 * 1024 - 4) })).toBe(true);
    expect(boundedJson({ text: 'a'.repeat(1024 * 1024 - 3) })).toBe(false);
  });

  it('tokenizes the closed grammar with exact token and length bounds', () => {
    expect(tokenizeRequirement('a AND (b || c)')).toEqual(['a', 'AND', '(', 'b', '||', 'c', ')']);
    expect(tokenizeRequirement('urn:ep.action-v1')).toEqual(['urn:ep.action-v1']);
    expect(tokenizeRequirement('')).toBeNull();
    expect(tokenizeRequirement('a!')).toBeNull();
    expect(tokenizeRequirement('a'.repeat(4097))).toBeNull();
    expect(tokenizeRequirement(Array(128).fill('a').join(' OR '))).toHaveLength(255);
    expect(tokenizeRequirement(Array(129).fill('a').join(' OR '))).toBeNull();
  });

  it('evaluates the requirement grammar and refuses malformed or over-deep forms', () => {
    const satisfied = new Set(['a', 'c']);
    expect(evalRequirement('a AND c', satisfied)).toEqual({ valid: true, value: true });
    expect(evalRequirement('a AND b OR c', satisfied)).toEqual({ valid: true, value: true });
    expect(evalRequirement('a AND (b OR c)', satisfied)).toEqual({ valid: true, value: true });
    expect(evalRequirement('b OR c', new Set())).toEqual({ valid: true, value: false });
    for (const expression of ['a b', '(a', 'a)', 'AND a', 'a OR', '()', 'AND', 'OR', '&&', '||', ')']) {
      expect(evalRequirement(expression, satisfied)).toEqual({ valid: false, value: false });
    }
    expect(evalRequirement(`${'('.repeat(34)}a${')'.repeat(34)}`, satisfied)).toEqual({ valid: false, value: false });
  });
});

describe('AEC execution mutation oracles', () => {
  const {
    deepFreeze, validLogRecord, validComponent,
    humanFloorSatisfied, evidenceSatisfied, consumptionKey, instant,
  } = __aecExecutionSecurityInternals;

  it('deep-freezes nested and cyclic snapshots without changing primitives', () => {
    expect(deepFreeze(null)).toBeNull();
    expect(deepFreeze('x')).toBe('x');
    const value = { nested: { list: [1] } };
    expect(deepFreeze(value)).toBe(value);
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.nested)).toBe(true);
    expect(Object.isFrozen(value.nested.list)).toBe(true);
    const cyclic = {};
    cyclic.self = cyclic;
    expect(() => deepFreeze(cyclic)).not.toThrow();
    expect(Object.isFrozen(cyclic)).toBe(true);
  });

  it('accepts only structurally complete evidence acknowledgements', () => {
    const { canonical } = __atomicEvidenceSecurityInternals;
    const entry = { type: 'decision', allow: true };
    const localBody = { seq: 0, prev_hash: 'genesis', ...entry };
    const base = {
      ...localBody,
      hash: crypto.createHash('sha256').update(canonical(localBody)).digest('hex'),
    };
    const atomicBody = { seq: 0, prev_hash: 'genesis', record_id: '1234567890abcdef', ...entry };
    const atomic = {
      ...atomicBody,
      hash: crypto.createHash('sha256').update(canonical(atomicBody)).digest('hex'),
    };
    expect(validLogRecord(base, false, entry)).toBe(true);
    expect(validLogRecord(atomic, true, entry)).toBe(true);
    for (const record of [
      null, [], {}, { ...base, seq: -1 }, { ...base, seq: 0.5 },
      { ...base, prev_hash: 'bad' }, { ...base, hash: 'bad' },
    ]) expect(validLogRecord(record, false, entry)).toBe(false);
    expect(validLogRecord(base, true, entry)).toBe(false);
    expect(validLogRecord({ ...base, record_id: 1 }, true, entry)).toBe(false);
    expect(validLogRecord({ ...base, record_id: '1234567890abcde' }, true, entry)).toBe(false);
    expect(validLogRecord(base, false, { ...entry, allow: false })).toBe(false);
  });

  it('derives the human floor only from valid and action-bound typed components', () => {
    const classA = { type: 'ep-receipt', valid: true, bound: true };
    const quorum = { type: 'ep-quorum', valid: true, bound: true };
    expect(validComponent({ components: [classA] }, 'ep-receipt')).toBe(true);
    expect(validComponent({ components: [{ ...classA, valid: false }] }, 'ep-receipt')).toBe(false);
    expect(validComponent({ components: [{ ...classA, bound: false }] }, 'ep-receipt')).toBe(false);
    expect(validComponent({}, 'ep-receipt')).toBe(false);
    expect(validComponent(null, 'ep-receipt')).toBe(false);
    expect(humanFloorSatisfied({ components: [classA] }, 'class_a')).toBe(true);
    expect(humanFloorSatisfied({ components: [quorum] }, 'quorum')).toBe(true);
    expect(humanFloorSatisfied({ components: [classA] }, 'quorum')).toBe(false);
    expect(humanFloorSatisfied({ components: [quorum] }, 'class_a')).toBe(false);
    expect(humanFloorSatisfied({ components: [classA] }, 'class_a_or_quorum')).toBe(true);
    expect(humanFloorSatisfied({ components: [quorum] }, 'class_a_or_quorum')).toBe(true);
    expect(humanFloorSatisfied({ components: [] }, 'class_a_or_quorum')).toBe(false);
  });

  it('accepts the legacy allow result only when the new satisfaction field is absent', () => {
    expect(evidenceSatisfied({ satisfied: true, allow: false })).toBe(true);
    expect(evidenceSatisfied({ satisfied: false, allow: true })).toBe(false);
    expect(evidenceSatisfied({ allow: true })).toBe(true);
    expect(evidenceSatisfied({ allow: false })).toBe(false);
    expect(evidenceSatisfied(null)).toBe(false);
    expect(evidenceSatisfied({ get satisfied() { throw new Error('hostile result'); } })).toBe(false);
  });

  it('keys consumption only by a bare lowercase SHA-256 digest', () => {
    expect(consumptionKey({ action_digest: HEX })).toBe(`aec:action:${HEX}`);
    for (const action_digest of [null, '', `sha256:${HEX}`, HEX.toUpperCase(), HEX.slice(1), `${HEX}0`]) {
      expect(consumptionKey({ action_digest })).toBeNull();
    }
    expect(consumptionKey(null)).toBeNull();
  });

  it('normalizes only finite clock values', () => {
    expect(instant(() => 0)).toBe('1970-01-01T00:00:00.000Z');
    expect(instant(new Date('2026-07-11T12:00:00Z'))).toBe(at);
    expect(instant('2026-07-11T12:00:00Z')).toBe(at);
    expect(instant('invalid')).toBeNull();
    expect(instant(Number.POSITIVE_INFINITY)).toBeNull();
    expect(instant(() => { throw new Error('clock down'); })).toBeNull();
  });
});

describe('atomic evidence mutation oracles', () => {
  const { canonical, assertLogEntry, validateAtomicRecord, validHead } = __atomicEvidenceSecurityInternals;

  it('canonicalizes recursively with stable key order', () => {
    expect(canonical({ z: 1, a: [true, { y: null, x: 'v' }] }))
      .toBe('{"a":[true,{"x":"v","y":null}],"z":1}');
    expect(canonical(null)).toBe('null');
    expect(canonical('x')).toBe('"x"');
  });

  it('accepts bounded canonical entries and rejects every unsafe value class', () => {
    expect(() => assertLogEntry({ type: 'decision', safe: Number.MAX_SAFE_INTEGER })).not.toThrow();
    for (const value of [null, [], { seq: 1 }, { prev_hash: 'x' }, { record_id: 'x' }, { hash: 'x' },
      { n: 1.5 }, { n: Number.MAX_SAFE_INTEGER + 1 }, { x: undefined }, { x: () => true }]) {
      expect(() => assertLogEntry(value)).toThrow();
    }
    const alias = { x: true };
    expect(() => assertLogEntry({ a: alias, b: alias })).toThrow(/cycle or alias/);
    const cyclic = {};
    cyclic.self = cyclic;
    expect(() => assertLogEntry(cyclic)).toThrow(/cycle or alias/);
  });

  it('enforces atomic-entry depth, node, and string limits', () => {
    let atLimit = true;
    for (let i = 0; i < 64; i++) atLimit = [atLimit];
    expect(() => assertLogEntry({ value: atLimit })).toThrow(/resource limits/);
    expect(() => assertLogEntry({ values: Array(49_998).fill(null) })).not.toThrow();
    expect(() => assertLogEntry({ values: Array(49_999).fill(null) })).toThrow(/resource limits/);
    expect(() => assertLogEntry({ text: 'a'.repeat(1024 * 1024 - 8) })).not.toThrow();
    expect(() => assertLogEntry({ text: 'a'.repeat(1024 * 1024) })).toThrow(/string limit/);
  });

  it('validates recovered records against stable id, content, and hash', async () => {
    const backend = createMemoryAtomicEvidenceBackend();
    const log = createAtomicEvidenceLog(backend, { recordIdFactory: () => 'validated-record-id-01' });
    const entry = { type: 'decision', allow: true };
    const record = await log.record(entry);
    expect(validateAtomicRecord(record, record.record_id, entry)).toBe(true);
    expect(validateAtomicRecord(record, 'wrong-record-id-0001', entry)).toBe(false);
    expect(validateAtomicRecord({ ...record, seq: -1 }, record.record_id, entry)).toBe(false);
    expect(validateAtomicRecord({ ...record, prev_hash: 'bad' }, record.record_id, entry)).toBe(false);
    expect(validateAtomicRecord({ ...record, hash: OTHER_HEX }, record.record_id, entry)).toBe(false);
    expect(validateAtomicRecord(record, record.record_id, { ...entry, allow: false })).toBe(false);
    expect(validateAtomicRecord(null, record.record_id, entry)).toBe(false);
  });

  it('accepts only null or a complete non-negative shared head', () => {
    expect(validHead(null)).toBe(true);
    expect(validHead({ seq: 0, hash: HEX })).toBe(true);
    for (const head of [undefined, {}, [], { seq: -1, hash: HEX }, { seq: 0.5, hash: HEX }, { seq: 0, hash: 'bad' }]) {
      expect(validHead(head)).toBe(false);
    }
  });
});
