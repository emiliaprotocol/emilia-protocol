// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from 'vitest';
import {
  MemoryConsumptionStore,
  createDurableConsumptionStore,
  createMemoryBackend,
} from '../packages/gate/store.js';
import {
  __relianceSecurityInternals,
  RELIANCE_PROFILE_VERSION,
  validateRelianceProfile,
} from '../packages/verify/reliance.js';
import {
  __authoritySecurityInternals,
  authorityBinding,
  authorityResultCore,
  evaluateAuthorityVerdict,
  normalizeAuthorityRecord,
} from '../lib/authority/resolver.js';

function token(prefix = 'owner') {
  let n = 0;
  return () => `${prefix}-${String(++n).padStart(24, '0')}`;
}

describe('mutation oracles for the replay kernel', () => {
  it('memory store separates reserved and committed state', async () => {
    const store = new MemoryConsumptionStore();
    expect(await store.reserve('a')).toBe(true);
    expect(await store.reserve('a')).toBe(false);
    expect(await store.consume('a')).toBe(false);
    expect(await store.commit('a')).toBe(true);
    expect(await store.has('a')).toBe(true);
    expect(store.size).toBe(1);
    expect(await store.reserve('b')).toBe(true);
    expect(await store.release('b')).toBe(true);
    expect(await store.has('b')).toBe(false);
  });

  it('durable store requires every atomic primitive and a token source', () => {
    expect(() => createDurableConsumptionStore({})).toThrow(/addIfAbsent/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {} })).toThrow(/compareAndSet/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {}, compareAndSet() {} })).toThrow(/deleteIfValue/);
    expect(() => createDurableConsumptionStore({ addIfAbsent() {}, compareAndSet() {}, deleteIfValue() {} })).toThrow(/has/);
    expect(() => createDurableConsumptionStore(createMemoryBackend(), { reservationTokenFactory: 'not-a-function' })).toThrow(/must be a function/);
  });

  it('commits only its exact opaque reservation and then refuses replay', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, {
      ttlSeconds: 60,
      reservationTokenFactory: token(),
    });
    expect(await store.reserve('a')).toBe(true);
    expect(await backend.get('a')).toMatch(/^reserved:v2:/);
    expect(await store.commit('a')).toBe(true);
    expect(await backend.get('a')).toBe('committed:v2');
    expect(await store.reserve('a')).toBe(false);
    expect(await store.consume('a')).toBe(false);
  });

  it('a non-owner cannot commit or release an existing reservation', async () => {
    const backend = createMemoryBackend();
    const owner = createDurableConsumptionStore(backend, { reservationTokenFactory: token('owner') });
    const stranger = createDurableConsumptionStore(backend, { reservationTokenFactory: token('stranger') });
    expect(await owner.reserve('a')).toBe(true);
    await expect(stranger.commit('a')).rejects.toThrow(/does not own/);
    await expect(stranger.release('a')).rejects.toThrow(/does not own/);
    expect(await backend.has('a')).toBe(true);
  });

  it('refuses weak reservation tokens before touching shared state', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, { reservationTokenFactory: () => 'short' });
    await expect(store.reserve('a')).rejects.toThrow(/at least 16/);
    expect(await backend.has('a')).toBe(false);
  });

  it('enforces the exact 16-character token boundary and strict backend booleans', async () => {
    const backend = createMemoryBackend();
    const exact = createDurableConsumptionStore(backend, { reservationTokenFactory: () => '1234567890abcdef' });
    expect(await exact.reserve('exact')).toBe(true);

    const short = createDurableConsumptionStore(backend, { reservationTokenFactory: () => '1234567890abcde' });
    await expect(short.reserve('short')).rejects.toThrow(/at least 16/);
    const nonString = createDurableConsumptionStore(backend, { reservationTokenFactory: () => null });
    await expect(nonString.reserve('null')).rejects.toThrow(/unpredictable string/);

    const truthyBackend = {
      async addIfAbsent() { return 1; },
      async compareAndSet() { return 1; },
      async deleteIfValue() { return 1; },
      async has() { return 1; },
    };
    const strict = createDurableConsumptionStore(truthyBackend, { reservationTokenFactory: () => '1234567890abcdef' });
    expect(await strict.reserve('truthy')).toBe(false);
    expect(await strict.consume('truthy')).toBe(false);
    expect(await strict.has('truthy')).toBe(false);
  });

  it('passes TTL only to committed states and rejects missing secure randomness', async () => {
    const calls = [];
    const backend = {
      async addIfAbsent(_key, _value, options) { calls.push(options); return true; },
      async compareAndSet(_key, _expected, _replacement, options) { calls.push(options); return true; },
      async deleteIfValue() { return true; },
      async has() { return false; },
    };
    const store = createDurableConsumptionStore(backend, { ttlSeconds: 30, reservationTokenFactory: () => '1234567890abcdef' });
    expect(await store.reserve('a')).toBe(true);
    expect(await store.commit('a')).toBe(true);
    expect(await store.consume('b')).toBe(true);
    expect(calls).toEqual([undefined, { ttlSeconds: 30 }, { ttlSeconds: 30 }]);

    const original = globalThis.crypto;
    vi.stubGlobal('crypto', {});
    try {
      const noRandom = createDurableConsumptionStore(createMemoryBackend());
      await expect(noRandom.reserve('no-random')).rejects.toThrowError(
        'secure crypto.randomUUID() is required for durable reservation fencing',
      );
    } finally {
      vi.stubGlobal('crypto', original);
    }
  });

  it('rejects an absent backend through the durable contract instead of a native throw', () => {
    expect(() => createDurableConsumptionStore()).toThrowError(
      /backend must implement async addIfAbsent\(\)/,
    );
  });

  it('does not record ownership when the atomic reservation loses', async () => {
    const backend = {
      async addIfAbsent() { return false; },
      async compareAndSet() { return true; },
      async deleteIfValue() { return true; },
      async has() { return false; },
    };
    const store = createDurableConsumptionStore(backend, {
      reservationTokenFactory: () => '1234567890abcdef',
    });
    expect(await store.reserve('lost')).toBe(false);
    await expect(store.commit('lost')).rejects.toThrow(/does not own reservation lost/);
    await expect(store.release('lost')).rejects.toThrow(/does not own reservation lost/);
  });

  it('uses a secure default owner token and exposes exact shared state', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend);
    expect(await store.reserve('a')).toBe(true);
    expect(await backend.get('a')).toMatch(/^reserved:v2:[0-9a-f-]{36}$/);
    expect(await store.has('a')).toBe(true);
    expect(await store.release('a')).toBe(true);
    expect(await store.has('a')).toBe(false);
    expect(await store.consume('b')).toBe(true);
    expect(await store.has('b')).toBe(true);
  });

  it('fails closed when reservation ownership changes after local acquisition', async () => {
    const backend = createMemoryBackend();
    const store = createDurableConsumptionStore(backend, { reservationTokenFactory: token() });
    expect(await store.reserve('commit')).toBe(true);
    const commitValue = await backend.get('commit');
    expect(await backend.deleteIfValue('commit', commitValue)).toBe(true);
    expect(await backend.addIfAbsent('commit', 'reserved:v2:replacement-owner-token')).toBe(true);
    await expect(store.commit('commit')).rejects.toThrow(/ownership was lost/);
    expect(await backend.get('commit')).toBe('reserved:v2:replacement-owner-token');

    expect(await store.reserve('release')).toBe(true);
    const releaseValue = await backend.get('release');
    expect(await backend.deleteIfValue('release', releaseValue)).toBe(true);
    expect(await backend.addIfAbsent('release', 'reserved:v2:replacement-owner-token')).toBe(true);
    await expect(store.release('release')).rejects.toThrow(/ownership was lost/);
    expect(await backend.get('release')).toBe('reserved:v2:replacement-owner-token');
  });
});

describe('mutation oracles for reliance parsing and signed material', () => {
  const {
    strictInstantMs, toMs, pubKeyB64u, digestHex, parseNonNegativeDecimal,
    decimalGreaterThan, decimalEqual, exactMaterial, decimalMaterial,
    signedActionMaterial,
  } = __relianceSecurityInternals;

  it('strictly parses RFC3339 instants across calendar and offset boundaries', () => {
    expect(Number.isFinite(strictInstantMs('2024-02-29T23:59:59Z'))).toBe(true);
    expect(Number.isFinite(strictInstantMs('2026-01-01T00:00:00+23:59'))).toBe(true);
    for (const invalid of [
      null, 0, '', '2026-01-01', '2026-02-29T00:00:00Z',
      '2026-01-01T24:00:00Z', '2026-01-01T00:60:00Z',
      '2026-01-01T00:00:60Z', '2026-01-01T00:00:00+24:00',
      '2026-01-01T00:00:00+00:60',
    ]) expect(Number.isNaN(strictInstantMs(invalid))).toBe(true);
  });

  it('normalizes all supported evaluation-time and key/digest forms exactly', () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(123456);
    expect(toMs(undefined)).toBe(123456);
    now.mockRestore();
    expect(toMs(new Date(789))).toBe(789);
    expect(Number.isNaN(toMs(new Date('invalid')))).toBe(true);
    expect(toMs(0)).toBe(0);
    expect(Number.isNaN(toMs(Number.POSITIVE_INFINITY))).toBe(true);
    expect(Number.isNaN(toMs({}))).toBe(true);
    expect(pubKeyB64u('key')).toBe('key');
    expect(pubKeyB64u({ public_key: 'nested' })).toBe('nested');
    expect(pubKeyB64u({ public_key: 1 })).toBeNull();
    expect(pubKeyB64u(null)).toBeNull();
    expect(digestHex(`SHA256:${'AB'.repeat(32)}`)).toBe('ab'.repeat(32));
    expect(digestHex('ab'.repeat(32))).toBe('ab'.repeat(32));
    expect(digestHex('sha256:abc')).toBeNull();
    expect(digestHex(null)).toBeNull();
  });

  it('compares non-negative decimal material without scale or syntax ambiguity', () => {
    expect(parseNonNegativeDecimal(0)).toEqual({ coefficient: 0n, scale: 0 });
    expect(parseNonNegativeDecimal('001')).toBeNull();
    expect(parseNonNegativeDecimal('1.230')).toEqual({ coefficient: 1230n, scale: 3 });
    for (const invalid of [-1, Number.NaN, Number.POSITIVE_INFINITY, '-1', '+1', '1e2', '1.', '.1', '', null]) {
      expect(parseNonNegativeDecimal(invalid)).toBeNull();
    }
    expect(decimalGreaterThan('1.01', '1.001')).toBe(true);
    expect(decimalGreaterThan('1.001', '1.01')).toBe(false);
    expect(decimalGreaterThan('1.0', '1.00')).toBe(false);
    expect(decimalGreaterThan('bad', '1')).toBeNull();
    expect(decimalEqual('1.0', '1.00')).toBe(true);
    expect(decimalEqual('1.01', '1.00')).toBe(false);
    expect(decimalEqual('bad', '1')).toBeNull();
  });

  it('detects exact and decimal ambiguity, including empty and invalid sets', () => {
    expect(exactMaterial([])).toEqual({ value: null, ambiguous: false });
    expect(exactMaterial([null, undefined])).toEqual({ value: null, ambiguous: false });
    expect(exactMaterial(['x', 'x'])).toEqual({ value: 'x', ambiguous: false });
    expect(exactMaterial(['x', 'y'])).toEqual({ value: 'x', ambiguous: true });
    expect(decimalMaterial([])).toEqual({ value: null, ambiguous: false });
    expect(decimalMaterial([null])).toEqual({ value: null, ambiguous: false });
    expect(decimalMaterial(['1.0', '1.00'])).toEqual({ value: '1.0', ambiguous: false });
    expect(decimalMaterial(['1.0', '2.0'])).toEqual({ value: '1.0', ambiguous: true });
    expect(decimalMaterial(['bad'])).toEqual({ value: null, ambiguous: true });
  });

  it('extracts only signed authority material and marks every conflicting source', () => {
    const contexts = [
      { policy_hash: 'sha256:p', organization_id: 'org' },
      { policy_hash: 'sha256:p', organization_id: 'org' },
    ];
    expect(signedActionMaterial({ action: {
      action_type: 'wire.release', amount_usd: '10.00',
      policy_hash: 'sha256:p', organization_id: 'org',
    } }, contexts)).toEqual({
      action_type: 'wire.release', amount: '10.00', currency: 'USD',
      organization_id: 'org', policy_hash: 'sha256:p', ambiguous: false,
    });
    expect(signedActionMaterial({ action: {
      action_type: 'wire.release', parameters: { amount: '10', currency: 'EUR' },
      policy_hash: 'sha256:p', organization_id: 'org',
    } }, contexts)).toMatchObject({ amount: '10', currency: 'EUR', ambiguous: false });
    expect(signedActionMaterial({ action: {
      action_type: 'wire.release', amount: '1', parameters: { amount: '2' },
      currency: 'USD', policy_hash: 'sha256:p', organization_id: 'org',
    } }, contexts).ambiguous).toBe(true);
    expect(signedActionMaterial({ action: {
      action_type: 'wire.release', amount: '1', currency: 'USD',
      policy_hash: 'sha256:other', organization_id: 'other',
    } }, contexts).ambiguous).toBe(true);
    expect(signedActionMaterial({}, [])).toEqual({
      action_type: null, amount: null, currency: null,
      organization_id: null, policy_hash: null, ambiguous: false,
    });
  });

  it('validates each reliance-profile field independently and preserves optionality', () => {
    const minimal = { '@type': RELIANCE_PROFILE_VERSION };
    expect(validateRelianceProfile(minimal)).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, required_assurance: 'signed' })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, required_assurance: 'class_a' })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, required_assurance: 'quorum' })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, required_authority: false })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, required_evidence: [] })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({
      ...minimal,
      required_evidence: ['receipt', 'class_a_or_quorum', 'authority_proof', 'consumption_proof'],
    })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, accepted_issuer_keys: [] })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, accepted_registry_keys: [] })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, accepted_policy_hashes: [] })).toEqual({ ok: true, issues: [] });
    expect(validateRelianceProfile({ ...minimal, max_revocation_staleness_sec: 0 })).toEqual({ ok: true, issues: [] });

    expect(validateRelianceProfile('profile')).toEqual({ ok: false, issues: ['profile is not an object'] });
    expect(validateRelianceProfile([])).toEqual({ ok: false, issues: ['profile is not an object'] });
    expect(validateRelianceProfile({ ...minimal, required_authority: 0 }).issues).toEqual([
      'required_authority must be a boolean',
    ]);
    expect(validateRelianceProfile({ ...minimal, required_evidence: null }).issues).toEqual([
      'required_evidence must be an array',
    ]);
    expect(validateRelianceProfile({ ...minimal, required_evidence: [null] }).issues).toEqual([
      'unsupported required_evidence entry: null',
    ]);
    expect(validateRelianceProfile({ ...minimal, accepted_issuer_keys: [null] }).issues).toEqual([
      'accepted_issuer_keys contains an invalid key entry',
    ]);
    expect(validateRelianceProfile({ ...minimal, accepted_policy_hashes: ['good', ''] }).issues).toEqual([
      'accepted_policy_hashes contains an invalid policy hash',
    ]);
  });

  it('requires every authority-registry pin field with exact epoch and digest boundaries', () => {
    const minimal = { '@type': RELIANCE_PROFILE_VERSION };
    const validPin = {
      issuer_id: 'registry', organization_id: 'org', public_key: 'spki', min_epoch: 0,
      registry_head: `sha256:${'ab'.repeat(32)}`,
    };
    expect(validateRelianceProfile({ ...minimal, accepted_registry_keys: [validPin] })).toEqual({ ok: true, issues: [] });
    for (const invalidPin of [
      { ...validPin, issuer_id: '' },
      { ...validPin, issuer_id: 1 },
      { ...validPin, organization_id: '' },
      { ...validPin, organization_id: 1 },
      { ...validPin, public_key: 1 },
      { ...validPin, min_epoch: -1 },
      { ...validPin, min_epoch: 0.5 },
      { ...validPin, registry_head: `${'ab'.repeat(32)}` },
      { ...validPin, registry_head: `xsha256:${'ab'.repeat(32)}` },
      { ...validPin, registry_head: `sha256:${'ab'.repeat(32)}x` },
      { ...validPin, registry_head: 1 },
    ]) {
      expect(validateRelianceProfile({ ...minimal, accepted_registry_keys: [invalidPin] }).issues).toEqual([
        'accepted_registry_keys contains an invalid key entry',
      ]);
    }
  });
});

describe('mutation oracles for authority normalization and delegation', () => {
  const { strictInstantMs, meetsAssurance, checkDelegation } = __authoritySecurityInternals;

  it('uses strict authority time and the complete assurance ordering', () => {
    expect(Number.isFinite(strictInstantMs('2024-02-29T00:00:00-23:59'))).toBe(true);
    for (const invalid of [null, '2025-02-29T00:00:00Z', '2026-01-01T00:00:00-24:00', '2026-01-01T00:00:00-00:60']) {
      expect(Number.isNaN(strictInstantMs(invalid))).toBe(true);
    }
    expect(meetsAssurance('A', 'A')).toBe(true);
    expect(meetsAssurance('A', 'B')).toBe(true);
    expect(meetsAssurance('B', 'A')).toBe(false);
    expect(meetsAssurance('C', 'C')).toBe(true);
    expect(meetsAssurance('A', null)).toBe(true);
    expect(meetsAssurance('X', 'A')).toBe(false);
    expect(meetsAssurance('A', 'X')).toBe(false);
  });

  it('normalizes and binds every authority field without truthy fallbacks', () => {
    expect(normalizeAuthorityRecord(null)).toBeNull();
    expect(normalizeAuthorityRecord({
      authority_id: '', subject_type: '', subject_ref: '', organization_id: '', role: '',
      assurance_class: '', status: '', valid_from: '', valid_to: '', revoked_at: '',
      scope: 'wire.release', max_amount_usd: '0', currency: '', delegation_parent: '', policy_hash: '',
    })).toEqual({
      authority_id: '', subject_type: '', subject_ref: '', organization_id: '', role: '',
      assurance_class: '', status: '', valid_from: '', valid_to: '', revoked_at: '',
      action_scopes: ['wire.release'], max_amount_usd: 0, currency: '', delegation_parent: '', policy_hash: '',
    });
    const core = authorityResultCore({
      action_type: '', amount: 0, authority_id: '', currency: '', issued_at: '',
      max_amount_usd: 0, policy_hash: '', registry_epoch: 0, role: '', scope: [],
      subject_ref: '', verdict: 'authorized',
    });
    expect(core).toEqual({
      '@version': 'EP-AUTHORITY-REGISTRY-v1', action_type: '', amount: 0,
      authority_id: '', currency: '', issued_at: '', max_amount_usd: 0,
      policy_hash: '', registry_epoch: 0, role: '', scope: [], subject_ref: '', verdict: 'authorized',
    });
    expect(authorityBinding({
      authority_id: '', verdict: 'authorized', registry_head: '', registry_epoch: 0, policy_hash: '',
    })).toMatchObject({
      authority_id: '', authority_verdict: 'authorized', authority_registry_head: '',
      authority_registry_epoch: 0, policy_hash: '',
    });

    const populatedCore = authorityResultCore({
      action_type: 'wire.release', amount: 10, authority_id: 'authority', currency: 'USD',
      issued_at: '2026-07-10T00:00:00Z', max_amount_usd: 20, policy_hash: 'sha256:policy',
      registry_epoch: 7, role: 'cfo', scope: ['wire.release'], subject_ref: 'alice',
      verdict: 'authorized',
    });
    expect(populatedCore).toEqual({
      '@version': 'EP-AUTHORITY-REGISTRY-v1', action_type: 'wire.release', amount: 10,
      authority_id: 'authority', currency: 'USD', issued_at: '2026-07-10T00:00:00Z',
      max_amount_usd: 20, policy_hash: 'sha256:policy', registry_epoch: 7, role: 'cfo',
      scope: ['wire.release'], subject_ref: 'alice', verdict: 'authorized',
    });
    expect(authorityBinding({
      ...populatedCore, registry_head: `sha256:${'11'.repeat(32)}`,
    })).toMatchObject({
      authority_id: 'authority', authority_verdict: 'authorized',
      authority_registry_head: `sha256:${'11'.repeat(32)}`,
      authority_registry_epoch: 7, policy_hash: 'sha256:policy',
    });

    expect(normalizeAuthorityRecord({
      authority_id: 'authority', subject_type: 'human', subject_ref: 'alice', organization_id: 'org',
      role: 'cfo', assurance_class: 'A', status: 'active', valid_from: 'from', valid_to: 'to',
      revoked_at: 'revoked', action_scopes: ['wire.release'], max_amount_usd: 25, currency: 'EUR',
      delegation_parent: 'parent', policy_hash: 'sha256:policy',
    })).toEqual({
      authority_id: 'authority', subject_type: 'human', subject_ref: 'alice', organization_id: 'org',
      role: 'cfo', assurance_class: 'A', status: 'active', valid_from: 'from', valid_to: 'to',
      revoked_at: 'revoked', action_scopes: ['wire.release'], max_amount_usd: 25, currency: 'EUR',
      delegation_parent: 'parent', policy_hash: 'sha256:policy',
    });
  });

  it('checks every monotone delegation dimension at exact boundaries', () => {
    const at = '2026-07-10T00:00:00Z';
    const root = {
      authority_id: 'root', organization_id: 'org', status: 'active',
      valid_from: at, valid_to: at, action_scopes: ['wire.release'],
      max_amount_usd: 100, currency: 'USD', policy_hash: 'sha256:p', assurance_class: 'A',
    };
    const leaf = {
      authority_id: 'leaf', organization_id: 'org', delegation_parent: 'root',
      action_scopes: ['wire.release'], max_amount_usd: 100, currency: 'USD',
      policy_hash: 'sha256:p', assurance_class: 'A',
    };
    expect(checkDelegation(leaf, () => root, at)).toEqual({ ok: true });
    expect(checkDelegation({ ...leaf, delegation_parent: null }, () => null, at)).toEqual({ ok: true });
    expect(checkDelegation(leaf, () => null, at)).toEqual({ ok: false, detail: 'delegation_parent_missing' });
    expect(checkDelegation(leaf, () => ({ ...root, authority_id: 'leaf' }), at)).toEqual({ ok: false, detail: 'delegation_cycle' });
    expect(checkDelegation(leaf, () => ({ ...root, organization_id: 'other' }), at)).toEqual({ ok: false, detail: 'delegation_organization_mismatch' });
    expect(checkDelegation(leaf, () => ({ ...root, revoked_at: at }), at)).toEqual({ ok: false, detail: 'delegation_parent_revoked' });
    expect(checkDelegation(leaf, () => ({ ...root, valid_from: 'bad' }), at)).toEqual({ ok: false, detail: 'delegation_parent_invalid_window' });
    expect(checkDelegation(leaf, () => ({ ...root, valid_from: '2026-07-10T00:00:01Z' }), at)).toEqual({ ok: false, detail: 'delegation_parent_not_yet_valid' });
    expect(checkDelegation(leaf, () => ({ ...root, valid_to: '2026-07-09T23:59:59Z' }), at)).toEqual({ ok: false, detail: 'delegation_parent_expired' });
    expect(checkDelegation({ ...leaf, action_scopes: null }, () => root, at)).toEqual({ ok: false, detail: 'delegation_scope_widened' });
    expect(checkDelegation({ ...leaf, action_scopes: ['other'] }, () => root, at)).toEqual({ ok: false, detail: 'delegation_scope_widened' });
    expect(checkDelegation({ ...leaf, max_amount_usd: 101 }, () => root, at)).toEqual({ ok: false, detail: 'delegation_amount_widened' });
    expect(checkDelegation({ ...leaf, currency: 'EUR' }, () => root, at)).toEqual({ ok: false, detail: 'delegation_amount_widened' });
    expect(checkDelegation({ ...leaf, policy_hash: null }, () => root, at)).toEqual({ ok: false, detail: 'delegation_policy_widened' });
    expect(checkDelegation({ ...leaf, assurance_class: 'X' }, () => root, at)).toEqual({ ok: false, detail: 'delegation_assurance_widened' });
    expect(checkDelegation({ ...leaf, max_amount_usd: 0 }, () => ({ ...root, max_amount_usd: 0 }), at)).toEqual({ ok: true });
    expect(checkDelegation({ ...leaf, max_amount_usd: -1 }, () => root, at)).toEqual({ ok: false, detail: 'delegation_amount_widened' });
    expect(checkDelegation(leaf, () => ({ ...root, max_amount_usd: -1 }), at)).toEqual({ ok: false, detail: 'delegation_amount_widened' });
    expect(checkDelegation(leaf, () => ({ ...root, action_scopes: null }), at)).toEqual({ ok: true });
    expect(checkDelegation(leaf, () => ({ ...root, policy_hash: null }), at)).toEqual({ ok: true });
  });

  it('binds every authority verdict field and fails closed for absent context shapes', () => {
    const snapshot = { epoch: 7, head: `sha256:${'22'.repeat(32)}` };
    const record = {
      authority_id: 'authority', subject_ref: 'alice', organization_id: 'org', role: 'cfo',
      status: 'active', assurance_class: 'A', action_scopes: ['wire.release'],
      max_amount_usd: 50, currency: 'USD', policy_hash: 'sha256:policy',
      valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z',
    };
    const input = {
      organization_id: 'org', approver_id: 'alice', action_type: 'wire.release', amount: 50,
      currency: 'USD', policy_hash: 'sha256:policy', issued_at: '2026-07-10T00:00:00Z',
      expected_min_epoch: 7, requiredAssurance: 'A', required_role: 'cfo',
    };
    expect(evaluateAuthorityVerdict({ record, snapshot, unavailable: false }, input)).toEqual({
      action_type: 'wire.release', amount: 50, currency: 'USD', issued_at: '2026-07-10T00:00:00Z',
      policy_hash: 'sha256:policy', subject_ref: 'alice', registry_epoch: 7,
      registry_head: snapshot.head, authority_id: 'authority', role: 'cfo', scope: ['wire.release'],
      max_amount_usd: 50, verdict: 'authorized', authorized: true, detail: 'ok', assurance_class: 'A',
    });

    for (const ctx of [undefined, null, {}, { snapshot: null }, { unavailable: true, snapshot }]) {
      const result = evaluateAuthorityVerdict(ctx, input);
      expect(result).toMatchObject({
        verdict: 'registry_unavailable', authorized: false,
        registry_epoch: null, registry_head: null,
      });
    }
    const noInput = evaluateAuthorityVerdict({ snapshot }, null);
    expect(noInput).toMatchObject({
      action_type: null, amount: null, currency: null, issued_at: null,
      policy_hash: null, subject_ref: null, registry_epoch: 7,
      registry_head: snapshot.head, verdict: 'unknown_authority', authorized: false,
    });
    expect(evaluateAuthorityVerdict({ snapshot, record }, []).verdict).toBe('unknown_authority');
  });

  it('rejects every unprovable amount component and accepts exact zero', () => {
    const snapshot = { epoch: 1, head: `sha256:${'33'.repeat(32)}` };
    const baseRecord = {
      authority_id: 'authority', subject_ref: 'alice', organization_id: 'org', status: 'active',
      assurance_class: 'A', action_scopes: ['wire.release'], max_amount_usd: 0, currency: 'USD',
    };
    const baseInput = {
      organization_id: 'org', approver_id: 'alice', action_type: 'wire.release', amount: 0,
      currency: 'USD', issued_at: '2026-07-10T00:00:00Z', requiredAssurance: 'A',
    };
    expect(evaluateAuthorityVerdict({ snapshot, record: baseRecord }, baseInput).verdict).toBe('authorized');
    for (const max_amount_usd of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const result = evaluateAuthorityVerdict({ snapshot, record: { ...baseRecord, max_amount_usd } }, baseInput);
      expect(result).toMatchObject({ verdict: 'amount_exceeded', detail: 'amount_or_ceiling_unprovable' });
    }
    for (const amount of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      const result = evaluateAuthorityVerdict({ snapshot, record: baseRecord }, { ...baseInput, amount });
      expect(result).toMatchObject({ verdict: 'amount_exceeded', detail: 'amount_or_ceiling_unprovable' });
    }
    for (const currency of [null, '', 0]) {
      const result = evaluateAuthorityVerdict({ snapshot, record: baseRecord }, { ...baseInput, currency });
      expect(result).toMatchObject({ verdict: 'amount_exceeded', detail: 'amount_or_ceiling_unprovable' });
    }
  });

  it('accepts seven delegation edges and rejects an eighth', () => {
    const at = '2026-07-10T00:00:00Z';
    const make = (index, parent) => ({
      authority_id: `a${index}`, organization_id: 'org', status: 'active', assurance_class: 'A',
      action_scopes: ['wire.release'], max_amount_usd: 1, currency: 'USD', delegation_parent: parent,
    });
    const chain = Array.from({ length: 10 }, (_, i) => make(i, i === 9 ? null : `a${i + 1}`));
    const byId = new Map(chain.map((record) => [record.authority_id, record]));
    expect(checkDelegation(chain[2], (id) => byId.get(id), at)).toEqual({ ok: true });
    expect(checkDelegation(chain[1], (id) => byId.get(id), at)).toEqual({ ok: false, detail: 'delegation_too_deep' });
  });
});
