// SPDX-License-Identifier: Apache-2.0
/**
 * Synthetic consequence-admission lifecycle runner.
 *
 * Every profile starts with a closed result from its native authorization
 * system. This runner never re-evaluates native policy. It only checks the
 * result's integrity and bindings before exercising one shared residual
 * lifecycle: exact-action comparison, reserve, provider entry, terminal or
 * indeterminate outcome, and authenticated reconciliation.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS = JSON.parse(readFileSync(resolve(HERE, 'vectors.json'), 'utf8'));
const NOW = '2026-09-24T18:00:00.000Z';
const MATERIAL_FIELDS = Object.freeze([
  'action_type',
  'amount',
  'currency',
  'payee',
  'provider_operation',
]);
const MATERIAL_FIELD_SET = new Set(MATERIAL_FIELDS);

const LOCAL_MANDATE_KEYS = crypto.generateKeyPairSync('ed25519');
const PROVIDER_KEYS = crypto.generateKeyPairSync('ed25519');

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
    );
  }
  return value;
}

function canonicalize(value) {
  return JSON.stringify(sorted(value));
}

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function publicSpki(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}

function normalizeAction(profile, action) {
  if (action === null || typeof action !== 'object' || Array.isArray(action)) {
    return { mapping: 'INDETERMINATE', reason: 'material_action_not_an_object' };
  }
  const keys = Object.keys(action);
  const missing = MATERIAL_FIELDS.filter((field) => !keys.includes(field));
  const unknown = keys.filter((field) => !MATERIAL_FIELD_SET.has(field));
  if (missing.length > 0) {
    return {
      mapping: 'INDETERMINATE',
      reason: 'omitted_material_field',
      fields: missing.sort(),
    };
  }
  if (unknown.length > 0) {
    return {
      mapping: 'INDETERMINATE',
      reason: 'unknown_material_field_without_mapping_rule',
      fields: unknown.sort(),
    };
  }
  const normalized = Object.fromEntries(MATERIAL_FIELDS.map((field) => [field, action[field]]));
  if (profile.normalization.currency === 'ASCII_UPPERCASE_ISO4217') {
    if (typeof normalized.currency !== 'string' || !/^[A-Za-z]{3}$/.test(normalized.currency)) {
      return { mapping: 'INDETERMINATE', reason: 'currency_not_mappable_under_profile' };
    }
    normalized.currency = normalized.currency.toUpperCase();
  }
  return { mapping: 'MAPPED', action: normalized, action_digest: digest(normalized) };
}

function nativeIntegrityPayload(authority) {
  const {
    integrity: _integrity,
    wrapper_id: _wrapperId,
    ...payload
  } = authority;
  return payload;
}

function buildNativeAuthority(profile, options = {}) {
  const projected = normalizeAction(profile, CORPUS.base_action);
  assert.equal(projected.mapping, 'MAPPED');
  const authorityBase = {
    profile_id: profile.id,
    native_system: profile.native_system,
    authorization_owner: profile.authorization_owner,
    native_authority_id: profile.native_authority_id,
    native_result: profile.native_result,
    native_verified: true,
    native_authorized: true,
    exact_action_digest: projected.action_digest,
    replay_unit: digest({
      profile_id: profile.id,
      native_authority_id: profile.native_authority_id,
    }),
    context: clone(CORPUS.base_context),
    status: {
      checked_at: NOW,
      expires_at: options.stale ? '2026-09-24T17:59:59.000Z' : '2026-09-24T18:05:00.000Z',
      revoked: Boolean(options.revoked),
    },
    wrapper_id: options.wrapperId ?? 'wrapper:original',
  };
  const payload = Buffer.from(canonicalize(nativeIntegrityPayload(authorityBase)), 'utf8');
  const integrity = profile.id === 'local-signed-mandate'
    ? {
        kind: 'ED25519_SIGNATURE',
        key_id: 'local:mandate-key:1',
        public_key_spki: publicSpki(LOCAL_MANDATE_KEYS.publicKey),
        signature: crypto.sign(null, payload, LOCAL_MANDATE_KEYS.privateKey).toString('base64url'),
      }
    : {
        kind: 'PINNED_NATIVE_VERIFIER_RESULT_DIGEST',
        verifier_result_digest: digest(nativeIntegrityPayload(authorityBase)),
      };
  return { ...authorityBase, integrity };
}

function verifyNativeResult(authority) {
  if (authority.profile_id === 'local-signed-mandate') {
    if (authority.integrity?.kind !== 'ED25519_SIGNATURE') return false;
    if (authority.integrity.public_key_spki !== publicSpki(LOCAL_MANDATE_KEYS.publicKey)) return false;
    try {
      const publicKey = crypto.createPublicKey({
        key: Buffer.from(authority.integrity.public_key_spki, 'base64url'),
        type: 'spki',
        format: 'der',
      });
      return crypto.verify(
        null,
        Buffer.from(canonicalize(nativeIntegrityPayload(authority)), 'utf8'),
        publicKey,
        Buffer.from(authority.integrity.signature, 'base64url'),
      );
    } catch {
      return false;
    }
  }
  return authority.integrity?.kind === 'PINNED_NATIVE_VERIFIER_RESULT_DIGEST'
    && authority.integrity.verifier_result_digest === digest(nativeIntegrityPayload(authority));
}

class LifecycleStore {
  constructor() {
    this.operations = new Map();
    this.replayOwners = new Map();
  }

  reserve({ operationId, replayUnit, owner, bindings }) {
    if (this.operations.has(operationId) || this.replayOwners.has(replayUnit)) return null;
    const entry = {
      operation_id: operationId,
      replay_unit: replayUnit,
      owner,
      state: 'RESERVED',
      provider_entered: false,
      provider_calls: 0,
      bindings,
    };
    this.operations.set(operationId, entry);
    this.replayOwners.set(replayUnit, operationId);
    return entry;
  }

  recoverPreEntry(operationId, owner) {
    const entry = this.operations.get(operationId);
    if (!entry || entry.owner !== owner || entry.state !== 'RESERVED' || entry.provider_entered) {
      return false;
    }
    this.operations.delete(operationId);
    this.replayOwners.delete(entry.replay_unit);
    return true;
  }

  operation(operationId) {
    return this.operations.get(operationId) ?? null;
  }
}

class ConsequenceAdmissionGate {
  constructor(profile) {
    this.profile = profile;
    this.store = new LifecycleStore();
    this.providerCalls = 0;
    this.dispatchOwners = new Set();
    this.authorizationDecisionsByAeb = 0;
  }

  inspect({ authority, observedAction, context }) {
    if (!verifyNativeResult(authority) || authority.native_verified !== true) {
      return { state: 'REFUSED', reason: 'native_verifier_result_invalid' };
    }
    for (const [field, expected] of Object.entries({
      profile_id: this.profile.id,
      native_system: this.profile.native_system,
      authorization_owner: this.profile.authorization_owner,
      native_authority_id: this.profile.native_authority_id,
      native_result: this.profile.native_result,
    })) {
      if (authority[field] !== expected) {
        return { state: 'REFUSED', reason: `native_${field}_pin_mismatch` };
      }
    }
    // The native system owns this verdict. AEB consumes it and never runs a
    // second policy decision over the same request.
    if (authority.native_authorized !== true) {
      return { state: 'REFUSED', reason: 'native_authority_not_permitted' };
    }
    if (authority.status.revoked) return { state: 'REFUSED', reason: 'native_authority_revoked' };
    const expiresAt = Date.parse(authority.status.expires_at);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.parse(NOW)) {
      return { state: 'REFUSED', reason: 'native_authority_stale' };
    }
    for (const field of ['audience', 'tenant', 'executor', 'provider']) {
      if (authority.context[field] !== CORPUS.base_context[field]) {
        return { state: 'REFUSED', reason: `${field}_authority_outside_gate_pin` };
      }
      if (authority.context[field] !== context[field]) {
        return { state: 'REFUSED', reason: `${field}_binding_mismatch` };
      }
    }
    const projected = normalizeAction(this.profile, observedAction);
    if (projected.mapping === 'INDETERMINATE') {
      return {
        state: 'INDETERMINATE',
        stage: 'ACTION_MAPPING',
        reason: projected.reason,
        fields: projected.fields ?? [],
      };
    }
    if (projected.action_digest !== authority.exact_action_digest) {
      return {
        state: 'REEVALUATION_REQUIRED',
        reason: 'material_action_changed_native_authority_must_be_reevaluated',
      };
    }
    return { state: 'READY', action_digest: projected.action_digest };
  }

  admit({ authority, observedAction, context, operationId, owner, mode = 'SUCCESS' }) {
    const inspected = this.inspect({ authority, observedAction, context });
    if (inspected.state !== 'READY') {
      return { ...inspected, provider_calls: this.providerCalls };
    }
    const entry = this.store.reserve({
      operationId,
      replayUnit: authority.replay_unit,
      owner,
      bindings: {
        action_digest: inspected.action_digest,
        provider: context.provider,
      },
    });
    if (!entry) {
      return {
        state: 'REFUSED',
        reason: 'native_replay_or_operation_conflict',
        provider_calls: this.providerCalls,
      };
    }
    if (mode === 'PRE_ENTRY_CRASH') {
      return {
        state: 'PRE_ENTRY_CRASHED',
        retry_safe_after_owner_recovery: true,
        provider_calls: this.providerCalls,
      };
    }
    entry.state = 'PROVIDER_ENTRY';
    entry.provider_entered = true;
    entry.provider_calls += 1;
    this.providerCalls += 1;
    this.dispatchOwners.add(owner);
    if (mode === 'POST_ENTRY_RESPONSE_LOSS') {
      entry.state = 'INDETERMINATE';
      return {
        state: 'INDETERMINATE',
        reason: 'provider_entered_response_lost',
        retry_allowed: false,
        provider_calls: this.providerCalls,
      };
    }
    entry.state = 'EXECUTED';
    return { state: 'EXECUTED', provider_calls: this.providerCalls };
  }

  reconcile(operationId, evidence) {
    const entry = this.store.operation(operationId);
    if (!entry || entry.state !== 'INDETERMINATE') {
      return { state: entry?.state ?? 'REFUSED', reason: 'operation_not_indeterminate' };
    }
    const { signature, ...body } = evidence;
    let authenticated = false;
    try {
      authenticated = crypto.verify(
        null,
        Buffer.from(canonicalize(body), 'utf8'),
        PROVIDER_KEYS.publicKey,
        Buffer.from(signature, 'base64url'),
      );
    } catch {
      authenticated = false;
    }
    if (!authenticated) return { state: 'INDETERMINATE', reason: 'provider_evidence_unauthenticated' };
    if (body.provider !== entry.bindings.provider) {
      return { state: 'INDETERMINATE', reason: 'provider_binding_mismatch' };
    }
    if (body.operation_id !== entry.operation_id) {
      return { state: 'INDETERMINATE', reason: 'operation_binding_mismatch' };
    }
    if (body.action_digest !== entry.bindings.action_digest) {
      return { state: 'INDETERMINATE', reason: 'action_binding_mismatch' };
    }
    if (body.outcome !== 'EXECUTED') {
      return { state: 'INDETERMINATE', reason: 'provider_outcome_not_terminal' };
    }
    entry.state = 'EXECUTED';
    return { state: 'EXECUTED', reconciled: true };
  }
}

function signProviderEvidence(entry, overrides = {}) {
  const body = {
    provider: entry.bindings.provider,
    operation_id: entry.operation_id,
    action_digest: entry.bindings.action_digest,
    outcome: 'EXECUTED',
    observed_at: '2026-09-24T18:00:10.000Z',
    ...overrides,
  };
  return {
    ...body,
    signature: crypto.sign(
      null,
      Buffer.from(canonicalize(body), 'utf8'),
      PROVIDER_KEYS.privateKey,
    ).toString('base64url'),
  };
}

function baseInput(profile, caseId, authority = buildNativeAuthority(profile)) {
  return {
    authority,
    observedAction: clone(CORPUS.base_action),
    context: clone(CORPUS.base_context),
    operationId: `operation:${caseId.toLowerCase()}`,
    owner: `dispatch-owner:${caseId.toLowerCase()}`,
  };
}

async function executeCase(vector, profile) {
  const gate = new ConsequenceAdmissionGate(profile);
  const input = baseInput(profile, vector.id);
  let observed;

  switch (vector.scenario) {
    case 'ADMIT_THEN_REPLAY': {
      const first = gate.admit(input);
      const replayAuthority = { ...input.authority, wrapper_id: 'wrapper:refreshed' };
      const second = gate.admit({
        ...input,
        authority: replayAuthority,
        operationId: `${input.operationId}:replay`,
        owner: `${input.owner}:replay`,
      });
      observed = {
        first: first.state,
        second: second.state,
        second_reason: second.reason,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'MUTATE_MATERIAL_FIELD': {
      input.observedAction[vector.field] = vector.value;
      const result = gate.admit(input);
      observed = {
        state: result.state,
        reason: result.reason ?? null,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'OMIT_MATERIAL_FIELD': {
      delete input.observedAction[vector.field];
      const result = gate.admit(input);
      if (!('stage' in result) || !('fields' in result)) {
        throw new TypeError('omitted material field did not produce mapping details');
      }
      observed = {
        state: result.state,
        stage: result.stage,
        reason: result.reason,
        fields: result.fields,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'ADD_UNKNOWN_MATERIAL_FIELD': {
      input.observedAction[vector.field] = vector.value;
      const result = gate.admit(input);
      if (!('stage' in result) || !('fields' in result)) {
        throw new TypeError('unknown material field did not produce mapping details');
      }
      observed = {
        state: result.state,
        stage: result.stage,
        reason: result.reason,
        fields: result.fields,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'MUTATE_CONTEXT': {
      input.context[vector.field] = vector.value;
      const result = gate.admit(input);
      observed = {
        state: result.state,
        reason: result.reason,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'STALE_AUTHORITY': {
      input.authority = buildNativeAuthority(profile, { stale: true });
      const result = gate.admit(input);
      observed = { state: result.state, reason: result.reason, provider_calls: gate.providerCalls };
      break;
    }
    case 'REVOKED_AUTHORITY': {
      input.authority = buildNativeAuthority(profile, { revoked: true });
      const result = gate.admit(input);
      observed = { state: result.state, reason: result.reason, provider_calls: gate.providerCalls };
      break;
    }
    case 'TAMPER_NATIVE_SIGNATURE': {
      if (
        input.authority.integrity.kind !== 'ED25519_SIGNATURE'
        || typeof input.authority.integrity.signature !== 'string'
      ) {
        throw new TypeError('signature tamper scenario requires signed native authority');
      }
      const signature = Buffer.from(input.authority.integrity.signature, 'base64url');
      signature[0] ^= 0x01;
      input.authority.integrity.signature = signature.toString('base64url');
      const result = gate.admit(input);
      observed = { state: result.state, reason: result.reason, provider_calls: gate.providerCalls };
      break;
    }
    case 'REFRESH_WRAPPER_AND_REPLAY': {
      const first = gate.admit(input);
      const refreshed = buildNativeAuthority(profile, { wrapperId: 'wrapper:refreshed' });
      const second = gate.admit({
        ...input,
        authority: refreshed,
        operationId: `${input.operationId}:second`,
        owner: `${input.owner}:second`,
      });
      observed = {
        first: first.state,
        second: second.state,
        replay_unit_stable: input.authority.replay_unit === refreshed.replay_unit,
        wrapper_changed: input.authority.wrapper_id !== refreshed.wrapper_id,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'CONCURRENT_RESERVATION': {
      const firstInput = { ...input, operationId: `${input.operationId}:a`, owner: `${input.owner}:a` };
      const secondInput = { ...input, operationId: `${input.operationId}:b`, owner: `${input.owner}:b` };
      const results = await Promise.all([
        Promise.resolve().then(() => gate.admit(firstInput)),
        Promise.resolve().then(() => gate.admit(secondInput)),
      ]);
      observed = {
        states: results.map((result) => result.state).sort(),
        provider_calls: gate.providerCalls,
        dispatch_owner_count: gate.dispatchOwners.size,
      };
      break;
    }
    case 'PRE_ENTRY_CRASH_AND_RECOVER': {
      const crashed = gate.admit({ ...input, mode: 'PRE_ENTRY_CRASH' });
      const recovered = gate.store.recoverPreEntry(input.operationId, input.owner);
      const retry = gate.admit(input);
      observed = {
        first: crashed.state,
        recovered,
        retry: retry.state,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'POST_ENTRY_RESPONSE_LOSS': {
      const lost = gate.admit({ ...input, mode: 'POST_ENTRY_RESPONSE_LOSS' });
      const retry = gate.admit({
        ...input,
        operationId: `${input.operationId}:retry`,
        owner: `${input.owner}:retry`,
      });
      observed = {
        first: lost.state,
        retry: retry.state,
        retry_reason: retry.reason,
        retry_allowed: lost.retry_allowed,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'AUTHENTICATED_RECONCILIATION': {
      const lost = gate.admit({ ...input, mode: 'POST_ENTRY_RESPONSE_LOSS' });
      const entry = gate.store.operation(input.operationId);
      const reconciled = gate.reconcile(input.operationId, signProviderEvidence(entry));
      observed = {
        first: lost.state,
        final: reconciled.state,
        authenticated: reconciled.reconciled === true,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'MISMATCHED_RECONCILIATION': {
      gate.admit({ ...input, mode: 'POST_ENTRY_RESPONSE_LOSS' });
      const entry = gate.store.operation(input.operationId);
      const attempts = [
        gate.reconcile(input.operationId, signProviderEvidence(entry, { provider: 'provider:other' })),
        gate.reconcile(input.operationId, signProviderEvidence(entry, { operation_id: 'operation:other' })),
        gate.reconcile(input.operationId, signProviderEvidence(entry, { action_digest: digest({ other: true }) })),
      ];
      observed = {
        states: attempts.map((attempt) => attempt.state),
        reasons: attempts.map((attempt) => attempt.reason),
        final_state: gate.store.operation(input.operationId).state,
        provider_calls: gate.providerCalls,
      };
      break;
    }
    case 'DISCLOSE_BYPASS_PATH': {
      observed = {
        coverage: 'CONFIGURED_PATHS_ONLY',
        covered_paths: profile.covered_paths,
        known_uncovered_paths: profile.known_uncovered_paths,
        complete_mediation_claimed: false,
      };
      break;
    }
    default:
      throw new TypeError(`unknown scenario: ${vector.scenario}`);
  }

  const passed = expectedResult(vector.expected, observed);
  return {
    id: vector.id,
    profile: profile.id,
    native_system: profile.native_system,
    authorization_owner: profile.authorization_owner,
    native_authorization_redecided_by_aeb: gate.authorizationDecisionsByAeb !== 0,
    expected: vector.expected,
    observed,
    passed,
  };
}

function expectedResult(expected, observed) {
  switch (expected) {
    case 'EXECUTED_THEN_REFUSED':
      return observed.first === 'EXECUTED'
        && observed.second === 'REFUSED'
        && observed.provider_calls === 1;
    case 'EXECUTED':
      return observed.state === 'EXECUTED' && observed.provider_calls === 1;
    case 'REEVALUATION_REQUIRED':
      return observed.state === 'REEVALUATION_REQUIRED' && observed.provider_calls === 0;
    case 'INDETERMINATE':
      return observed.state === 'INDETERMINATE'
        ? observed.provider_calls === 0
        : observed.final_state === 'INDETERMINATE'
          && observed.states.every((state) => state === 'INDETERMINATE')
          && observed.provider_calls === 1;
    case 'REFUSED':
      return observed.state === 'REFUSED' && observed.provider_calls === 0;
    case 'ONE_EXECUTED_ONE_REFUSED':
      return JSON.stringify(observed.states) === JSON.stringify(['EXECUTED', 'REFUSED'])
        && observed.provider_calls === 1
        && observed.dispatch_owner_count === 1;
    case 'EXECUTED_AFTER_RECOVERY':
      return observed.first === 'PRE_ENTRY_CRASHED'
        && observed.recovered === true
        && observed.retry === 'EXECUTED'
        && observed.provider_calls === 1;
    case 'INDETERMINATE_NO_REDISPATCH':
      return observed.first === 'INDETERMINATE'
        && observed.retry === 'REFUSED'
        && observed.retry_allowed === false
        && observed.provider_calls === 1;
    case 'EXECUTED_WITHOUT_REDISPATCH':
      return observed.first === 'INDETERMINATE'
        && observed.final === 'EXECUTED'
        && observed.authenticated === true
        && observed.provider_calls === 1;
    case 'DISCLOSED_UNCOVERED_PATH':
      return observed.coverage === 'CONFIGURED_PATHS_ONLY'
        && observed.known_uncovered_paths.length > 0
        && observed.complete_mediation_claimed === false;
    default:
      throw new TypeError(`unknown expected result: ${expected}`);
  }
}

function validateCorpus() {
  assert.equal(CORPUS['@version'], 'EP-CONSEQUENCE-ADMISSION-LIFECYCLE-VECTORS-v0.1');
  assert.equal(new Set(CORPUS.profiles.map((profile) => profile.id)).size, CORPUS.profiles.length);
  assert.equal(new Set(CORPUS.cases.map((entry) => entry.id)).size, CORPUS.cases.length);
  const profiles = new Set(CORPUS.profiles.map((profile) => profile.id));
  for (const entry of CORPUS.cases) assert.equal(profiles.has(entry.profile), true, entry.id);
}

export async function runSuite() {
  validateCorpus();
  const profiles = Object.fromEntries(CORPUS.profiles.map((profile) => [profile.id, profile]));
  const cases = await Promise.all(
    CORPUS.cases.map((vector) => executeCase(vector, profiles[vector.profile])),
  );
  return {
    '@version': 'EP-CONSEQUENCE-ADMISSION-LIFECYCLE-REPORT-v0.1',
    suite_id: CORPUS.suite_id,
    evaluated_at: NOW,
    passed: cases.every((entry) => entry.passed),
    authorization_decisions_by_aeb: cases.filter(
      (entry) => entry.native_authorization_redecided_by_aeb,
    ).length,
    profiles: CORPUS.profiles.map((profile) => ({
      id: profile.id,
      native_system: profile.native_system,
      authorization_owner: profile.authorization_owner,
      native_fixture_integrity: profile.id === 'local-signed-mandate'
        ? 'PINNED_ED25519_SIGNATURE'
        : 'PINNED_NATIVE_VERIFIER_RESULT_DIGEST',
    })),
    cases,
    defining_contract: {
      native_authorization_remains_native: true,
      exact_action_checked_at_executor_boundary: true,
      stable_native_replay_unit: true,
      reserve_before_provider_entry: true,
      provider_entry_attempts: 'AT_MOST_ONE',
      post_entry_uncertainty: 'STICKY_INDETERMINATE',
      reconciliation: 'AUTHENTICATED_SAME_PROVIDER_OPERATION_ACTION',
      coverage_claim: 'CONFIGURED_PATHS_ONLY',
    },
    claim_boundary: CORPUS.claim_boundary,
    results_digest: digest(cases),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = await runSuite();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}
