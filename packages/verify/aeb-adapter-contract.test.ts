// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import {
  AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
  InMemoryAebConsumptionStore,
  aebReservationKey,
  adapterPinDigest,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  authorizeAebExecution,
  authorizeAebExecutionDurable,
  createAebNativeVerificationAttestationAdapter,
  reconcileAebExecution,
  reconcileAebExecutionDurable,
  signAebNativeVerificationAttestation,
  verifyAebEvaluation,
} from './aeb-adapter-contract.js';

const vectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/aeb-adapter.v1.json', import.meta.url), 'utf8'));

const CAID = `caid:1:order.purchase.1:jcs-sha256:${'A'.repeat(43)}`;
const OTHER_CAID = `caid:1:order.purchase.1:jcs-sha256:${'B'.repeat(43)}`;
const NOW = '2026-07-21T12:00:00Z';

test('AEB-ADAPTER-v1 publishes the refusal and lifecycle vector set', () => {
  assert.equal(vectors['@version'], 'AEB-ADAPTER-v1');
  assert.deepEqual(vectors.vectors.map((vector) => vector.id), [
    'multi_leg_same_caid_satisfies_all_of',
    'stale_status_is_indeterminate',
    'revoked_evidence_is_unsatisfied',
    'caid_mismatch_is_not_equivalence',
    'consumption_is_atomic_and_one_time',
    'unsigned_or_non_rederivable_verdict_is_not_authority',
    'unaccepted_mapper_is_indeterminate',
    'material_information_loss_refuses_equivalence',
    'duplicate_or_initiating_human_cannot_satisfy_quorum',
    'authority_predicates_are_first_class_requirement_terms',
    'executor_cannot_satisfy_approval_role',
    'native_replay_unit_is_fenced_across_aeb_wrappers',
    'presenter_status_cannot_establish_current_authority',
    'registry_kind_substitution_is_indeterminate',
    'aec_is_the_composition_engine',
    'same_caid_different_normalized_action_refuses',
    'production_path_requires_durable_ownership_fenced_store',
    'signed_native_bridge_composes_wimse_possession_and_human_authorization',
  ]);
});

function status(overrides = {}) {
  return {
    checked_at: '2026-07-21T11:59:00Z',
    expires_at: '2026-07-21T13:00:00Z',
    revocation_checked: true,
    revoked: false,
    consumed: false,
    ...overrides,
  };
}

function makeAdapter() {
  return {
    id: 'test:operator',
    version: '1',
    verifyNative({ artifact, status: inputStatus, trust_roots }) {
      const trusted = trust_roots.includes(artifact.root);
      return {
        native_verification: trusted ? 'VERIFIED' : 'FAILED',
        acceptance: trusted ? 'ACCEPTED' : 'REJECTED',
        evidence_digest: digestAeb(artifact),
        status_digest: digestAeb({
          checked_at: inputStatus.checked_at,
          expires_at: inputStatus.expires_at,
          revocation_checked: inputStatus.revocation_checked,
          revoked: inputStatus.revoked,
          consumed: inputStatus.consumed,
          unavailable: inputStatus.unavailable === true,
        }),
        evidence_role: artifact.role,
        subject: artifact.subject,
        replay_unit: digestAeb({ adapter: 'test:operator', replay_id: artifact.replay_id }),
        reasons: trusted ? [] : ['native_trust_root_not_pinned'],
      };
    },
    mapAction({ artifact, native }) {
      return {
        mapping: native.native_verification === 'VERIFIED' ? 'MATCH' : 'INDETERMINATE',
        caid: artifact.caid,
        action_digest: digestAeb({ action_type: 'order.purchase.1', order_id: artifact.order_id }),
        reasons: [],
      };
    },
  };
}

function registryEntry(entryId, kind, version, definition) {
  const entry = { kind, version, status: 'active', definition };
  entry.definition_digest = registryEntryDigest(entryId, entry);
  return entry;
}

function setup(requirement = {
  '@version': 'AEB-REQUIREMENT-v1',
  all_of: ['operator-of-record', 'human-authorization'],
  terms: [
    { type: 'distinct-human-quorum', role: 'human-authorization', threshold: 2 },
    { type: 'initiator-exclusion', roles: ['human-authorization'] },
    { type: 'executor-exclusion', roles: ['human-authorization'] },
    { type: 'one-time-consumption' },
  ],
}) {
  const adapter = makeAdapter();
  const profile = {
    version: 'test-mapping-v1',
    definition: { source: 'test' },
    registry_entry_ref: 'mapping:test:order',
    mapper_id: 'mapper:test',
    resolver: {
      id: 'resolver:test',
      version: '1',
      implementation_digest: digestAeb({ implementation: 'resolver:test:1' }),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: ['created_at'],
    },
  };
  profile.profile_digest = mappingProfileDigest('test:order', profile);
  const entries = {
    'mapping:test:order': registryEntry('mapping:test:order', 'mapping-profile', '1', { profile_digest: profile.profile_digest }),
    'role:operator-of-record': registryEntry('role:operator-of-record', 'evidence-role', '1', { role: 'operator-of-record', subject_kinds: ['workload'] }),
    'role:human-authorization': registryEntry('role:human-authorization', 'evidence-role', '1', { role: 'human-authorization', subject_kinds: ['human'] }),
    'extension:receipt-lifecycle': registryEntry('extension:receipt-lifecycle', 'receipt-extension', '1', { extension: 'receipt-lifecycle' }),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1', registry_id: 'registry:test', epoch: 1, entries,
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pin = {
    version: '1', trust_roots: ['root:test'], config: { mode: 'offline' }, max_status_age_sec: 3600,
  };
  pin.config_digest = adapterPinDigest('test:operator', pin);
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const key = keyPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const config = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:test',
    evaluator_keys: { 'eval:test': { public_key: key } },
    registry,
    accepted_mappers: ['mapper:test'],
    adapters: { 'test:operator': pin },
    profiles: { 'test:order': profile },
    requirements: { 'req:purchase': requirement },
  };
  return { adapter, config, keyPair };
}

function leg(role, caid = CAID, ref = `artifact:${role}`, subject = { id: role === 'human-authorization' ? 'human:alice' : 'workload:operator', kind: role === 'human-authorization' ? 'human' : 'workload' }) {
  return {
    adapter_id: 'test:operator', profile_id: 'test:order', artifact_ref: ref,
    artifact: { root: 'root:test', role, caid, order_id: 'o-1', replay_id: ref, subject }, status: status(),
  };
}

function defaultLegs() {
  return [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }),
  ];
}

function evaluate(setupResult, legs = defaultLegs(), bindings = {}) {
  return evaluateAebEvidence({
    config: setupResult.config,
    adapters: { 'test:operator': setupResult.adapter },
    operation_id: 'op-1', consumption_nonce: 'nonce-1', initiator_id: 'agent:init', executor_id: 'workload:executor',
    requirement_ref: 'req:purchase', caid: CAID,
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    legs, evaluated_at: NOW, signer: { key_id: 'eval:test', private_key: setupResult.keyPair.privateKey },
    ...bindings,
  });
}

function verificationInputs(legs = defaultLegs()) {
  return {
    artifacts: Object.fromEntries(legs.map((item) => [item.artifact_ref, item.artifact])),
    current_statuses: Object.fromEntries(legs.map((item) => [item.artifact_ref, status()])),
  };
}

test('AEB evaluates and re-derives a multi-leg CAID join', () => {
  const s = setup();
  const result = evaluate(s);
  assert.equal(result.record.verdict, 'SATISFIED');
  assert.equal(result.valid, true);
  const checked = verifyAebEvaluation(result.record, {
    config: s.config, adapters: { 'test:operator': s.adapter },
    mode: 'historical',
    artifacts: {
      'artifact:operator-of-record': { root: 'root:test', role: 'operator-of-record', caid: CAID, order_id: 'o-1', replay_id: 'artifact:operator-of-record', subject: { id: 'workload:operator', kind: 'workload' } },
      'artifact:human-alice': { root: 'root:test', role: 'human-authorization', caid: CAID, order_id: 'o-1', replay_id: 'artifact:human-alice', subject: { id: 'human:alice', kind: 'human' } },
      'artifact:human-bob': { root: 'root:test', role: 'human-authorization', caid: CAID, order_id: 'o-1', replay_id: 'artifact:human-bob', subject: { id: 'human:bob', kind: 'human' } },
    },
  });
  assert.equal(checked.valid, true, JSON.stringify({ checked, record: result.record }));
  assert.deepEqual(checked.checks, { schema: true, signature: true, pinned_config: true, rederived: true, current_status: true, verdict: true });
  assert.equal(result.record.composition.engine, 'EP-AEC-v1');
  assert.equal(result.record.composition.satisfied, true);
  assert.equal(result.record.authority_constraints.distinct_human_quorum, true);
  assert.equal(result.record.authority_constraints.initiator_exclusion, true);
  assert.equal(result.record.authority_constraints.executor_exclusion, true);
  assert.equal(result.record.authority_constraints.one_time_consumption, true);
  assert.equal(result.record.executor_id, 'workload:executor');
});

test('execution verification requires current status, now, and exact action; default is historical', () => {
  const s = setup();
  const result = evaluate(s);
  const inputs = verificationInputs();
  const base = {
    config: s.config,
    adapters: { 'test:operator': s.adapter },
    artifacts: inputs.artifacts,
  };

  const implicit = verifyAebEvaluation(result.record, base);
  assert.equal(implicit.valid, true, JSON.stringify(implicit));
  assert.equal(implicit.execution_authorizing, false);

  const historical = verifyAebEvaluation(result.record, { ...base, mode: 'historical' });
  assert.equal(historical.valid, true, JSON.stringify(historical));
  assert.equal(historical.execution_authorizing, false);
  assert.equal(authorizeAebExecution(result.record, {
    verification: historical,
    local_authorization: true,
    store: new InMemoryAebConsumptionStore(),
  }).reason, 'execution_verification_required');

  const omittedNow = verifyAebEvaluation(result.record, {
    ...base,
    mode: 'execution',
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: inputs.current_statuses,
  });
  assert.equal(omittedNow.valid, false);
  assert.equal(omittedNow.execution_authorizing, false);
  assert.ok(omittedNow.reasons.includes('execution_now_required'));

  const omittedStatus = verifyAebEvaluation(result.record, {
    ...base,
    mode: 'execution',
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    now: NOW,
  });
  assert.equal(omittedStatus.valid, false);
  assert.equal(omittedStatus.execution_authorizing, false);
  assert.ok(omittedStatus.reasons.some((reason) => reason.startsWith('current_status_unavailable:')));

  const omittedAction = verifyAebEvaluation(result.record, {
    ...base,
    mode: 'execution',
    current_statuses: inputs.current_statuses,
    now: NOW,
  });
  assert.equal(omittedAction.valid, false);
  assert.equal(omittedAction.execution_authorizing, false);
  assert.ok(omittedAction.reasons.includes('expected_action_required'));

  const executable = verifyAebEvaluation(result.record, {
    ...base,
    mode: 'execution',
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: inputs.current_statuses,
    now: NOW,
  });
  assert.equal(executable.valid, true, JSON.stringify(executable));
  assert.equal(executable.execution_authorizing, true);

  const currentPteExecution = verifyAebEvaluation(result.record, {
    ...base,
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: inputs.current_statuses,
    now: NOW,
  });
  assert.equal(currentPteExecution.valid, true, JSON.stringify(currentPteExecution));
  assert.equal(currentPteExecution.execution_authorizing, true);
});

test('AEB gives adapters only immutable relying-party-pinned configuration', () => {
  const s = setup();
  const verifyNative = s.adapter.verifyNative;
  const mapAction = s.adapter.mapAction;
  s.adapter.verifyNative = (input) => {
    assert.equal(input.adapter_config.mode, 'offline');
    assert.equal(Object.isFrozen(input.adapter_config), true);
    assert.equal(Object.isFrozen(input.trust_roots), true);
    assert.equal(Object.isFrozen(input.artifact), true);
    assert.throws(() => { input.adapter_config.mode = 'ambient-network'; }, TypeError);
    return verifyNative(input);
  };
  s.adapter.mapAction = (input) => {
    assert.equal(Object.isFrozen(input.profile), true);
    assert.equal(Object.isFrozen(input.status), true);
    return mapAction(input);
  };
  const malicious = defaultLegs();
  malicious[0].artifact.adapter_config = { mode: 'presenter-selected' };
  const result = evaluate(s, malicious);
  assert.equal(result.record.verdict, 'SATISFIED');
  assert.equal(s.config.adapters['test:operator'].config.mode, 'offline');
});

test('signed native bridge composes WIMSE possession and human authorization', () => {
  const requirement = {
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: ['workload-possession', 'human-authorization'],
    terms: [
      { type: 'initiator-exclusion', roles: ['human-authorization'] },
      { type: 'one-time-consumption' },
    ],
  };
  const s = setup(requirement);
  s.config.registry.entries['role:workload-possession'] = registryEntry(
    'role:workload-possession', 'evidence-role', '1',
    { role: 'workload-possession', subject_kinds: ['workload'] },
  );
  s.config.registry.registry_digest = unifiedRegistryDigest(s.config.registry);

  const nativeKey = crypto.generateKeyPairSync('ed25519');
  const keyId = 'native-verifier:test';
  const publicKey = nativeKey.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const adapter = createAebNativeVerificationAttestationAdapter({ id: 'bridge:native', version: '1' });
  const pin = {
    version: '1',
    trust_roots: [{ key_id: keyId, public_key: publicKey }],
    config: { audience: 'rp:test', accepted_protocols: ['wimse', 'ep-authorization-receipt'] },
    max_status_age_sec: 3600,
  };
  pin.config_digest = adapterPinDigest('bridge:native', pin);
  s.config.adapters = { 'bridge:native': pin };

  const profile = s.config.profiles['test:order'];
  const expectedAction = { action_type: 'order.purchase.1', order_id: 'o-1' };
  const actionDigest = digestAeb(expectedAction);
  const statement = (protocol_id, role, subject, nativeRef) => signAebNativeVerificationAttestation({
    '@version': AEB_NATIVE_VERIFICATION_ATTESTATION_VERSION,
    protocol_id,
    audience: 'rp:test',
    native_artifact_ref: nativeRef,
    native_artifact_digest: digestAeb({ nativeRef }),
    evidence_role: role,
    subject,
    verified_at: '2026-07-21T11:58:00Z',
    expires_at: '2026-07-21T12:10:00Z',
    mapping: {
      profile_digest: profile.profile_digest,
      mapper_id: profile.mapper_id,
      resolver_digest: profile.resolver.implementation_digest,
      caid: CAID,
      normalized_action_digest: actionDigest,
    },
  }, { key_id: keyId, private_key: nativeKey.privateKey });
  const legs = [
    {
      adapter_id: 'bridge:native', profile_id: 'test:order', artifact_ref: 'statement:wimse',
      artifact: statement('wimse', 'workload-possession', { id: 'workload:buyer', kind: 'workload' }, 'urn:wimse:presentation:1'),
      status: status(),
    },
    {
      adapter_id: 'bridge:native', profile_id: 'test:order', artifact_ref: 'statement:human',
      artifact: statement('ep-authorization-receipt', 'human-authorization', { id: 'human:alice', kind: 'human' }, 'urn:ep:receipt:1'),
      status: status(),
    },
  ];
  const result = evaluateAebEvidence({
    config: s.config,
    adapters: { 'bridge:native': adapter },
    operation_id: 'op-wimse-1', consumption_nonce: 'nonce-wimse-1', initiator_id: 'agent:init',
    requirement_ref: 'req:purchase', caid: CAID, expected_action: expectedAction, legs, evaluated_at: NOW,
    signer: { key_id: 'eval:test', private_key: s.keyPair.privateKey },
  });
  assert.equal(result.record.verdict, 'SATISFIED', JSON.stringify(result.record.reasons));
  assert.equal(result.record.composition.engine, 'EP-AEC-v1');
  const nativeInputs = verificationInputs(legs);
  const verified = verifyAebEvaluation(result.record, {
    mode: 'execution',
    config: s.config,
    adapters: { 'bridge:native': adapter },
    artifacts: nativeInputs.artifacts,
    current_statuses: nativeInputs.current_statuses,
    expected_action: expectedAction,
    now: NOW,
  });
  assert.equal(verified.valid, true, JSON.stringify(verified));
  assert.equal(verified.execution_authorizing, true);
  const omittedAction = verifyAebEvaluation(result.record, {
    mode: 'execution',
    config: s.config,
    adapters: { 'bridge:native': adapter },
    artifacts: nativeInputs.artifacts,
    current_statuses: nativeInputs.current_statuses,
    now: NOW,
  });
  assert.equal(omittedAction.valid, false);
  assert.equal(omittedAction.execution_authorizing, false);
  assert.ok(omittedAction.reasons.includes('expected_action_required'));

  const forged = structuredClone(legs);
  forged[0].artifact.mapping.caid = OTHER_CAID;
  const refused = evaluateAebEvidence({
    config: s.config,
    adapters: { 'bridge:native': adapter },
    operation_id: 'op-wimse-2', consumption_nonce: 'nonce-wimse-2', initiator_id: 'agent:init',
    requirement_ref: 'req:purchase', caid: CAID, expected_action: expectedAction, legs: forged, evaluated_at: NOW,
    signer: { key_id: 'eval:test', private_key: s.keyPair.privateKey },
  });
  assert.notEqual(refused.record.verdict, 'SATISFIED');
  assert.ok(refused.record.legs[0].reasons.includes('native_attestation_signature_invalid'));
});

test('AEB refuses RSA and P-256 evaluator keys and signers', () => {
  for (const [algorithm, options] of [
    ['rsa', { modulusLength: 2048 }],
    ['ec', { namedCurve: 'prime256v1' }],
  ]) {
    const s = setup();
    const keyPair = crypto.generateKeyPairSync(algorithm, options);
    s.config.evaluator_keys['eval:test'].public_key = keyPair.publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    const result = evaluate(s, defaultLegs(), {
      signer: { key_id: 'eval:test', private_key: keyPair.privateKey },
    });
    assert.equal(result.valid, false, `${algorithm} evaluator must be refused`);
    assert.equal(result.record.signature, undefined);
    assert.ok(result.record.reasons.includes('invalid_evaluator_key:eval:test'));
    assert.ok(result.record.reasons.includes('evaluator_signer_not_ed25519'));
  }
});

test('AEB refuses a forged verdict and a changed pinned trust root', () => {
  const s = setup();
  const result = evaluate(s);
  const forged = structuredClone(result.record);
  forged.verdict = 'SATISFIED';
  forged.legs[0].evidence_role = 'human-authorization';
  assert.equal(verifyAebEvaluation(forged, {
    mode: 'historical', config: s.config, adapters: { 'test:operator': s.adapter }, artifacts: {},
  }).valid, false);
  const changedConfig = structuredClone(s.config);
  changedConfig.adapters['test:operator'].trust_roots = ['attacker-root'];
  assert.equal(verifyAebEvaluation(result.record, {
    mode: 'historical', config: changedConfig, adapters: { 'test:operator': s.adapter }, artifacts: {},
  }).valid, false);
});

test('AEB distinguishes stale or unavailable evidence from a hard rejection', () => {
  const s = setup();
  const stale = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    { ...leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }), status: status({ checked_at: '2026-07-20T00:00:00Z' }) },
  ]);
  assert.equal(stale.record.verdict, 'INDETERMINATE');
  const revoked = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    { ...leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }), status: status({ revoked: true }) },
  ]);
  assert.equal(revoked.record.verdict, 'UNSATISFIED');
});

test('AEB freezes indeterminate execution and consumes a satisfied authorization once', () => {
  const s = setup();
  const store = new InMemoryAebConsumptionStore();
  const indeterminate = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    { ...leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }), status: status({ unavailable: true }) },
  ]);
  const frozen = authorizeAebExecution(indeterminate.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  });
  assert.equal(frozen.state, 'RECONCILIATION_REQUIRED');
  assert.equal(frozen.invoke_allowed, false);

  const satisfied = evaluate(s);
  const authorized = authorizeAebExecution(satisfied.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  });
  assert.equal(authorized.state, 'AUTHORIZED');
  assert.equal(authorized.invoke_allowed, true);
  assert.equal(reconcileAebExecution(store, authorized.reservation_key, 'COMMITTED').state, 'CONSUMED');
  assert.equal(authorizeAebExecution(satisfied.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  }).reason, 'consumption_conflict');
});

test('AEB treats a material CAID mismatch as unsatisfied', () => {
  const s = setup({
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: ['operator-of-record'],
    terms: [{ type: 'one-time-consumption' }],
  });
  const result = evaluate(s, [leg('operator-of-record', OTHER_CAID)]);
  assert.equal(result.record.verdict, 'UNSATISFIED');
  assert.ok(result.record.reasons.includes('caid_mismatch'));
});

test('AEB refuses legs that claim one CAID for different normalized actions', () => {
  const s = setup();
  const changed = leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' });
  changed.artifact.order_id = 'o-2';
  const result = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    changed,
  ]);
  assert.equal(result.record.verdict, 'UNSATISFIED');
  assert.ok(result.record.reasons.includes('normalized_action_digest_mismatch'));
});

test('AEB refuses unaccepted mappers and material information loss', () => {
  const unaccepted = setup();
  unaccepted.config.accepted_mappers = ['mapper:attacker'];
  const mapperResult = evaluate(unaccepted);
  assert.equal(mapperResult.record.verdict, 'INDETERMINATE');
  assert.ok(mapperResult.record.reasons.includes('mapper_not_accepted:test:order'));

  const lossy = setup();
  const profile = lossy.config.profiles['test:order'];
  profile.semantic_equivalence.omitted_material_fields = ['/amount'];
  profile.profile_digest = mappingProfileDigest('test:order', profile);
  const entry = lossy.config.registry.entries['mapping:test:order'];
  entry.definition = { profile_digest: profile.profile_digest };
  entry.definition_digest = registryEntryDigest('mapping:test:order', entry);
  lossy.config.registry.registry_digest = unifiedRegistryDigest(lossy.config.registry);
  const lossResult = evaluate(lossy);
  assert.equal(lossResult.record.verdict, 'INDETERMINATE');
  assert.ok(lossResult.record.reasons.includes('material_information_loss:test:order'));
});

test('AEB enforces distinct-human quorum and initiator exclusion', () => {
  const s = setup();
  const duplicate = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice-1', { id: 'human:alice', kind: 'human' }),
    leg('human-authorization', CAID, 'artifact:human-alice-2', { id: 'human:alice', kind: 'human' }),
  ]);
  assert.equal(duplicate.record.verdict, 'UNSATISFIED');
  assert.ok(duplicate.record.reasons.includes('quorum_not_met:human-authorization'));

  const selfApproved = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:initiator', { id: 'agent:init', kind: 'human' }),
    leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }),
  ]);
  assert.equal(selfApproved.record.verdict, 'UNSATISFIED');
  assert.ok(selfApproved.record.reasons.includes('initiator_excluded:human-authorization'));
});

test('AEB expresses authority controls as first-class requirement terms', () => {
  const s = setup({
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: ['operator-of-record', 'human-authorization'],
    terms: [
      { type: 'distinct-human-quorum', role: 'human-authorization', threshold: 2 },
      { type: 'initiator-exclusion', roles: ['human-authorization'] },
      { type: 'executor-exclusion', roles: ['human-authorization'] },
      { type: 'one-time-consumption' },
    ],
  });
  const result = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:human-alice', { id: 'human:alice', kind: 'human' }),
    leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }),
  ]);
  assert.equal(result.record.verdict, 'SATISFIED');
  assert.deepEqual(result.record.authority_constraints, {
    distinct_human_quorum: true,
    initiator_exclusion: true,
    executor_exclusion: true,
    one_time_consumption: true,
  });
});

test('AEB binds the executor and refuses approver-as-executor', () => {
  const s = setup();
  const result = evaluate(s, [
    leg('operator-of-record'),
    leg('human-authorization', CAID, 'artifact:executor', { id: 'workload:executor', kind: 'human' }),
    leg('human-authorization', CAID, 'artifact:human-bob', { id: 'human:bob', kind: 'human' }),
  ]);
  assert.equal(result.record.executor_id, 'workload:executor');
  assert.equal(result.record.verdict, 'UNSATISFIED');
  assert.equal(result.record.authority_constraints.executor_exclusion, false);
  assert.ok(result.record.reasons.includes('executor_excluded:human-authorization'));
});

test('execution-time verification refuses stale or newly revoked trusted status', () => {
  const s = setup();
  const result = evaluate(s);
  const artifacts = Object.fromEntries(defaultLegs().map((item) => [item.artifact_ref, item.artifact]));
  const currentStatuses = Object.fromEntries(defaultLegs().map((item) => [item.artifact_ref, status()]));

  const current = verifyAebEvaluation(result.record, {
    mode: 'execution',
    config: s.config,
    adapters: { 'test:operator': s.adapter },
    artifacts,
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: currentStatuses,
    now: NOW,
  });
  assert.equal(current.valid, true, JSON.stringify(current));

  const revoked = structuredClone(currentStatuses);
  revoked['artifact:human-alice'].revoked = true;
  const refused = verifyAebEvaluation(result.record, {
    mode: 'execution',
    config: s.config,
    adapters: { 'test:operator': s.adapter },
    artifacts,
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: revoked,
    now: NOW,
  });
  assert.equal(refused.valid, false);
  assert.equal(refused.checks.current_status, false);
  assert.ok(refused.reasons.includes('current_status_revoked:artifact:human-alice'));

  const expired = verifyAebEvaluation(result.record, {
    mode: 'execution',
    config: s.config,
    adapters: { 'test:operator': s.adapter },
    artifacts,
    expected_action: { action_type: 'order.purchase.1', order_id: 'o-1' },
    current_statuses: currentStatuses,
    now: '2026-07-21T13:00:01Z',
  });
  assert.equal(expired.valid, false);
  assert.equal(expired.checks.current_status, false);
});

test('AEB fails closed on unknown, duplicate, or weakened authority terms', () => {
  for (const terms of [
    [{ type: 'one-time-consumption' }, { type: 'presenter-override' }],
    [{ type: 'one-time-consumption' }, { type: 'one-time-consumption' }],
    [{ type: 'initiator-exclusion', roles: ['human-authorization'] }],
  ]) {
    const s = setup({
      '@version': 'AEB-REQUIREMENT-v1',
      all_of: ['operator-of-record', 'human-authorization'],
      terms,
    });
    const result = evaluate(s);
    assert.equal(result.record.verdict, 'INDETERMINATE');
    assert.ok(result.record.reasons.includes('invalid_requirement:req:purchase'));
  }
});

test('AEB uses one unified registry and refuses cross-kind substitution', () => {
  const s = setup();
  assert.equal(s.config.registry.entries['extension:receipt-lifecycle'].kind, 'receipt-extension');
  const roleEntry = s.config.registry.entries['role:human-authorization'];
  roleEntry.kind = 'mapping-profile';
  roleEntry.definition_digest = registryEntryDigest('role:human-authorization', roleEntry);
  s.config.registry.registry_digest = unifiedRegistryDigest(s.config.registry);
  const result = evaluate(s);
  assert.equal(result.record.verdict, 'INDETERMINATE');
  assert.ok(result.record.reasons.includes('role_not_registered:human-authorization'));
});

test('AEB refuses unknown or duplicate policy members instead of ignoring them', () => {
  const unknown = setup();
  unknown.config.requirements['req:purchase'].presenter_override = true;
  const unknownResult = evaluate(unknown);
  assert.equal(unknownResult.record.verdict, 'INDETERMINATE');
  assert.ok(unknownResult.record.reasons.includes('invalid_requirement:req:purchase'));

  const duplicate = setup();
  duplicate.config.requirements['req:purchase'].all_of.push('operator-of-record');
  const duplicateResult = evaluate(duplicate);
  assert.equal(duplicateResult.record.verdict, 'INDETERMINATE');
  assert.ok(duplicateResult.record.reasons.includes('invalid_requirement:req:purchase'));
});

test('execution refuses a record that does not require one-time consumption', () => {
  const s = setup();
  const result = evaluate(s);
  const weakened = structuredClone(result.record);
  weakened.authority_constraints.one_time_consumption = false;
  const decision = authorizeAebExecution(weakened, {
    verification: { valid: true, execution_authorizing: true },
    local_authorization: true,
    store: new InMemoryAebConsumptionStore(),
  });
  assert.equal(decision.invoke_allowed, false);
  assert.equal(decision.reason, 'one_time_consumption_not_required');
});

test('production execution requires durable ownership-fenced permanent custody', async () => {
  const s = setup();
  const result = evaluate(s);
  assert.equal((await authorizeAebExecutionDurable(result.record, {
    verification: { valid: true, execution_authorizing: false },
    local_authorization: true,
    store: {},
  })).reason, 'execution_verification_required');
  const otherTenant = structuredClone(result.record);
  otherTenant.evaluator.id = 'rp:other';
  assert.notEqual(aebReservationKey(result.record), aebReservationKey(otherTenant));
  const insecure = await authorizeAebExecutionDurable(result.record, {
    verification: { valid: true, execution_authorizing: true },
    local_authorization: true,
    store: { reserve: async () => true, commit: async () => true, release: async () => true },
  });
  assert.equal(insecure.reason, 'secure_consumption_store_required');

  const states = new Map();
  const store = {
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    atomicReplayFenced: true,
    replayOwners: new Map(),
    async reserve(key, replayKeys) {
      if (states.has(key)) return 'CONSUMPTION_CONFLICT';
      if (replayKeys.some((replayKey) => this.replayOwners.has(replayKey))) return 'NATIVE_REPLAY_CONFLICT';
      states.set(key, 'RESERVED');
      for (const replayKey of replayKeys) this.replayOwners.set(replayKey, key);
      return 'RESERVED';
    },
    async commit(key) {
      if (states.get(key) !== 'RESERVED') return false;
      states.set(key, 'CONSUMED');
      return true;
    },
    async release(key) {
      if (states.get(key) !== 'RESERVED') return false;
      states.delete(key);
      for (const [replayKey, owner] of this.replayOwners) {
        if (owner === key) this.replayOwners.delete(replayKey);
      }
      return true;
    },
  };
  const authorized = await authorizeAebExecutionDurable(result.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  });
  assert.equal(authorized.state, 'AUTHORIZED');
  assert.equal((await reconcileAebExecutionDurable(store, authorized.reservation_key, 'COMMITTED')).state, 'CONSUMED');
  assert.equal((await authorizeAebExecutionDurable(result.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  })).reason, 'consumption_conflict');

  const replayedUnderNewOperation = evaluate(s, defaultLegs(), {
    operation_id: 'op-2',
    consumption_nonce: 'nonce-2',
  });
  assert.equal(replayedUnderNewOperation.record.verdict, 'SATISFIED');
  assert.equal((await authorizeAebExecutionDurable(replayedUnderNewOperation.record, {
    verification: { valid: true, execution_authorizing: true }, local_authorization: true, store,
  })).reason, 'native_replay_conflict');
});
