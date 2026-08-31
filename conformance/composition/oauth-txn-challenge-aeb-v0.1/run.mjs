// SPDX-License-Identifier: Apache-2.0
/**
 * Compose OAuth transaction-challenge evidence through the native compiler and
 * the existing consequence-admission kernel. The adapter verifies the native
 * JWTs. The compiler keeps verification, matching, satisfaction, and local
 * authorization separate. The kernel alone models reservation and lifecycle.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeCaid } from '../../../packages/verify/vendor/caid.mjs';
import {
  InMemoryAebConsumptionStore,
  adapterPinDigest,
  aebReservationKey,
  authorizeAebExecution,
  digestAeb,
  evaluateAebEvidence,
  mappingProfileDigest,
  registryEntryDigest,
  unifiedRegistryDigest,
  verifyAebEvaluation,
} from '../../../packages/verify/dist/aeb-adapter-contract.js';
import {
  OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
  OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
  OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
  OAUTH_TXN_CHALLENGE_DRAFT_REVISION,
  OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
  OAUTH_TXN_CHALLENGE_MAPPER_ID,
  OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS,
  OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
  createOAuthTransactionChallengeActionDefinition,
  createOAuthTransactionChallengeAebAdapter,
} from '../../../packages/verify/dist/aeb-oauth-transaction-challenge-adapter.js';
import {
  AEB_NATIVE_COMPILER_VERSION,
  AEB_NATIVE_DESCRIPTOR_VERSION,
  aebNativeDescriptorDigest,
  compileAebNativeEvidence,
} from '../../../packages/verify/dist/aeb-native-compiler.js';
import {
  AEB_CONSEQUENCE_CASE_VERSION,
  AEB_CONSEQUENCE_CONFORMANCE_VERSION,
  AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
  canonicalizeAebConsequenceConformance,
  evaluateAebConsequenceCase,
  parseAebConsequenceCase,
} from '../../../packages/verify/dist/aeb-consequence-conformance.js';

export const PROFILE = 'OAUTH-TXN-CHALLENGE-AEB-COMPOSITION-v0.1';
export const REPORT_VERSION = 'OAUTH-TXN-CHALLENGE-AEB-REPORT-v0.1';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../../..');
const SOURCE_LOCK_PATH = resolve(HERE, 'source-lock.json');
const NATIVE_FIXTURE_PATH = resolve(HERE, 'native-fixture.json');
const VECTORS_PATH = resolve(HERE, 'vectors.json');
const REFERENCE_PATH = resolve(HERE, 'report.reference.json');

export const SOURCE_LOCK = Object.freeze(JSON.parse(readFileSync(SOURCE_LOCK_PATH, 'utf8')));
export const NATIVE_FIXTURE = Object.freeze(JSON.parse(readFileSync(NATIVE_FIXTURE_PATH, 'utf8')));
const VECTORS = Object.freeze(JSON.parse(readFileSync(VECTORS_PATH, 'utf8')));
const LOCAL_IMPLEMENTATION_FILES = Object.freeze([
  'packages/verify/src/aeb-adapter-contract.ts',
  'packages/verify/dist/aeb-adapter-contract.js',
  'packages/verify/src/aeb-oauth-transaction-challenge-adapter.ts',
  'packages/verify/dist/aeb-oauth-transaction-challenge-adapter.js',
  'packages/verify/src/aeb-native-compiler.ts',
  'packages/verify/dist/aeb-native-compiler.js',
  'packages/verify/src/aeb-consequence-conformance.ts',
  'packages/verify/dist/aeb-consequence-conformance.js',
  'packages/verify/vendor/caid.mjs',
  'conformance/composition/oauth-txn-challenge-aeb-v0.1/run.mjs',
]);

const RESOURCE = 'https://payments.example';
const AUTHORIZATION_SERVER = 'https://as.example';
const CLIENT_ID = 'agent-client-42';
const SUBJECT = 'principal:customer-42';
const TXN = '97053963-771d-49cc-a4e3-20aad399c312';
const ACTION_TYPE = 'payment.initiate.1';
const INITIATOR_ID = 'agent:accounting';
const EXECUTOR_ID = 'executor:payment-gate';
const PROVIDER_ID = 'provider:payments-primary';
const PROFILE_ID = 'profile:oauth-txn-payment-v0.1';
const REQUIREMENT_REF = 'requirement:oauth-transaction-authorization';
const DESCRIPTOR_ID = 'descriptor:oauth-transaction-challenge-jwt-pair:v0.1';
const STATUS_CHECKED_AT = '2026-08-31T19:00:29Z';
const STATUS_VALID_UNTIL = '2026-08-31T19:05:00Z';
const EVALUATOR_KEY_ID = 'evaluator:oauth-txn-local-race';
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const EVALUATOR_PRIVATE_KEY = crypto.createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.alloc(32, 0x4f)]),
  format: 'der',
  type: 'pkcs8',
});
const EVALUATOR_PUBLIC_KEY = crypto.createPublicKey(EVALUATOR_PRIVATE_KEY)
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');

export const EXACT_NONCLAIMS = Object.freeze([
  'challenge_is_not_authorization',
  'pending_transaction_authorization_id_is_not_authorization',
  'access_token_does_not_prove_named_human_identity',
  'profile_does_not_reperform_authorization_server_policy_or_consent_correctness',
  'sender_constrained_token_or_channel_binding_is_not_established',
  'nonreusable_transaction_rule_is_application_profile_not_oauth_requirement',
  'compiler_report_is_not_authorization_or_credential',
  'native_verification_does_not_prove_provider_entry_execution_or_outcome',
  'local_atomicity_does_not_prove_remote_or_downstream_exactly_once',
  'single_process_promise_race_does_not_establish_distributed_store_concurrency',
  'profile_is_signed_jwt_with_inline_exact_rar_not_the_full_base_draft',
  'indeterminate_does_not_prove_provider_success_or_failure',
  'test_harness_is_not_independent_implementation_or_production_mediation',
  'internet_draft_is_not_ietf_adoption_or_endorsement',
]);

const AUTHORIZATION_DETAILS = Object.freeze([{
  type: 'payment',
  actions: ['initiate'],
  locations: ['https://payments.example/accounts/123'],
  instructedAmount: { currency: 'GBP', amount: '5000.00' },
  creditorName: 'Example Ltd',
}]);
const ACTOR = Object.freeze({ sub: 'workload:payment-agent' });

function clone(value) {
  return structuredClone(value);
}

function sameJson(left, right) {
  return canonicalizeAebConsequenceConformance(left)
    === canonicalizeAebConsequenceConformance(right);
}

function sha256Text(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function actionFor(variant) {
  const action = {
    action_type: ACTION_TYPE,
    oauth_transaction: {
      txn: TXN,
      authorization_details: clone(AUTHORIZATION_DETAILS),
      actor: clone(ACTOR),
      verified_context: {
        challenge_issuer: RESOURCE,
        challenge_audience: AUTHORIZATION_SERVER,
        access_token_issuer: AUTHORIZATION_SERVER,
        access_token_subject: SUBJECT,
        access_token_audience: RESOURCE,
        access_token_client_id: CLIENT_ID,
      },
    },
  };
  if (variant === 'material_details_change') {
    action.oauth_transaction.authorization_details[0].instructedAmount.amount = '5000.01';
  } else if (variant === 'transaction_mismatch') {
    action.oauth_transaction.txn = '97053963-771d-49cc-a4e3-20aad399c999';
  } else if (variant !== 'exact') {
    throw new TypeError(`unknown expected-action variant: ${variant}`);
  }
  return action;
}

function artifactFor(variant) {
  if (variant === 'primary') {
    return {
      challenge_jwt: NATIVE_FIXTURE.challenge_jwt,
      access_token_jwt: NATIVE_FIXTURE.access_token_jwt,
    };
  }
  if (variant === 'twin') {
    return {
      challenge_jwt: NATIVE_FIXTURE.challenge_jwt,
      access_token_jwt: NATIVE_FIXTURE.twin_access_token_jwt,
    };
  }
  if (variant === 'challenge_only') {
    return { challenge_jwt: NATIVE_FIXTURE.challenge_jwt };
  }
  throw new TypeError(`unknown native-artifact variant: ${variant}`);
}

function registryEntry(id, kind, definition) {
  const entry = {
    kind,
    version: '1',
    status: 'active',
    definition,
    definition_digest: '',
  };
  entry.definition_digest = registryEntryDigest(id, entry);
  return entry;
}

function compilerAxes(compiler) {
  return {
    verified: compiler.axes.verified.result,
    accepted: compiler.axes.accepted.result,
    match: compiler.axes.match.result,
    satisfied: compiler.axes.satisfied.result,
    local_authorization: compiler.axes.local_authorization.result,
  };
}

function consequenceProjection(result, fields) {
  return Object.fromEntries(fields.map((field) => [field, result[field]]));
}

function compilerMaterials(expectedVariant) {
  const expectedAction = actionFor(expectedVariant);
  const definition = createOAuthTransactionChallengeActionDefinition(ACTION_TYPE, true);
  const resolver = {
    id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
    version: '2',
    implementation_digest: digestAeb({
      implementation: OAUTH_TXN_CHALLENGE_MAPPER_ID,
      revision: '2',
      input: 'signed-challenge-and-issued-access-token',
    }),
  };
  const profile = {
    version: OAUTH_TXN_CHALLENGE_MAPPING_VERSION,
    definition,
    registry_entry_ref: `mapping:${PROFILE_ID}`,
    mapper_id: OAUTH_TXN_CHALLENGE_MAPPER_ID,
    resolver,
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [...OAUTH_TXN_CHALLENGE_OMITTED_NONMATERIAL_FIELDS],
    },
    profile_digest: '',
  };
  profile.profile_digest = mappingProfileDigest(PROFILE_ID, profile);

  const detailsDescriptor = {
    id: 'emilia:oauth-rar-exact-grant-check',
    version: '1',
    implementation_digest: digestAeb({
      implementation: 'emilia:oauth-rar-exact-grant-check',
      revision: '1',
      rule: 'requested_equals_granted_equals_relying_party_expected',
    }),
  };
  const config = {
    '@version': OAUTH_TXN_CHALLENGE_CONFIG_VERSION,
    evidence_role: 'transaction-authorization',
    subject: {
      id: 'organization:authorization-server',
      kind: 'organization',
      native_id: AUTHORIZATION_SERVER,
    },
    action_type: ACTION_TYPE,
    protected_resource: RESOURCE,
    authorization_server: AUTHORIZATION_SERVER,
    oauth_client_id: CLIENT_ID,
    oauth_subject: SUBJECT,
    require_actor_context: true,
    replay_equivalence: 'nonreusable-protected-resource-transaction',
    clock_skew_seconds: 2,
    max_challenge_lifetime_seconds: 120,
    max_access_token_lifetime_seconds: 180,
    max_status_age_seconds: 120,
    details_verifier: detailsDescriptor,
  };
  const trustRoots = [
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'protected-resource-challenge',
      issuer: RESOURCE,
      key_id: 'resource-ed25519-static-1',
      algorithm: 'EdDSA',
      public_key: NATIVE_FIXTURE.protected_resource_public_spki,
    },
    {
      '@version': OAUTH_TXN_CHALLENGE_TRUST_ROOT_VERSION,
      use: 'authorization-server-access-token',
      issuer: AUTHORIZATION_SERVER,
      key_id: 'as-ed25519-static-1',
      algorithm: 'EdDSA',
      public_key: NATIVE_FIXTURE.authorization_server_public_spki,
    },
  ];
  const detailsVerifier = {
    ...detailsDescriptor,
    verify(input) {
      return digestAeb(input.requested) === digestAeb(input.granted)
        && digestAeb(input.granted) === digestAeb(input.expected)
        ? { verified: true, reason: null }
        : { verified: false, reason: 'authorization_details_broadened_or_mismatched' };
    },
  };
  const adapter = createOAuthTransactionChallengeAebAdapter({
    config,
    trust_roots: trustRoots,
    details_verifier: detailsVerifier,
  });
  const adapterPin = {
    version: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
    trust_roots: trustRoots,
    config,
    max_status_age_sec: 120,
    config_digest: '',
  };
  adapterPin.config_digest = adapterPinDigest(OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID, adapterPin);

  const requirement = {
    '@version': 'AEB-REQUIREMENT-v1',
    all_of: ['transaction-authorization'],
    terms: [{ type: 'one-time-consumption' }],
  };
  const entries = {
    [profile.registry_entry_ref]: registryEntry(
      profile.registry_entry_ref,
      'mapping-profile',
      { profile_digest: profile.profile_digest },
    ),
    'role:transaction-authorization': registryEntry(
      'role:transaction-authorization',
      'evidence-role',
      { role: 'transaction-authorization', subject_kinds: ['organization'] },
    ),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:oauth-txn-challenge-aeb-v0.1',
    epoch: 1,
    entries,
    registry_digest: '',
  };
  registry.registry_digest = unifiedRegistryDigest(registry);
  const pins = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:emilia:oauth-txn-challenge-aeb-v0.1',
    evaluator_keys: {
      [EVALUATOR_KEY_ID]: { public_key: EVALUATOR_PUBLIC_KEY },
    },
    registry,
    accepted_mappers: [profile.mapper_id],
    adapters: { [OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID]: adapterPin },
    profiles: { [PROFILE_ID]: profile },
    requirements: { [REQUIREMENT_REF]: requirement },
  };
  const computed = computeCaid(expectedAction, {
    suite: 'jcs-sha256',
    definitions: definition.definitions,
  });
  assert.equal(computed.digest, digestAeb(expectedAction));
  const descriptor = {
    '@version': AEB_NATIVE_DESCRIPTOR_VERSION,
    protocol: {
      id: 'oauth-transaction-authorization-challenge',
      revision: OAUTH_TXN_CHALLENGE_DRAFT_REVISION,
    },
    source: {
      media_type: 'application/json',
      schema: { id: 'emilia:oauth-txn-challenge-jwt-pair', revision: 'v0.1' },
    },
    verifier: {
      implementation_id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
      implementation_revision: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
      implementation_digest: digestAeb({
        implementation: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
        revision: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
      }),
    },
    adapter: {
      id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
      revision: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
    },
    mapping_profile: {
      id: PROFILE_ID,
      revision: profile.version,
      digest: profile.profile_digest,
    },
    target_action_type: ACTION_TYPE,
    replay_scope: 'nonreusable-protected-resource-transaction',
    descriptor_digest: '',
  };
  descriptor.descriptor_digest = aebNativeDescriptorDigest(DESCRIPTOR_ID, descriptor);
  return {
    adapter,
    config,
    descriptor,
    expectedAction,
    expectedCaid: computed.caid,
    pins,
    profile,
    requirement,
    trustRoots,
  };
}

export function buildCompilerFixture({
  artifact_variant = 'primary',
  expected_variant = 'exact',
  artifact_ref = 'urn:emilia:wrapper:oauth-txn:v0.1',
} = {}) {
  const materials = compilerMaterials(expected_variant);
  const input = {
    pins: materials.pins,
    adapters: { [OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID]: materials.adapter },
    native_descriptors: {
      pins: { [DESCRIPTOR_ID]: materials.descriptor.descriptor_digest },
      registry: { [DESCRIPTOR_ID]: materials.descriptor },
    },
    native_legs: [{
      native_descriptor_id: DESCRIPTOR_ID,
      adapter_id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
      profile_id: PROFILE_ID,
      artifact_ref,
      artifact: artifactFor(artifact_variant),
      status: {
        checked_at: STATUS_CHECKED_AT,
        expires_at: STATUS_VALID_UNTIL,
        revocation_checked: true,
        revoked: false,
        consumed: false,
      },
    }],
    expected_action: { caid: materials.expectedCaid, value: materials.expectedAction },
    requirement: { ref: REQUIREMENT_REF, definition: materials.requirement },
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    evaluated_at: VECTORS.evaluated_at,
    local_policy_input: {
      policy_id: 'policy:oauth-transaction-admission',
      policy_version: '1',
      decision: 'ALLOW',
      reasons: [],
    },
  };
  return { ...materials, input, compiler: compileAebNativeEvidence(input) };
}

function signedExecutionAuthorization(fixture, operationId, consumptionNonce) {
  const nativeLeg = fixture.input.native_legs[0];
  const leg = {
    adapter_id: nativeLeg.adapter_id,
    profile_id: nativeLeg.profile_id,
    artifact_ref: nativeLeg.artifact_ref,
    artifact: nativeLeg.artifact,
    status: nativeLeg.status,
  };
  const evaluated = evaluateAebEvidence({
    config: fixture.pins,
    adapters: { [OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID]: fixture.adapter },
    operation_id: operationId,
    consumption_nonce: consumptionNonce,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    requirement_ref: REQUIREMENT_REF,
    caid: fixture.expectedCaid,
    expected_action: fixture.expectedAction,
    legs: [leg],
    evaluated_at: VECTORS.evaluated_at,
    signer: { key_id: EVALUATOR_KEY_ID, private_key: EVALUATOR_PRIVATE_KEY },
  });
  assert.equal(evaluated.valid, true, JSON.stringify(evaluated.reasons));
  const verification = verifyAebEvaluation(evaluated.record, {
    config: fixture.pins,
    adapters: { [OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID]: fixture.adapter },
    artifacts: { [leg.artifact_ref]: leg.artifact },
    mode: 'execution',
    expected_action: fixture.expectedAction,
    current_statuses: { [leg.artifact_ref]: leg.status },
    now: VECTORS.evaluated_at,
  });
  assert.equal(verification.valid, true, JSON.stringify(verification.reasons));
  assert.equal(verification.execution_authorizing, true);
  return { record: evaluated.record, verification };
}

function twoPartyBarrier() {
  let arrivals = 0;
  let release;
  const open = new Promise((resolvePromise) => { release = resolvePromise; });
  return {
    get arrivals() { return arrivals; },
    async arrive() {
      arrivals += 1;
      if (arrivals === 2) release();
      await open;
    },
  };
}

function requirementForConsequence() {
  return {
    role: 'transaction-authorization',
    principal_kind: 'ORGANIZATION',
    minimum: 1,
    distinct_principals: false,
    exclude_initiator: false,
    exclude_executor: false,
  };
}

function consequenceInput({
  id,
  compiler,
  mode = 'ADMISSION',
  operation_id = `oauth-txn:${id}`,
  prior = false,
  consumed_replay_units = [],
  observation = null,
  reconciliation = null,
}) {
  assert.equal(compiler.legs.length, 1, `${id}: exactly one OAuth native leg required`);
  const leg = compiler.legs[0];
  assert.equal(leg.action.mapping, 'MATCH', `${id}: consequence input requires an exact mapped action`);
  assert.equal(typeof leg.action.caid, 'string');
  assert.equal(typeof leg.action.normalized_action_digest, 'string');
  const operation = {
    operation_id,
    provider_id: PROVIDER_ID,
    initiator_id: INITIATOR_ID,
    executor_id: EXECUTOR_ID,
    caid: leg.action.caid,
    normalized_action_digest: leg.action.normalized_action_digest,
    requirements: [requirementForConsequence()],
  };
  const priorOperations = prior ? [{
    operation_id,
    caid: operation.caid,
    normalized_action_digest: operation.normalized_action_digest,
    custody: 'INVOKING',
    provider_outcome: 'INDETERMINATE',
    effect_relation: 'INDETERMINATE',
  }] : [];
  return parseAebConsequenceCase({
    '@version': AEB_CONSEQUENCE_CASE_VERSION,
    id,
    mode,
    evaluated_at: VECTORS.evaluated_at,
    operation,
    evidence: [{
      wrapper_digest: leg.artifact_digest,
      native_replay_unit: leg.replay_unit,
      native_verification: leg.native_result.verification,
      mapped_caid: leg.action.caid,
      mapped_action_digest: leg.action.normalized_action_digest,
      role: leg.evidence.role,
      principal_kind: 'ORGANIZATION',
      principal_id: leg.evidence.subject.id,
      status: {
        verdict: 'CURRENT',
        authority_pinned: true,
        checked_at: STATUS_CHECKED_AT,
        valid_until: STATUS_VALID_UNTIL,
      },
    }],
    local_policy: 'PERMIT',
    reservation: {
      atomicity: 'local_atomic',
      prior_operations: priorOperations,
      consumed_native_replay_units: consumed_replay_units,
    },
    observation,
    reconciliation,
  });
}

function compilerDetails(compiler) {
  return {
    compiler_report_digest: compiler.report_digest,
    artifact_digest: compiler.legs[0]?.artifact_digest ?? null,
    native_replay_unit: compiler.legs[0]?.replay_unit ?? null,
    compiler_replay_unit: compiler.replay_unit,
    compiler_local_authorization: compiler.axes.local_authorization.result,
    compiler_provider_entry: compiler.lifecycle.provider_entry.result,
    compiler_provider_outcome: compiler.lifecycle.provider_outcome.result,
    compiler_observed_effect: compiler.lifecycle.observed_effect.result,
    report_is_credential: compiler.report_is_credential,
  };
}

async function evaluateVector(entry) {
  let observed;
  let details;
  if (entry.id === 'exact_transaction_admits') {
    const fixture = buildCompilerFixture();
    const consequence = evaluateAebConsequenceCase(consequenceInput({
      id: entry.id,
      compiler: fixture.compiler,
    }));
    observed = {
      compiler_axes: compilerAxes(fixture.compiler),
      consequence: consequenceProjection(consequence, ['decision', 'reservation']),
      provider_entry: 'AUTHORIZED_NOT_ENTERED',
    };
    details = compilerDetails(fixture.compiler);
  } else if (entry.id === 'material_details_change_refuses'
      || entry.id === 'transaction_mismatch_refuses'
      || entry.id === 'challenge_alone_refuses') {
    const expectedVariant = entry.id === 'material_details_change_refuses'
      ? 'material_details_change'
      : entry.id === 'transaction_mismatch_refuses' ? 'transaction_mismatch' : 'exact';
    const artifactVariant = entry.id === 'challenge_alone_refuses' ? 'challenge_only' : 'primary';
    const fixture = buildCompilerFixture({
      expected_variant: expectedVariant,
      artifact_variant: artifactVariant,
      artifact_ref: `urn:emilia:wrapper:${entry.id}`,
    });
    observed = {
      compiler_axes: compilerAxes(fixture.compiler),
      provider_entry: 'REFUSED_BEFORE_ENTRY',
    };
    details = compilerDetails(fixture.compiler);
  } else if (entry.id === 'twin_token_concurrent_admission_one_reservation') {
    const first = buildCompilerFixture({
      artifact_variant: 'primary',
      artifact_ref: 'urn:emilia:wrapper:oauth-txn:first-token',
    });
    const twin = buildCompilerFixture({
      artifact_variant: 'twin',
      artifact_ref: 'urn:emilia:wrapper:oauth-txn:twin-token',
    });
    const firstAuthorization = signedExecutionAuthorization(
      first,
      'oauth-txn:twin:first-operation',
      'oauth-txn:twin:first-consumption',
    );
    const twinAuthorization = signedExecutionAuthorization(
      twin,
      'oauth-txn:twin:second-operation',
      'oauth-txn:twin:second-consumption',
    );
    const store = new InMemoryAebConsumptionStore();
    const barrier = twoPartyBarrier();
    const authorize = async (authorization) => {
      await barrier.arrive();
      return authorizeAebExecution(authorization.record, {
        verification: authorization.verification,
        local_authorization: true,
        store,
      });
    };
    const decisions = await Promise.all([
      authorize(firstAuthorization),
      authorize(twinAuthorization),
    ]);
    const reservationStates = [firstAuthorization, twinAuthorization]
      .map((authorization) => store.state(aebReservationKey(authorization.record)))
      .sort();
    observed = {
      same_native_replay_unit: first.compiler.legs[0].replay_unit
        === twin.compiler.legs[0].replay_unit,
      promise_race: {
        arrivals: barrier.arrivals,
        admission_states: decisions.map((decision) => decision.state).sort(),
        admission_reasons: decisions.map((decision) => decision.reason).sort(),
        reservation_states: reservationStates,
      },
      provider_entry: 'ONE_ENTRY_AUTHORIZED_OTHER_REFUSED',
    };
    details = {
      first: compilerDetails(first.compiler),
      twin: compilerDetails(twin.compiler),
      signed_evaluations_verified_for_execution: true,
      store: 'InMemoryAebConsumptionStore',
      concurrency_scope: 'single_process_promise_barrier',
    };
  } else if (entry.id === 'timeout_after_dispatch_indeterminate') {
    const fixture = buildCompilerFixture();
    const consequence = evaluateAebConsequenceCase(consequenceInput({
      id: entry.id,
      compiler: fixture.compiler,
      mode: 'INVOCATION_OBSERVATION',
      prior: true,
      observation: {
        source: 'TIMEOUT_AFTER_DISPATCH',
        provider_outcome: 'INDETERMINATE',
        effect_relation: 'INDETERMINATE',
      },
    }));
    observed = {
      consequence: consequenceProjection(consequence, [
        'decision', 'provider_outcome', 'effect_relation', 'retry', 'reconciliation', 'reasons',
      ]),
      provider_entry: 'DISPATCHED_OUTCOME_UNKNOWN',
    };
    details = compilerDetails(fixture.compiler);
  } else if (entry.id === 'blind_retry_refused') {
    const fixture = buildCompilerFixture();
    const consequence = evaluateAebConsequenceCase(consequenceInput({
      id: entry.id,
      compiler: fixture.compiler,
      mode: 'RETRY',
      prior: true,
    }));
    observed = {
      consequence: consequenceProjection(consequence, [
        'decision', 'provider_outcome', 'effect_relation', 'retry', 'reconciliation', 'reasons',
      ]),
      provider_entry: 'REENTRY_REFUSED',
    };
    details = compilerDetails(fixture.compiler);
  } else if (entry.id === 'reconciliation_mismatch_refused') {
    const fixture = buildCompilerFixture();
    const leg = fixture.compiler.legs[0];
    const operationId = `oauth-txn:${entry.id}`;
    const consequence = evaluateAebConsequenceCase(consequenceInput({
      id: entry.id,
      operation_id: operationId,
      compiler: fixture.compiler,
      mode: 'RECONCILIATION',
      prior: true,
      reconciliation: {
        authenticated: true,
        provider_id: 'provider:payments-other',
        operation_id: operationId,
        caid: leg.action.caid,
        normalized_action_digest: leg.action.normalized_action_digest,
        provider_outcome: 'COMMITTED',
        effect_relation: 'OBSERVED_AS_REQUESTED',
      },
    }));
    observed = {
      consequence: consequenceProjection(consequence, [
        'decision', 'provider_outcome', 'effect_relation', 'retry', 'reconciliation', 'reasons',
      ]),
      provider_entry: 'NO_REEXECUTION_RECONCILIATION_REFUSED',
    };
    details = compilerDetails(fixture.compiler);
  } else if (entry.id === 'wrapper_reference_stability') {
    const first = buildCompilerFixture({ artifact_ref: 'urn:emilia:wrapper:first' });
    const second = buildCompilerFixture({ artifact_ref: 'urn:emilia:wrapper:second' });
    observed = {
      same_leg_replay_unit: first.compiler.legs[0].replay_unit
        === second.compiler.legs[0].replay_unit,
      same_compiler_replay_unit: first.compiler.replay_unit === second.compiler.replay_unit,
      provider_entry: 'NOT_EVALUATED',
    };
    details = {
      first: compilerDetails(first.compiler),
      second: compilerDetails(second.compiler),
    };
  } else {
    throw new TypeError(`unknown vector: ${entry.id}`);
  }
  return {
    id: entry.id,
    passed: sameJson(observed, entry.expected),
    expected: entry.expected,
    observed,
    details,
  };
}

export function verifySourceLock() {
  const failures = [];
  const expectedUpstream = {
    id: 'draft-rosomakho-oauth-txn-challenge-00',
    url: 'https://www.ietf.org/archive/id/draft-rosomakho-oauth-txn-challenge-00.txt',
    bytes: 70435,
    sha256: 'a50c1fee4ce4ae486aa6e6739e9927586dc5c14a209434f44f76200354a8cead',
  };
  if (SOURCE_LOCK['@version'] !== 'OAUTH-TXN-CHALLENGE-AEB-SOURCE-LOCK-v0.2') {
    failures.push({ field: '@version', reason: 'source_lock_version_mismatch' });
  }
  if (!sameJson(SOURCE_LOCK.upstream, expectedUpstream)) {
    failures.push({ field: 'upstream', reason: 'upstream_source_lock_mismatch' });
  }
  const lockedImplementation = SOURCE_LOCK.local_implementation;
  if (!lockedImplementation || typeof lockedImplementation !== 'object'
      || Array.isArray(lockedImplementation)
      || !sameJson(Object.keys(lockedImplementation).sort(), [...LOCAL_IMPLEMENTATION_FILES].sort())) {
    failures.push({ field: 'local_implementation', reason: 'implementation_path_set_mismatch' });
  } else {
    for (const relativePath of LOCAL_IMPLEMENTATION_FILES) {
      const actual = crypto.createHash('sha256')
        .update(readFileSync(resolve(REPO_ROOT, relativePath)))
        .digest('hex');
      if (lockedImplementation[relativePath] !== actual) {
        failures.push({ field: relativePath, reason: 'implementation_digest_mismatch' });
      }
    }
  }
  for (const field of [
    'protected_resource_public_spki',
    'authorization_server_public_spki',
    'challenge_jwt',
    'access_token_jwt',
    'twin_access_token_jwt',
  ]) {
    if (typeof NATIVE_FIXTURE[field] !== 'string'
        || sha256Text(NATIVE_FIXTURE[field]) !== NATIVE_FIXTURE.sha256?.[field]) {
      failures.push({ field, reason: 'native_fixture_digest_mismatch' });
    }
  }
  return { valid: failures.length === 0, failures };
}

export async function verifyUpstreamSource(fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') throw new TypeError('fetch implementation required');
  const response = await fetchImpl(SOURCE_LOCK.upstream.url);
  if (!response.ok) return { valid: false, status: response.status, bytes: 0, sha256: null };
  const bytes = Buffer.from(await response.arrayBuffer());
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  return {
    valid: bytes.length === SOURCE_LOCK.upstream.bytes && sha256 === SOURCE_LOCK.upstream.sha256,
    status: response.status,
    bytes: bytes.length,
    sha256,
  };
}

export async function runSuite() {
  const sourceVerification = verifySourceLock();
  assert.equal(sourceVerification.valid, true, JSON.stringify(sourceVerification.failures));
  assert.equal(VECTORS['@version'], 'OAUTH-TXN-CHALLENGE-AEB-VECTORS-v0.1');
  assert.equal(VECTORS.cases.length, 9);
  const cases = await Promise.all(VECTORS.cases.map(evaluateVector));
  const passed = cases.filter((entry) => entry.passed).length;
  const body = {
    '@version': REPORT_VERSION,
    profile: PROFILE,
    executed_at: VECTORS.evaluated_at,
    implementation: {
      owner: 'EMILIA Protocol',
      revision: 'v0.1',
      independent_implementation: false,
      production_mediation: false,
    },
    source_pins: {
      source_lock_digest: digestAeb(SOURCE_LOCK),
      native_fixture_digest: digestAeb(NATIVE_FIXTURE),
      upstream_id: SOURCE_LOCK.upstream.id,
      upstream_url: SOURCE_LOCK.upstream.url,
      upstream_bytes: SOURCE_LOCK.upstream.bytes,
      upstream_sha256: SOURCE_LOCK.upstream.sha256,
      local_implementation_digest: digestAeb(SOURCE_LOCK.local_implementation),
      adapter_id: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_ID,
      adapter_version: OAUTH_TXN_CHALLENGE_AEB_ADAPTER_VERSION,
      native_compiler_version: AEB_NATIVE_COMPILER_VERSION,
      consequence_kernel_version: AEB_CONSEQUENCE_CONFORMANCE_VERSION,
    },
    claim_scope: {
      atomicity: AEB_CONSEQUENCE_LOCAL_ATOMIC_SCOPE,
      guarantees: [
        'source_pinned_native_pair_verified_under_relying_party_keys',
        'primary_local_implementation_bytes_pinned',
        'verified_issuer_audience_subject_client_actor_transaction_and_exact_rar_compiled_to_caid',
        'one_transaction_replay_unit_survives_access_token_reissuance_and_wrapper_changes',
        'single_process_atomic_store_reserves_exactly_one_concurrent_twin_transaction',
        'timeout_consumes_retry_authority_until_exact_authenticated_reconciliation',
      ],
      exclusions: [...EXACT_NONCLAIMS],
    },
    summary: {
      total: cases.length,
      passed,
      failed: cases.length - passed,
    },
    cases,
  };
  return Object.freeze({ ...body, report_digest: digestAeb(body) });
}

function parseArgs(argv) {
  const options = { check: false, emit: false, output: null };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--check') options.check = true;
    else if (argument === '--emit') options.emit = true;
    else if (argument === '--output') {
      options.output = argv[index + 1];
      index += 1;
    } else throw new TypeError(`unknown argument: ${argument}`);
  }
  if (options.emit && !options.output) throw new TypeError('--emit requires --output');
  return options;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const options = parseArgs(process.argv.slice(2));
  const report = await runSuite();
  if (options.check) {
    const reference = JSON.parse(readFileSync(REFERENCE_PATH, 'utf8'));
    assert.deepEqual(report, reference, 'deterministic report differs from reference');
    assert.equal(report.summary.failed, 0, JSON.stringify(report.cases.filter((entry) => !entry.passed)));
    process.stdout.write(
      `${PROFILE}: ${report.summary.passed}/${report.summary.total} cases passed; reference matched\n`,
    );
  } else if (options.emit) {
    writeFileSync(resolve(options.output), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  } else {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
