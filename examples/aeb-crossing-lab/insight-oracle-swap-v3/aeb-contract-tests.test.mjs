// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { hashTypedData } from './node_modules/viem/_esm/utils/signature/hashTypedData.js';
import { privateKeyToAccount } from './node_modules/viem/_esm/accounts/privateKeyToAccount.js';

import insightAebAdapter, {
  ACTION_TYPE,
  ADAPTER_ID,
  ADAPTER_VERSION,
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_TYPES,
  InMemoryReservationStore,
  MAPPER_ID,
  executeCrossing,
} from './adapter.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pinnedRoot = join(here, '..', '..', '..');

const contract = await import(
  pathToFileURL(join(pinnedRoot, 'packages/verify/aeb-adapter-contract.js')).href
);
const caidReference = await import(pathToFileURL(join(pinnedRoot, 'caid/impl/js/caid.mjs')).href);
const fixture = JSON.parse(await readFile(join(here, 'signed-nonproduction-fixture.json'), 'utf8'));
const adapterBytes = await readFile(join(here, 'adapter.mjs'));

const PROFILE_ID = 'insight-evm-swap-exact-input-single';
const PROFILE_VERSION = 'INSIGHT-EVM-SWAP-EXACT-INPUT-SINGLE-MAPPING-v1';
const ROLE = 'action-authorization';
const REQUIREMENT_REF = 'requirement:insight-swap-action-authorization';
const ARTIFACT_REF = 'insight:synthetic:swap-authorization:v3';
const EVALUATED_AT = new Date((fixture.testClock.checkedAt + 100) * 1000).toISOString();
const STATUS = Object.freeze({
  checked_at: new Date(fixture.testClock.checkedAt * 1000).toISOString(),
  expires_at: new Date((fixture.testClock.checkedAt + 250) * 1000).toISOString(),
  revocation_checked: true,
  revoked: false,
  consumed: false,
  unavailable: false,
});
const ADAPTER_CONFIG = Object.freeze({
  '@version': 'INSIGHT-AEB-EVM-SWAP-ADAPTER-CONFIG-v1',
  evidence_role: ROLE,
  subject_kind: 'human',
});
const authoritySigner = privateKeyToAccount(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
);

const ACTION_DEFINITION = Object.freeze({
  '@version': PROFILE_VERSION,
  source: 'insight-oracle-safety-check-v3+swap-authorization-v2',
  source_media_type: 'application/json',
  projection: 'exact-executable-swap-and-bound-oracle-checks-v1',
  action_type: ACTION_TYPE,
  suite: 'jcs-sha256',
  definitions: [
    {
      action_type: ACTION_TYPE,
      required_fields: [
        { name: 'action_type', type: 'string' },
        { name: 'subject_chain_id', type: 'amount-string' },
        { name: 'execution_domain', type: 'string' },
        { name: 'spending_wallet', type: 'string' },
        { name: 'router', type: 'string' },
        { name: 'calldata', type: 'string' },
        { name: 'native_value', type: 'amount-string' },
        { name: 'source_asset_id', type: 'string' },
        { name: 'destination_asset_id', type: 'string' },
        { name: 'raw_input_amount', type: 'amount-string' },
        { name: 'minimum_output_amount', type: 'amount-string' },
        { name: 'recipient', type: 'string' },
        { name: 'deadline', type: 'amount-string' },
        { name: 'nonce', type: 'string' },
        { name: 'router_call', type: 'object' },
      ],
      optional_fields: [],
    },
  ],
});

function sha256Bytes(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

async function resignAuthorization(artifact) {
  const data = artifact.authorization.data;
  const typedData = {
    domain: AUTHORIZATION_DOMAIN,
    types: AUTHORIZATION_TYPES,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    message: {
      ...data,
      authorizationVersion: BigInt(data.authorizationVersion),
      subjectChainId: BigInt(data.subjectChainId),
      nativeValue: BigInt(data.nativeValue),
      rawInputAmount: BigInt(data.rawInputAmount),
      minimumOutputAmount: BigInt(data.minimumOutputAmount),
      deadline: BigInt(data.deadline),
    },
  };
  artifact.authorization.uid = hashTypedData(typedData);
  artifact.authorization.signature = await authoritySigner.signTypedData(typedData);
}

function registryEntry(id, kind, version, definition) {
  const entry = { kind, version, status: 'active', definition };
  entry.definition_digest = contract.registryEntryDigest(id, entry);
  return entry;
}

function makeContext() {
  const artifact = structuredClone({
    authorization: fixture.authorization,
    sourceCheck: fixture.sourceCheck,
    destinationCheck: fixture.destinationCheck,
    profile: fixture.nativeProfile,
  });
  const expectedAction = structuredClone(fixture.expectedAction);
  const caidResult = caidReference.computeCaid(expectedAction, {
    suite: 'jcs-sha256',
    definitions: ACTION_DEFINITION.definitions,
  });
  assert.ok(!('refusals' in caidResult), `pinned CAID refused: ${JSON.stringify(caidResult)}`);

  const profile = {
    version: PROFILE_VERSION,
    definition: ACTION_DEFINITION,
    registry_entry_ref: `mapping:${PROFILE_ID}`,
    mapper_id: MAPPER_ID,
    resolver: {
      id: MAPPER_ID,
      version: ADAPTER_VERSION,
      implementation_digest: sha256Bytes(adapterBytes),
    },
    semantic_equivalence: {
      assertion: 'EQUIVALENT_UNDER_PROFILE',
      loss_policy: 'NO_MATERIAL_FIELD_LOSS',
      omitted_material_fields: [],
      omitted_nonmaterial_fields: [],
    },
  };
  profile.profile_digest = contract.mappingProfileDigest(PROFILE_ID, profile);

  const entries = {
    [`mapping:${PROFILE_ID}`]: registryEntry(`mapping:${PROFILE_ID}`, 'mapping-profile', '1', {
      profile_digest: profile.profile_digest,
    }),
    [`role:${ROLE}`]: registryEntry(`role:${ROLE}`, 'evidence-role', '1', {
      role: ROLE,
      subject_kinds: ['human'],
    }),
  };
  const registry = {
    '@version': 'EP-EVIDENCE-REGISTRY-v1',
    registry_id: 'registry:insight-aeb-synthetic-review',
    epoch: 1,
    entries,
  };
  registry.registry_digest = contract.unifiedRegistryDigest(registry);

  const pin = {
    version: ADAPTER_VERSION,
    trust_roots: [structuredClone(fixture.trust)],
    config: structuredClone(ADAPTER_CONFIG),
    max_status_age_sec: 300,
  };
  pin.config_digest = contract.adapterPinDigest(ADAPTER_ID, pin);

  const evaluator = crypto.generateKeyPairSync('ed25519');
  const evaluatorKeyId = 'eval:insight-aeb-synthetic-review';
  const config = {
    '@version': 'AEB-ADAPTER-v1',
    relying_party_id: 'rp:insight-emilia-synthetic-review',
    evaluator_keys: {
      [evaluatorKeyId]: {
        public_key: evaluator.publicKey
          .export({ type: 'spki', format: 'der' })
          .toString('base64url'),
      },
    },
    registry,
    accepted_mappers: [MAPPER_ID],
    adapters: { [ADAPTER_ID]: pin },
    profiles: { [PROFILE_ID]: profile },
    requirements: {
      [REQUIREMENT_REF]: {
        '@version': 'AEB-REQUIREMENT-v1',
        all_of: [ROLE],
        terms: [{ type: 'one-time-consumption' }],
      },
    },
  };
  return {
    artifact,
    expectedAction,
    caid: caidResult.caid,
    actionDigest: caidResult.digest,
    profile,
    config,
    evaluator,
    evaluatorKeyId,
  };
}

function adapterInput(context, overrides = {}) {
  return {
    artifact: context.artifact,
    artifact_ref: ARTIFACT_REF,
    status: STATUS,
    trust_roots: context.config.adapters[ADAPTER_ID].trust_roots,
    adapter_config: ADAPTER_CONFIG,
    expected_action: context.expectedAction,
    now: EVALUATED_AT,
    ...overrides,
  };
}

function evaluate(context, expectedAction = context.expectedAction) {
  return contract.evaluateAebEvidence({
    config: context.config,
    adapters: { [ADAPTER_ID]: insightAebAdapter },
    operation_id: 'operation:insight-synthetic-swap-001',
    consumption_nonce: 'nonce:insight-synthetic-swap-001',
    initiator_id: 'agent:insight-synthetic-caller',
    executor_id: 'executor:insight-synthetic-crossing',
    requirement_ref: REQUIREMENT_REF,
    caid: context.caid,
    expected_action: expectedAction,
    legs: [
      {
        adapter_id: ADAPTER_ID,
        profile_id: PROFILE_ID,
        artifact_ref: ARTIFACT_REF,
        artifact: context.artifact,
        status: STATUS,
      },
    ],
    evaluated_at: EVALUATED_AT,
    signer: { key_id: context.evaluatorKeyId, private_key: context.evaluator.privateKey },
  });
}

async function testPinnedNativeShapeAndActualDigests() {
  const context = makeContext();
  const input = adapterInput(context);
  const native = insightAebAdapter.verifyNative(input);
  assert.equal(native.native_verification, 'VERIFIED');
  assert.equal(native.acceptance, 'ACCEPTED');
  assert.deepEqual(Object.keys(native), [
    'native_verification',
    'acceptance',
    'evidence_digest',
    'status_digest',
    'evidence_role',
    'subject',
    'replay_unit',
    'reasons',
  ]);
  assert.deepEqual(Object.keys(native.subject), ['id', 'kind']);
  assert.equal(native.subject.kind, 'human');
  assert.equal(native.evidence_digest, contract.digestAeb(context.artifact));
  assert.equal(
    native.status_digest,
    contract.digestAeb({
      checked_at: STATUS.checked_at,
      expires_at: STATUS.expires_at,
      revocation_checked: STATUS.revocation_checked,
      revoked: STATUS.revoked,
      consumed: STATUS.consumed,
      unavailable: false,
    })
  );
  const mapping = insightAebAdapter.mapAction({
    ...input,
    profile: context.profile,
    native,
  });
  assert.equal(mapping.mapping, 'MATCH', JSON.stringify(mapping));
  assert.equal(mapping.caid, context.caid);
  assert.equal(mapping.action_digest, context.actionDigest);
  assert.equal(mapping.action_digest, contract.digestAeb(context.expectedAction));
  return 'native fields, {id, kind}, artifact/status digests, MATCH, CAID and action digest match the pin';
}

async function testPinnedEvaluatorAndVerifierAccept() {
  const context = makeContext();
  const evaluated = evaluate(context);
  assert.equal(evaluated.valid, true, JSON.stringify(evaluated.reasons));
  assert.equal(evaluated.record.verdict, 'SATISFIED');
  assert.equal(evaluated.record.legs[0].native_verification, 'VERIFIED');
  assert.equal(evaluated.record.legs[0].mapping, 'MATCH');
  assert.equal(evaluated.record.legs[0].action_digest, context.actionDigest);
  const verified = contract.verifyAebEvaluation(evaluated.record, {
    config: context.config,
    adapters: { [ADAPTER_ID]: insightAebAdapter },
    artifacts: { [ARTIFACT_REF]: context.artifact },
    mode: 'execution',
    expected_action: context.expectedAction,
    current_statuses: { [ARTIFACT_REF]: STATUS },
    now: EVALUATED_AT,
  });
  assert.equal(verified.valid, true, JSON.stringify(verified.reasons));
  assert.equal(verified.execution_authorizing, true);
  assert.deepEqual(verified.checks, {
    schema: true,
    signature: true,
    pinned_config: true,
    rederived: true,
    current_status: true,
    verdict: true,
  });
  return 'evaluateAebEvidence and verifyAebEvaluation both accept and rederive the exact record';
}

async function testExpectedActionMismatchIsPinnedMismatch() {
  const context = makeContext();
  const changed = structuredClone(context.expectedAction);
  changed.minimum_output_amount = (BigInt(changed.minimum_output_amount) + 1n).toString();
  const evaluated = evaluate(context, changed);
  assert.equal(evaluated.valid, false);
  assert.equal(evaluated.record.verdict, 'UNSATISFIED');
  assert.equal(evaluated.record.legs[0].mapping, 'MISMATCH');
  return 'a material expected Action Object substitution produces MISMATCH and UNSATISFIED';
}

async function testArtifactAndStatusRebindingRefused() {
  const context = makeContext();
  const evaluated = evaluate(context);
  assert.equal(evaluated.valid, true);

  const tamperedArtifact = structuredClone(context.artifact);
  tamperedArtifact.authorization.label = 'tampered wrapper field';
  const artifactVerification = contract.verifyAebEvaluation(evaluated.record, {
    config: context.config,
    adapters: { [ADAPTER_ID]: insightAebAdapter },
    artifacts: { [ARTIFACT_REF]: tamperedArtifact },
    mode: 'execution',
    expected_action: context.expectedAction,
    current_statuses: { [ARTIFACT_REF]: STATUS },
    now: EVALUATED_AT,
  });
  assert.equal(artifactVerification.valid, false);
  assert.ok(artifactVerification.reasons.includes('evaluation_not_rederivable'));

  const revokedStatus = { ...STATUS, revoked: true };
  const statusVerification = contract.verifyAebEvaluation(evaluated.record, {
    config: context.config,
    adapters: { [ADAPTER_ID]: insightAebAdapter },
    artifacts: { [ARTIFACT_REF]: context.artifact },
    mode: 'execution',
    expected_action: context.expectedAction,
    current_statuses: { [ARTIFACT_REF]: revokedStatus },
    now: EVALUATED_AT,
  });
  assert.equal(statusVerification.valid, false);
  assert.equal(statusVerification.checks.current_status, false);
  return 'the pinned verifier refuses substituted actual artifact and current supplied status';
}

async function testSummariesCannotBypassAdapterState() {
  const context = makeContext();
  const forgedSummary = {
    native_verification: 'VERIFIED',
    acceptance: 'ACCEPTED',
    evidence_digest: contract.digestAeb(context.artifact),
    status_digest: contract.digestAeb(STATUS),
    evidence_role: ROLE,
    subject: { id: 'human:forged', kind: 'human' },
    replay_unit: contract.digestAeb({ forged: true }),
    reasons: [],
  };
  const mapping = insightAebAdapter.mapAction({
    ...adapterInput(context),
    profile: context.profile,
    native: forgedSummary,
  });
  assert.equal(mapping.mapping, 'INDETERMINATE');
  assert.deepEqual(mapping.reasons, ['insight:native_verification_required']);
  return 'a caller-supplied VERIFIED summary cannot stand in for actual native verification';
}

async function testMalformedRegistryDatesFailClosedThroughPinnedInput() {
  for (const value of ['not-a-date', '2040-02-30T00:00:00.000Z', '2040-01-01']) {
    const context = makeContext();
    const trustRoots = structuredClone(context.config.adapters[ADAPTER_ID].trust_roots);
    trustRoots[0].priceKeyRegistry.public_keys[0].validUntil = value;
    const native = insightAebAdapter.verifyNative(
      adapterInput(context, { trust_roots: trustRoots })
    );
    assert.equal(native.native_verification, 'FAILED', value);
    assert.equal(native.acceptance, 'REJECTED', value);
    assert.ok(
      native.reasons.some((reason) => reason.startsWith('ORACLE_KEY_INVALID:')),
      value
    );
  }
  return 'malformed and impossible registry validity dates return native FAILED/REJECTED';
}

async function testNativeFailureAndMappingVocabulary() {
  const context = makeContext();
  const artifact = structuredClone(context.artifact);
  artifact.authorization.signature = `0x${'00'.repeat(65)}`;
  const native = insightAebAdapter.verifyNative(adapterInput(context, { artifact }));
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');

  const accepted = insightAebAdapter.verifyNative(adapterInput(context));
  const changed = structuredClone(context.expectedAction);
  changed.router_call.recipient = '0x0000000000000000000000000000000000000001';
  const mapping = insightAebAdapter.mapAction({
    ...adapterInput(context),
    expected_action: changed,
    profile: context.profile,
    native: accepted,
  });
  assert.equal(mapping.mapping, 'MISMATCH');
  return 'native failure is FAILED and a concrete projection mismatch is MISMATCH';
}

async function testEvaluatorAndExecuteCrossingReturnTheSameCaid() {
  const context = makeContext();
  const evaluated = evaluate(context);
  assert.equal(evaluated.valid, true, JSON.stringify(evaluated.reasons));

  let submittedAction;
  const executed = await executeCrossing({
    bundle: context.artifact,
    config: fixture.trust,
    expectedAction: context.expectedAction,
    store: new InMemoryReservationStore(),
    submitter: async (action) => {
      submittedAction = action;
      return { status: 'COMMITTED', providerReference: 'synthetic-provider-ref' };
    },
    authenticateProviderResult: async (providerResult) =>
      providerResult.providerReference === 'synthetic-provider-ref',
    admissionNowSeconds: fixture.testClock.checkedAt + 100,
    submissionNowSeconds: fixture.testClock.checkedAt + 101,
  });
  assert.equal(executed.decision, 'SUBMITTED');
  assert.equal(executed.caid, evaluated.record.legs[0].caid);
  assert.equal(executed.actionDigest, evaluated.record.legs[0].action_digest);
  assert.deepEqual(submittedAction, context.expectedAction);
  return 'the AEB evaluator, executeCrossing, and submitter share one Action Object and CAID';
}

async function testCorrectlySignedUnsupportedAuthorizationVersionIsRefused() {
  const context = makeContext();
  context.artifact.authorization.data.authorizationVersion = 999;
  await resignAuthorization(context.artifact);

  const native = insightAebAdapter.verifyNative(adapterInput(context));
  assert.equal(native.native_verification, 'FAILED');
  assert.equal(native.acceptance, 'REJECTED');
  assert.ok(
    native.reasons.some((reason) =>
      reason.startsWith('UNSUPPORTED_AUTHORIZATION_VERSION:')
    )
  );
  const evaluated = evaluate(context);
  assert.equal(evaluated.valid, false);
  assert.equal(evaluated.record.verdict, 'UNSATISFIED');
  assert.notEqual(evaluated.record.legs[0].mapping, 'MATCH');
  return 'the current evaluator refuses a correctly signed authorizationVersion=999';
}

const tests = [
  testPinnedNativeShapeAndActualDigests,
  testPinnedEvaluatorAndVerifierAccept,
  testExpectedActionMismatchIsPinnedMismatch,
  testArtifactAndStatusRebindingRefused,
  testSummariesCannotBypassAdapterState,
  testMalformedRegistryDatesFailClosedThroughPinnedInput,
  testNativeFailureAndMappingVocabulary,
  testEvaluatorAndExecuteCrossingReturnTheSameCaid,
  testCorrectlySignedUnsupportedAuthorizationVersionIsRefused,
];

for (const test of tests) {
  const detail = await test();
  console.log(`PASS ${test.name}: ${detail}`);
}
console.log(`PASS ${tests.length}/${tests.length} pinned AEB/CAID acceptance tests`);
