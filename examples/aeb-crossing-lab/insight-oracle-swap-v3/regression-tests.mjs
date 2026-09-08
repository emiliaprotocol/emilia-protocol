// SPDX-License-Identifier: Apache-2.0
// @ts-nocheck -- runtime assertions are the contract for this standalone JavaScript suite.

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { encodeFunctionData, hashTypedData, keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_TYPES,
  EXACT_INPUT_SINGLE_ABI,
  InMemoryReservationStore,
  executeCrossing,
  mapAction,
  verifyNative,
} from './adapter.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const profile = JSON.parse(await readFile(join(here, 'authorization-profile.json'), 'utf8'));
const fixture = JSON.parse(await readFile(join(here, 'signed-nonproduction-fixture.json'), 'utf8'));
const make = () => ({
  bundle: structuredClone({
    profile,
    authorization: fixture.authorization,
    sourceCheck: fixture.sourceCheck,
    destinationCheck: fixture.destinationCheck,
  }),
  config: structuredClone(fixture.trust),
  expectedAction: structuredClone(fixture.expectedAction),
});
const FRESH = fixture.testClock.checkedAt + 100;
const STALE = fixture.testClock.checkedAt + 301;
const authoritySigner = privateKeyToAccount(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
);

async function resignAuthorization(bundle) {
  const message = {
    ...bundle.authorization.data,
    authorizationVersion: BigInt(bundle.authorization.data.authorizationVersion),
    subjectChainId: BigInt(bundle.authorization.data.subjectChainId),
    nativeValue: BigInt(bundle.authorization.data.nativeValue),
    rawInputAmount: BigInt(bundle.authorization.data.rawInputAmount),
    minimumOutputAmount: BigInt(bundle.authorization.data.minimumOutputAmount),
    deadline: BigInt(bundle.authorization.data.deadline),
  };
  const typedData = {
    domain: AUTHORIZATION_DOMAIN,
    types: AUTHORIZATION_TYPES,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    message,
  };
  bundle.authorization.uid = hashTypedData(typedData);
  bundle.authorization.signature = await authoritySigner.signTypedData(typedData);
}

async function testPinnedSynchronousAdapterShape() {
  const { bundle, config } = make();
  const verified = verifyNative(bundle, config, FRESH);
  assert.equal(typeof verified?.then, 'undefined');
  assert.equal(verified.acceptance, 'ACCEPTED');
  assert.deepEqual(Object.keys(verified), [
    'native_verification',
    'acceptance',
    'evidence_digest',
    'status_digest',
    'evidence_role',
    'subject',
    'replay_unit',
    'reasons',
  ]);
  assert.match(verified.evidence_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(verified.status_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(verified.replay_unit, /^sha256:[0-9a-f]{64}$/);
  const mapped = mapAction(verified, fixture.expectedAction);
  assert.deepEqual(Object.keys(mapped), ['mapping', 'caid', 'action_digest', 'reasons']);
  assert.equal(mapped.mapping, 'MATCH');
  assert.match(mapped.caid, /^caid:1:evm-swap-exact-input-single\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
  assert.match(mapped.action_digest, /^sha256:[0-9a-f]{64}$/);
  const wrapperOnlyChange = structuredClone(bundle);
  wrapperOnlyChange.authorization.label = 'wrapper metadata does not define replay identity';
  assert.equal(verifyNative(wrapperOnlyChange, config, FRESH).replay_unit, verified.replay_unit);
  const mappedAgain = mapAction(verified, structuredClone(fixture.expectedAction));
  assert.equal(mappedAgain.caid, mapped.caid);
  assert.equal(mappedAgain.action_digest, mapped.action_digest);
  return 'adapter is synchronous and exposes the pinned native/mapping fields plus CAID';
}

async function testPositivePath() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  let submitterCalls = 0;
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter: async () => {
      submitterCalls += 1;
      return {
        status: 'COMMITTED',
        providerReference: 'synthetic-provider-ref',
      };
    },
    authenticateProviderResult: async (providerResult) =>
      providerResult.providerReference === 'synthetic-provider-ref',
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(result.decision, 'SUBMITTED');
  assert.equal(submitterCalls, 1);
  assert.equal(store.snapshot(result.replayUnit).state, 'CONSUMED');
  assert.match(result.caid, /^caid:1:/);
  return 'authenticated commit drives adapter/store/submitter and consumes authority';
}

async function testExpiredAfterReservation() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  let submitterCalls = 0;
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter: async () => {
      submitterCalls += 1;
      return { status: 'COMMITTED', authenticated: true };
    },
    admissionNowSeconds: FRESH,
    submissionNowSeconds: STALE,
  });
  assert.equal(result.decision, 'STOP_EXPIRED_AFTER_RESERVATION');
  assert.equal(result.detail.code, 'ORACLE_CHECK_STALE');
  assert.equal(submitterCalls, 0);
  const reservation = store.snapshot(result.replayUnit);
  assert.equal(reservation.state, 'RELEASED_NOT_ENTERED');
  assert.equal(reservation.providerCalls, 0);
  assert.throws(() => store.reserve(result.replayUnit), /REPLAY_FENCED/);
  return 'expiry uses RELEASED_NOT_ENTERED, makes zero calls, and preserves replay fence';
}

async function testAmbiguousSubmission() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  let submitterCalls = 0;
  const submitter = async () => {
    submitterCalls += 1;
    return { status: 'AMBIGUOUS', providerReference: null };
  };
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter,
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(result.decision, 'RECONCILE');
  assert.equal(submitterCalls, 1);
  const reservation = store.snapshot(result.replayUnit);
  assert.equal(reservation.state, 'RESERVED');
  assert.equal(reservation.providerEntered, true);
  assert.equal(reservation.reconciliationRequired, true);
  const blindRetry = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter,
    admissionNowSeconds: FRESH + 2,
    submissionNowSeconds: FRESH + 3,
  });
  assert.equal(blindRetry.stage, 'RESERVATION');
  assert.equal(blindRetry.detail.code, 'REPLAY_FENCED');
  assert.equal(submitterCalls, 1);
  return 'ambiguous entry remains RESERVED, requires reconciliation, and blocks retry';
}

async function testUnboundLegacyActionStops() {
  const { bundle, config } = make();
  const verified = verifyNative(bundle, config, FRESH);
  const legacyFiveFieldAction = {
    subjectChainId: fixture.executionAction.subjectChainId,
    sourceAssetId: fixture.executionAction.sourceAssetId,
    destinationAssetId: fixture.executionAction.destinationAssetId,
    action: 'swap',
    tradeAmountUsd: 3500,
  };
  const mapped = mapAction(verified, legacyFiveFieldAction);
  assert.equal(mapped.code, 'STOP_NOT_EXACT_ACTION_BOUND');
  assert.equal(mapped.mapping, 'MISMATCH');
  assert.ok(mapped.missingMaterialFields.includes('action_type'));
  assert.ok(mapped.missingMaterialFields.includes('raw_input_amount'));
  assert.ok(mapped.missingMaterialFields.includes('minimum_output_amount'));
  return 'legacy request remains stopped for material-field loss';
}

async function testEveryExecutableFieldIsBound() {
  const { bundle, config } = make();
  const mutations = {
    subject_chain_id: '10',
    execution_domain: 'eip155:10',
    spending_wallet: '0x0000000000000000000000000000000000000003',
    router: '0x0000000000000000000000000000000000000001',
    calldata: `${fixture.expectedAction.calldata.slice(0, -2)}${
      fixture.expectedAction.calldata.endsWith('00') ? '01' : '00'
    }`,
    native_value: '1',
    source_asset_id: fixture.expectedAction.destination_asset_id,
    destination_asset_id: fixture.expectedAction.source_asset_id,
    raw_input_amount: (BigInt(fixture.expectedAction.raw_input_amount) + 1n).toString(),
    minimum_output_amount: (BigInt(fixture.expectedAction.minimum_output_amount) + 1n).toString(),
    recipient: '0x0000000000000000000000000000000000000002',
    deadline: (BigInt(fixture.expectedAction.deadline) + 1n).toString(),
    nonce: `0x${'11'.repeat(32)}`,
  };
  const mismatchNames = {
    subject_chain_id: 'subjectChainId',
    execution_domain: 'executionDomain',
    spending_wallet: 'spendingWallet',
    calldata: 'calldataHash',
    native_value: 'nativeValue',
    source_asset_id: 'sourceAssetId',
    destination_asset_id: 'destinationAssetId',
    raw_input_amount: 'rawInputAmount',
    minimum_output_amount: 'minimumOutputAmount',
  };
  const verified = verifyNative(bundle, config, FRESH);
  for (const [field, value] of Object.entries(mutations)) {
    const mapped = mapAction(verified, { ...fixture.expectedAction, [field]: value });
    assert.equal(mapped.code, 'NOT_EQUIVALENT', `${field} substitution must stop`);
    assert.equal(mapped.mapping, 'MISMATCH', `${field} substitution must be a pinned mismatch`);
    const expectedMismatch = mismatchNames[field] ?? field;
    assert.ok(mapped.mismatches.includes(expectedMismatch), `${field} mismatch must be named`);
  }
  return 'wallet, domain, all executable fields, and nonce are substitution-tested';
}

async function testExactChecksAreBound() {
  const { bundle, config } = make();
  const changed = structuredClone(bundle);
  changed.authorization.data.destinationCheckUid = changed.sourceCheck.uid;
  assert.equal(verifyNative(changed, config, FRESH).code, 'AUTHORIZATION_UID_MISMATCH');

  const substituted = structuredClone(bundle);
  substituted.destinationCheck = fixture.hostileFixtures.alternateValidDestinationCheck;
  assert.equal(verifyNative(substituted, config, FRESH).code, 'BOUND_CHECK_MISMATCH');

  const observationTamper = structuredClone(bundle);
  observationTamper.sourceCheck.observations[0].feedId = 'tampered:feed';
  assert.equal(verifyNative(observationTamper, config, FRESH).code, 'OBSERVATIONS_HASH_MISMATCH');
  return 'authorization signature, exact UIDs, and observation preimages reject substitution';
}

async function testFutureDatedChecksRefused() {
  const { bundle, config } = make();
  const result = verifyNative(bundle, config, fixture.testClock.checkedAt - 1);
  assert.equal(result.acceptance, 'REJECTED');
  assert.equal(result.code, 'ORACLE_CHECK_FUTURE_DATED');
  return 'future-dated checks are rejected using the caller-supplied deterministic clock';
}

async function testFreshnessConflictRefused() {
  const { bundle, config } = make();
  config.maximumCheckAgeSeconds = 600;
  const result = verifyNative(bundle, config, fixture.testClock.checkedAt + 350);
  assert.equal(result.acceptance, 'REJECTED');
  assert.equal(result.code, 'FRESHNESS_POLICY_CONFLICT');
  return 'runtime/profile freshness disagreement fails closed';
}

async function testImmutableActionHandoff() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  const originalReserve = store.reserve.bind(store);
  const authorizedRouter = expectedAction.router;
  store.reserve = (key) => {
    originalReserve(key);
    expectedAction.router = '0x0000000000000000000000000000000000000001';
  };
  let receivedAction;
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter: async (action) => {
      receivedAction = action;
      return { status: 'COMMITTED', providerReference: 'synthetic-provider-ref' };
    },
    authenticateProviderResult: async (providerResult) =>
      providerResult.providerReference === 'synthetic-provider-ref',
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(result.decision, 'SUBMITTED');
  assert.equal(receivedAction.router, authorizedRouter);
  assert.equal(Object.isFrozen(receivedAction), true);
  assert.notEqual(receivedAction, expectedAction);
  return 'caller mutation cannot cross the detached, frozen action handoff';
}

async function testThrowingSubmitterReturnsReconciliation() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  let calls = 0;
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter: async () => {
      calls += 1;
      throw new Error('synthetic connection reset after possible entry');
    },
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(result.decision, 'RECONCILE');
  assert.equal(result.stage, 'SUBMITTER_EXCEPTION');
  assert.equal(result.detail.reconciliation, 'RECONCILIATION_REQUIRED');
  assert.equal(calls, 1);
  const reservation = store.snapshot(result.replayUnit);
  assert.equal(reservation.state, 'RESERVED');
  assert.equal(reservation.reconciliationRequired, true);
  assert.throws(() => store.reserve(result.replayUnit), /REPLAY_FENCED/);
  return 'post-entry exception returns reconciliation while RESERVED authority stays fenced';
}

async function testRouterCalldataSemantics() {
  const { bundle, config, expectedAction } = make();
  const hostileRecipient = '0x0000000000000000000000000000000000000004';
  expectedAction.calldata = encodeFunctionData({
    abi: EXACT_INPUT_SINGLE_ABI,
    functionName: 'exactInputSingle',
    args: [
      {
        tokenIn: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
        tokenOut: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        fee: 3000,
        recipient: hostileRecipient,
        deadline: BigInt(expectedAction.deadline),
        amountIn: BigInt(expectedAction.raw_input_amount),
        amountOutMinimum: BigInt(expectedAction.minimum_output_amount),
        sqrtPriceLimitX96: 0n,
      },
    ],
  });
  bundle.authorization.data.calldataHash = keccak256(expectedAction.calldata);
  await resignAuthorization(bundle);
  const verified = verifyNative(bundle, config, FRESH);
  assert.equal(verified.acceptance, 'ACCEPTED');
  const mapped = mapAction(verified, expectedAction);
  assert.equal(mapped.mapping, 'MISMATCH');
  assert.equal(mapped.code, 'ROUTER_CALL_SEMANTIC_MISMATCH');
  assert.ok(mapped.semanticMismatches.includes('recipient'));
  return 'decoded calldata must agree with named assets, amounts, recipient, and deadline';
}

async function testProfilePinAndOperatorIndependence() {
  const { bundle, config } = make();
  const unpinned = structuredClone(config);
  unpinned.expectedProfileDigest = `0x${'00'.repeat(32)}`;
  assert.equal(verifyNative(bundle, unpinned, FRESH).code, 'UNPINNED_PROFILE');

  const grouped = structuredClone(config);
  grouped.operatorGroupByProvider = {
    chainlink: 'same-operator',
    pyth: 'same-operator',
    api3: 'same-operator',
  };
  assert.equal(verifyNative(bundle, grouped, FRESH).code, 'SOURCE_GROUP_COUNT_MISMATCH');

  const deficientQuorum = structuredClone(config);
  deficientQuorum.minimumParticipantCount = 4;
  assert.equal(verifyNative(bundle, deficientQuorum, FRESH).code, 'PARTICIPANT_QUORUM_DEFICIENT');

  const missingOperator = structuredClone(config);
  delete missingOperator.operatorGroupByProvider.api3;
  assert.equal(verifyNative(bundle, missingOperator, FRESH).code, 'UNPINNED_PROVIDER_OPERATOR');

  const revokedKey = structuredClone(config);
  revokedKey.priceKeyRegistry.revoked_keys = [
    { key_id: revokedKey.priceKeyRegistry.public_keys[0].key_id },
  ];
  assert.equal(verifyNative(bundle, revokedKey, FRESH).code, 'ORACLE_KEY_INVALID');
  return 'profile and provider/operator independence are independently relying-party pinned';
}

async function testMalformedRegistryValidityDatesFailClosed() {
  const malformedValues = [
    'not-a-date',
    '2040-02-30T00:00:00.000Z',
    '2040-01-01',
    '2040-01-01T00:00:00+00:00',
    '',
  ];
  for (const value of malformedValues) {
    const { bundle, config } = make();
    config.priceKeyRegistry.public_keys[0].validUntil = value;
    const result = verifyNative(bundle, config, FRESH);
    assert.equal(result.native_verification, 'FAILED', `${value} must fail native verification`);
    assert.equal(result.acceptance, 'REJECTED', `${value} must be rejected`);
    assert.equal(result.code, 'ORACLE_KEY_INVALID', `${value} must fail closed at the key window`);
  }

  const reversed = make();
  reversed.config.priceKeyRegistry.public_keys[0].validFrom = '2040-01-01T00:00:00.000Z';
  reversed.config.priceKeyRegistry.public_keys[0].validUntil = '2020-01-01T00:00:00.000Z';
  const result = verifyNative(reversed.bundle, reversed.config, FRESH);
  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.equal(result.code, 'ORACLE_KEY_INVALID');
  return 'malformed, non-RFC3339, impossible, missing, and reversed registry windows fail closed';
}

async function testUnauthenticatedCommitRequiresReconciliation() {
  const { bundle, config, expectedAction } = make();
  const store = new InMemoryReservationStore();
  const result = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store,
    submitter: async () => ({ status: 'COMMITTED', authenticated: true }),
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(result.decision, 'RECONCILE');
  assert.equal(result.detail.code, 'UNAUTHENTICATED_COMMITTED_RESULT');
  assert.equal(store.snapshot(result.replayUnit).state, 'RESERVED');
  return 'a bare JSON COMMITTED string cannot consume authority';
}

async function testEvaluatorAndExecuteCrossingShareActionIdentity() {
  const { bundle, config, expectedAction } = make();
  const verified = verifyNative(bundle, config, FRESH);
  const evaluated = mapAction(verified, expectedAction);
  assert.equal(evaluated.mapping, 'MATCH');

  let submittedAction;
  const executed = await executeCrossing({
    bundle,
    config,
    expectedAction,
    store: new InMemoryReservationStore(),
    submitter: async (action) => {
      submittedAction = action;
      return { status: 'COMMITTED', providerReference: 'synthetic-provider-ref' };
    },
    authenticateProviderResult: async (providerResult) =>
      providerResult.providerReference === 'synthetic-provider-ref',
    admissionNowSeconds: FRESH,
    submissionNowSeconds: FRESH + 1,
  });
  assert.equal(executed.decision, 'SUBMITTED');
  assert.equal(executed.caid, evaluated.caid);
  assert.equal(executed.actionDigest, evaluated.action_digest);
  assert.deepEqual(submittedAction, expectedAction);
  return 'evaluation, execution, and submission share one Action Object, CAID, and digest';
}

async function testAuthorizationVersion999IsRejectedAfterResigning() {
  const { bundle, config } = make();
  bundle.authorization.data.authorizationVersion = 999;
  await resignAuthorization(bundle);
  const result = verifyNative(bundle, config, FRESH);
  assert.equal(result.native_verification, 'FAILED');
  assert.equal(result.acceptance, 'REJECTED');
  assert.equal(result.code, 'UNSUPPORTED_AUTHORIZATION_VERSION');
  return 'a correctly signed authorizationVersion=999 is rejected; only version 2 is accepted';
}

const tests = [
  testPinnedSynchronousAdapterShape,
  testPositivePath,
  testExpiredAfterReservation,
  testAmbiguousSubmission,
  testUnboundLegacyActionStops,
  testEveryExecutableFieldIsBound,
  testExactChecksAreBound,
  testFutureDatedChecksRefused,
  testFreshnessConflictRefused,
  testImmutableActionHandoff,
  testThrowingSubmitterReturnsReconciliation,
  testRouterCalldataSemantics,
  testProfilePinAndOperatorIndependence,
  testMalformedRegistryValidityDatesFailClosed,
  testUnauthenticatedCommitRequiresReconciliation,
  testEvaluatorAndExecuteCrossingShareActionIdentity,
  testAuthorizationVersion999IsRejectedAfterResigning,
];

for (const test of tests) {
  const detail = await test();
  console.log(`PASS ${test.name}: ${detail}`);
}
console.log(`PASS ${tests.length}/${tests.length} crossing-lab tests`);
