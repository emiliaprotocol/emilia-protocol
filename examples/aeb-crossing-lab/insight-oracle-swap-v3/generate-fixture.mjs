// SPDX-License-Identifier: Apache-2.0
// @ts-nocheck -- deterministic fixture generator consumes external package shapes.

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  concat,
  encodeAbiParameters,
  encodeFunctionData,
  hashTypedData,
  keccak256,
  toBytes,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { V3_DOMAIN, V3_PRIMARY_TYPE, V3_TYPES } from 'verify-insight-receipt';
import {
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_TYPES,
  ACTION_TYPE,
  EXACT_INPUT_SINGLE_ABI,
  computeProfileDigest,
} from './adapter-src.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const profile = JSON.parse(await readFile(join(here, 'authorization-profile.json'), 'utf8'));
const profileDigest = computeProfileDigest(profile);

// Public Anvil test keys only. They must never hold value or enter production trust roots.
const priceSigner = privateKeyToAccount(
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
);
const authoritySigner = privateKeyToAccount(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
);

const CHECKED_AT = 2_000_000_000;
const CHECK_VALID_UNTIL = CHECKED_AT + 600;
const AUTHORIZATION_DEADLINE = CHECKED_AT + 500;
const WETH = 'eip155:1/erc20:0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
const USDC = 'eip155:1/erc20:0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const WETH_ADDRESS = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
const USDC_ADDRESS = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const ROUTER = '0xe592427a0aece92de3edee1f18e0157c05861564';
const RECIPIENT = '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC';
const SPENDING_WALLET = authoritySigner.address;
const EXECUTION_DOMAIN = 'eip155:1';
const RAW_INPUT_AMOUNT = 1_000_000_000_000_000_000n;
const MINIMUM_OUTPUT_AMOUNT = 3_400_000_000n;

const requestDomain = {
  name: 'Insight Canonical Pre-Trade Request',
  version: '1',
  chainId: 1,
};
const requestTypes = {
  CanonicalPreTradeRequest: [
    { name: 'subjectChainId', type: 'uint256' },
    { name: 'sourceAssetId', type: 'string' },
    { name: 'destinationAssetId', type: 'string' },
    { name: 'action', type: 'string' },
    { name: 'tradeAmountUsd', type: 'uint256' },
  ],
};

const entryAbi = [
  { name: 'provider', type: 'string' },
  { name: 'feedId', type: 'string' },
  { name: 'value', type: 'uint256' },
  { name: 'timestamp', type: 'uint256' },
  { name: 'dataAgeSeconds', type: 'uint256' },
  { name: 'included', type: 'bool' },
  { name: 'exclusionReason', type: 'string' },
];

function providerObservationsHash(observations) {
  const hashes = observations
    .map((entry) =>
      keccak256(
        encodeAbiParameters(entryAbi, [
          entry.provider,
          entry.feedId,
          BigInt(entry.value),
          BigInt(entry.timestamp),
          BigInt(entry.dataAgeSeconds),
          entry.included,
          entry.exclusionReason,
        ])
      )
    )
    .sort();
  return keccak256(concat(hashes));
}

async function signedCheck(role, sourceAssetId, destinationAssetId, price, observations) {
  const included = observations.filter((entry) => entry.included);
  const prices = included.map((entry) => Number(entry.value));
  const maxPrice = Math.max(...prices);
  const minPrice = Math.min(...prices);
  const agreementBps =
    maxPrice > 0 ? Math.round((1 - (maxPrice - minPrice) / maxPrice) * 10_000) : 10_000;
  const maxDataAgeSeconds = Math.max(...included.map((entry) => Number(entry.dataAgeSeconds)));
  const requestHash = hashTypedData({
    domain: requestDomain,
    types: requestTypes,
    primaryType: 'CanonicalPreTradeRequest',
    message: {
      subjectChainId: 1n,
      sourceAssetId,
      destinationAssetId,
      action: 'swap',
      tradeAmountUsd: 3_500_000_000n,
    },
  });
  const message = {
    verdict: 'PASS',
    sourceAssetId,
    destinationAssetId,
    subjectChainId: 1n,
    action: 'swap',
    tradeAmountUsd: 3_500_000_000n,
    consensusPrice: BigInt(price),
    maxDeviationBps: 25n,
    manipulationRiskBps: 100n,
    participantCount: BigInt(included.length),
    requiredParticipantCount: 3n,
    coverageStatus: 'SUFFICIENT',
    independenceStatus: 'ASSESSED',
    sourceGroupCount: 3n,
    crossProviderAgreementBps: BigInt(agreementBps),
    maxStablecoinDepegBps: 0n,
    maxDataAgeSeconds: BigInt(maxDataAgeSeconds),
    recommendedMaxPositionUsd: 10_000_000_000n,
    reasonCodesHash: keccak256(toBytes('PASS')),
    requestHash,
    evaluationScope: 'SOURCE_ASSET_ONLY',
    evaluatedAssetIdsHash: keccak256(
      encodeAbiParameters([{ type: 'string[]', name: 'assetIds' }], [[sourceAssetId]])
    ),
    providerObservationsHash: providerObservationsHash(observations),
    validUntil: BigInt(CHECK_VALID_UNTIL),
    checkedAt: BigInt(CHECKED_AT),
    schemaVersion: 3n,
    requiredSourceGroupCount: 2n,
  };
  const args = {
    domain: V3_DOMAIN,
    types: V3_TYPES,
    primaryType: V3_PRIMARY_TYPE,
    message,
  };
  const uid = hashTypedData(args);
  const signature = await priceSigner.signTypedData(args);
  return {
    role,
    observations,
    uid,
    schemaVersion: 3,
    attester: priceSigner.address,
    attesterLabel: 'PUBLIC ANVIL TEST KEY — NONPRODUCTION',
    signedAt: new Date(CHECKED_AT * 1000).toISOString(),
    validForSeconds: 600,
    validUntil: CHECK_VALID_UNTIL,
    signature,
    data: Object.fromEntries(
      Object.entries(message).map(([key, value]) => [
        key,
        typeof value === 'bigint' ? Number(value) : value,
      ])
    ),
    eip712: { domain: V3_DOMAIN, types: V3_TYPES, primaryType: V3_PRIMARY_TYPE },
  };
}

const sourceObservations = [
  {
    provider: 'chainlink',
    feedId: 'synthetic:weth-usd:chainlink',
    value: '350000000000',
    timestamp: String(CHECKED_AT - 8),
    dataAgeSeconds: '8',
    included: true,
    exclusionReason: '',
  },
  {
    provider: 'pyth',
    feedId: 'synthetic:weth-usd:pyth',
    value: '350050000000',
    timestamp: String(CHECKED_AT - 10),
    dataAgeSeconds: '10',
    included: true,
    exclusionReason: '',
  },
  {
    provider: 'api3',
    feedId: 'synthetic:weth-usd:api3',
    value: '349980000000',
    timestamp: String(CHECKED_AT - 12),
    dataAgeSeconds: '12',
    included: true,
    exclusionReason: '',
  },
];
const destinationObservations = [
  {
    provider: 'chainlink',
    feedId: 'synthetic:usdc-usd:chainlink',
    value: '100000000',
    timestamp: String(CHECKED_AT - 7),
    dataAgeSeconds: '7',
    included: true,
    exclusionReason: '',
  },
  {
    provider: 'pyth',
    feedId: 'synthetic:usdc-usd:pyth',
    value: '99990000',
    timestamp: String(CHECKED_AT - 9),
    dataAgeSeconds: '9',
    included: true,
    exclusionReason: '',
  },
  {
    provider: 'api3',
    feedId: 'synthetic:usdc-usd:api3',
    value: '100010000',
    timestamp: String(CHECKED_AT - 11),
    dataAgeSeconds: '11',
    included: true,
    exclusionReason: '',
  },
];

const sourceCheck = await signedCheck('source', WETH, USDC, '350000000000', sourceObservations);
const destinationCheck = await signedCheck(
  'destination',
  USDC,
  WETH,
  '100000000',
  destinationObservations
);
const alternateDestinationCheck = await signedCheck(
  'destination',
  USDC,
  WETH,
  '100000000',
  destinationObservations.map((entry, index) =>
    index === 2 ? { ...entry, feedId: `${entry.feedId}:alternate-valid-check` } : entry
  )
);

const calldata = encodeFunctionData({
  abi: EXACT_INPUT_SINGLE_ABI,
  functionName: 'exactInputSingle',
  args: [
    {
      tokenIn: WETH_ADDRESS,
      tokenOut: USDC_ADDRESS,
      fee: 3000,
      recipient: RECIPIENT,
      deadline: BigInt(AUTHORIZATION_DEADLINE),
      amountIn: RAW_INPUT_AMOUNT,
      amountOutMinimum: MINIMUM_OUTPUT_AMOUNT,
      sqrtPriceLimitX96: 0n,
    },
  ],
});

const nonce = keccak256(toBytes('emilia-option2-nonproduction-action-1'));
const actionData = {
  authorizationVersion: 2,
  subjectChainId: 1,
  executionDomain: EXECUTION_DOMAIN,
  spendingWallet: SPENDING_WALLET,
  router: ROUTER,
  calldataHash: keccak256(calldata),
  nativeValue: '0',
  sourceAssetId: WETH,
  destinationAssetId: USDC,
  rawInputAmount: RAW_INPUT_AMOUNT.toString(),
  minimumOutputAmount: MINIMUM_OUTPUT_AMOUNT.toString(),
  recipient: RECIPIENT,
  deadline: AUTHORIZATION_DEADLINE,
  nonce,
  sourceCheckUid: sourceCheck.uid,
  destinationCheckUid: destinationCheck.uid,
  mappingProfileDigest: profileDigest,
};
const authorizationArgs = {
  domain: AUTHORIZATION_DOMAIN,
  types: AUTHORIZATION_TYPES,
  primaryType: AUTHORIZATION_PRIMARY_TYPE,
  message: {
    ...actionData,
    authorizationVersion: 2n,
    subjectChainId: 1n,
    nativeValue: 0n,
    rawInputAmount: RAW_INPUT_AMOUNT,
    minimumOutputAmount: MINIMUM_OUTPUT_AMOUNT,
    deadline: BigInt(AUTHORIZATION_DEADLINE),
  },
};
const authorization = {
  uid: hashTypedData(authorizationArgs),
  authority: authoritySigner.address,
  label: 'PUBLIC ANVIL TEST AUTHORITY — NONPRODUCTION',
  signedAt: new Date(CHECKED_AT * 1000).toISOString(),
  signature: await authoritySigner.signTypedData(authorizationArgs),
  data: actionData,
  eip712: {
    domain: AUTHORIZATION_DOMAIN,
    types: AUTHORIZATION_TYPES,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
  },
};

const fixture = {
  schema: 'INSIGHT-EMILIA-AEB-OPTION2-FIXTURE-v2',
  classification: 'NONPRODUCTION_SYNTHETIC',
  warning:
    'Public Anvil test keys and a synthetic calldata example. Never use these keys or this authorization for value-bearing execution.',
  reviewBase: 'b03dcde235d19c898d06b02c2544cf4db891765d',
  generatedAt: '2033-05-18T03:33:20.000Z',
  nativeProfile: profile,
  testClock: {
    checkedAt: CHECKED_AT,
    relyingPartyMaximumCheckAgeSeconds: 300,
    maximumFutureClockSkewSeconds: 0,
    receiptValidUntil: CHECK_VALID_UNTIL,
    authorizationDeadline: AUTHORIZATION_DEADLINE,
  },
  trust: {
    expectedAuthority: authoritySigner.address,
    expectedSpendingWallet: SPENDING_WALLET,
    expectedExecutionDomain: EXECUTION_DOMAIN,
    expectedAebReviewBase: profile.aebReviewBase,
    expectedProfileDigest: profileDigest,
    expectedPriceKeyRole: 'sample',
    maximumCheckAgeSeconds: profile.acceptancePolicy.maximumCheckAgeSeconds,
    maximumFutureClockSkewSeconds: profile.acceptancePolicy.maximumFutureClockSkewSeconds,
    minimumParticipantCount: 3,
    minimumSourceGroupCount: 3,
    operatorGroupByProvider: {
      chainlink: 'chainlink-labs',
      pyth: 'pyth-data-association',
      api3: 'api3-dao',
    },
    priceKeyRegistry: {
      schema_version: 1,
      generated_at: new Date(CHECKED_AT * 1000).toISOString(),
      public_keys: [
        {
          key_id: 'public-anvil-account-0-sample-only',
          public_key: priceSigner.address,
          algorithm: 'EIP-712/secp256k1',
          validFrom: '2020-01-01T00:00:00.000Z',
          validUntil: '2040-01-01T00:00:00.000Z',
          revoked: false,
          role: 'sample',
          note: 'Public Anvil key; nonproduction fixtures only.',
        },
      ],
      revoked_keys: [],
    },
  },
  profileDigest,
  executionAction: {
    subjectChainId: 1,
    executionDomain: EXECUTION_DOMAIN,
    spendingWallet: SPENDING_WALLET,
    router: ROUTER,
    calldata,
    nativeValue: '0',
    sourceAssetId: WETH,
    destinationAssetId: USDC,
    rawInputAmount: RAW_INPUT_AMOUNT.toString(),
    minimumOutputAmount: MINIMUM_OUTPUT_AMOUNT.toString(),
    recipient: RECIPIENT,
    deadline: AUTHORIZATION_DEADLINE,
    nonce,
  },
  expectedAction: {
    action_type: ACTION_TYPE,
    subject_chain_id: '1',
    execution_domain: EXECUTION_DOMAIN,
    spending_wallet: SPENDING_WALLET.toLowerCase(),
    router: ROUTER.toLowerCase(),
    calldata: calldata.toLowerCase(),
    native_value: '0',
    source_asset_id: WETH,
    destination_asset_id: USDC,
    raw_input_amount: RAW_INPUT_AMOUNT.toString(),
    minimum_output_amount: MINIMUM_OUTPUT_AMOUNT.toString(),
    recipient: RECIPIENT.toLowerCase(),
    deadline: String(AUTHORIZATION_DEADLINE),
    nonce: nonce.toLowerCase(),
    router_call: {
      function: 'exactInputSingle',
      token_in: WETH_ADDRESS,
      token_out: USDC_ADDRESS,
      fee: '3000',
      recipient: RECIPIENT.toLowerCase(),
      deadline: String(AUTHORIZATION_DEADLINE),
      amount_in: RAW_INPUT_AMOUNT.toString(),
      amount_out_minimum: MINIMUM_OUTPUT_AMOUNT.toString(),
      sqrt_price_limit_x96: '0',
    },
  },
  sourceCheck,
  destinationCheck,
  hostileFixtures: {
    alternateValidDestinationCheck: alternateDestinationCheck,
    purpose:
      'Cryptographically valid and action-compatible, but not the exact destination check UID bound by the authorization.',
  },
  authorization,
  executionClaimScope: {
    transaction: 'SYNTHETIC_NOT_SUBMITTED',
    included: false,
    inclusionEvidence: null,
    finality: 'NOT_OBSERVED',
    finalityEvidence: null,
  },
};

await writeFile(
  join(here, 'signed-nonproduction-fixture.json'),
  `${JSON.stringify(fixture, null, 2)}\n`
);
console.log(`wrote signed-nonproduction-fixture.json`);
console.log(`sourceCheckUid=${sourceCheck.uid}`);
console.log(`destinationCheckUid=${destinationCheck.uid}`);
console.log(`authorizationUid=${authorization.uid}`);
console.log(`profileDigest=${profileDigest}`);
