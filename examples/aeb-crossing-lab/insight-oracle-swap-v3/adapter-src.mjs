// SPDX-License-Identifier: Apache-2.0
// @ts-nocheck -- standalone adapter source is validated by deterministic runtime tests.

import {
  V3_DOMAIN,
  V3_PRIMARY_TYPE,
  V3_TYPES,
  canonicalizeJcs,
  secp256k1,
  toV3Message,
} from './bundle-primitives.mjs';
import {
  concat,
  decodeFunctionData,
  encodeAbiParameters,
  hashTypedData,
  isAddress,
  keccak256,
  sha256,
  toBytes,
  toHex,
} from './bundle-primitives.mjs';

export const ADAPTER_ID = 'native:insight-oracle-swap-authorization';
export const ADAPTER_VERSION = '1.0.0';
export const ACTION_TYPE = 'evm-swap-exact-input-single.1';
export const MAPPER_ID = 'mapper:insight-evm-swap-exact-input-single.1';

export const AUTHORIZATION_DOMAIN = {
  name: 'Insight AEB Swap Action Authorization',
  version: '2',
  chainId: 1,
};

export const AUTHORIZATION_PRIMARY_TYPE = 'SwapActionAuthorization';

export const AUTHORIZATION_TYPES = {
  SwapActionAuthorization: [
    { name: 'authorizationVersion', type: 'uint256' },
    { name: 'subjectChainId', type: 'uint256' },
    { name: 'executionDomain', type: 'string' },
    { name: 'spendingWallet', type: 'address' },
    { name: 'router', type: 'address' },
    { name: 'calldataHash', type: 'bytes32' },
    { name: 'nativeValue', type: 'uint256' },
    { name: 'sourceAssetId', type: 'string' },
    { name: 'destinationAssetId', type: 'string' },
    { name: 'rawInputAmount', type: 'uint256' },
    { name: 'minimumOutputAmount', type: 'uint256' },
    { name: 'recipient', type: 'address' },
    { name: 'deadline', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
    { name: 'sourceCheckUid', type: 'bytes32' },
    { name: 'destinationCheckUid', type: 'bytes32' },
    { name: 'mappingProfileDigest', type: 'bytes32' },
  ],
};

export const EXACT_INPUT_SINGLE_ABI = [
  {
    type: 'function',
    name: 'exactInputSingle',
    stateMutability: 'payable',
    inputs: [
      {
        name: 'params',
        type: 'tuple',
        components: [
          { name: 'tokenIn', type: 'address' },
          { name: 'tokenOut', type: 'address' },
          { name: 'fee', type: 'uint24' },
          { name: 'recipient', type: 'address' },
          { name: 'deadline', type: 'uint256' },
          { name: 'amountIn', type: 'uint256' },
          { name: 'amountOutMinimum', type: 'uint256' },
          { name: 'sqrtPriceLimitX96', type: 'uint160' },
        ],
      },
    ],
    outputs: [{ name: 'amountOut', type: 'uint256' }],
  },
];

const PINNED_ACTION_KEYS = [
  'action_type',
  'calldata',
  'deadline',
  'destination_asset_id',
  'execution_domain',
  'minimum_output_amount',
  'native_value',
  'nonce',
  'raw_input_amount',
  'recipient',
  'router',
  'router_call',
  'source_asset_id',
  'spending_wallet',
  'subject_chain_id',
];

const OBSERVATION_ENTRY_ABI = [
  { name: 'provider', type: 'string' },
  { name: 'feedId', type: 'string' },
  { name: 'value', type: 'uint256' },
  { name: 'timestamp', type: 'uint256' },
  { name: 'dataAgeSeconds', type: 'uint256' },
  { name: 'included', type: 'bool' },
  { name: 'exclusionReason', type: 'string' },
];

const CANONICAL_REQUEST_DOMAIN = {
  name: 'Insight Canonical Pre-Trade Request',
  version: '1',
  chainId: 1,
};

const CANONICAL_REQUEST_TYPES = {
  CanonicalPreTradeRequest: [
    { name: 'subjectChainId', type: 'uint256' },
    { name: 'sourceAssetId', type: 'string' },
    { name: 'destinationAssetId', type: 'string' },
    { name: 'action', type: 'string' },
    { name: 'tradeAmountUsd', type: 'uint256' },
  ],
};

const verifiedInternals = new WeakMap();
const pinnedAdapterInternals = new WeakMap();

const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

function parseRfc3339Ms(value) {
  if (typeof value !== 'string') return Number.NaN;
  const match = value.match(RFC3339_RE);
  if (!match) return Number.NaN;
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const milliseconds = Number(fraction.padEnd(3, '0'));
  const date = new Date(0);
  date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  date.setUTCHours(Number(hour), Number(minute), Number(second), milliseconds);
  if (date.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`)
    return Number.NaN;
  return date.getTime();
}

function normalizeAddress(value) {
  return typeof value === 'string' ? value.toLowerCase() : value;
}

function normalizeUint(value, field = 'uint256') {
  if (typeof value === 'bigint' && value >= 0n) return value.toString(10);
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value).toString(10);
  }
  if (typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value)) {
    return BigInt(value).toString(10);
  }
  throw new Error(`${field} is not a canonical uint256`);
}

function toSafeTimestamp(value, field) {
  const normalized = normalizeUint(value, field);
  const number = Number(normalized);
  if (!Number.isSafeInteger(number)) throw new Error(`${field} exceeds safe timestamp range`);
  return number;
}

function jcs(value) {
  const serialized = canonicalizeJcs(value);
  if (typeof serialized !== 'string') throw new Error('JCS serialization failed');
  return serialized;
}

function sha256PrefixedBytes(bytes) {
  return `sha256:${sha256(bytes).slice(2)}`;
}

function sha256PrefixedText(value) {
  return sha256PrefixedBytes(toBytes(value));
}

function sha256PrefixedJcs(value) {
  return sha256PrefixedText(jcs(value));
}

export function digestAeb(value) {
  return sha256PrefixedJcs(value);
}

function base64urlSha256Jcs(value) {
  const hex = sha256(toBytes(jcs(value))).slice(2);
  return Buffer.from(hex, 'hex').toString('base64url');
}

export function computeProfileDigest(profile) {
  return keccak256(toBytes(jcs(profile)));
}

function authorizationMessage(data) {
  return {
    authorizationVersion: BigInt(normalizeUint(data.authorizationVersion, 'authorizationVersion')),
    subjectChainId: BigInt(normalizeUint(data.subjectChainId, 'subjectChainId')),
    executionDomain: data.executionDomain,
    spendingWallet: data.spendingWallet,
    router: data.router,
    calldataHash: data.calldataHash,
    nativeValue: BigInt(normalizeUint(data.nativeValue, 'nativeValue')),
    sourceAssetId: data.sourceAssetId,
    destinationAssetId: data.destinationAssetId,
    rawInputAmount: BigInt(normalizeUint(data.rawInputAmount, 'rawInputAmount')),
    minimumOutputAmount: BigInt(normalizeUint(data.minimumOutputAmount, 'minimumOutputAmount')),
    recipient: data.recipient,
    deadline: BigInt(normalizeUint(data.deadline, 'deadline')),
    nonce: data.nonce,
    sourceCheckUid: data.sourceCheckUid,
    destinationCheckUid: data.destinationCheckUid,
    mappingProfileDigest: data.mappingProfileDigest,
  };
}

function authorizationTypedData(data) {
  return {
    domain: AUTHORIZATION_DOMAIN,
    types: AUTHORIZATION_TYPES,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    message: authorizationMessage(data),
  };
}

function recoverSigner(hash, signature) {
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error('signature must be a 65-byte hex value');
  }
  const recoveryValue = Number(`0x${signature.slice(130)}`);
  const recoveryBit = recoveryValue >= 27 ? recoveryValue - 27 : recoveryValue;
  if (recoveryBit !== 0 && recoveryBit !== 1) throw new Error('invalid signature recovery bit');
  const point = secp256k1.Signature.fromCompact(signature.slice(2, 130))
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(hash.slice(2))
    .toBytes(false);
  return `0x${keccak256(toHex(point.slice(1))).slice(-40)}`;
}

function findRegistryKey(registry, address) {
  const keys = registry?.public_keys ?? registry?.keys ?? [];
  return keys.find((entry) => normalizeAddress(entry.public_key) === normalizeAddress(address));
}

function registryKeyIsValid(entry, checkedAt, registry) {
  if (!entry || entry.revoked) return false;
  const revoked = registry?.revoked_keys ?? registry?.revoked ?? [];
  if (revoked.some((candidate) => candidate?.key_id === entry.key_id)) return false;
  const from = parseRfc3339Ms(entry.validFrom ?? entry.valid_from);
  const until = parseRfc3339Ms(entry.validUntil ?? entry.valid_until);
  const at = checkedAt * 1000;
  return (
    Number.isFinite(from) && Number.isFinite(until) && from < until && at >= from && at <= until
  );
}

function nativeResult({
  acceptance,
  code,
  reason,
  evidenceDigest = null,
  statusDigest,
  subject = null,
  replayUnit = null,
  internal,
}) {
  const result = {
    native_verification: acceptance === 'ACCEPTED' ? 'VERIFIED' : 'FAILED',
    acceptance,
    evidence_digest: evidenceDigest,
    status_digest: statusDigest ?? sha256PrefixedJcs({ acceptance, code, reason: reason ?? null }),
    evidence_role: 'ACTION_AUTHORIZATION',
    subject,
    replay_unit: replayUnit,
    reasons: reason ? [`${code}:${reason}`] : [],
  };
  Object.defineProperties(result, {
    ok: { value: acceptance === 'ACCEPTED', enumerable: false },
    code: { value: code, enumerable: false },
    reason: { value: reason, enumerable: false },
  });
  if (internal) verifiedInternals.set(result, internal);
  return result;
}

function failNative(code, reason, context = {}) {
  return nativeResult({ acceptance: 'REJECTED', code, reason, ...context });
}

function mappingResult({ mapping, code, reason, caid = null, actionDigest = null, internal }) {
  const result = {
    mapping,
    caid,
    action_digest: actionDigest,
    reasons: reason ? [`${code}:${reason}`] : [],
  };
  Object.defineProperties(result, {
    ok: { value: mapping === 'MATCH', enumerable: false },
    code: { value: code, enumerable: false },
    reason: { value: reason, enumerable: false },
  });
  if (internal) {
    for (const [key, value] of Object.entries(internal)) {
      Object.defineProperty(result, key, { value, enumerable: false });
    }
  }
  return result;
}

function computeObservationHash(observations) {
  const hashes = observations
    .map((entry) =>
      keccak256(
        encodeAbiParameters(OBSERVATION_ENTRY_ABI, [
          entry.provider,
          entry.feedId,
          BigInt(normalizeUint(entry.value, 'observation.value')),
          BigInt(normalizeUint(entry.timestamp, 'observation.timestamp')),
          BigInt(normalizeUint(entry.dataAgeSeconds, 'observation.dataAgeSeconds')),
          entry.included,
          entry.exclusionReason,
        ])
      )
    )
    .sort();
  return keccak256(concat(hashes));
}

function roundedAgreementBps(prices) {
  const maximum = prices.reduce((a, b) => (a > b ? a : b));
  const minimum = prices.reduce((a, b) => (a < b ? a : b));
  if (maximum === 0n) return 10_000n;
  const numerator = minimum * 10_000n;
  return (numerator + maximum / 2n) / maximum;
}

function verifyCheckPreimages(check, config) {
  const observations = check.observations;
  if (!Array.isArray(observations) || observations.length === 0)
    return { code: 'OBSERVATIONS_MISSING', reason: 'provider observations are required' };
  if (computeObservationHash(observations) !== check.data.providerObservationsHash)
    return {
      code: 'OBSERVATIONS_HASH_MISMATCH',
      reason: 'observations do not open the signed hash',
    };

  const included = observations.filter((entry) => entry.included);
  const includedProviders = new Set(included.map((entry) => entry.provider));
  if (includedProviders.size !== included.length)
    return { code: 'DUPLICATE_PROVIDER', reason: 'included providers must be distinct' };
  if (included.length !== Number(check.data.participantCount))
    return { code: 'PARTICIPANT_COUNT_MISMATCH', reason: 'observations do not match signed count' };
  const pinnedMinimumParticipants = Number(config.minimumParticipantCount);
  const signedRequiredParticipants = Number(check.data.requiredParticipantCount);
  if (
    !Number.isSafeInteger(pinnedMinimumParticipants) ||
    included.length < pinnedMinimumParticipants ||
    included.length < signedRequiredParticipants
  ) {
    return {
      code: 'PARTICIPANT_QUORUM_DEFICIENT',
      reason: 'included observations do not meet signed and relying-party participant minima',
    };
  }

  const prices = included.map((entry) => BigInt(normalizeUint(entry.value, 'observation.value')));
  if (roundedAgreementBps(prices) !== BigInt(check.data.crossProviderAgreementBps))
    return { code: 'AGREEMENT_MISMATCH', reason: 'observations do not match signed agreement' };
  const maxDataAgeSeconds = included
    .map((entry) => BigInt(normalizeUint(entry.dataAgeSeconds, 'observation.dataAgeSeconds')))
    .reduce((a, b) => (a > b ? a : b));
  if (maxDataAgeSeconds !== BigInt(check.data.maxDataAgeSeconds))
    return {
      code: 'DATA_AGE_MISMATCH',
      reason: 'observations do not match signed maximum data age',
    };

  const operatorGroups = new Set();
  for (const entry of included) {
    const group = config.operatorGroupByProvider?.[entry.provider];
    if (typeof group !== 'string' || group.length === 0)
      return {
        code: 'UNPINNED_PROVIDER_OPERATOR',
        reason: `no relying-party operator group is pinned for ${entry.provider}`,
      };
    operatorGroups.add(group);
  }
  const signedGroupCount = Number(check.data.sourceGroupCount);
  const signedRequiredGroups = Number(check.data.requiredSourceGroupCount);
  const pinnedRequiredGroups = Number(config.minimumSourceGroupCount);
  if (operatorGroups.size !== signedGroupCount)
    return {
      code: 'SOURCE_GROUP_COUNT_MISMATCH',
      reason: 'independently recomputed operator groups do not match the signed count',
    };
  if (
    !Number.isSafeInteger(pinnedRequiredGroups) ||
    operatorGroups.size < signedRequiredGroups ||
    operatorGroups.size < pinnedRequiredGroups
  ) {
    return {
      code: 'OPERATOR_INDEPENDENCE_DEFICIENT',
      reason: 'operator groups do not meet signed and relying-party independence minima',
    };
  }

  const requestHash = hashTypedData({
    domain: CANONICAL_REQUEST_DOMAIN,
    types: CANONICAL_REQUEST_TYPES,
    primaryType: 'CanonicalPreTradeRequest',
    message: {
      subjectChainId: BigInt(check.data.subjectChainId),
      sourceAssetId: check.data.sourceAssetId,
      destinationAssetId: check.data.destinationAssetId,
      action: check.data.action,
      tradeAmountUsd: BigInt(check.data.tradeAmountUsd),
    },
  });
  if (requestHash !== check.data.requestHash)
    return {
      code: 'REQUEST_HASH_MISMATCH',
      reason: 'check fields do not open the signed request hash',
    };
  const evaluatedAssetIdsHash = keccak256(
    encodeAbiParameters([{ type: 'string[]', name: 'assetIds' }], [[check.data.sourceAssetId]])
  );
  if (evaluatedAssetIdsHash !== check.data.evaluatedAssetIdsHash)
    return {
      code: 'EVALUATED_ASSETS_HASH_MISMATCH',
      reason: 'evaluated asset does not open the signed hash',
    };
  return null;
}

function verifyFreshness(check, nowSeconds, profile, config) {
  const checkedAt = toSafeTimestamp(check?.data?.checkedAt, 'checkedAt');
  const validUntil = toSafeTimestamp(check?.data?.validUntil, 'validUntil');
  if (validUntil < checkedAt)
    return { code: 'ORACLE_WINDOW_INVALID', reason: 'validUntil precedes checkedAt' };
  const maximumAge = Number(profile.acceptancePolicy.maximumCheckAgeSeconds);
  const maximumSkew = Number(profile.acceptancePolicy.maximumFutureClockSkewSeconds);
  if (
    config.maximumCheckAgeSeconds !== maximumAge ||
    config.maximumFutureClockSkewSeconds !== maximumSkew
  ) {
    return {
      code: 'FRESHNESS_POLICY_CONFLICT',
      reason: 'runtime freshness policy differs from the independently pinned profile',
    };
  }
  if (checkedAt > nowSeconds + maximumSkew)
    return { code: 'ORACLE_CHECK_FUTURE_DATED', reason: 'checkedAt is after verifier time' };
  if (nowSeconds > validUntil || nowSeconds - checkedAt > maximumAge)
    return { code: 'ORACLE_CHECK_STALE', reason: 'check is stale at this decision point' };
  return null;
}

function checkCommonBinding(check, actionData, role) {
  const data = check.data;
  if (
    normalizeUint(data.subjectChainId) !== normalizeUint(actionData.subjectChainId) ||
    data.action !== 'swap'
  )
    return false;
  if (role === 'source')
    return (
      data.sourceAssetId === actionData.sourceAssetId &&
      data.destinationAssetId === actionData.destinationAssetId
    );
  return (
    data.sourceAssetId === actionData.destinationAssetId &&
    data.destinationAssetId === actionData.sourceAssetId
  );
}

function verifySignedCheck(check, config, nowSeconds, profile, role) {
  if (check?.schemaVersion !== 3)
    return { code: 'ORACLE_SCHEMA_REJECTED', reason: `${role} check must use schema v3` };
  const args = {
    domain: V3_DOMAIN,
    types: V3_TYPES,
    primaryType: V3_PRIMARY_TYPE,
    message: toV3Message(check.data ?? {}),
  };
  const expectedUid = hashTypedData(args);
  if (expectedUid !== check.uid)
    return { code: 'ORACLE_CHECK_UID_MISMATCH', reason: `${role} check data changed` };
  if (
    !isAddress(check.attester) ||
    recoverSigner(expectedUid, check.signature) !== normalizeAddress(check.attester)
  )
    return { code: 'ORACLE_CHECK_SIGNATURE_INVALID', reason: `${role} signature is invalid` };
  const registryKey = findRegistryKey(config.priceKeyRegistry, check.attester);
  const checkedAt = toSafeTimestamp(check.data.checkedAt, 'checkedAt');
  if (!registryKeyIsValid(registryKey, checkedAt, config.priceKeyRegistry))
    return { code: 'ORACLE_KEY_INVALID', reason: `${role} key is not valid at checkedAt` };
  if (registryKey.role !== config.expectedPriceKeyRole)
    return { code: 'ORACLE_KEY_ROLE_REJECTED', reason: `${role} key role is not accepted` };
  if (check.data.verdict !== 'PASS')
    return { code: 'NON_PASS_ORACLE_CHECK', reason: `${role} verdict is not PASS` };
  return verifyCheckPreimages(check, config) ?? verifyFreshness(check, nowSeconds, profile, config);
}

function deriveReplayUnit(authorizationUid) {
  return sha256PrefixedText(`emilia:aeb:replay-unit:v1\0${authorizationUid}`);
}

export function verifyNative(bundle, config, nowSeconds) {
  try {
    const { authorization, sourceCheck, destinationCheck, profile } = bundle ?? {};
    if (!authorization || !sourceCheck || !destinationCheck || !profile)
      return failNative('MALFORMED_BUNDLE', 'authorization, both checks, and profile are required');
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0)
      return failNative('INVALID_VERIFIER_TIME', 'nowSeconds must be a nonnegative safe integer');

    const profileDigest = computeProfileDigest(profile);
    if (profileDigest !== config.expectedProfileDigest)
      return failNative('UNPINNED_PROFILE', 'profile does not match the relying-party pin');
    if (profileDigest !== authorization.data.mappingProfileDigest)
      return failNative('PROFILE_DIGEST_MISMATCH', 'authorization does not bind this profile');
    if (profile.aebReviewBase !== config.expectedAebReviewBase)
      return failNative(
        'AEB_SOURCE_PIN_MISMATCH',
        'profile does not match the relying-party AEB source pin'
      );

    const authArgs = authorizationTypedData(authorization.data);
    const expectedAuthorizationUid = hashTypedData(authArgs);
    const replayUnit = deriveReplayUnit(authorization.uid);
    const subject = `${authorization.data.executionDomain}:${normalizeAddress(authorization.data.spendingWallet)}`;
    if (normalizeUint(authorization.data.authorizationVersion, 'authorizationVersion') !== '2')
      return failNative(
        'UNSUPPORTED_AUTHORIZATION_VERSION',
        'only authorization version 2 is accepted',
        { replayUnit, subject }
      );
    if (expectedAuthorizationUid !== authorization.uid)
      return failNative('AUTHORIZATION_UID_MISMATCH', 'authorization data changed after signing', {
        replayUnit,
        subject,
      });
    if (!isAddress(authorization.authority) || !isAddress(authorization.data.spendingWallet))
      return failNative(
        'MALFORMED_AUTHORITY',
        'authority and spending wallet must be EVM addresses',
        { replayUnit, subject }
      );
    if (normalizeAddress(authorization.authority) !== normalizeAddress(config.expectedAuthority))
      return failNative('UNPINNED_AUTHORITY', 'authorization signer is not pinned', {
        replayUnit,
        subject,
      });
    if (
      recoverSigner(expectedAuthorizationUid, authorization.signature) !==
      normalizeAddress(authorization.authority)
    )
      return failNative('AUTHORIZATION_SIGNATURE_INVALID', 'authorization signature is invalid', {
        replayUnit,
        subject,
      });
    if (
      normalizeAddress(authorization.data.spendingWallet) !==
      normalizeAddress(config.expectedSpendingWallet)
    )
      return failNative('SPENDING_WALLET_MISMATCH', 'spending wallet is not the pinned wallet', {
        replayUnit,
        subject,
      });
    if (authorization.data.executionDomain !== config.expectedExecutionDomain)
      return failNative('EXECUTION_DOMAIN_MISMATCH', 'execution domain is not pinned', {
        replayUnit,
        subject,
      });
    if (
      authorization.data.executionDomain !==
      `eip155:${normalizeUint(authorization.data.subjectChainId)}`
    )
      return failNative(
        'EXECUTION_DOMAIN_CHAIN_MISMATCH',
        'execution domain disagrees with chain',
        { replayUnit, subject }
      );
    if (toSafeTimestamp(authorization.data.deadline, 'deadline') < nowSeconds)
      return failNative('AUTHORIZATION_EXPIRED', 'action authorization deadline has passed', {
        replayUnit,
        subject,
      });

    for (const [role, check] of [
      ['source', sourceCheck],
      ['destination', destinationCheck],
    ]) {
      const invalid = verifySignedCheck(check, config, nowSeconds, profile, role);
      if (invalid) return failNative(invalid.code, invalid.reason, { replayUnit, subject });
      if (!checkCommonBinding(check, authorization.data, role))
        return failNative('ORACLE_CHECK_ACTION_MISMATCH', `${role} check mismatches action pair`, {
          replayUnit,
          subject,
        });
    }
    if (
      authorization.data.sourceCheckUid !== sourceCheck.uid ||
      authorization.data.destinationCheckUid !== destinationCheck.uid
    )
      return failNative('BOUND_CHECK_MISMATCH', 'authorization does not bind these exact checks', {
        replayUnit,
        subject,
      });

    const evidenceBinding = {
      authorization_uid: authorization.uid,
      destination_check_uid: destinationCheck.uid,
      mapping_profile_digest: profileDigest,
      source_check_uid: sourceCheck.uid,
    };
    const evidenceDigest = sha256PrefixedJcs(evidenceBinding);
    const statusDigest = sha256PrefixedJcs({
      acceptance: 'ACCEPTED',
      evidence_digest: evidenceDigest,
      subject,
    });
    return nativeResult({
      acceptance: 'ACCEPTED',
      code: 'VERIFIED',
      evidenceDigest,
      statusDigest,
      subject,
      replayUnit,
      internal: {
        authorizationData: structuredClone(authorization.data),
        authorizationUid: authorization.uid,
        profile: structuredClone(profile),
        profileDigest,
      },
    });
  } catch (error) {
    return failNative('MALFORMED_BUNDLE', error instanceof Error ? error.message : String(error));
  }
}

function missingMaterialFields(expectedAction) {
  return PINNED_ACTION_KEYS.filter(
    (field) => !Object.prototype.hasOwnProperty.call(expectedAction ?? {}, field)
  );
}

function normalizeExpectedAction(expectedAction) {
  return {
    subjectChainId: normalizeUint(expectedAction.subjectChainId, 'subjectChainId'),
    executionDomain: expectedAction.executionDomain,
    spendingWallet: normalizeAddress(expectedAction.spendingWallet),
    router: normalizeAddress(expectedAction.router),
    calldataHash: keccak256(expectedAction.calldata),
    nativeValue: normalizeUint(expectedAction.nativeValue, 'nativeValue'),
    sourceAssetId: expectedAction.sourceAssetId,
    destinationAssetId: expectedAction.destinationAssetId,
    rawInputAmount: normalizeUint(expectedAction.rawInputAmount, 'rawInputAmount'),
    minimumOutputAmount: normalizeUint(expectedAction.minimumOutputAmount, 'minimumOutputAmount'),
    recipient: normalizeAddress(expectedAction.recipient),
    deadline: normalizeUint(expectedAction.deadline, 'deadline'),
    nonce: expectedAction.nonce,
  };
}

function normalizeAuthorizationAction(data) {
  return {
    subjectChainId: normalizeUint(data.subjectChainId, 'subjectChainId'),
    executionDomain: data.executionDomain,
    spendingWallet: normalizeAddress(data.spendingWallet),
    router: normalizeAddress(data.router),
    calldataHash: data.calldataHash,
    nativeValue: normalizeUint(data.nativeValue, 'nativeValue'),
    sourceAssetId: data.sourceAssetId,
    destinationAssetId: data.destinationAssetId,
    rawInputAmount: normalizeUint(data.rawInputAmount, 'rawInputAmount'),
    minimumOutputAmount: normalizeUint(data.minimumOutputAmount, 'minimumOutputAmount'),
    recipient: normalizeAddress(data.recipient),
    deadline: normalizeUint(data.deadline, 'deadline'),
    nonce: data.nonce,
  };
}

function parseErc20AssetId(assetId) {
  const match = /^eip155:(0|[1-9]\d*)\/erc20:(0x[0-9a-fA-F]{40})$/.exec(assetId ?? '');
  if (!match) throw new Error(`unsupported asset identifier: ${String(assetId)}`);
  return { chainId: normalizeUint(match[1]), token: normalizeAddress(match[2]) };
}

function decodeAndCheckRouterCall(expectedAction, profile) {
  if (!profile.routerSemantics?.supportedRouters?.includes(normalizeAddress(expectedAction.router)))
    return { code: 'UNSUPPORTED_ROUTER', reason: 'router is not pinned by this profile' };
  const decoded = decodeFunctionData({
    abi: EXACT_INPUT_SINGLE_ABI,
    data: expectedAction.calldata,
  });
  if (decoded.functionName !== 'exactInputSingle' || !decoded.args?.[0])
    return { code: 'UNSUPPORTED_ROUTER_CALL', reason: 'calldata is not exactInputSingle' };
  const params = decoded.args[0];
  const source = parseErc20AssetId(expectedAction.sourceAssetId);
  const destination = parseErc20AssetId(expectedAction.destinationAssetId);
  const semanticMismatches = [];
  if (source.chainId !== normalizeUint(expectedAction.subjectChainId))
    semanticMismatches.push('sourceAssetId.chainId');
  if (destination.chainId !== normalizeUint(expectedAction.subjectChainId))
    semanticMismatches.push('destinationAssetId.chainId');
  if (normalizeAddress(params.tokenIn) !== source.token)
    semanticMismatches.push('tokenIn/sourceAssetId');
  if (normalizeAddress(params.tokenOut) !== destination.token)
    semanticMismatches.push('tokenOut/destinationAssetId');
  if (normalizeAddress(params.recipient) !== normalizeAddress(expectedAction.recipient))
    semanticMismatches.push('recipient');
  if (normalizeUint(params.amountIn) !== normalizeUint(expectedAction.rawInputAmount))
    semanticMismatches.push('amountIn/rawInputAmount');
  if (normalizeUint(params.amountOutMinimum) !== normalizeUint(expectedAction.minimumOutputAmount))
    semanticMismatches.push('amountOutMinimum/minimumOutputAmount');
  if (normalizeUint(params.deadline) !== normalizeUint(expectedAction.deadline))
    semanticMismatches.push('deadline');
  if (normalizeUint(expectedAction.nativeValue) !== profile.routerSemantics.requiredNativeValue)
    semanticMismatches.push('nativeValue');
  if (semanticMismatches.length > 0)
    return {
      code: 'ROUTER_CALL_SEMANTIC_MISMATCH',
      reason: `decoded router call mismatch: ${semanticMismatches.join(', ')}`,
      semanticMismatches,
    };
  return {
    params: {
      amount_in: normalizeUint(params.amountIn),
      amount_out_minimum: normalizeUint(params.amountOutMinimum),
      deadline: normalizeUint(params.deadline),
      fee: normalizeUint(params.fee),
      function: 'exactInputSingle',
      recipient: normalizeAddress(params.recipient),
      sqrt_price_limit_x96: normalizeUint(params.sqrtPriceLimitX96),
      token_in: normalizeAddress(params.tokenIn),
      token_out: normalizeAddress(params.tokenOut),
    },
  };
}

export function mapAction(verified, expectedAction) {
  const internal = verifiedInternals.get(verified);
  if (!internal || verified.acceptance !== 'ACCEPTED')
    return mappingResult({
      mapping: 'INDETERMINATE',
      code: 'NATIVE_NOT_VERIFIED',
      reason: 'verifyNative must accept before mapping',
    });
  try {
    const missing = missingMaterialFields(expectedAction);
    if (missing.length > 0)
      return mappingResult({
        mapping: 'MISMATCH',
        code: 'STOP_NOT_EXACT_ACTION_BOUND',
        reason: `expected action is missing material fields: ${missing.join(', ')}`,
        internal: { missingMaterialFields: missing },
      });
    const actionObject = structuredClone(expectedAction);
    const executionAction = typedActionToExecutionAction(actionObject);
    const expected = normalizeExpectedAction(executionAction);
    const authorized = normalizeAuthorizationAction(internal.authorizationData);
    const mismatches = Object.keys(expected).filter(
      (field) => expected[field] !== authorized[field]
    );
    if (mismatches.length > 0)
      return mappingResult({
        mapping: 'MISMATCH',
        code: 'NOT_EQUIVALENT',
        reason: `material field mismatch: ${mismatches.join(', ')}`,
        internal: { mismatches },
      });

    const decoded = decodeAndCheckRouterCall(executionAction, internal.profile);
    if (decoded.code)
      return mappingResult({
        mapping: decoded.code.startsWith('UNSUPPORTED') ? 'INDETERMINATE' : 'MISMATCH',
        code: decoded.code,
        reason: decoded.reason,
        internal: { semanticMismatches: decoded.semanticMismatches ?? [] },
      });

    if (jcs(decoded.params) !== jcs(actionObject.router_call))
      return mappingResult({
        mapping: 'MISMATCH',
        code: 'ROUTER_CALL_PROJECTION_MISMATCH',
        reason: 'expected action router_call differs from decoded calldata',
      });
    const actionDigest = sha256PrefixedJcs(actionObject);
    const caid = `caid:1:${internal.profile.mappingOutput.versionedActionType}:jcs-sha256:${base64urlSha256Jcs(actionObject)}`;
    return mappingResult({
      mapping: 'MATCH',
      code: 'MATCH',
      caid,
      actionDigest,
      internal: { actionObject },
    });
  } catch (error) {
    return mappingResult({
      mapping: 'INDETERMINATE',
      code: 'MALFORMED_ACTION',
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

function exactObjectKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    Object.keys(value).every((key) => keys.includes(key))
  );
}

function normalizedStatus(status) {
  return {
    checked_at: status?.checked_at,
    expires_at: status?.expires_at,
    revocation_checked: status?.revocation_checked,
    revoked: status?.revoked,
    consumed: status?.consumed,
    unavailable: status?.unavailable === true,
  };
}

function validateSuppliedStatus(status, now) {
  const normalized = normalizedStatus(status);
  const checkedAt = parseRfc3339Ms(normalized.checked_at);
  const expiresAt = parseRfc3339Ms(normalized.expires_at);
  const nowMs = parseRfc3339Ms(now);
  if (
    !Number.isFinite(checkedAt) ||
    !Number.isFinite(expiresAt) ||
    !Number.isFinite(nowMs) ||
    checkedAt >= expiresAt
  ) {
    return { acceptance: 'REJECTED', reason: 'aeb_status_time_invalid' };
  }
  if (normalized.unavailable || normalized.revocation_checked !== true)
    return {
      acceptance: 'INDETERMINATE',
      reason: normalized.unavailable ? 'aeb_status_unavailable' : 'aeb_status_not_authenticated',
    };
  if (normalized.revoked || normalized.consumed)
    return {
      acceptance: 'REJECTED',
      reason: normalized.revoked ? 'aeb_status_revoked' : 'aeb_status_consumed',
    };
  if (checkedAt > nowMs || nowMs >= expiresAt)
    return { acceptance: 'REJECTED', reason: 'aeb_status_outside_validity' };
  return null;
}

function pinnedSubject(artifact, adapterConfig) {
  const authority = normalizeAddress(artifact?.authorization?.authority);
  const chainId = normalizeUint(artifact?.authorization?.data?.subjectChainId, 'subjectChainId');
  const kind = adapterConfig?.subject_kind;
  if (!isAddress(authority) || !['human', 'workload', 'organization', 'system'].includes(kind))
    throw new Error('pinned subject cannot be derived');
  return { id: `did:pkh:eip155:${chainId}:${authority}`, kind };
}

function pinnedFallback(input, reason, acceptance = 'REJECTED') {
  let evidenceDigest;
  let statusDigest;
  try {
    evidenceDigest = digestAeb(input?.artifact ?? null);
  } catch {
    evidenceDigest = digestAeb(null);
  }
  try {
    statusDigest = digestAeb(normalizedStatus(input?.status));
  } catch {
    statusDigest = digestAeb(normalizedStatus(null));
  }
  let subject = { id: 'system:insight-aeb-unresolved', kind: 'system' };
  try {
    subject = pinnedSubject(input?.artifact, input?.adapter_config);
  } catch {
    // Keep the closed fallback subject.
  }
  return {
    native_verification: 'FAILED',
    acceptance,
    evidence_digest: evidenceDigest,
    status_digest: statusDigest,
    evidence_role: input?.adapter_config?.evidence_role ?? 'action-authorization',
    subject,
    replay_unit: digestAeb({
      adapter_id: ADAPTER_ID,
      artifact: input?.artifact ?? null,
    }),
    reasons: [reason],
  };
}

function typedActionToExecutionAction(action) {
  if (!exactObjectKeys(action, PINNED_ACTION_KEYS) || action.action_type !== ACTION_TYPE)
    throw new Error(
      'expected_action must use the exact closed evm-swap-exact-input-single.1 schema'
    );
  if (
    !exactObjectKeys(action.router_call, [
      'amount_in',
      'amount_out_minimum',
      'deadline',
      'fee',
      'function',
      'recipient',
      'sqrt_price_limit_x96',
      'token_in',
      'token_out',
    ])
  )
    throw new Error('expected_action.router_call has an invalid shape');
  return {
    subjectChainId: normalizeUint(action.subject_chain_id, 'subject_chain_id'),
    executionDomain: action.execution_domain,
    spendingWallet: action.spending_wallet,
    router: action.router,
    calldata: action.calldata,
    nativeValue: normalizeUint(action.native_value, 'native_value'),
    sourceAssetId: action.source_asset_id,
    destinationAssetId: action.destination_asset_id,
    rawInputAmount: normalizeUint(action.raw_input_amount, 'raw_input_amount'),
    minimumOutputAmount: normalizeUint(action.minimum_output_amount, 'minimum_output_amount'),
    recipient: action.recipient,
    deadline: normalizeUint(action.deadline, 'deadline'),
    nonce: action.nonce,
  };
}

function profileSupportsPinnedAction(profile) {
  return (
    profile?.definition?.action_type === ACTION_TYPE &&
    profile?.definition?.suite === 'jcs-sha256' &&
    profile?.mapper_id === MAPPER_ID &&
    profile?.semantic_equivalence?.assertion === 'EQUIVALENT_UNDER_PROFILE' &&
    profile?.semantic_equivalence?.loss_policy === 'NO_MATERIAL_FIELD_LOSS' &&
    Array.isArray(profile?.semantic_equivalence?.omitted_material_fields) &&
    profile.semantic_equivalence.omitted_material_fields.length === 0
  );
}

function pinnedVerifyNative(input) {
  let fallback;
  try {
    fallback = pinnedFallback(input, 'insight:authorization_unverified');
    if (!input || typeof input !== 'object') return fallback;
    if (!Array.isArray(input.trust_roots) || input.trust_roots.length !== 1) {
      fallback.reasons = ['insight:trust_roots_invalid'];
      return fallback;
    }
    if (
      input.adapter_config?.['@version'] !== 'INSIGHT-AEB-EVM-SWAP-ADAPTER-CONFIG-v1' ||
      input.adapter_config?.evidence_role !== 'action-authorization' ||
      !['human', 'workload', 'organization', 'system'].includes(input.adapter_config?.subject_kind)
    ) {
      fallback.reasons = ['insight:adapter_config_invalid'];
      return fallback;
    }
    const statusIssue = validateSuppliedStatus(input.status, input.now);
    const nowMs = parseRfc3339Ms(input.now);
    if (!Number.isFinite(nowMs)) {
      fallback.reasons = ['insight:verifier_time_invalid'];
      return fallback;
    }
    const legacy = verifyNative(input.artifact, input.trust_roots[0], Math.floor(nowMs / 1000));
    const result = {
      native_verification: legacy.native_verification,
      acceptance: legacy.acceptance,
      evidence_digest: digestAeb(input.artifact),
      status_digest: digestAeb(normalizedStatus(input.status)),
      evidence_role: input.adapter_config.evidence_role,
      subject: pinnedSubject(input.artifact, input.adapter_config),
      replay_unit: legacy.replay_unit,
      reasons: [...legacy.reasons],
    };
    if (statusIssue) {
      result.acceptance = statusIssue.acceptance;
      if (statusIssue.acceptance === 'REJECTED') result.native_verification = 'FAILED';
      result.reasons = [statusIssue.reason];
    }
    if (result.native_verification === 'VERIFIED') {
      pinnedAdapterInternals.set(result, { legacy, profile: input.artifact.profile });
    }
    return result;
  } catch {
    return fallback ?? pinnedFallback(input, 'insight:adapter_evaluation_error');
  }
}

function pinnedMapAction(input) {
  const reverified = pinnedVerifyNative(input);
  const internal = pinnedAdapterInternals.get(reverified);
  let suppliedMatches = false;
  try {
    suppliedMatches = jcs(input?.native) === jcs(reverified);
  } catch {
    suppliedMatches = false;
  }
  if (
    !internal ||
    reverified.native_verification !== 'VERIFIED' ||
    !suppliedMatches
  ) {
    return {
      mapping: 'INDETERMINATE',
      caid: null,
      action_digest: null,
      reasons: ['insight:native_verification_required'],
    };
  }
  try {
    if (!profileSupportsPinnedAction(input.profile)) {
      return {
        mapping: 'INDETERMINATE',
        caid: null,
        action_digest: null,
        reasons: ['insight:mapping_profile_not_pinned'],
      };
    }
    const mapped = mapAction(internal.legacy, input.expected_action);
    if (mapped.mapping !== 'MATCH') {
      return {
        mapping: mapped.mapping === 'INDETERMINATE' ? 'INDETERMINATE' : 'MISMATCH',
        caid: null,
        action_digest: null,
        reasons: mapped.reasons,
      };
    }
    return {
      mapping: 'MATCH',
      caid: mapped.caid,
      action_digest: mapped.action_digest,
      reasons: [],
    };
  } catch (error) {
    return {
      mapping: 'MISMATCH',
      caid: null,
      action_digest: null,
      reasons: [`insight:${error instanceof Error ? error.message : String(error)}`],
    };
  }
}

export const insightAebAdapter = Object.freeze({
  id: ADAPTER_ID,
  version: ADAPTER_VERSION,
  verifyNative: pinnedVerifyNative,
  mapAction: pinnedMapAction,
});

export default insightAebAdapter;

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function immutableSnapshot(value) {
  return deepFreeze(structuredClone(value));
}

export class InMemoryReservationStore {
  #records = new Map();

  reserve(replayUnit) {
    if (this.#records.has(replayUnit)) throw new Error(`REPLAY_FENCED:${replayUnit}`);
    this.#records.set(replayUnit, {
      state: 'RESERVED',
      providerEntered: false,
      providerCalls: 0,
      reconciliationRequired: false,
    });
  }

  markProviderEntered(replayUnit) {
    const record = this.#required(replayUnit);
    if (record.state !== 'RESERVED' || record.providerEntered)
      throw new Error(`BAD_STATE:${record.state}`);
    record.providerEntered = true;
    record.providerCalls += 1;
  }

  releaseTerminal(replayUnit, reason) {
    const record = this.#required(replayUnit);
    if (record.state !== 'RESERVED' || record.providerEntered)
      throw new Error(`BAD_STATE:${record.state}`);
    record.state = 'RELEASED_NOT_ENTERED';
    record.reason = reason;
  }

  markReconciliationRequired(replayUnit, detail) {
    const record = this.#required(replayUnit);
    if (record.state !== 'RESERVED' || !record.providerEntered)
      throw new Error(`BAD_STATE:${record.state}`);
    record.reconciliationRequired = true;
    record.reconciliationDetail = detail;
  }

  markCommitted(replayUnit, providerResult) {
    const record = this.#required(replayUnit);
    if (record.state !== 'RESERVED' || !record.providerEntered)
      throw new Error(`BAD_STATE:${record.state}`);
    record.state = 'CONSUMED';
    record.providerResult = providerResult;
  }

  snapshot(replayUnit) {
    return structuredClone(this.#required(replayUnit));
  }
  #required(replayUnit) {
    const record = this.#records.get(replayUnit);
    if (!record) throw new Error(`UNKNOWN_RESERVATION:${replayUnit}`);
    return record;
  }
}

export async function executeCrossing({
  bundle,
  config,
  expectedAction,
  store,
  submitter,
  authenticateProviderResult,
  admissionNowSeconds,
  submissionNowSeconds,
}) {
  const bundleSnapshot = immutableSnapshot(bundle);
  const configSnapshot = immutableSnapshot(config);
  const actionSnapshot = immutableSnapshot(expectedAction);
  const admitted = verifyNative(bundleSnapshot, configSnapshot, admissionNowSeconds);
  if (admitted.acceptance !== 'ACCEPTED')
    return { decision: 'STOP', stage: 'ADMISSION', detail: admitted };
  const mapped = mapAction(admitted, actionSnapshot);
  if (mapped.mapping !== 'MATCH') return { decision: 'STOP', stage: 'MAPPING', detail: mapped };
  try {
    store.reserve(admitted.replay_unit);
  } catch (error) {
    return {
      decision: 'STOP',
      stage: 'RESERVATION',
      detail: {
        code: 'REPLAY_FENCED',
        reason: error instanceof Error ? error.message : String(error),
      },
    };
  }

  const submissionCheck = verifyNative(bundleSnapshot, configSnapshot, submissionNowSeconds);
  if (submissionCheck.acceptance !== 'ACCEPTED') {
    store.releaseTerminal(admitted.replay_unit, submissionCheck.code);
    const expired = ['ORACLE_CHECK_STALE', 'AUTHORIZATION_EXPIRED'].includes(submissionCheck.code);
    return {
      decision: expired ? 'STOP_EXPIRED_AFTER_RESERVATION' : 'STOP_AFTER_RESERVATION',
      stage: 'PRE_SUBMISSION_FRESHNESS',
      replayUnit: admitted.replay_unit,
      detail: submissionCheck,
    };
  }

  store.markProviderEntered(admitted.replay_unit);
  let providerResult;
  try {
    providerResult = await submitter(actionSnapshot);
  } catch (error) {
    const detail = {
      code: 'SUBMITTER_EXCEPTION_AFTER_ENTRY',
      message: error instanceof Error ? error.message : String(error),
      reconciliation: 'RECONCILIATION_REQUIRED',
    };
    store.markReconciliationRequired(admitted.replay_unit, detail);
    return {
      decision: 'RECONCILE',
      stage: 'SUBMITTER_EXCEPTION',
      replayUnit: admitted.replay_unit,
      detail,
    };
  }
  let authenticatedCommit = false;
  if (providerResult?.status === 'COMMITTED' && typeof authenticateProviderResult === 'function') {
    try {
      authenticatedCommit =
        (await authenticateProviderResult(providerResult, actionSnapshot)) === true;
    } catch {
      authenticatedCommit = false;
    }
  }
  if (providerResult?.status !== 'COMMITTED' || !authenticatedCommit) {
    const detail = {
      ...providerResult,
      code:
        providerResult?.status === 'COMMITTED'
          ? 'UNAUTHENTICATED_COMMITTED_RESULT'
          : 'INDETERMINATE_PROVIDER_RESULT',
      reconciliation: 'RECONCILIATION_REQUIRED',
    };
    store.markReconciliationRequired(admitted.replay_unit, detail);
    return {
      decision: 'RECONCILE',
      stage:
        providerResult?.status === 'AMBIGUOUS'
          ? 'SUBMISSION_AMBIGUOUS'
          : 'UNCLASSIFIED_PROVIDER_RESULT',
      replayUnit: admitted.replay_unit,
      detail,
    };
  }
  store.markCommitted(admitted.replay_unit, providerResult);
  return {
    decision: 'SUBMITTED',
    stage: 'PROVIDER_COMMITTED',
    replayUnit: admitted.replay_unit,
    caid: mapped.caid,
    actionDigest: mapped.action_digest,
    detail: providerResult,
  };
}
