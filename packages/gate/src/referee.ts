// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic, offline EMILIA Referee core.
 *
 * The referee does not discover trust roots, executables, protocols, policy,
 * or network state.  It evaluates one caller-pinned runner output as a
 * non-authorizing self-test claim and keeps native verification, relying-party
 * acceptance, binding, evidence composition, provider outcome, and observed
 * effect as independent facts.
 */

import path from 'node:path';

export const REFEREE_EVALUATION_VERSION = 'EP-REFEREE-EVALUATION-v1';
export const REFEREE_RUNNER_REQUEST_VERSION = 'EP-REFEREE-RUNNER-REQUEST-v1';
export const REFEREE_RUNNER_OUTPUT_VERSION = 'EP-REFEREE-RUNNER-OUTPUT-v1';
export const REFEREE_RESULT_VERSION = 'EP-REFEREE-RESULT-v1';

// Explicit aliases make the wire-version names easy to discover without
// changing the single canonical values used by the schemas.
export const EP_REFEREE_EVALUATION_VERSION = REFEREE_EVALUATION_VERSION;
export const EP_REFEREE_RUNNER_REQUEST_VERSION = REFEREE_RUNNER_REQUEST_VERSION;
export const EP_REFEREE_RUNNER_OUTPUT_VERSION = REFEREE_RUNNER_OUTPUT_VERSION;
export const EP_REFEREE_RESULT_VERSION = REFEREE_RESULT_VERSION;

const MAX_IDENTIFIER_BYTES = 512;
const MAX_EXECUTABLE_BYTES = 4 * 1024;
const MAX_RUNNER_ARGUMENTS = 256;
const MAX_RUNNER_ARGUMENT_BYTES = 64 * 1024;
const MAX_RUNNER_ARGUMENT_VECTOR_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REASON_CODE = /^[a-z][a-z0-9_]{0,127}$/;

const EVALUATION_KEYS = Object.freeze([
  'version', 'runner_pin', 'request', 'output',
] as const);
const RUNNER_PIN_KEYS = Object.freeze([
  'executable', 'executable_sha256', 'args',
] as const);
const RUNNER_REQUEST_KEYS = Object.freeze([
  'version', 'case_id', 'protocol_id', 'expected_caid',
  'expected_action_digest', 'aec_required', 'execution_scope', 'input',
] as const);
const RUNNER_OUTPUT_KEYS = Object.freeze([
  'version', 'case_id', 'protocol_id', 'native_verification', 'rp_acceptance',
  'caid', 'action_digest', 'aec_satisfaction', 'provider_outcome',
  'effect_relation', 'execution_scope',
] as const);

const NATIVE_VERIFICATIONS = new Set<RefereeNativeVerification>([
  'VERIFIED', 'REJECTED', 'INDETERMINATE',
]);
const RP_ACCEPTANCES = new Set<RefereeRpAcceptance>([
  'ACCEPTED', 'REJECTED', 'INDETERMINATE',
]);
const AEC_SATISFACTIONS = new Set<RefereeAecSatisfaction>([
  'SATISFIED', 'NOT_SATISFIED', 'INDETERMINATE', 'NOT_ASSESSED',
]);
const PROVIDER_OUTCOMES = new Set<RefereeProviderOutcome>([
  'COMMITTED', 'PROVEN_NOT_COMMITTED', 'INDETERMINATE', 'NOT_ASSESSED',
]);
const EFFECT_RELATIONS = new Set<RefereeEffectRelation>([
  'OBSERVED_AS_REQUESTED', 'DIVERGED', 'INDETERMINATE', 'NOT_ASSESSED',
]);
const EXECUTION_SCOPES = new Set<RefereeExecutionScope>([
  'local_atomic', 'federated',
]);

export type RefereeJson =
  | null
  | boolean
  | number
  | string
  | RefereeJson[]
  | { [key: string]: RefereeJson };

export type RefereeStatus =
  | 'CONFORMANT'
  | 'NON_CONFORMANT'
  | 'INDETERMINATE';
export type RefereeExecutionScope = 'local_atomic' | 'federated';
export type RefereeNativeVerification =
  | 'VERIFIED'
  | 'REJECTED'
  | 'INDETERMINATE';
export type RefereeRpAcceptance =
  | 'ACCEPTED'
  | 'REJECTED'
  | 'INDETERMINATE';
export type RefereeCaidActionMatch = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export type RefereeAecSatisfaction =
  | 'SATISFIED'
  | 'NOT_SATISFIED'
  | 'INDETERMINATE'
  | 'NOT_ASSESSED';
export type RefereeProviderOutcome =
  | 'COMMITTED'
  | 'PROVEN_NOT_COMMITTED'
  | 'INDETERMINATE'
  | 'NOT_ASSESSED';
export type RefereeEffectRelation =
  | 'OBSERVED_AS_REQUESTED'
  | 'DIVERGED'
  | 'INDETERMINATE'
  | 'NOT_ASSESSED';

export interface RefereeRunnerPinV1 {
  readonly executable: string;
  readonly executable_sha256: `sha256:${string}`;
  readonly args: readonly string[];
}

/** The only JSON document written to a protocol runner's stdin. */
export interface RefereeRunnerRequestV1 {
  readonly version: typeof REFEREE_RUNNER_REQUEST_VERSION;
  readonly case_id: string;
  readonly protocol_id: string;
  readonly expected_caid: string;
  readonly expected_action_digest: string;
  readonly aec_required: boolean;
  readonly execution_scope: RefereeExecutionScope;
  readonly input: RefereeJson;
}

/** The only accepted JSON document on a protocol runner's stdout. */
export interface RefereeRunnerOutputV1 {
  readonly version: typeof REFEREE_RUNNER_OUTPUT_VERSION;
  readonly case_id: string;
  readonly protocol_id: string;
  readonly native_verification: RefereeNativeVerification;
  readonly rp_acceptance: RefereeRpAcceptance;
  readonly caid: string | null;
  readonly action_digest: string | null;
  readonly aec_satisfaction: RefereeAecSatisfaction;
  readonly provider_outcome: RefereeProviderOutcome;
  readonly effect_relation: RefereeEffectRelation;
  readonly execution_scope: RefereeExecutionScope;
}

export interface RefereeEvaluationInputV1 {
  readonly version: typeof REFEREE_EVALUATION_VERSION;
  readonly runner_pin: RefereeRunnerPinV1;
  readonly request: RefereeRunnerRequestV1;
  readonly output: RefereeRunnerOutputV1;
}

export interface RefereeResultDimensionsV1 {
  readonly native_verification: Readonly<{
    value: RefereeNativeVerification;
  }>;
  readonly rp_acceptance: Readonly<{
    value: RefereeRpAcceptance;
  }>;
  readonly caid_action_match: Readonly<{
    value: RefereeCaidActionMatch;
    expected_caid: string;
    observed_caid: string | null;
    expected_action_digest: string;
    observed_action_digest: string | null;
  }>;
  readonly aec_satisfaction: Readonly<{
    required: boolean;
    value: RefereeAecSatisfaction;
  }>;
  readonly provider_outcome: Readonly<{
    value: RefereeProviderOutcome;
  }>;
  readonly effect_relation: Readonly<{
    value: RefereeEffectRelation;
  }>;
}

/**
 * A Referee result is evidence about one self-test only.  Its fixed false
 * execution_authorizing value is a semantic boundary, not configuration.
 */
export interface RefereeResultV1 {
  readonly version: typeof REFEREE_RESULT_VERSION;
  readonly status: RefereeStatus;
  readonly claim_scope: 'SELF_TEST';
  readonly execution_authorizing: false;
  readonly case_id: string;
  readonly protocol_id: string;
  readonly runner_pin: Readonly<RefereeRunnerPinV1>;
  readonly execution_scope: RefereeExecutionScope;
  readonly remote_atomicity_claimed: false;
  readonly dimensions: Readonly<RefereeResultDimensionsV1>;
  readonly reason_codes: readonly string[];
}

export interface RefereeIndeterminateInputV1 {
  readonly runner_pin: RefereeRunnerPinV1;
  readonly request: RefereeRunnerRequestV1;
  readonly reason_code: string;
}

export class RefereeValidationError extends TypeError {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = 'RefereeValidationError';
    this.code = code;
  }
}

function fail(code: string): never {
  throw new RefereeValidationError(code);
}

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject<const T extends readonly string[]>(
  value: unknown,
  keys: T,
): Record<T[number], unknown> {
  if (!plain(value)) fail('invalid_schema');
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail('unknown_key');
  const expected = new Set<string>(keys);
  for (const key of ownKeys as string[]) {
    if (!expected.has(key)) fail('unknown_key');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('invalid_schema');
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail('missing_key');
  }
  return value as Record<T[number], unknown>;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function assertJson(
  value: unknown,
  depth = 0,
  ancestors = new Set<object>(),
): asserts value is RefereeJson {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (hasUnpairedSurrogate(value)) fail('invalid_json');
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('invalid_json');
    return;
  }
  if (typeof value !== 'object') fail('invalid_json');
  const containerDepth = depth + 1;
  if (containerDepth > MAX_JSON_DEPTH) fail('invalid_json');
  if (ancestors.has(value)) fail('invalid_json');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Reflect.ownKeys(value).some((key) => {
        if (key === 'length') return false;
        return typeof key !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(key);
      })) fail('invalid_json');
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !('value' in descriptor)) fail('invalid_json');
        assertJson(descriptor.value, containerDepth, ancestors);
      }
      return;
    }
    if (!plain(value)) fail('invalid_json');
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || hasUnpairedSurrogate(key)) fail('invalid_json');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) fail('invalid_json');
      assertJson(descriptor.value, containerDepth, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function frozenJsonCopy(value: unknown): Readonly<RefereeJson> {
  assertJson(value);
  return deepFreeze(structuredClone(value));
}

function identifier(value: unknown): string {
  if (typeof value !== 'string'
    || Buffer.byteLength(value, 'utf8') > MAX_IDENTIFIER_BYTES
    || !IDENTIFIER.test(value)) fail('invalid_identifier');
  return value;
}

function enumValue<T extends string>(
  value: unknown,
  values: ReadonlySet<T>,
  code: string,
): T {
  if (typeof value !== 'string' || !values.has(value as T)) fail(code);
  return value as T;
}

export function parseRefereeRunnerPin(value: unknown): Readonly<RefereeRunnerPinV1> {
  const object = exactObject(value, RUNNER_PIN_KEYS);
  if (typeof object.executable !== 'string'
    || !path.isAbsolute(object.executable)
    || object.executable.length === 0
    || object.executable.includes('\0')
    || hasUnpairedSurrogate(object.executable)
    || Buffer.byteLength(object.executable, 'utf8') > MAX_EXECUTABLE_BYTES) {
    fail('invalid_executable');
  }
  if (typeof object.executable_sha256 !== 'string'
    || !DIGEST.test(object.executable_sha256)) {
    fail('invalid_executable_digest');
  }
  const executableSha256 = object.executable_sha256 as `sha256:${string}`;
  if (!Array.isArray(object.args) || object.args.length > MAX_RUNNER_ARGUMENTS) {
    fail('invalid_arguments');
  }
  let totalBytes = 0;
  const args = object.args.map((argument) => {
    if (typeof argument !== 'string'
      || argument.includes('\0')
      || hasUnpairedSurrogate(argument)
      || Buffer.byteLength(argument, 'utf8') > MAX_RUNNER_ARGUMENT_BYTES) {
      fail('invalid_arguments');
    }
    totalBytes += Buffer.byteLength(argument, 'utf8');
    return argument;
  });
  if (totalBytes > MAX_RUNNER_ARGUMENT_VECTOR_BYTES) fail('invalid_arguments');
  return deepFreeze({
    executable: object.executable,
    executable_sha256: executableSha256,
    args,
  });
}

export function parseRefereeRunnerRequest(
  value: unknown,
): Readonly<RefereeRunnerRequestV1> {
  const object = exactObject(value, RUNNER_REQUEST_KEYS);
  if (object.version !== REFEREE_RUNNER_REQUEST_VERSION) fail('invalid_version');
  const expectedCaid = object.expected_caid;
  if (typeof expectedCaid !== 'string' || !CAID.test(expectedCaid)) {
    fail('invalid_caid');
  }
  const expectedActionDigest = object.expected_action_digest;
  if (typeof expectedActionDigest !== 'string' || !DIGEST.test(expectedActionDigest)) {
    fail('invalid_action_digest');
  }
  if (typeof object.aec_required !== 'boolean') fail('invalid_aec_required');
  const parsed: RefereeRunnerRequestV1 = {
    version: REFEREE_RUNNER_REQUEST_VERSION,
    case_id: identifier(object.case_id),
    protocol_id: identifier(object.protocol_id),
    expected_caid: expectedCaid,
    expected_action_digest: expectedActionDigest,
    aec_required: object.aec_required,
    execution_scope: enumValue(
      object.execution_scope,
      EXECUTION_SCOPES,
      'invalid_execution_scope',
    ),
    input: frozenJsonCopy(object.input) as RefereeJson,
  };
  return deepFreeze(parsed);
}

export function parseRefereeRunnerOutput(
  value: unknown,
): Readonly<RefereeRunnerOutputV1> {
  const object = exactObject(value, RUNNER_OUTPUT_KEYS);
  if (object.version !== REFEREE_RUNNER_OUTPUT_VERSION) fail('invalid_version');
  const caid = object.caid;
  if (caid !== null && (typeof caid !== 'string' || !CAID.test(caid))) {
    fail('invalid_caid');
  }
  const actionDigest = object.action_digest;
  if (actionDigest !== null
    && (typeof actionDigest !== 'string' || !DIGEST.test(actionDigest))) {
    fail('invalid_action_digest');
  }
  return deepFreeze({
    version: REFEREE_RUNNER_OUTPUT_VERSION,
    case_id: identifier(object.case_id),
    protocol_id: identifier(object.protocol_id),
    native_verification: enumValue(
      object.native_verification,
      NATIVE_VERIFICATIONS,
      'invalid_native_verification',
    ),
    rp_acceptance: enumValue(
      object.rp_acceptance,
      RP_ACCEPTANCES,
      'invalid_rp_acceptance',
    ),
    caid,
    action_digest: actionDigest,
    aec_satisfaction: enumValue(
      object.aec_satisfaction,
      AEC_SATISFACTIONS,
      'invalid_aec_satisfaction',
    ),
    provider_outcome: enumValue(
      object.provider_outcome,
      PROVIDER_OUTCOMES,
      'invalid_provider_outcome',
    ),
    effect_relation: enumValue(
      object.effect_relation,
      EFFECT_RELATIONS,
      'invalid_effect_relation',
    ),
    execution_scope: enumValue(
      object.execution_scope,
      EXECUTION_SCOPES,
      'invalid_execution_scope',
    ),
  });
}

export function parseRefereeEvaluationInput(
  value: unknown,
): Readonly<RefereeEvaluationInputV1> {
  const object = exactObject(value, EVALUATION_KEYS);
  if (object.version !== REFEREE_EVALUATION_VERSION) fail('invalid_version');
  return deepFreeze({
    version: REFEREE_EVALUATION_VERSION,
    runner_pin: parseRefereeRunnerPin(object.runner_pin),
    request: parseRefereeRunnerRequest(object.request),
    output: parseRefereeRunnerOutput(object.output),
  });
}

function matchCaidAndAction(
  request: Readonly<RefereeRunnerRequestV1>,
  output: Readonly<RefereeRunnerOutputV1>,
): RefereeCaidActionMatch {
  if ((output.caid !== null && output.caid !== request.expected_caid)
    || (output.action_digest !== null
      && output.action_digest !== request.expected_action_digest)) {
    return 'MISMATCH';
  }
  if (output.caid === null || output.action_digest === null) {
    return 'INDETERMINATE';
  }
  return 'MATCH';
}

function resultDimensions(
  request: Readonly<RefereeRunnerRequestV1>,
  output: Readonly<RefereeRunnerOutputV1>,
): Readonly<RefereeResultDimensionsV1> {
  return deepFreeze({
    native_verification: { value: output.native_verification },
    rp_acceptance: { value: output.rp_acceptance },
    caid_action_match: {
      value: matchCaidAndAction(request, output),
      expected_caid: request.expected_caid,
      observed_caid: output.caid,
      expected_action_digest: request.expected_action_digest,
      observed_action_digest: output.action_digest,
    },
    aec_satisfaction: {
      required: request.aec_required,
      value: output.aec_satisfaction,
    },
    provider_outcome: { value: output.provider_outcome },
    effect_relation: { value: output.effect_relation },
  });
}

function baseResult(
  runnerPin: Readonly<RefereeRunnerPinV1>,
  request: Readonly<RefereeRunnerRequestV1>,
  status: RefereeStatus,
  dimensions: Readonly<RefereeResultDimensionsV1>,
  reasonCodes: readonly string[],
): Readonly<RefereeResultV1> {
  return deepFreeze({
    version: REFEREE_RESULT_VERSION,
    status,
    claim_scope: 'SELF_TEST' as const,
    execution_authorizing: false as const,
    case_id: request.case_id,
    protocol_id: request.protocol_id,
    runner_pin: runnerPin,
    execution_scope: request.execution_scope,
    remote_atomicity_claimed: false as const,
    dimensions,
    reason_codes: [...reasonCodes],
  });
}

/** Evaluate one already-produced, caller-pinned protocol-runner output. */
export function evaluateReferee(value: unknown): Readonly<RefereeResultV1> {
  const { runner_pin: runnerPin, request, output } = parseRefereeEvaluationInput(value);
  const dimensions = resultDimensions(request, output);
  const reasons: string[] = [];
  let definiteFailure = false;
  let uncertainty = false;

  const nonConformant = (reason: string) => {
    reasons.push(reason);
    definiteFailure = true;
  };
  const indeterminate = (reason: string) => {
    reasons.push(reason);
    uncertainty = true;
  };

  if (output.case_id !== request.case_id) nonConformant('case_id_mismatch');
  if (output.protocol_id !== request.protocol_id) nonConformant('protocol_id_mismatch');
  if (output.execution_scope !== request.execution_scope) {
    nonConformant('execution_scope_mismatch');
  }

  if (dimensions.native_verification.value === 'REJECTED') {
    nonConformant('native_verification_rejected');
  } else if (dimensions.native_verification.value === 'INDETERMINATE') {
    indeterminate('native_verification_indeterminate');
  }

  if (dimensions.rp_acceptance.value === 'REJECTED') {
    nonConformant('rp_acceptance_rejected');
  } else if (dimensions.rp_acceptance.value === 'INDETERMINATE') {
    indeterminate('rp_acceptance_indeterminate');
  }

  if (dimensions.caid_action_match.value === 'MISMATCH') {
    nonConformant('caid_action_mismatch');
  } else if (dimensions.caid_action_match.value === 'INDETERMINATE') {
    indeterminate('caid_action_indeterminate');
  }

  if (dimensions.aec_satisfaction.value === 'NOT_SATISFIED') {
    nonConformant('aec_not_satisfied');
  } else if (dimensions.aec_satisfaction.value === 'INDETERMINATE') {
    indeterminate('aec_indeterminate');
  } else if (request.aec_required
    && dimensions.aec_satisfaction.value === 'NOT_ASSESSED') {
    nonConformant('aec_not_assessed');
  }

  if (dimensions.provider_outcome.value === 'INDETERMINATE') {
    indeterminate('provider_outcome_indeterminate');
  }

  if (dimensions.effect_relation.value === 'DIVERGED') {
    nonConformant('effect_diverged');
  } else if (dimensions.effect_relation.value === 'INDETERMINATE') {
    indeterminate('effect_indeterminate');
  }

  const status: RefereeStatus = definiteFailure
    ? 'NON_CONFORMANT'
    : uncertainty
      ? 'INDETERMINATE'
      : 'CONFORMANT';
  return baseResult(runnerPin, request, status, dimensions, reasons);
}

/** Convert a bounded runner failure into an explicit no-claim result. */
export function createIndeterminateRefereeResult(
  value: RefereeIndeterminateInputV1,
): Readonly<RefereeResultV1> {
  const object = exactObject(value, ['runner_pin', 'request', 'reason_code'] as const);
  const runnerPin = parseRefereeRunnerPin(object.runner_pin);
  const request = parseRefereeRunnerRequest(object.request);
  if (typeof object.reason_code !== 'string' || !REASON_CODE.test(object.reason_code)) {
    fail('invalid_reason_code');
  }
  const dimensions: Readonly<RefereeResultDimensionsV1> = deepFreeze({
    native_verification: { value: 'INDETERMINATE' },
    rp_acceptance: { value: 'INDETERMINATE' },
    caid_action_match: {
      value: 'INDETERMINATE',
      expected_caid: request.expected_caid,
      observed_caid: null,
      expected_action_digest: request.expected_action_digest,
      observed_action_digest: null,
    },
    aec_satisfaction: {
      required: request.aec_required,
      value: request.aec_required ? 'INDETERMINATE' : 'NOT_ASSESSED',
    },
    provider_outcome: { value: 'NOT_ASSESSED' },
    effect_relation: { value: 'NOT_ASSESSED' },
  });
  return baseResult(
    runnerPin,
    request,
    'INDETERMINATE',
    dimensions,
    [object.reason_code],
  );
}
