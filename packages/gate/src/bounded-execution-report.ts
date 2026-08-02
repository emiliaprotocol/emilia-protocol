// SPDX-License-Identifier: Apache-2.0
/**
 * Canonical relying-party report over one verified bounded execution program.
 *
 * The report authenticates a Gate runtime snapshot and a supplied inventory of
 * Gate-recorded program occurrences. It is not evidence of external effect
 * truth, program safety, complete mediation, or activity outside Gate.
 */
import {
  EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION,
  EXECUTION_PROGRAM_RUNTIME_VERSION,
  executionProgramReportSnapshotMarker,
  type ExecutionProgramOccurrence,
  type ExecutionProgramReportSnapshot,
  type ExecutionProgramReportSnapshotBody,
  type ExecutionProgramRuntimeState,
} from './admission-store.js';
import {
  BOUNDED_EXECUTION_PROGRAM_VERSION,
  EXECUTION_PROGRAM_CLAIM_BOUNDARY,
  type VerifiedBoundedExecutionProgram,
} from './bounded-execution-program.js';
import {
  RISK_DIGEST,
  riskDigest,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const BOUNDED_EXECUTION_REPORT_VERSION = 'EP-BOUNDED-EXECUTION-REPORT-v1';
export const BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY =
  'gate_recorded_program_occurrences_only_not_external_effect_truth_not_program_safety_not_complete_mediation_not_absence_of_outside_gate_actions';
export const BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM =
  'EXECUTED_OUTSIDE_THE_PLAN_NOT_CLAIMED_REQUIRES_SEPARATELY_SIGNED_EXTERNAL_INVENTORY_ROOT';

const INPUT_KEYS = [
  'report_id', 'relying_party_id', 'report_interval', 'generated_at',
  'verified_program', 'report_snapshot',
] as const;
const SIGNER_KEYS = ['relying_party_id', 'key_id', 'private_key'] as const;
const VERIFIED_PROGRAM_KEYS = [
  'accepted', 'verified', 'reason', 'program_digest', 'program',
  'authorizer_id', 'claim_boundary',
] as const;
const RUNTIME_KEYS = [
  '@version', 'tenant_id', 'program_id', 'program_digest', 'version', 'status',
  'status_sequence', 'status_observed_at', 'status_expires_at', 'authorizer_id',
  'registered_at', 'superseded_by_program_digest', 'total_occurrences',
  'budgets', 'program',
] as const;
const RUNTIME_BUDGET_KEYS = [
  'budget_id', 'unit', 'limit', 'reserved', 'consumed',
] as const;
const PROGRAM_BUDGET_KEYS = ['budget_id', 'unit', 'limit'] as const;
const OCCURRENCE_KEYS = [
  'tenant_id', 'program_digest', 'node_id', 'occurrence_id', 'admission_id',
  'snapshot_digest', 'state', 'charges', 'created_at', 'updated_at',
] as const;
const REPORT_SNAPSHOT_KEYS = [
  '@version', 'tenant_id', 'program_digest', 'runtime_state', 'occurrences',
  'snapshot_marker',
] as const;
const CHARGE_KEYS = ['budget_id', 'amount'] as const;
const INTERVAL_KEYS = ['start', 'end'] as const;
const BODY_KEYS = [
  '@version', 'report_id', 'relying_party_id', 'tenant_id', 'program_id',
  'program_version', 'program_digest', 'subject_id', 'audience',
  'report_interval', 'generated_at', 'runtime_state_digest',
  'occurrence_inventory_digest', 'report_snapshot_marker',
  'node_buckets', 'budget_usage', 'status',
  'supersession', 'claim_boundary', 'outside_plan_claim', 'issuer',
] as const;
const ISSUER_KEYS = ['id', 'key_id'] as const;
const SUPERSESSION_KEYS = [
  'supersedes_program_digest', 'superseded_by_program_digest',
] as const;
const NODE_BUCKET_KEYS = [
  'node_id', 'max_occurrences', 'terminal_recorded_outcomes',
  'unresolved_post_entry', 'released_pre_entry', 'never_attempted',
] as const;
const TERMINAL_KEYS = ['occurrence_id', 'outcome'] as const;
const UNRESOLVED_KEYS = ['occurrence_id', 'recorded_state'] as const;
const NEVER_ATTEMPTED_KEYS = [
  'reserved_occurrence_ids', 'unallocated_occurrence_count',
] as const;
const BUDGET_USAGE_KEYS = [
  'budget_id', 'unit', 'limit', 'reserved', 'consumed', 'remaining',
] as const;
const CONTEXT_KEYS = [
  'trusted_keys', 'expected_report_id', 'expected_relying_party_id',
  'expected_tenant_id', 'expected_program_id', 'expected_program_version',
  'expected_program_digest', 'expected_subject_id', 'expected_audience',
  'expected_report_interval', 'expected_runtime_state_digest',
  'expected_occurrence_inventory_digest', 'expected_report_snapshot_marker',
  'now', 'max_report_age_ms',
] as const;
const TRUSTED_KEY_KEYS = ['issuer_id', 'public_key'] as const;

const OCCURRENCE_STATES = new Set([
  'RESERVED', 'RELEASED', 'INVOKING', 'INDETERMINATE',
  'COMMITTED', 'PROVEN_NOT_COMMITTED',
]);
const CONSUMED_STATES = new Set([
  'INVOKING', 'INDETERMINATE', 'COMMITTED', 'PROVEN_NOT_COMMITTED',
]);
const TERMINAL_STATES = new Set(['COMMITTED', 'PROVEN_NOT_COMMITTED']);
const UNRESOLVED_STATES = new Set(['INVOKING', 'INDETERMINATE']);
const MAX_OCCURRENCES = 1_000_000;

export interface BoundedExecutionReportSigner {
  relying_party_id: string;
  key_id: string;
  private_key: any;
}

export interface VerifiedBoundedExecutionProgramResult {
  accepted: true;
  verified: true;
  reason: null;
  program_digest: string;
  program: Readonly<VerifiedBoundedExecutionProgram>;
  authorizer_id: string;
  claim_boundary: typeof EXECUTION_PROGRAM_CLAIM_BOUNDARY;
}

export interface BoundedExecutionReportInput {
  report_id: string;
  relying_party_id: string;
  report_interval: { start: string; end: string };
  generated_at: string;
  verified_program: VerifiedBoundedExecutionProgramResult;
  report_snapshot: Readonly<ExecutionProgramReportSnapshot>;
}

export interface BoundedExecutionReportVerificationContext {
  trusted_keys: TrustedRiskKeys;
  expected_report_id: string;
  expected_relying_party_id: string;
  expected_tenant_id: string;
  expected_program_id: string;
  expected_program_version: number;
  expected_program_digest: string;
  expected_subject_id: string;
  expected_audience: string;
  expected_report_interval: { start: string; end: string };
  expected_runtime_state_digest: string;
  expected_occurrence_inventory_digest: string;
  expected_report_snapshot_marker: string;
  now: string;
  max_report_age_ms: number;
}

export class BoundedExecutionReportValidationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'BoundedExecutionReportValidationError';
    this.code = code;
  }
}

function refuse(code: string, message: string): never {
  throw new BoundedExecutionReportValidationError(code, message);
}

function byteOrder(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function safeNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function safePositiveInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0 && Number(value) <= maximum;
}

function descriptorValue(owner: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(owner, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
    refuse('non_data_json', 'accessors are outside the report JSON data model');
  }
  return descriptor.value;
}

/** Clone JSON data without invoking hostile accessors or accepting sparse arrays. */
function strictJsonClone(value: unknown, seen = new WeakSet<object>()): any {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) refuse('non_json_number', 'report numbers must be finite');
    return value;
  }
  if (typeof value !== 'object' || seen.has(value)) {
    refuse('non_json_value', 'report values must be acyclic JSON data');
  }
  seen.add(value);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      refuse('non_json_array', 'report arrays must use the ordinary Array prototype');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes('length')) {
      refuse('non_json_array', 'report arrays must be dense and property-free');
    }
    const clone: any[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
        refuse('non_json_array', 'report arrays must contain enumerable data elements');
      }
      clone.push(strictJsonClone(descriptor.value, seen));
    }
    seen.delete(value);
    return clone;
  }
  if (!riskRecord(value)) refuse('non_json_object', 'report objects must be plain data objects');
  const clone: RiskRecord = {};
  for (const key of Object.keys(value)) {
    clone[key] = strictJsonClone(descriptorValue(value, key), seen);
  }
  seen.delete(value);
  return clone;
}

function canonicalInstant(value: unknown, label: string): string {
  if (typeof value !== 'string') refuse('instant_invalid', `${label} must be RFC 3339`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    refuse('instant_invalid', `${label} must be a canonical RFC 3339 instant`);
  }
  return value;
}

function normalizeInterval(value: unknown, label: string): { start: string; end: string } {
  if (!riskExact(value, INTERVAL_KEYS)) refuse('interval_invalid', `${label} must be closed`);
  const start = canonicalInstant(value.start, `${label}.start`);
  const end = canonicalInstant(value.end, `${label}.end`);
  if (Date.parse(end) <= Date.parse(start)) refuse('interval_invalid', `${label} must be increasing`);
  return { start, end };
}

function identifier(value: unknown, label: string): string {
  if (!riskIdentifier(value)) refuse('identifier_invalid', `${label} is invalid`);
  return value;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !RISK_DIGEST.test(value)) {
    refuse('digest_invalid', `${label} is invalid`);
  }
  return value;
}

function sortedUniqueStrings(value: unknown, label: string): value is string[] {
  if (!Array.isArray(value)) return false;
  let previous: string | null = null;
  for (const entry of value) {
    if (!riskIdentifier(entry) || (previous !== null && byteOrder(previous, entry) >= 0)) {
      return false;
    }
    previous = entry;
  }
  return true;
}

function normalizeCharges(value: unknown): RiskRecord[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
    refuse('occurrence_charge_invalid', 'occurrence charges are invalid');
  }
  const seen = new Set<string>();
  const charges = value.map((entry) => {
    if (!riskExact(entry, CHARGE_KEYS)
        || !riskIdentifier(entry.budget_id)
        || !safePositiveInteger(entry.amount)) {
      refuse('occurrence_charge_invalid', 'occurrence charge is invalid');
    }
    if (seen.has(entry.budget_id)) {
      refuse('occurrence_charge_invalid', 'occurrence charge is duplicated');
    }
    seen.add(entry.budget_id);
    return { budget_id: entry.budget_id, amount: entry.amount };
  });
  return charges.sort((left, right) => byteOrder(left.budget_id, right.budget_id));
}

function normalizeOccurrences(value: unknown, requireDeterministicOrder = false): RiskRecord[] {
  let snapshot: unknown;
  try {
    snapshot = strictJsonClone(value);
  } catch (error) {
    if (error instanceof BoundedExecutionReportValidationError) {
      refuse('occurrence_invalid', `occurrence inventory is invalid: ${error.message}`);
    }
    throw error;
  }
  if (!Array.isArray(snapshot) || snapshot.length > MAX_OCCURRENCES) {
    refuse('occurrence_invalid', 'occurrence inventory is invalid');
  }
  const occurrenceIds = new Set<string>();
  const admissionIds = new Set<string>();
  const occurrences = snapshot.map((entry) => {
    if (!riskExact(entry, OCCURRENCE_KEYS)
        || !riskIdentifier(entry.tenant_id)
        || !RISK_DIGEST.test(entry.program_digest)
        || !riskIdentifier(entry.node_id)
        || !riskIdentifier(entry.occurrence_id)
        || !riskIdentifier(entry.admission_id)
        || !RISK_DIGEST.test(entry.snapshot_digest)
        || typeof entry.state !== 'string' || !OCCURRENCE_STATES.has(entry.state)) {
      refuse('occurrence_invalid', 'occurrence record is invalid');
    }
    if (occurrenceIds.has(entry.occurrence_id)) {
      refuse('occurrence_duplicated', 'occurrence identifier is duplicated');
    }
    if (admissionIds.has(entry.admission_id)) {
      refuse('occurrence_duplicated', 'occurrence admission identifier is duplicated');
    }
    occurrenceIds.add(entry.occurrence_id);
    admissionIds.add(entry.admission_id);
    const createdAt = canonicalInstant(entry.created_at, 'occurrence.created_at');
    const updatedAt = canonicalInstant(entry.updated_at, 'occurrence.updated_at');
    if (Date.parse(updatedAt) < Date.parse(createdAt)) {
      refuse('occurrence_time_invalid', 'occurrence update precedes creation');
    }
    return {
      tenant_id: entry.tenant_id,
      program_digest: entry.program_digest,
      node_id: entry.node_id,
      occurrence_id: entry.occurrence_id,
      admission_id: entry.admission_id,
      snapshot_digest: entry.snapshot_digest,
      state: entry.state,
      charges: normalizeCharges(entry.charges),
      created_at: createdAt,
      updated_at: updatedAt,
    };
  });
  const ordered = [...occurrences].sort((left, right) => (
    byteOrder(left.node_id, right.node_id)
      || byteOrder(left.occurrence_id, right.occurrence_id)
  ));
  if (requireDeterministicOrder && ordered.some((entry, index) => (
    entry.node_id !== occurrences[index].node_id
    || entry.occurrence_id !== occurrences[index].occurrence_id
  ))) {
    refuse('report_snapshot_order_invalid', 'report snapshot occurrences are not in deterministic order');
  }
  return ordered;
}

function normalizeRuntimeState(value: unknown): RiskRecord {
  let state: unknown;
  try {
    state = strictJsonClone(value);
  } catch (error) {
    if (error instanceof BoundedExecutionReportValidationError) {
      refuse('runtime_state_invalid', `runtime state is invalid: ${error.message}`);
    }
    throw error;
  }
  if (!riskExact(state, RUNTIME_KEYS)
      || state['@version'] !== EXECUTION_PROGRAM_RUNTIME_VERSION
      || !riskIdentifier(state.tenant_id)
      || !riskIdentifier(state.program_id)
      || !RISK_DIGEST.test(state.program_digest)
      || !safePositiveInteger(state.version)
      || !['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED'].includes(state.status)
      || !safeNonNegativeInteger(state.status_sequence)
      || !riskIdentifier(state.authorizer_id)
      || !safeNonNegativeInteger(state.total_occurrences)
      || (state.superseded_by_program_digest !== null
        && !RISK_DIGEST.test(state.superseded_by_program_digest))
      || !riskRecord(state.program)
      || !Array.isArray(state.budgets) || state.budgets.length < 1
      || state.budgets.length > 64) {
    refuse('runtime_state_invalid', 'runtime state is not a closed v1 state');
  }
  const registeredAt = canonicalInstant(state.registered_at, 'runtime_state.registered_at');
  const statusObservedAt = canonicalInstant(
    state.status_observed_at,
    'runtime_state.status_observed_at',
  );
  const statusExpiresAt = canonicalInstant(
    state.status_expires_at,
    'runtime_state.status_expires_at',
  );
  if (Date.parse(statusExpiresAt) <= Date.parse(statusObservedAt)) {
    refuse('runtime_status_invalid', 'runtime status validity interval is invalid');
  }
  if ((state.status !== 'SUPERSEDED' && state.superseded_by_program_digest !== null)
      || (state.status === 'SUPERSEDED' && state.superseded_by_program_digest === null)) {
    refuse('runtime_supersession_invalid', 'runtime status and successor digest conflict');
  }
  const budgetIds = new Set<string>();
  const budgets = state.budgets.map((entry: unknown) => {
    if (!riskExact(entry, RUNTIME_BUDGET_KEYS)
        || !riskIdentifier(entry.budget_id)
        || !riskIdentifier(entry.unit)
        || !safePositiveInteger(entry.limit)
        || !safeNonNegativeInteger(entry.reserved)
        || !safeNonNegativeInteger(entry.consumed)
        || entry.reserved + entry.consumed > entry.limit) {
      refuse('runtime_budget_invalid', 'runtime budget is invalid');
    }
    if (budgetIds.has(entry.budget_id)) refuse('runtime_budget_invalid', 'runtime budget is duplicated');
    budgetIds.add(entry.budget_id);
    return {
      budget_id: entry.budget_id,
      unit: entry.unit,
      limit: entry.limit,
      reserved: entry.reserved,
      consumed: entry.consumed,
    };
  }).sort((left, right) => byteOrder(left.budget_id, right.budget_id));
  return {
    '@version': state['@version'],
    tenant_id: state.tenant_id,
    program_id: state.program_id,
    program_digest: state.program_digest,
    version: state.version,
    status: state.status,
    status_sequence: state.status_sequence,
    status_observed_at: statusObservedAt,
    status_expires_at: statusExpiresAt,
    authorizer_id: state.authorizer_id,
    registered_at: registeredAt,
    superseded_by_program_digest: state.superseded_by_program_digest,
    total_occurrences: state.total_occurrences,
    budgets,
    program: state.program,
  };
}

function normalizeReportSnapshot(value: unknown): {
  runtime: RiskRecord;
  occurrences: RiskRecord[];
  snapshotMarker: string;
} {
  let snapshot: unknown;
  try {
    snapshot = strictJsonClone(value);
  } catch (error) {
    if (error instanceof BoundedExecutionReportValidationError) {
      refuse('report_snapshot_invalid', `report snapshot is invalid: ${error.message}`);
    }
    throw error;
  }
  if (!riskExact(snapshot, REPORT_SNAPSHOT_KEYS)
      || snapshot['@version'] !== EXECUTION_PROGRAM_REPORT_SNAPSHOT_VERSION
      || !riskIdentifier(snapshot.tenant_id)
      || !RISK_DIGEST.test(snapshot.program_digest)
      || !RISK_DIGEST.test(snapshot.snapshot_marker)) {
    refuse('report_snapshot_invalid', 'report snapshot is not a closed v1 snapshot');
  }
  const { snapshot_marker: snapshotMarker, ...markerBody } = snapshot;
  if (snapshotMarker !== executionProgramReportSnapshotMarker(
    markerBody as Readonly<ExecutionProgramReportSnapshotBody>,
  )) {
    refuse('report_snapshot_marker_invalid', 'report snapshot marker does not authenticate its body');
  }
  const runtime = normalizeRuntimeState(snapshot.runtime_state);
  const occurrences = normalizeOccurrences(snapshot.occurrences, true);
  if (snapshot.tenant_id !== runtime.tenant_id
      || snapshot.program_digest !== runtime.program_digest) {
    refuse('report_snapshot_binding_invalid', 'report snapshot tenant or program binding differs');
  }
  return { runtime, occurrences, snapshotMarker };
}

function normalizeVerifiedProgram(value: unknown): VerifiedBoundedExecutionProgramResult {
  let result: unknown;
  try {
    result = strictJsonClone(value);
  } catch {
    refuse('program_verification_invalid', 'verified program result is invalid');
  }
  if (!riskExact(result, VERIFIED_PROGRAM_KEYS)
      || result.accepted !== true || result.verified !== true || result.reason !== null
      || !RISK_DIGEST.test(result.program_digest)
      || !riskRecord(result.program)
      || !riskIdentifier(result.authorizer_id)
      || result.claim_boundary !== EXECUTION_PROGRAM_CLAIM_BOUNDARY
      || result.program['@version'] !== BOUNDED_EXECUTION_PROGRAM_VERSION
      || result.program.claim_boundary !== EXECUTION_PROGRAM_CLAIM_BOUNDARY
      || !riskIdentifier(result.program.program_id)
      || !riskIdentifier(result.program.tenant_id)
      || !safePositiveInteger(result.program.version)
      || !riskIdentifier(result.program.subject_id)
      || !riskIdentifier(result.program.audience)
      || !Array.isArray(result.program.budgets) || result.program.budgets.length < 1
      || !Array.isArray(result.program.nodes) || result.program.nodes.length < 1) {
    refuse('program_verification_invalid', 'an accepted verified bounded program is required');
  }
  return result as VerifiedBoundedExecutionProgramResult;
}

function programModel(program: Readonly<VerifiedBoundedExecutionProgram>): {
  budgets: Map<string, RiskRecord>;
  nodes: Map<string, RiskRecord>;
} {
  const budgets = new Map<string, RiskRecord>();
  for (const entry of program.budgets as unknown[]) {
    if (!riskExact(entry, PROGRAM_BUDGET_KEYS)
        || !riskIdentifier(entry.budget_id)
        || !riskIdentifier(entry.unit)
        || !safePositiveInteger(entry.limit)
        || budgets.has(entry.budget_id)) {
      refuse('program_verification_invalid', 'verified program budget is invalid');
    }
    budgets.set(entry.budget_id, entry);
  }
  const nodes = new Map<string, RiskRecord>();
  for (const entry of program.nodes as unknown[]) {
    if (!riskRecord(entry)
        || !riskIdentifier(entry.node_id)
        || !safePositiveInteger(entry.max_occurrences, MAX_OCCURRENCES)
        || !Array.isArray(entry.charges)
        || nodes.has(entry.node_id)) {
      refuse('program_verification_invalid', 'verified program node is invalid');
    }
    const charges = normalizeCharges(entry.charges);
    for (const charge of charges) {
      if (!budgets.has(charge.budget_id)) {
        refuse('program_verification_invalid', 'verified node charges an unknown budget');
      }
    }
    nodes.set(entry.node_id, { ...entry, charges });
  }
  return { budgets, nodes };
}

function validateDerivation(
  verified: VerifiedBoundedExecutionProgramResult,
  runtime: RiskRecord,
  occurrences: RiskRecord[],
  interval: { start: string; end: string },
): { model: ReturnType<typeof programModel>; aggregates: Map<string, { reserved: number; consumed: number }> } {
  const program = verified.program;
  if (runtime.tenant_id !== program.tenant_id
      || runtime.program_id !== program.program_id
      || runtime.version !== program.version
      || runtime.program_digest !== verified.program_digest
      || runtime.authorizer_id !== verified.authorizer_id
      || riskDigest(runtime.program) !== riskDigest(program)) {
    refuse('runtime_program_mismatch', 'runtime state does not bind the verified program');
  }
  if (Date.parse(runtime.registered_at) < Date.parse(interval.start)
      || Date.parse(runtime.registered_at) > Date.parse(interval.end)) {
    refuse('report_interval_invalid', 'report interval must contain program registration');
  }
  if (Date.parse(runtime.status_observed_at) > Date.parse(interval.end)
      || Date.parse(runtime.status_expires_at) <= Date.parse(interval.end)) {
    refuse('runtime_status_invalid', 'runtime status is not current at the interval end');
  }
  const model = programModel(program);
  if (runtime.budgets.length !== model.budgets.size) {
    refuse('runtime_budget_invalid', 'runtime and program budget sets differ');
  }
  for (const runtimeBudget of runtime.budgets) {
    const declared = model.budgets.get(runtimeBudget.budget_id);
    if (!declared || declared.limit !== runtimeBudget.limit
        || declared.unit !== runtimeBudget.unit) {
      refuse('runtime_budget_invalid', 'runtime budget differs from the verified program');
    }
  }

  const aggregates = new Map<string, { reserved: number; consumed: number }>();
  for (const budgetId of model.budgets.keys()) {
    aggregates.set(budgetId, { reserved: 0, consumed: 0 });
  }
  if (!safePositiveInteger(program.max_total_occurrences, MAX_OCCURRENCES)
      || runtime.total_occurrences !== occurrences.length
      || runtime.total_occurrences > program.max_total_occurrences) {
    refuse('occurrence_inventory_mismatch', 'runtime total occurrence count does not reconcile');
  }
  const occurrencesByNode = new Map<string, number>();
  for (const occurrence of occurrences) {
    if (occurrence.tenant_id !== runtime.tenant_id
        || occurrence.program_digest !== runtime.program_digest) {
      refuse('occurrence_program_mismatch', 'occurrence tenant or program digest is substituted');
    }
    const node = model.nodes.get(occurrence.node_id);
    if (!node) refuse('occurrence_node_unknown', 'occurrence references an unknown program node');
    if (riskDigest(occurrence.charges) !== riskDigest(node.charges)) {
      refuse('occurrence_charge_mismatch', 'occurrence charges differ from the program node');
    }
    if (Date.parse(occurrence.created_at) < Date.parse(runtime.registered_at)
        || Date.parse(occurrence.created_at) < Date.parse(interval.start)
        || Date.parse(occurrence.updated_at) > Date.parse(interval.end)) {
      refuse('occurrence_time_invalid', 'occurrence is outside the report interval');
    }
    if (occurrence.state !== 'RELEASED') {
      const count = (occurrencesByNode.get(occurrence.node_id) ?? 0) + 1;
      if (count > node.max_occurrences) {
        refuse('occurrence_ceiling_invalid', 'node occurrence ceiling is exceeded');
      }
      occurrencesByNode.set(occurrence.node_id, count);
    }
    for (const charge of occurrence.charges) {
      const aggregate = aggregates.get(charge.budget_id)!;
      if (occurrence.state === 'RESERVED') aggregate.reserved += charge.amount;
      if (CONSUMED_STATES.has(occurrence.state)) aggregate.consumed += charge.amount;
      if (!Number.isSafeInteger(aggregate.reserved) || !Number.isSafeInteger(aggregate.consumed)) {
        refuse('budget_reconciliation_invalid', 'occurrence budget aggregate overflowed');
      }
    }
  }
  for (const runtimeBudget of runtime.budgets) {
    const aggregate = aggregates.get(runtimeBudget.budget_id)!;
    if (aggregate.reserved !== runtimeBudget.reserved
        || aggregate.consumed !== runtimeBudget.consumed) {
      refuse('budget_reconciliation_invalid', 'runtime budget does not reconcile to occurrences');
    }
  }
  return { model, aggregates };
}

function deriveNodeBuckets(model: ReturnType<typeof programModel>, occurrences: RiskRecord[]) {
  const byNode = new Map<string, RiskRecord[]>();
  for (const nodeId of model.nodes.keys()) byNode.set(nodeId, []);
  for (const occurrence of occurrences) byNode.get(occurrence.node_id)!.push(occurrence);
  return [...model.nodes.values()]
    .sort((left, right) => byteOrder(left.node_id, right.node_id))
    .map((node) => {
      const entries = byNode.get(node.node_id)!;
      const terminal = entries
        .filter((entry) => TERMINAL_STATES.has(entry.state))
        .map((entry) => ({ occurrence_id: entry.occurrence_id, outcome: entry.state }))
        .sort((left, right) => byteOrder(left.occurrence_id, right.occurrence_id));
      const unresolved = entries
        .filter((entry) => UNRESOLVED_STATES.has(entry.state))
        .map((entry) => ({ occurrence_id: entry.occurrence_id, recorded_state: entry.state }))
        .sort((left, right) => byteOrder(left.occurrence_id, right.occurrence_id));
      const released = entries
        .filter((entry) => entry.state === 'RELEASED')
        .map((entry) => entry.occurrence_id)
        .sort(byteOrder);
      const reserved = entries
        .filter((entry) => entry.state === 'RESERVED')
        .map((entry) => entry.occurrence_id)
        .sort(byteOrder);
      const allocated = terminal.length + unresolved.length + reserved.length;
      return {
        node_id: node.node_id,
        max_occurrences: node.max_occurrences,
        terminal_recorded_outcomes: terminal,
        unresolved_post_entry: unresolved,
        released_pre_entry: released,
        never_attempted: {
          reserved_occurrence_ids: reserved,
          unallocated_occurrence_count: node.max_occurrences - allocated,
        },
      };
    });
}

function deriveBudgetUsage(model: ReturnType<typeof programModel>, runtime: RiskRecord) {
  const runtimeById = new Map<string, RiskRecord>(
    runtime.budgets.map((entry: RiskRecord) => [entry.budget_id, entry]),
  );
  return [...model.budgets.values()]
    .sort((left, right) => byteOrder(left.budget_id, right.budget_id))
    .map((budget) => {
      const state = runtimeById.get(budget.budget_id)!;
      return {
        budget_id: budget.budget_id,
        unit: budget.unit,
        limit: budget.limit,
        reserved: state.reserved,
        consumed: state.consumed,
        remaining: state.limit - state.reserved - state.consumed,
      };
    });
}

function validateReportBody(value: unknown): asserts value is RiskRecord {
  if (!riskExact(value, BODY_KEYS)
      || value['@version'] !== BOUNDED_EXECUTION_REPORT_VERSION
      || !riskIdentifier(value.report_id)
      || !riskIdentifier(value.relying_party_id)
      || !riskIdentifier(value.tenant_id)
      || !riskIdentifier(value.program_id)
      || !safePositiveInteger(value.program_version)
      || !RISK_DIGEST.test(value.program_digest)
      || !riskIdentifier(value.subject_id)
      || !riskIdentifier(value.audience)
      || !RISK_DIGEST.test(value.runtime_state_digest)
      || !RISK_DIGEST.test(value.occurrence_inventory_digest)
      || !RISK_DIGEST.test(value.report_snapshot_marker)
      || !['ACTIVE', 'SUSPENDED', 'REVOKED', 'SUPERSEDED'].includes(value.status)
      || !riskExact(value.issuer, ISSUER_KEYS)
      || !riskIdentifier(value.issuer.id)
      || !riskIdentifier(value.issuer.key_id)
      || value.issuer.id !== value.relying_party_id
      || value.claim_boundary !== BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY
      || value.outside_plan_claim !== BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM) {
    refuse('report_schema_invalid', 'signed report is not a closed v1 body');
  }
  const interval = normalizeInterval(value.report_interval, 'report_interval');
  const generatedAt = canonicalInstant(value.generated_at, 'generated_at');
  if (Date.parse(generatedAt) < Date.parse(interval.end)) {
    refuse('report_time_invalid', 'report generation precedes the report interval end');
  }
  if (!riskExact(value.supersession, SUPERSESSION_KEYS)
      || (value.supersession.supersedes_program_digest !== null
        && !RISK_DIGEST.test(value.supersession.supersedes_program_digest))
      || (value.supersession.superseded_by_program_digest !== null
        && !RISK_DIGEST.test(value.supersession.superseded_by_program_digest))
      || (value.status !== 'SUPERSEDED'
        && value.supersession.superseded_by_program_digest !== null)
      || (value.status === 'SUPERSEDED'
        && value.supersession.superseded_by_program_digest === null)) {
    refuse('report_supersession_invalid', 'report status and supersession are inconsistent');
  }

  if (!Array.isArray(value.node_buckets) || value.node_buckets.length < 1
      || value.node_buckets.length > 256) {
    refuse('report_node_buckets_invalid', 'node buckets are invalid');
  }
  let previousNode: string | null = null;
  const occurrenceIds = new Set<string>();
  for (const node of value.node_buckets) {
    if (!riskExact(node, NODE_BUCKET_KEYS)
        || !riskIdentifier(node.node_id)
        || !safePositiveInteger(node.max_occurrences, MAX_OCCURRENCES)
        || (previousNode !== null && byteOrder(previousNode, node.node_id) >= 0)
        || !Array.isArray(node.terminal_recorded_outcomes)
        || !Array.isArray(node.unresolved_post_entry)
        || !sortedUniqueStrings(node.released_pre_entry, 'released_pre_entry')
        || !riskExact(node.never_attempted, NEVER_ATTEMPTED_KEYS)
        || !sortedUniqueStrings(
          node.never_attempted.reserved_occurrence_ids,
          'reserved_occurrence_ids',
        )
        || !safeNonNegativeInteger(node.never_attempted.unallocated_occurrence_count)) {
      refuse('report_node_buckets_invalid', 'node bucket is invalid or not canonical');
    }
    previousNode = node.node_id;
    let previousTerminal: string | null = null;
    for (const terminal of node.terminal_recorded_outcomes) {
      if (!riskExact(terminal, TERMINAL_KEYS)
          || !riskIdentifier(terminal.occurrence_id)
          || !TERMINAL_STATES.has(terminal.outcome)
          || (previousTerminal !== null
            && byteOrder(previousTerminal, terminal.occurrence_id) >= 0)) {
        refuse('report_node_buckets_invalid', 'terminal bucket is invalid or not canonical');
      }
      previousTerminal = terminal.occurrence_id;
    }
    let previousUnresolved: string | null = null;
    for (const unresolved of node.unresolved_post_entry) {
      if (!riskExact(unresolved, UNRESOLVED_KEYS)
          || !riskIdentifier(unresolved.occurrence_id)
          || !UNRESOLVED_STATES.has(unresolved.recorded_state)
          || (previousUnresolved !== null
            && byteOrder(previousUnresolved, unresolved.occurrence_id) >= 0)) {
        refuse('report_node_buckets_invalid', 'unresolved bucket is invalid or not canonical');
      }
      previousUnresolved = unresolved.occurrence_id;
    }
    const allocated = node.terminal_recorded_outcomes.length
      + node.unresolved_post_entry.length
      + node.never_attempted.reserved_occurrence_ids.length
      + node.never_attempted.unallocated_occurrence_count;
    if (allocated !== node.max_occurrences) {
      refuse('report_node_buckets_invalid', 'node capacity buckets do not reconcile');
    }
    const ids = [
      ...node.terminal_recorded_outcomes.map((entry: RiskRecord) => entry.occurrence_id),
      ...node.unresolved_post_entry.map((entry: RiskRecord) => entry.occurrence_id),
      ...node.released_pre_entry,
      ...node.never_attempted.reserved_occurrence_ids,
    ];
    for (const occurrenceId of ids) {
      if (occurrenceIds.has(occurrenceId)) {
        refuse('report_node_buckets_invalid', 'occurrence appears in more than one bucket');
      }
      occurrenceIds.add(occurrenceId);
    }
  }

  if (!Array.isArray(value.budget_usage) || value.budget_usage.length < 1
      || value.budget_usage.length > 64) {
    refuse('report_budget_usage_invalid', 'budget usage is invalid');
  }
  let previousBudget: string | null = null;
  for (const budget of value.budget_usage) {
    if (!riskExact(budget, BUDGET_USAGE_KEYS)
        || !riskIdentifier(budget.budget_id)
        || !riskIdentifier(budget.unit)
        || !safePositiveInteger(budget.limit)
        || !safeNonNegativeInteger(budget.reserved)
        || !safeNonNegativeInteger(budget.consumed)
        || !safeNonNegativeInteger(budget.remaining)
        || budget.reserved + budget.consumed + budget.remaining !== budget.limit
        || (previousBudget !== null && byteOrder(previousBudget, budget.budget_id) >= 0)) {
      refuse('report_budget_usage_invalid', 'budget usage is invalid or not canonical');
    }
    previousBudget = budget.budget_id;
  }
}

function normalizeContext(value: unknown): BoundedExecutionReportVerificationContext | null {
  try {
    const context = strictJsonClone(value);
    if (!riskExact(context, CONTEXT_KEYS)
        || !riskRecord(context.trusted_keys)
        || Object.keys(context.trusted_keys).length < 1
        || !Object.values(context.trusted_keys).every((entry) => (
          riskExact(entry, TRUSTED_KEY_KEYS)
          && riskIdentifier(entry.issuer_id)
          && typeof entry.public_key === 'string' && entry.public_key.length > 0
        ))
        || !riskIdentifier(context.expected_report_id)
        || !riskIdentifier(context.expected_relying_party_id)
        || !riskIdentifier(context.expected_tenant_id)
        || !riskIdentifier(context.expected_program_id)
        || !safePositiveInteger(context.expected_program_version)
        || !RISK_DIGEST.test(context.expected_program_digest)
        || !riskIdentifier(context.expected_subject_id)
        || !riskIdentifier(context.expected_audience)
        || !RISK_DIGEST.test(context.expected_runtime_state_digest)
        || !RISK_DIGEST.test(context.expected_occurrence_inventory_digest)
        || !RISK_DIGEST.test(context.expected_report_snapshot_marker)
        || !safeNonNegativeInteger(context.max_report_age_ms)) return null;
    context.expected_report_interval = normalizeInterval(
      context.expected_report_interval,
      'expected_report_interval',
    );
    context.now = canonicalInstant(context.now, 'verification now');
    return context as BoundedExecutionReportVerificationContext;
  } catch {
    return null;
  }
}

/** Digest of the complete normalized ExecutionProgramRuntimeState. */
export function boundedExecutionRuntimeStateDigest(state: unknown): string {
  return riskDigest(normalizeRuntimeState(state));
}

/** Digest of every supplied full occurrence record in deterministic order. */
export function boundedExecutionOccurrenceInventoryDigest(occurrences: unknown): string {
  return riskDigest({
    '@version': `${BOUNDED_EXECUTION_REPORT_VERSION}:OCCURRENCE-INVENTORY`,
    occurrences: normalizeOccurrences(occurrences),
  });
}

/** Digest of the complete signed report, including its Ed25519 proof. */
export function boundedExecutionReportDigest(artifact: unknown): string {
  const snapshot = strictJsonClone(artifact);
  if (!riskRecord(snapshot) || !riskRecord(snapshot.proof)) {
    refuse('report_artifact_invalid', 'signed report artifact is invalid');
  }
  const { proof: _proof, ...body } = snapshot;
  validateReportBody(body);
  return riskDigest(snapshot);
}

/** Build and sign one closed report from an accepted program verification result. */
export function signBoundedExecutionReport(
  rawInput: BoundedExecutionReportInput | RiskRecord,
  rawSigner: BoundedExecutionReportSigner,
): RiskRecord {
  if (!riskExact(rawInput, INPUT_KEYS)) {
    refuse('report_input_invalid', 'report input must be a closed object');
  }
  if (!riskExact(rawSigner, SIGNER_KEYS)
      || !riskIdentifier(rawSigner.relying_party_id)
      || !riskIdentifier(rawSigner.key_id)) {
    refuse('report_signer_invalid', 'report signer must be a closed relying-party signer');
  }
  const reportId = identifier(rawInput.report_id, 'report_id');
  const relyingPartyId = identifier(rawInput.relying_party_id, 'relying_party_id');
  if (relyingPartyId !== rawSigner.relying_party_id) {
    refuse('report_signer_invalid', 'report signer must be the named relying party');
  }
  const interval = normalizeInterval(rawInput.report_interval, 'report_interval');
  const generatedAt = canonicalInstant(rawInput.generated_at, 'generated_at');
  if (Date.parse(generatedAt) < Date.parse(interval.end)) {
    refuse('report_time_invalid', 'report generation precedes the interval end');
  }
  const verified = normalizeVerifiedProgram(rawInput.verified_program);
  const { runtime, occurrences, snapshotMarker } = normalizeReportSnapshot(
    rawInput.report_snapshot,
  );
  const { model } = validateDerivation(verified, runtime, occurrences, interval);
  const body = {
    '@version': BOUNDED_EXECUTION_REPORT_VERSION,
    report_id: reportId,
    relying_party_id: relyingPartyId,
    tenant_id: runtime.tenant_id,
    program_id: runtime.program_id,
    program_version: runtime.version,
    program_digest: runtime.program_digest,
    subject_id: verified.program.subject_id,
    audience: verified.program.audience,
    report_interval: interval,
    generated_at: generatedAt,
    runtime_state_digest: riskDigest(runtime),
    occurrence_inventory_digest: riskDigest({
      '@version': `${BOUNDED_EXECUTION_REPORT_VERSION}:OCCURRENCE-INVENTORY`,
      occurrences,
    }),
    report_snapshot_marker: snapshotMarker,
    node_buckets: deriveNodeBuckets(model, occurrences),
    budget_usage: deriveBudgetUsage(model, runtime),
    status: runtime.status,
    supersession: {
      supersedes_program_digest: verified.program.supersedes_program_digest,
      superseded_by_program_digest: runtime.superseded_by_program_digest,
    },
    claim_boundary: BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY,
    outside_plan_claim: BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM,
  };
  validateReportBody({
    ...body,
    issuer: { id: relyingPartyId, key_id: rawSigner.key_id },
  });
  try {
    return signRiskBody(BOUNDED_EXECUTION_REPORT_VERSION, body, {
      issuer_id: relyingPartyId,
      key_id: rawSigner.key_id,
      private_key: rawSigner.private_key,
    });
  } catch {
    refuse('report_signer_invalid', 'report signing key must be Ed25519');
  }
}

/** Verify signature, closed schema, RP pin, complete expected tuple, and freshness. */
export function verifyBoundedExecutionReport(
  artifact: unknown,
  rawContext?: BoundedExecutionReportVerificationContext,
): RiskRecord {
  const fail = (
    reason: string,
    verified = false,
    reportDigest: string | null = null,
  ) => riskFreeze({
    accepted: false,
    verified,
    reason,
    report_digest: reportDigest,
    claim_boundary: BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY,
    outside_plan_claim: BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM,
  });
  const context = normalizeContext(rawContext);
  if (!context) return fail('verification_context_required');

  let snapshot: unknown;
  try {
    snapshot = strictJsonClone(artifact);
  } catch {
    return fail('report_artifact_invalid');
  }
  const signed = verifyRiskBody(
    snapshot,
    BOUNDED_EXECUTION_REPORT_VERSION,
    context.trusted_keys,
  );
  if (!signed.valid || !signed.body || !signed.artifact_digest) {
    return fail(signed.reason ?? 'report_signature_invalid');
  }
  try {
    validateReportBody(signed.body);
  } catch (error) {
    return fail(
      error instanceof BoundedExecutionReportValidationError
        ? error.code : 'report_schema_invalid',
      true,
      signed.artifact_digest,
    );
  }
  const body = signed.body;
  const mismatch = (condition: boolean, reason: string): RiskRecord | null => (
    condition ? fail(reason, true, signed.artifact_digest) : null
  );
  const checks: Array<[boolean, string]> = [
    [body.report_id !== context.expected_report_id, 'report_id_mismatch'],
    [body.relying_party_id !== context.expected_relying_party_id, 'relying_party_mismatch'],
    [body.tenant_id !== context.expected_tenant_id, 'tenant_mismatch'],
    [body.program_id !== context.expected_program_id, 'program_id_mismatch'],
    [body.program_version !== context.expected_program_version, 'program_version_mismatch'],
    [body.program_digest !== context.expected_program_digest, 'program_digest_mismatch'],
    [body.subject_id !== context.expected_subject_id, 'subject_mismatch'],
    [body.audience !== context.expected_audience, 'audience_mismatch'],
    [body.report_interval.start !== context.expected_report_interval.start
      || body.report_interval.end !== context.expected_report_interval.end,
    'report_interval_mismatch'],
    [body.runtime_state_digest !== context.expected_runtime_state_digest,
      'runtime_state_digest_mismatch'],
    [body.occurrence_inventory_digest !== context.expected_occurrence_inventory_digest,
      'occurrence_inventory_digest_mismatch'],
    [body.report_snapshot_marker !== context.expected_report_snapshot_marker,
      'report_snapshot_marker_mismatch'],
  ];
  for (const [condition, reason] of checks) {
    const result = mismatch(condition, reason);
    if (result) return result;
  }
  const now = Date.parse(context.now);
  const generatedAt = Date.parse(body.generated_at);
  if (generatedAt > now) return fail('report_generated_in_future', true, signed.artifact_digest);
  if (now - generatedAt > context.max_report_age_ms) {
    return fail('report_stale', true, signed.artifact_digest);
  }
  return riskFreeze({
    accepted: true,
    verified: true,
    reason: null,
    report_digest: signed.artifact_digest,
    report_id: body.report_id,
    relying_party_id: body.relying_party_id,
    tenant_id: body.tenant_id,
    program_id: body.program_id,
    program_version: body.program_version,
    program_digest: body.program_digest,
    subject_id: body.subject_id,
    audience: body.audience,
    report_interval: body.report_interval,
    generated_at: body.generated_at,
    runtime_state_digest: body.runtime_state_digest,
    occurrence_inventory_digest: body.occurrence_inventory_digest,
    report_snapshot_marker: body.report_snapshot_marker,
    status: body.status,
    supersession: body.supersession,
    issuer_id: body.issuer.id,
    key_id: body.issuer.key_id,
    claim_boundary: BOUNDED_EXECUTION_REPORT_CLAIM_BOUNDARY,
    outside_plan_claim: BOUNDED_EXECUTION_REPORT_OUTSIDE_PLAN_CLAIM,
  });
}
