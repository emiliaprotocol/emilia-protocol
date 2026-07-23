// SPDX-License-Identifier: Apache-2.0
/**
 * Durable coordinator for heterogeneous Remedy Program case sets.
 *
 * A case set is an immutable tenant-scoped manifest. Every leg names one exact
 * child Remedy Program case and exact remedy bindings. The coordinator can
 * become terminal only after the repository's signed child-receipt verifier
 * accepts every leg against its full child state snapshot.
 */
import crypto from 'node:crypto';

import { canonicalize } from '../execution-binding.js';
import { verifyRemedyProgramReceipt } from './remedy-program-receipt.js';

export const REMEDY_CASE_SET_VERSION = 'EP-GATE-REMEDY-CASE-SET-v1';

type DataRecord = Record<string, any>;
type Failure = Readonly<{ ok: false; reason: string }>;

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,255}$/;
const CREATE_KEYS = new Set(['tenantId', 'caseSetId', 'ownerToken', 'legs']);
const RECORD_KEYS = new Set([
  'tenantId', 'caseSetId', 'ownerToken', 'expectedRevision', 'children',
]);
const STATUS_KEYS = new Set(['tenantId', 'caseSetId']);
const LEG_KEYS = new Set([
  'leg_id', 'child_instance_id', 'remedy_profile_digest',
  'destination_binding_digest', 'max_remedy_units', 'unit', 'original', 'remedy',
]);
const ORIGINAL_KEYS = new Set([
  'caid', 'action_digest', 'operation_id', 'consequence_mode',
  'consequence_digest', 'terminal_evidence_digest', 'outcome', 'occurred_at',
]);
const REMEDY_KEYS = new Set([
  'operation_id', 'caid', 'action_digest', 'owner_mode', 'owner_digest',
]);
const MANIFEST_KEYS = new Set(['version', 'tenant_id', 'case_set_id', 'legs']);
const CHILD_INPUT_KEYS = new Set(['legId', 'state', 'receipt']);
const OBSERVATION_KEYS = new Set([
  'leg_id', 'status', 'case_revision', 'receipt_content_digest',
  'state_snapshot_digest',
]);
const STATE_KEYS = new Set([
  'version', 'tenant_id', 'case_set_id', 'status', 'revision', 'created_at',
  'updated_at', 'owner_token_digest', 'manifest', 'manifest_digest',
  'observations', 'create_request_digest', 'last_request_digest',
]);
const ISSUER_KEYS = new Set(['issuer', 'tenant', 'environment', 'audience', 'key_id']);

export interface RemedyCaseSetState extends Record<string, unknown> {
  version: string;
  tenant_id: string;
  case_set_id: string;
  status: 'open' | 'indeterminate' | 'completed';
  revision: number;
}

export interface RemedyCaseSetResult extends Record<string, unknown> {
  ok: boolean;
  reason?: string;
  state?: RemedyCaseSetState;
}

export interface RemedyCaseSetStore {
  readonly durable: boolean;
  create(state: RemedyCaseSetState): unknown | Promise<unknown>;
  get(input: Readonly<{ tenantId: string; caseSetId: string }>): unknown | Promise<unknown>;
  compareAndSwap(input: Readonly<{
    tenantId: string;
    caseSetId: string;
    expectedRevision: number;
    ownerTokenDigest: string;
    state: RemedyCaseSetState;
  }>): unknown | Promise<unknown>;
}

export interface RemedyCaseSetCoordinatorOptions {
  store: RemedyCaseSetStore;
  tenantId: string;
  trustedReceiptKeys: Record<string, string>;
  expectedReceiptIssuer: {
    issuer: string;
    tenant: string;
    environment: string;
    audience: string;
    key_id: string;
  };
  now?: () => number;
}

function isRecord(value: unknown): value is DataRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDataRecord(value: unknown): value is DataRecord {
  if (!isRecord(value)) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function exactKeys(value: unknown, keys: Set<string>): value is DataRecord {
  return isDataRecord(value)
    && Object.keys(value).length === keys.size
    && Object.keys(value).every((key) => keys.has(key));
}

function validId(value: unknown): value is string {
  return typeof value === 'string' && ID.test(value);
}

function validContext(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
    && Buffer.byteLength(value, 'utf8') <= 512
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function instant(value: unknown): number {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function canonicalCopy<T>(value: T): T {
  return JSON.parse(canonicalize(value));
}

function canonicalDigest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}

function same(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T): Readonly<T> {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value as DataRecord)) deepFreeze(child);
  return value;
}

function fail(reason: string): Failure {
  return Object.freeze({ ok: false, reason });
}

function validOriginal(value: unknown): value is DataRecord {
  return exactKeys(value, ORIGINAL_KEYS)
    && typeof value.caid === 'string' && CAID.test(value.caid)
    && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
    && validId(value.operation_id)
    && ['receipt-program', 'action-escrow'].includes(value.consequence_mode)
    && typeof value.consequence_digest === 'string' && DIGEST.test(value.consequence_digest)
    && typeof value.terminal_evidence_digest === 'string' && DIGEST.test(value.terminal_evidence_digest)
    && ['executed', 'indeterminate'].includes(value.outcome)
    && Number.isFinite(instant(value.occurred_at));
}

function validRemedy(value: unknown): value is DataRecord {
  return exactKeys(value, REMEDY_KEYS)
    && validId(value.operation_id)
    && typeof value.caid === 'string' && CAID.test(value.caid)
    && typeof value.action_digest === 'string' && DIGEST.test(value.action_digest)
    && ['receipt-program', 'action-escrow'].includes(value.owner_mode)
    && typeof value.owner_digest === 'string' && DIGEST.test(value.owner_digest);
}

function validLeg(value: unknown): value is DataRecord {
  return exactKeys(value, LEG_KEYS)
    && validId(value.leg_id)
    && validId(value.child_instance_id)
    && typeof value.remedy_profile_digest === 'string' && DIGEST.test(value.remedy_profile_digest)
    && typeof value.destination_binding_digest === 'string'
    && DIGEST.test(value.destination_binding_digest)
    && Number.isSafeInteger(value.max_remedy_units) && value.max_remedy_units > 0
    && validContext(value.unit)
    && validOriginal(value.original)
    && validRemedy(value.remedy)
    && value.remedy.operation_id !== value.original.operation_id
    && value.remedy.action_digest !== value.original.action_digest;
}

function validManifest(value: unknown, tenantId?: string, caseSetId?: string): value is DataRecord {
  if (!exactKeys(value, MANIFEST_KEYS)
      || value.version !== REMEDY_CASE_SET_VERSION
      || !validContext(value.tenant_id)
      || (tenantId !== undefined && value.tenant_id !== tenantId)
      || !validId(value.case_set_id)
      || (caseSetId !== undefined && value.case_set_id !== caseSetId)
      || !Array.isArray(value.legs) || value.legs.length === 0 || value.legs.length > 256
      || !value.legs.every(validLeg)) return false;
  const unique = (selector: (leg: DataRecord) => string) => (
    new Set(value.legs.map(selector)).size === value.legs.length
  );
  return unique((leg) => leg.leg_id)
    && unique((leg) => leg.child_instance_id)
    && unique((leg) => leg.remedy.operation_id)
    && unique((leg) => leg.remedy.action_digest)
    && unique((leg) => leg.remedy.caid);
}

function validObservation(value: unknown): value is DataRecord {
  if (!exactKeys(value, OBSERVATION_KEYS) || !validId(value.leg_id)
      || !['pending', 'indeterminate', 'executed'].includes(value.status)) return false;
  const pending = value.status === 'pending';
  return pending
    ? value.case_revision === null
      && value.receipt_content_digest === null
      && value.state_snapshot_digest === null
    : Number.isSafeInteger(value.case_revision) && value.case_revision >= 0
      && typeof value.receipt_content_digest === 'string'
      && DIGEST.test(value.receipt_content_digest)
      && typeof value.state_snapshot_digest === 'string'
      && DIGEST.test(value.state_snapshot_digest);
}

function validState(value: unknown, tenantId?: string, caseSetId?: string): value is DataRecord {
  if (!exactKeys(value, STATE_KEYS)
      || value.version !== REMEDY_CASE_SET_VERSION
      || !validContext(value.tenant_id)
      || (tenantId !== undefined && value.tenant_id !== tenantId)
      || !validId(value.case_set_id)
      || (caseSetId !== undefined && value.case_set_id !== caseSetId)
      || !['open', 'indeterminate', 'completed'].includes(value.status)
      || !Number.isSafeInteger(value.revision) || value.revision < 0
      || !Number.isFinite(instant(value.created_at))
      || !Number.isFinite(instant(value.updated_at))
      || instant(value.updated_at) < instant(value.created_at)
      || typeof value.owner_token_digest !== 'string' || !DIGEST.test(value.owner_token_digest)
      || !validManifest(value.manifest, value.tenant_id, value.case_set_id)
      || typeof value.manifest_digest !== 'string'
      || value.manifest_digest !== canonicalDigest(value.manifest)
      || !Array.isArray(value.observations)
      || value.observations.length !== value.manifest.legs.length
      || !value.observations.every(validObservation)
      || typeof value.create_request_digest !== 'string' || !DIGEST.test(value.create_request_digest)
      || (value.last_request_digest !== null
        && (typeof value.last_request_digest !== 'string' || !DIGEST.test(value.last_request_digest)))) {
    return false;
  }
  const legIds = value.manifest.legs.map((leg: DataRecord) => leg.leg_id);
  if (value.observations.some((entry: DataRecord, index: number) => entry.leg_id !== legIds[index])) {
    return false;
  }
  const statuses = value.observations.map((entry: DataRecord) => entry.status);
  if (value.status === 'open') return statuses.every((status: string) => status === 'pending');
  if (value.status === 'completed') return statuses.every((status: string) => status === 'executed');
  return statuses.includes('indeterminate') && statuses.every((status: string) => status !== 'pending');
}

function validIssuer(value: unknown): value is DataRecord {
  return exactKeys(value, ISSUER_KEYS) && Object.values(value).every(validContext);
}

function publicKey(value: unknown): crypto.KeyObject | null {
  try {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.toString('base64url') !== value) return null;
    const key = crypto.createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    return key.asymmetricKeyType === 'ed25519' ? key : null;
  } catch {
    return null;
  }
}

function ownerDigest(value: string): string {
  return canonicalDigest({ owner_token: value });
}

function originalWithoutEvidence(value: DataRecord): DataRecord {
  const result = canonicalCopy(value);
  delete result.evidence_digest;
  return result;
}

/** Build a durable, ownership-fenced coordinator for one pinned tenant. */
export function createRemedyCaseSetCoordinator(options: RemedyCaseSetCoordinatorOptions) {
  if (!isDataRecord(options)
      || !options.store || options.store.durable !== true
      || typeof options.store.create !== 'function'
      || typeof options.store.get !== 'function'
      || typeof options.store.compareAndSwap !== 'function'
      || !validContext(options.tenantId)
      || !validIssuer(options.expectedReceiptIssuer)
      || options.expectedReceiptIssuer.tenant !== options.tenantId
      || !isDataRecord(options.trustedReceiptKeys)
      || Object.keys(options.trustedReceiptKeys).length === 0
      || !Object.entries(options.trustedReceiptKeys).every(
        ([keyId, key]) => validId(keyId) && publicKey(key) !== null,
      )
      || !Object.hasOwn(options.trustedReceiptKeys, options.expectedReceiptIssuer.key_id)
      || (options.now !== undefined && typeof options.now !== 'function')) {
    throw new TypeError('durable Remedy case-set coordinator configuration invalid');
  }
  const sourceStore = options.store;
  const store = Object.freeze({
    create: sourceStore.create.bind(sourceStore),
    get: sourceStore.get.bind(sourceStore),
    compareAndSwap: sourceStore.compareAndSwap.bind(sourceStore),
  });
  const tenantId = options.tenantId;
  const trustedReceiptKeys = deepFreeze(canonicalCopy(options.trustedReceiptKeys));
  const expectedReceiptIssuer = deepFreeze(canonicalCopy(options.expectedReceiptIssuer));
  const now = options.now ?? Date.now;

  const clock = (): number => {
    try {
      const value = now();
      return Number.isSafeInteger(value) && value >= 0 ? value : NaN;
    } catch {
      return NaN;
    }
  };

  const checkedState = (value: unknown, caseSetId: string): RemedyCaseSetResult => {
    try {
      const state = canonicalCopy(value);
      return validState(state, tenantId, caseSetId)
        ? { ok: true, state: deepFreeze(state) as RemedyCaseSetState }
        : fail('store_state_invalid');
    } catch {
      return fail('store_state_invalid');
    }
  };

  const load = async (caseSetId: string): Promise<RemedyCaseSetResult> => {
    try {
      const result: any = await store.get({ tenantId, caseSetId });
      if (!isDataRecord(result)) return fail('store_response_invalid');
      if (result.ok === true) return checkedState(result.state, caseSetId);
      if (result.reason === 'case_set_not_found') return fail('case_set_not_found');
      return fail('store_operation_failed');
    } catch {
      return fail('store_unavailable');
    }
  };

  async function create(input: unknown): Promise<RemedyCaseSetResult> {
    let value: DataRecord;
    try {
      value = canonicalCopy(input) as DataRecord;
    } catch {
      return fail('case_set_create_input_invalid');
    }
    if (!exactKeys(value, CREATE_KEYS)
        || value.tenantId !== tenantId
        || !validId(value.caseSetId)
        || !validContext(value.ownerToken) || Buffer.byteLength(value.ownerToken, 'utf8') > 256
        || !Array.isArray(value.legs)) return fail('case_set_create_input_invalid');
    const manifest = {
      version: REMEDY_CASE_SET_VERSION,
      tenant_id: tenantId,
      case_set_id: value.caseSetId,
      legs: value.legs,
    };
    if (!validManifest(manifest, tenantId, value.caseSetId)) {
      return fail('case_set_manifest_invalid');
    }
    const requestDigest = canonicalDigest(value);
    const existing = await load(value.caseSetId);
    if (existing.ok) {
      return (existing.state as DataRecord).create_request_digest === requestDigest
        ? { ok: true, idempotent: true, state: existing.state }
        : fail('case_set_exists');
    }
    if (existing.reason !== 'case_set_not_found') return existing;
    const at = clock();
    if (!Number.isFinite(at)) return fail('clock_invalid');
    const timestamp = new Date(at).toISOString();
    const state: DataRecord = {
      version: REMEDY_CASE_SET_VERSION,
      tenant_id: tenantId,
      case_set_id: value.caseSetId,
      status: 'open',
      revision: 0,
      created_at: timestamp,
      updated_at: timestamp,
      owner_token_digest: ownerDigest(value.ownerToken),
      manifest: canonicalCopy(manifest),
      manifest_digest: canonicalDigest(manifest),
      observations: manifest.legs.map((entry: DataRecord) => ({
        leg_id: entry.leg_id,
        status: 'pending',
        case_revision: null,
        receipt_content_digest: null,
        state_snapshot_digest: null,
      })),
      create_request_digest: requestDigest,
      last_request_digest: null,
    };
    if (!validState(state, tenantId, value.caseSetId)) return fail('case_set_manifest_invalid');
    try {
      const stored: any = await store.create(deepFreeze(canonicalCopy(state)) as RemedyCaseSetState);
      if (!isDataRecord(stored)) return fail('store_response_invalid');
      if (stored.ok === true) return checkedState(stored.state ?? state, value.caseSetId);
      if (stored.reason !== 'case_set_exists') return fail('store_operation_failed');
      const raced = await load(value.caseSetId);
      return raced.ok && (raced.state as DataRecord).create_request_digest === requestDigest
        ? { ok: true, idempotent: true, state: raced.state }
        : fail('case_set_exists');
    } catch {
      return fail('store_unavailable');
    }
  }

  function verifyChild(
    child: DataRecord,
    leg: DataRecord,
    previous: DataRecord,
  ): DataRecord | Failure {
    try {
      const state = canonicalCopy(child.state);
      if (!isDataRecord(state)
          || state.tenant_id !== tenantId
          || state.instance_id !== leg.child_instance_id
          || state.remedy_profile_digest !== leg.remedy_profile_digest
          || state.destination_binding_digest !== leg.destination_binding_digest
          || state.max_remedy_units !== leg.max_remedy_units
          || state.unit !== leg.unit
          || !same(originalWithoutEvidence(state.original), leg.original)) {
        return fail('child_receipt_binding_mismatch');
      }
      const attempts = [
        ...(state.active_remedy === null ? [] : [state.active_remedy]),
        ...(Array.isArray(state.remedies) ? state.remedies : []),
      ];
      if (attempts.length !== 1) return fail('child_receipt_binding_mismatch');
      const attempt = attempts[0];
      if (!isDataRecord(attempt)
          || attempt.remedy_operation_id !== leg.remedy.operation_id
          || attempt.remedy_caid !== leg.remedy.caid
          || attempt.remedy_action_digest !== leg.remedy.action_digest
          || attempt.destination_binding_digest !== leg.destination_binding_digest
          || attempt.units !== leg.max_remedy_units
          || attempt.unit !== leg.unit) return fail('child_receipt_binding_mismatch');
      const expected = {
        original_operation_id: leg.original.operation_id,
        original_action_digest: leg.original.action_digest,
        original_terminal_evidence_digest: leg.original.terminal_evidence_digest,
        case_instance_id: leg.child_instance_id,
        case_revision: state.revision,
        case_status: state.status,
        remedy_operation_id: leg.remedy.operation_id,
        remedy_action_digest: leg.remedy.action_digest,
        remedy_caid: leg.remedy.caid,
        destination_binding_digest: leg.destination_binding_digest,
        units: leg.max_remedy_units,
        unit: leg.unit,
        owner_mode: leg.remedy.owner_mode,
        owner_digest: leg.remedy.owner_digest,
      };
      const verified = verifyRemedyProgramReceipt(child.receipt, {
        trustedKeys: trustedReceiptKeys,
        expectedIssuer: expectedReceiptIssuer,
        state,
        expected,
      });
      if (verified.valid !== true || !isDataRecord(verified.payload)) {
        return fail(verified.reason === 'receipt_expected_binding_mismatch'
          || verified.reason === 'receipt_state_snapshot_mismatch'
          ? 'child_receipt_binding_mismatch' : 'child_receipt_invalid');
      }
      const remedy = verified.payload.remedy;
      const caseRecord = verified.payload.case;
      let status: 'executed' | 'indeterminate';
      if (remedy.status === 'executed' && remedy.outcome === 'executed'
          && state.status === 'remedied' && state.active_remedy === null
          && state.remedied_units === leg.max_remedy_units && state.remaining_units === 0) {
        status = 'executed';
      } else if (remedy.status === 'indeterminate' && remedy.outcome === 'indeterminate'
          && state.status === 'remedy_indeterminate' && state.active_remedy !== null) {
        status = 'indeterminate';
      } else {
        return fail('child_not_terminal_or_indeterminate');
      }
      const observation = {
        leg_id: leg.leg_id,
        status,
        case_revision: state.revision,
        receipt_content_digest: verified.content_digest,
        state_snapshot_digest: caseRecord.state_snapshot_digest,
      };
      if (previous.status === 'executed' && !same(previous, observation)) {
        return fail('completed_child_substitution');
      }
      if (previous.status !== 'pending') {
        if (observation.case_revision < previous.case_revision) return fail('child_revision_regression');
        if (observation.case_revision === previous.case_revision && !same(previous, observation)) {
          return fail('child_revision_conflict');
        }
      }
      return observation;
    } catch {
      return fail('child_receipt_invalid');
    }
  }

  async function recordChildren(input: unknown): Promise<RemedyCaseSetResult> {
    let value: DataRecord;
    try {
      value = canonicalCopy(input) as DataRecord;
    } catch {
      return fail('case_set_children_input_invalid');
    }
    if (!exactKeys(value, RECORD_KEYS)
        || value.tenantId !== tenantId
        || !validId(value.caseSetId)
        || !validContext(value.ownerToken) || Buffer.byteLength(value.ownerToken, 'utf8') > 256
        || !Number.isSafeInteger(value.expectedRevision) || value.expectedRevision < 0
        || !Array.isArray(value.children)) return fail('case_set_children_input_invalid');
    const loaded = await load(value.caseSetId);
    if (!loaded.ok) return loaded;
    const state = loaded.state as DataRecord;
    const requestDigest = canonicalDigest(value);
    if (state.last_request_digest === requestDigest) {
      return { ok: true, idempotent: true, state: loaded.state };
    }
    if (state.status === 'completed') return fail('case_set_terminal');
    if (state.owner_token_digest !== ownerDigest(value.ownerToken)) return fail('ownership_conflict');
    if (state.revision !== value.expectedRevision) return fail('state_transition_conflict');
    if (value.children.length !== state.manifest.legs.length) return fail('case_set_incomplete');
    const byLeg = new Map<string, DataRecord>();
    for (const child of value.children) {
      if (!exactKeys(child, CHILD_INPUT_KEYS) || !validId(child.legId) || byLeg.has(child.legId)) {
        return fail('case_set_child_set_invalid');
      }
      byLeg.set(child.legId, child);
    }
    if (state.manifest.legs.some((leg: DataRecord) => !byLeg.has(leg.leg_id))) {
      return fail('case_set_incomplete');
    }
    const observations: DataRecord[] = [];
    for (const [index, leg] of state.manifest.legs.entries()) {
      const result = verifyChild(byLeg.get(leg.leg_id)!, leg, state.observations[index]);
      if (result.ok === false && typeof result.reason === 'string') return result as Failure;
      observations.push(result as DataRecord);
    }
    const receiptDigests = observations.map((entry) => entry.receipt_content_digest);
    if (new Set(receiptDigests).size !== receiptDigests.length) {
      return fail('child_evidence_replayed');
    }
    const at = clock();
    if (!Number.isFinite(at)) return fail('clock_invalid');
    if (at < instant(state.updated_at)) return fail('clock_regression');
    const next = canonicalCopy(state);
    next.revision += 1;
    next.updated_at = new Date(at).toISOString();
    next.observations = observations;
    next.status = observations.every((entry) => entry.status === 'executed')
      ? 'completed' : 'indeterminate';
    next.last_request_digest = requestDigest;
    if (next.manifest_digest !== state.manifest_digest || !same(next.manifest, state.manifest)
        || !validState(next, tenantId, value.caseSetId)) return fail('case_set_state_invalid');
    try {
      const stored: any = await store.compareAndSwap({
        tenantId,
        caseSetId: value.caseSetId,
        expectedRevision: state.revision,
        ownerTokenDigest: state.owner_token_digest,
        state: deepFreeze(canonicalCopy(next)) as RemedyCaseSetState,
      });
      if (!isDataRecord(stored)) return fail('store_response_invalid');
      if (stored.ok === true) return checkedState(stored.state ?? next, value.caseSetId);
      if (stored.reason === 'revision_conflict') return fail('state_transition_conflict');
      if (stored.reason === 'ownership_conflict') return fail('ownership_conflict');
      return fail('store_operation_failed');
    } catch {
      return fail('store_unavailable');
    }
  }

  async function status(input: unknown): Promise<RemedyCaseSetResult> {
    let value: DataRecord;
    try {
      value = canonicalCopy(input) as DataRecord;
    } catch {
      return fail('case_set_lookup_invalid');
    }
    if (!exactKeys(value, STATUS_KEYS) || value.tenantId !== tenantId || !validId(value.caseSetId)) {
      return fail('case_set_lookup_invalid');
    }
    return load(value.caseSetId);
  }

  return Object.freeze({ create, recordChildren, status });
}

export default Object.freeze({
  REMEDY_CASE_SET_VERSION,
  createRemedyCaseSetCoordinator,
});
