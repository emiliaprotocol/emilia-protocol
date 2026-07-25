// SPDX-License-Identifier: Apache-2.0
/**
 * Runtime counterpart for Conservation of Authority.
 *
 * This module keeps path containment and aggregate sibling conservation
 * separate. A relying party pins one complete parent allocation snapshot to an
 * exact authority head and epoch. Every sibling is checked against that parent,
 * both resource dimensions are summed independently, and reservations cross a
 * single atomic store boundary before they can be committed.
 *
 * The memory store is deterministic conformance infrastructure, not durable
 * custody. The PostgreSQL adapter requires a real transaction callback and
 * serializes every mutation for one relying-party/parent pair.
 */

import crypto from 'node:crypto';

export const AUTHORITY_ALLOCATION_VERSION = 'EP-AUTHORITY-ALLOCATION-v1';
export const AUTHORITY_ALLOCATION_CURRENT_TABLE = 'ep_authority_allocation_current';
export const AUTHORITY_ALLOCATION_SNAPSHOT_TABLE = 'ep_authority_allocation_snapshots';
export const AUTHORITY_ALLOCATION_BRANCH_TABLE = 'ep_authority_allocation_branches';
export const AUTHORITY_ALLOCATION_RESERVATION_TABLE = 'ep_authority_allocation_reservations';

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{0,511}$/;
const OWNER_PATTERN = /^authority-owner:v1:[A-Za-z0-9_-]{16,128}$/;
const RFC3339_INSTANT =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const OWNER_DIGEST_DOMAIN = 'EMILIA-AUTHORITY-ALLOCATION-v1:OWNER\0';

export interface AuthorityAllocationBudget {
  cents: number;
  calls: number;
}

export interface AuthorityAllocationPin {
  relying_party_id: string;
  authority_head: string;
  authority_epoch: number;
}

export interface AuthorityBranchAllocation {
  allocation_id: string;
  parent_id: string;
  actions: readonly string[];
  audiences: readonly string[];
  budget: AuthorityAllocationBudget;
  expires_at: string;
}

export interface AuthorityAllocationSnapshot {
  version: typeof AUTHORITY_ALLOCATION_VERSION;
  relying_party_id: string;
  parent_id: string;
  authority_head: string;
  authority_epoch: number;
  actions: readonly string[];
  audiences: readonly string[];
  budget: AuthorityAllocationBudget;
  expires_at: string;
  sibling_allocations: readonly AuthorityBranchAllocation[];
}

export interface AuthorityAllocationReservationRequest {
  relying_party_id: string;
  parent_id: string;
  allocation_id: string;
  reservation_id: string;
  authority_head: string;
  authority_epoch: number;
  budget: AuthorityAllocationBudget;
  /** Used by the deterministic memory adapter. PostgreSQL uses database time. */
  now?: string | number | Date;
}

export interface AuthorityAllocationOwner {
  owner_token: string;
  fencing_token: number;
  authority_head: string;
  authority_epoch: number;
}

export interface AuthorityAllocationFinalizeRequest {
  relying_party_id: string;
  parent_id: string;
  allocation_id: string;
  reservation_id: string;
  authority_head: string;
  authority_epoch: number;
  owner_token: string;
  fencing_token: number;
}

export type AuthorityAllocationRefusalReason =
  | 'allocation_not_found'
  | 'allocation_expired'
  | 'authority_pin_mismatch'
  | 'budget_exceeded'
  | 'reservation_replayed'
  | 'reservation_not_found'
  | 'reservation_owner_mismatch'
  | 'reservation_already_committed'
  | 'reservation_already_released'
  | 'snapshot_conflict'
  | 'stale_authority_epoch'
  | 'reservations_in_flight';

export type AuthorityAllocationInstallResult =
  | { ok: true; installed: boolean; snapshot_fingerprint: string }
  | { ok: false; reason: AuthorityAllocationRefusalReason };

export type AuthorityAllocationReservationResult =
  | {
    ok: true;
    reservation_id: string;
    allocation_id: string;
    budget: AuthorityAllocationBudget;
    remaining: AuthorityAllocationBudget;
    owner: AuthorityAllocationOwner;
  }
  | { ok: false; reason: AuthorityAllocationRefusalReason };

export type AuthorityAllocationFinalizeResult =
  | { ok: true; state: 'committed' | 'released' }
  | { ok: false; reason: AuthorityAllocationRefusalReason };

export interface AuthorityAllocationReservationView {
  reservation_id: string;
  allocation_id: string;
  authority_head: string;
  authority_epoch: number;
  budget: AuthorityAllocationBudget;
  state: 'reserved' | 'committed' | 'released';
  fencing_token: number;
}

export interface AuthorityAllocationStateView {
  snapshot: AuthorityAllocationSnapshot;
  snapshot_fingerprint: string;
  usage: {
    parent: {
      reserved: AuthorityAllocationBudget;
      committed: AuthorityAllocationBudget;
    };
    branches: Record<string, {
      reserved: AuthorityAllocationBudget;
      committed: AuthorityAllocationBudget;
    }>;
  };
  reservations: AuthorityAllocationReservationView[];
}

export interface AuthorityAllocationStore {
  readonly durable: boolean;
  installSnapshot(
    snapshot: AuthorityAllocationSnapshot,
    pin: AuthorityAllocationPin,
  ): Promise<AuthorityAllocationInstallResult>;
  reserve(
    request: AuthorityAllocationReservationRequest,
  ): Promise<AuthorityAllocationReservationResult>;
  commit(
    request: AuthorityAllocationFinalizeRequest,
  ): Promise<AuthorityAllocationFinalizeResult>;
  release(
    request: AuthorityAllocationFinalizeRequest,
  ): Promise<AuthorityAllocationFinalizeResult>;
  inspect(pin: AuthorityAllocationPin & {
    parent_id: string;
  }): Promise<AuthorityAllocationStateView | null>;
}

export class AuthorityAllocationValidationError extends TypeError {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'AuthorityAllocationValidationError';
    this.code = code;
  }
}

type MutableReservation = AuthorityAllocationReservationView & {
  owner_token: string;
};

type MemoryParentState = {
  snapshot: AuthorityAllocationSnapshot;
  fingerprint: string;
  nextFence: number;
  reservations: Map<string, MutableReservation>;
};

type QueryRow = Record<string, unknown>;

export interface AuthorityAllocationPostgresQueryResult {
  rowCount: number | null;
  rows: QueryRow[];
}

export type AuthorityAllocationPostgresQuery = (
  text: string,
  params?: readonly unknown[],
) => Promise<AuthorityAllocationPostgresQueryResult>;

export interface AuthorityAllocationPostgresOptions {
  /**
   * Must run the callback in one PostgreSQL transaction. Database errors must
   * reject the callback so the transaction is rolled back.
   */
  transaction<T>(callback: (query: AuthorityAllocationPostgresQuery) => Promise<T>): Promise<T>;
}

function fail(code: string, message: string): never {
  throw new AuthorityAllocationValidationError(code, message);
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    fail('invalid_identifier', `${field} must be a non-empty bounded identifier`);
  }
  return value;
}

function authorityHead(value: unknown, field: string): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    fail('missing_authority_pin', `${field} must be an exact lowercase SHA-256 authority head`);
  }
  return value;
}

function authorityEpoch(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    fail('missing_authority_pin', `${field} must be a non-negative safe integer`);
  }
  return value as number;
}

function budget(value: unknown, field: string): AuthorityAllocationBudget {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('invalid_budget', `${field} must contain independent cents and calls limits`);
  }
  const candidate = value as Record<string, unknown>;
  for (const dimension of ['cents', 'calls'] as const) {
    if (!Number.isSafeInteger(candidate[dimension]) || (candidate[dimension] as number) < 0) {
      fail('invalid_budget', `${field}.${dimension} must be a non-negative safe integer`);
    }
  }
  return {
    cents: candidate.cents as number,
    calls: candidate.calls as number,
  };
}

function checkedAdd(left: number, right: number, field: string): number {
  const sum = left + right;
  if (!Number.isSafeInteger(sum)) fail('budget_overflow', `${field} exceeds safe integer range`);
  return sum;
}

function addBudget(
  left: AuthorityAllocationBudget,
  right: AuthorityAllocationBudget,
  field = 'budget',
): AuthorityAllocationBudget {
  return {
    cents: checkedAdd(left.cents, right.cents, `${field}.cents`),
    calls: checkedAdd(left.calls, right.calls, `${field}.calls`),
  };
}

function subtractBudget(
  ceiling: AuthorityAllocationBudget,
  used: AuthorityAllocationBudget,
): AuthorityAllocationBudget {
  return {
    cents: ceiling.cents - used.cents,
    calls: ceiling.calls - used.calls,
  };
}

function withinBudget(
  candidate: AuthorityAllocationBudget,
  ceiling: AuthorityAllocationBudget,
): boolean {
  return candidate.cents <= ceiling.cents && candidate.calls <= ceiling.calls;
}

function strictInstantMs(value: unknown, field: string): number {
  if (typeof value !== 'string') fail('invalid_expiry', `${field} must be an RFC 3339 instant`);
  const match = value.match(RFC3339_INSTANT);
  if (!match) fail('invalid_expiry', `${field} must be an RFC 3339 instant`);
  const [
    , yearText, monthText, dayText, hourText, minuteText, secondText,
    , offsetHourText, offsetMinuteText,
  ] = match;
  const localText = `${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondText}`;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(yearText), Number(monthText) - 1, Number(dayText));
  calendar.setUTCHours(Number(hourText), Number(minuteText), Number(secondText), 0);
  if (calendar.toISOString().slice(0, 19) !== localText) {
    fail('invalid_expiry', `${field} contains an impossible calendar instant`);
  }
  if (offsetHourText !== undefined
    && (Number(offsetHourText) > 23 || Number(offsetMinuteText) > 59)) {
    fail('invalid_expiry', `${field} contains an invalid offset`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail('invalid_expiry', `${field} must be an RFC 3339 instant`);
  return parsed;
}

function operationTimeMs(value: string | number | Date | undefined): number {
  if (value === undefined) return Date.now();
  const parsed = value instanceof Date
    ? value.getTime()
    : typeof value === 'string'
      ? strictInstantMs(value, 'now')
      : value;
  if (!Number.isFinite(parsed)) fail('invalid_time', 'now must identify a finite instant');
  return parsed;
}

function exactSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) fail('invalid_selector_set', `${field} must be an array`);
  const result = value.map((entry, index) => identifier(entry, `${field}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail('duplicate_selector', `${field} must not contain duplicate selectors`);
  }
  return result.sort();
}

function isSubset(child: readonly string[], parent: readonly string[]): boolean {
  const parentSet = new Set(parent);
  return child.every((entry) => parentSet.has(entry));
}

function cloneSnapshot(snapshot: AuthorityAllocationSnapshot): AuthorityAllocationSnapshot {
  return {
    ...snapshot,
    actions: [...snapshot.actions],
    audiences: [...snapshot.audiences],
    budget: { ...snapshot.budget },
    sibling_allocations: snapshot.sibling_allocations.map((allocation) => ({
      ...allocation,
      actions: [...allocation.actions],
      audiences: [...allocation.audiences],
      budget: { ...allocation.budget },
    })),
  };
}

function canonicalSnapshot(snapshot: AuthorityAllocationSnapshot): string {
  return JSON.stringify({
    version: snapshot.version,
    relying_party_id: snapshot.relying_party_id,
    parent_id: snapshot.parent_id,
    authority_head: snapshot.authority_head,
    authority_epoch: snapshot.authority_epoch,
    actions: snapshot.actions,
    audiences: snapshot.audiences,
    budget: snapshot.budget,
    expires_at: snapshot.expires_at,
    sibling_allocations: snapshot.sibling_allocations,
  });
}

function snapshotFingerprint(snapshot: AuthorityAllocationSnapshot): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalSnapshot(snapshot)).digest('hex')}`;
}

function parentKey(relyingPartyId: string, parentId: string): string {
  return JSON.stringify([relyingPartyId, parentId]);
}

function emptyBudget(): AuthorityAllocationBudget {
  return { cents: 0, calls: 0 };
}

function assertExactPin(
  actual: Pick<AuthorityAllocationSnapshot, 'relying_party_id' | 'authority_head' | 'authority_epoch'>,
  expected: AuthorityAllocationPin,
): void {
  const relyingPartyId = identifier(expected?.relying_party_id, 'pin.relying_party_id');
  const head = authorityHead(expected?.authority_head, 'pin.authority_head');
  const epoch = authorityEpoch(expected?.authority_epoch, 'pin.authority_epoch');
  if (actual.relying_party_id !== relyingPartyId
    || actual.authority_head !== head
    || actual.authority_epoch !== epoch) {
    fail('authority_pin_mismatch', 'snapshot does not match the relying-party authority pin');
  }
}

/**
 * Validate and normalize a complete authoritative allocation snapshot.
 * Throws AuthorityAllocationValidationError on every malformed or widening
 * condition and returns a detached, deterministically ordered snapshot.
 */
export function validateAuthorityAllocationSnapshot(
  input: AuthorityAllocationSnapshot,
  pin: AuthorityAllocationPin,
): AuthorityAllocationSnapshot {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    fail('invalid_snapshot', 'authority allocation snapshot must be an object');
  }
  if (input.version !== AUTHORITY_ALLOCATION_VERSION) {
    fail('unsupported_version', `snapshot.version must be ${AUTHORITY_ALLOCATION_VERSION}`);
  }
  const relyingPartyId = identifier(input.relying_party_id, 'snapshot.relying_party_id');
  const parentId = identifier(input.parent_id, 'snapshot.parent_id');
  const head = authorityHead(input.authority_head, 'snapshot.authority_head');
  const epoch = authorityEpoch(input.authority_epoch, 'snapshot.authority_epoch');
  const parentActions = exactSet(input.actions, 'snapshot.actions');
  const parentAudiences = exactSet(input.audiences, 'snapshot.audiences');
  const parentBudget = budget(input.budget, 'snapshot.budget');
  const parentExpiryMs = strictInstantMs(input.expires_at, 'snapshot.expires_at');
  if (!Array.isArray(input.sibling_allocations)) {
    fail('invalid_siblings', 'snapshot.sibling_allocations must be an array');
  }

  const seen = new Set<string>();
  let aggregate = emptyBudget();
  const siblings = input.sibling_allocations.map((raw, index) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      fail('invalid_branch', `snapshot.sibling_allocations[${index}] must be an object`);
    }
    const allocationId = identifier(raw.allocation_id, `sibling[${index}].allocation_id`);
    if (seen.has(allocationId)) fail('duplicate_branch', `duplicate allocation branch ${allocationId}`);
    seen.add(allocationId);
    const childParentId = identifier(raw.parent_id, `sibling[${index}].parent_id`);
    if (childParentId !== parentId) {
      fail('parent_mismatch', `allocation ${allocationId} does not name the authoritative parent`);
    }
    const actions = exactSet(raw.actions, `sibling[${index}].actions`);
    if (!isSubset(actions, parentActions)) {
      fail('child_action_widening', `allocation ${allocationId} widens the parent action set`);
    }
    const audiences = exactSet(raw.audiences, `sibling[${index}].audiences`);
    if (!isSubset(audiences, parentAudiences)) {
      fail('child_audience_widening', `allocation ${allocationId} widens the parent audience set`);
    }
    const childBudget = budget(raw.budget, `sibling[${index}].budget`);
    if (!withinBudget(childBudget, parentBudget)) {
      fail('child_budget_widening', `allocation ${allocationId} widens a parent budget dimension`);
    }
    const childExpiryMs = strictInstantMs(raw.expires_at, `sibling[${index}].expires_at`);
    if (childExpiryMs > parentExpiryMs) {
      fail('child_expiry_widening', `allocation ${allocationId} outlives its parent`);
    }
    aggregate = addBudget(aggregate, childBudget, 'aggregate_sibling_budget');
    return {
      allocation_id: allocationId,
      parent_id: childParentId,
      actions,
      audiences,
      budget: childBudget,
      expires_at: raw.expires_at,
    };
  }).sort((left, right) => left.allocation_id.localeCompare(right.allocation_id));

  if (!withinBudget(aggregate, parentBudget)) {
    fail('aggregate_sibling_overspend', 'aggregate sibling cents or calls exceed the parent budget');
  }

  const normalized: AuthorityAllocationSnapshot = {
    version: AUTHORITY_ALLOCATION_VERSION,
    relying_party_id: relyingPartyId,
    parent_id: parentId,
    authority_head: head,
    authority_epoch: epoch,
    actions: parentActions,
    audiences: parentAudiences,
    budget: parentBudget,
    expires_at: input.expires_at,
    sibling_allocations: siblings,
  };
  assertExactPin(normalized, pin);
  return normalized;
}

function validateReservationRequest(
  request: AuthorityAllocationReservationRequest,
): AuthorityAllocationReservationRequest {
  return {
    relying_party_id: identifier(request?.relying_party_id, 'request.relying_party_id'),
    parent_id: identifier(request?.parent_id, 'request.parent_id'),
    allocation_id: identifier(request?.allocation_id, 'request.allocation_id'),
    reservation_id: identifier(request?.reservation_id, 'request.reservation_id'),
    authority_head: authorityHead(request?.authority_head, 'request.authority_head'),
    authority_epoch: authorityEpoch(request?.authority_epoch, 'request.authority_epoch'),
    budget: budget(request?.budget, 'request.budget'),
    ...(request?.now === undefined ? {} : { now: request.now }),
  };
}

function validateFinalizeRequest(
  request: AuthorityAllocationFinalizeRequest,
): AuthorityAllocationFinalizeRequest {
  const ownerToken = request?.owner_token;
  if (typeof ownerToken !== 'string' || !OWNER_PATTERN.test(ownerToken)) {
    fail('invalid_owner_token', 'owner_token must be an authority-allocation owner capability');
  }
  if (!Number.isSafeInteger(request?.fencing_token) || request.fencing_token < 1) {
    fail('invalid_fencing_token', 'fencing_token must be a positive safe integer');
  }
  return {
    relying_party_id: identifier(request.relying_party_id, 'request.relying_party_id'),
    parent_id: identifier(request.parent_id, 'request.parent_id'),
    allocation_id: identifier(request.allocation_id, 'request.allocation_id'),
    reservation_id: identifier(request.reservation_id, 'request.reservation_id'),
    authority_head: authorityHead(request.authority_head, 'request.authority_head'),
    authority_epoch: authorityEpoch(request.authority_epoch, 'request.authority_epoch'),
    owner_token: ownerToken,
    fencing_token: request.fencing_token,
  };
}

function pinMatches(
  state: MemoryParentState,
  head: string,
  epoch: number,
): boolean {
  return state.snapshot.authority_head === head && state.snapshot.authority_epoch === epoch;
}

function usageFor(
  state: MemoryParentState,
  allocationId?: string,
): { reserved: AuthorityAllocationBudget; committed: AuthorityAllocationBudget } {
  let reserved = emptyBudget();
  let committed = emptyBudget();
  for (const reservation of state.reservations.values()) {
    if (allocationId !== undefined && reservation.allocation_id !== allocationId) continue;
    if (reservation.authority_head !== state.snapshot.authority_head
      || reservation.authority_epoch !== state.snapshot.authority_epoch) continue;
    if (reservation.state === 'reserved') {
      reserved = addBudget(reserved, reservation.budget);
    } else if (reservation.state === 'committed') {
      committed = addBudget(committed, reservation.budget);
    }
  }
  return { reserved, committed };
}

function stateView(state: MemoryParentState): AuthorityAllocationStateView {
  const branches: AuthorityAllocationStateView['usage']['branches'] = Object.create(null);
  for (const allocation of state.snapshot.sibling_allocations) {
    branches[allocation.allocation_id] = usageFor(state, allocation.allocation_id);
  }
  return {
    snapshot: cloneSnapshot(state.snapshot),
    snapshot_fingerprint: state.fingerprint,
    usage: {
      parent: usageFor(state),
      branches,
    },
    reservations: [...state.reservations.values()]
      .map(({ owner_token: _ownerToken, ...reservation }) => ({
        ...reservation,
        budget: { ...reservation.budget },
      }))
      .sort((left, right) => left.fencing_token - right.fencing_token),
  };
}

/**
 * Deterministic linearizable in-memory implementation for conformance tests.
 * Owner capabilities and fences are deterministic and therefore unsuitable
 * for production. The store is explicitly marked non-durable.
 */
export function createMemoryAuthorityAllocationStore(): AuthorityAllocationStore {
  const parents = new Map<string, MemoryParentState>();
  let queue: Promise<void> = Promise.resolve();
  const atomic = <T>(operation: () => T | Promise<T>): Promise<T> => {
    const result = queue.then(operation, operation);
    queue = result.then(() => undefined, () => undefined);
    return result;
  };

  return {
    durable: false,

    installSnapshot(snapshot, pin) {
      return atomic(() => {
        const normalized = validateAuthorityAllocationSnapshot(snapshot, pin);
        const fingerprint = snapshotFingerprint(normalized);
        const key = parentKey(normalized.relying_party_id, normalized.parent_id);
        const current = parents.get(key);
        if (current) {
          if (current.snapshot.authority_head === normalized.authority_head
            && current.snapshot.authority_epoch === normalized.authority_epoch) {
            return current.fingerprint === fingerprint
              ? { ok: true, installed: false, snapshot_fingerprint: fingerprint }
              : { ok: false, reason: 'snapshot_conflict' };
          }
          if (normalized.authority_epoch <= current.snapshot.authority_epoch) {
            return { ok: false, reason: 'stale_authority_epoch' };
          }
          if ([...current.reservations.values()].some((entry) => entry.state === 'reserved')) {
            return { ok: false, reason: 'reservations_in_flight' };
          }
        }
        parents.set(key, {
          snapshot: cloneSnapshot(normalized),
          fingerprint,
          nextFence: current?.nextFence ?? 1,
          reservations: current?.reservations ?? new Map(),
        });
        return { ok: true, installed: true, snapshot_fingerprint: fingerprint };
      });
    },

    reserve(rawRequest) {
      return atomic(() => {
        const request = validateReservationRequest(rawRequest);
        const state = parents.get(parentKey(request.relying_party_id, request.parent_id));
        if (!state) return { ok: false, reason: 'allocation_not_found' };
        if (!pinMatches(state, request.authority_head, request.authority_epoch)) {
          return { ok: false, reason: 'authority_pin_mismatch' };
        }
        if (state.reservations.has(request.reservation_id)) {
          return { ok: false, reason: 'reservation_replayed' };
        }
        const allocation = state.snapshot.sibling_allocations.find(
          (entry) => entry.allocation_id === request.allocation_id,
        );
        if (!allocation) return { ok: false, reason: 'allocation_not_found' };
        const at = operationTimeMs(request.now);
        if (at >= strictInstantMs(state.snapshot.expires_at, 'snapshot.expires_at')
          || at >= strictInstantMs(allocation.expires_at, 'allocation.expires_at')) {
          return { ok: false, reason: 'allocation_expired' };
        }
        const branchUsage = usageFor(state, allocation.allocation_id);
        const branchUsed = addBudget(branchUsage.reserved, branchUsage.committed);
        const branchCandidate = addBudget(branchUsed, request.budget);
        const parentUsage = usageFor(state);
        const parentUsed = addBudget(parentUsage.reserved, parentUsage.committed);
        const parentCandidate = addBudget(parentUsed, request.budget);
        if (!withinBudget(branchCandidate, allocation.budget)
          || !withinBudget(parentCandidate, state.snapshot.budget)) {
          return { ok: false, reason: 'budget_exceeded' };
        }
        const fencingToken = state.nextFence;
        state.nextFence += 1;
        const ownerToken = `authority-owner:v1:memory_${fencingToken.toString(36).padStart(16, '0')}`;
        state.reservations.set(request.reservation_id, {
          reservation_id: request.reservation_id,
          allocation_id: request.allocation_id,
          authority_head: request.authority_head,
          authority_epoch: request.authority_epoch,
          budget: { ...request.budget },
          state: 'reserved',
          fencing_token: fencingToken,
          owner_token: ownerToken,
        });
        return {
          ok: true,
          reservation_id: request.reservation_id,
          allocation_id: request.allocation_id,
          budget: { ...request.budget },
          remaining: subtractBudget(allocation.budget, branchCandidate),
          owner: {
            owner_token: ownerToken,
            fencing_token: fencingToken,
            authority_head: request.authority_head,
            authority_epoch: request.authority_epoch,
          },
        };
      });
    },

    commit(rawRequest) {
      return atomic(() => {
        const request = validateFinalizeRequest(rawRequest);
        const state = parents.get(parentKey(request.relying_party_id, request.parent_id));
        if (!state) return { ok: false, reason: 'reservation_not_found' };
        if (!pinMatches(state, request.authority_head, request.authority_epoch)) {
          return { ok: false, reason: 'authority_pin_mismatch' };
        }
        const reservation = state.reservations.get(request.reservation_id);
        if (!reservation || reservation.allocation_id !== request.allocation_id) {
          return { ok: false, reason: 'reservation_not_found' };
        }
        if (reservation.state === 'committed') {
          return { ok: false, reason: 'reservation_already_committed' };
        }
        if (reservation.state === 'released') {
          return { ok: false, reason: 'reservation_already_released' };
        }
        if (reservation.owner_token !== request.owner_token
          || reservation.fencing_token !== request.fencing_token
          || reservation.authority_head !== request.authority_head
          || reservation.authority_epoch !== request.authority_epoch) {
          return { ok: false, reason: 'reservation_owner_mismatch' };
        }
        reservation.state = 'committed';
        return { ok: true, state: 'committed' };
      });
    },

    release(rawRequest) {
      return atomic(() => {
        const request = validateFinalizeRequest(rawRequest);
        const state = parents.get(parentKey(request.relying_party_id, request.parent_id));
        if (!state) return { ok: false, reason: 'reservation_not_found' };
        if (!pinMatches(state, request.authority_head, request.authority_epoch)) {
          return { ok: false, reason: 'authority_pin_mismatch' };
        }
        const reservation = state.reservations.get(request.reservation_id);
        if (!reservation || reservation.allocation_id !== request.allocation_id) {
          return { ok: false, reason: 'reservation_not_found' };
        }
        if (reservation.state === 'committed') {
          return { ok: false, reason: 'reservation_already_committed' };
        }
        if (reservation.state === 'released') {
          return { ok: false, reason: 'reservation_already_released' };
        }
        if (reservation.owner_token !== request.owner_token
          || reservation.fencing_token !== request.fencing_token
          || reservation.authority_head !== request.authority_head
          || reservation.authority_epoch !== request.authority_epoch) {
          return { ok: false, reason: 'reservation_owner_mismatch' };
        }
        reservation.state = 'released';
        return { ok: true, state: 'released' };
      });
    },

    inspect(rawPin) {
      return atomic(() => {
        const relyingPartyId = identifier(rawPin?.relying_party_id, 'pin.relying_party_id');
        const parentId = identifier(rawPin?.parent_id, 'pin.parent_id');
        const head = authorityHead(rawPin?.authority_head, 'pin.authority_head');
        const epoch = authorityEpoch(rawPin?.authority_epoch, 'pin.authority_epoch');
        const state = parents.get(parentKey(relyingPartyId, parentId));
        if (!state) return null;
        if (!pinMatches(state, head, epoch)) {
          fail('authority_pin_mismatch', 'inspection requires the exact current authority pin');
        }
        return stateView(state);
      });
    },
  };
}

/**
 * PostgreSQL schema contract. Historical snapshots are append-only;
 * ep_authority_allocation_current identifies the one exact head+epoch that can
 * accept reservations. Reservation IDs are replay-fenced across all epochs for
 * one relying-party/parent pair, and owner capabilities are stored only as
 * domain-separated SHA-256 digests.
 */
export const AUTHORITY_ALLOCATION_DDL = `CREATE TABLE IF NOT EXISTS ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE} (
  relying_party_id    TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),
  parent_id           TEXT NOT NULL CHECK (octet_length(parent_id) BETWEEN 1 AND 512),
  authority_head      TEXT NOT NULL CHECK (authority_head ~ '^sha256:[0-9a-f]{64}$'),
  authority_epoch     BIGINT NOT NULL CHECK (authority_epoch >= 0),
  snapshot_fingerprint TEXT NOT NULL CHECK (snapshot_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  snapshot_json       JSONB NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
  installed_at        TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (relying_party_id, parent_id, authority_head, authority_epoch)
);
CREATE TABLE IF NOT EXISTS ${AUTHORITY_ALLOCATION_CURRENT_TABLE} (
  relying_party_id    TEXT NOT NULL,
  parent_id           TEXT NOT NULL,
  authority_head      TEXT NOT NULL,
  authority_epoch     BIGINT NOT NULL,
  snapshot_fingerprint TEXT NOT NULL,
  next_fencing_token  BIGINT NOT NULL DEFAULT 1 CHECK (next_fencing_token > 0),
  PRIMARY KEY (relying_party_id, parent_id),
  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch)
    REFERENCES ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE}
      (relying_party_id, parent_id, authority_head, authority_epoch)
);
CREATE TABLE IF NOT EXISTS ${AUTHORITY_ALLOCATION_BRANCH_TABLE} (
  relying_party_id TEXT NOT NULL,
  parent_id        TEXT NOT NULL,
  authority_head   TEXT NOT NULL,
  authority_epoch  BIGINT NOT NULL,
  allocation_id    TEXT NOT NULL CHECK (octet_length(allocation_id) BETWEEN 1 AND 512),
  budget_cents     BIGINT NOT NULL CHECK (budget_cents >= 0),
  budget_calls     BIGINT NOT NULL CHECK (budget_calls >= 0),
  expires_at       TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id),
  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch)
    REFERENCES ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE}
      (relying_party_id, parent_id, authority_head, authority_epoch)
);
CREATE TABLE IF NOT EXISTS ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} (
  relying_party_id TEXT NOT NULL,
  parent_id        TEXT NOT NULL,
  authority_head   TEXT NOT NULL,
  authority_epoch  BIGINT NOT NULL,
  allocation_id    TEXT NOT NULL,
  reservation_id   TEXT NOT NULL CHECK (octet_length(reservation_id) BETWEEN 1 AND 512),
  budget_cents     BIGINT NOT NULL CHECK (budget_cents >= 0),
  budget_calls     BIGINT NOT NULL CHECK (budget_calls >= 0),
  state            TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'released')),
  owner_digest     TEXT NOT NULL CHECK (owner_digest ~ '^sha256:[0-9a-f]{64}$'),
  fencing_token    BIGINT NOT NULL CHECK (fencing_token > 0),
  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
  finalized_at     TIMESTAMPTZ NULL,
  PRIMARY KEY (relying_party_id, parent_id, reservation_id),
  UNIQUE (relying_party_id, parent_id, fencing_token),
  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id)
    REFERENCES ${AUTHORITY_ALLOCATION_BRANCH_TABLE}
      (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id),
  CHECK (
    (state = 'reserved' AND finalized_at IS NULL)
    OR (state IN ('committed', 'released') AND finalized_at IS NOT NULL)
  )
);
REVOKE ALL ON ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE} FROM PUBLIC;
REVOKE ALL ON ${AUTHORITY_ALLOCATION_CURRENT_TABLE} FROM PUBLIC;
REVOKE ALL ON ${AUTHORITY_ALLOCATION_BRANCH_TABLE} FROM PUBLIC;
REVOKE ALL ON ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} FROM PUBLIC;`;

/** Exact statements used by createPostgresAuthorityAllocationStore(). */
export const AUTHORITY_ALLOCATION_SQL = Object.freeze({
  lockParent:
    `SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended(pg_catalog.jsonb_build_array($1::text, $2::text)::text, 0))`,
  readCurrent:
    `SELECT authority_head, authority_epoch, snapshot_fingerprint, next_fencing_token, clock_timestamp() AS database_now FROM ${AUTHORITY_ALLOCATION_CURRENT_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 FOR UPDATE`,
  activeReservations:
    `SELECT count(*)::bigint AS active FROM ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 AND state = 'reserved'`,
  insertSnapshot:
    `INSERT INTO ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE} (relying_party_id, parent_id, authority_head, authority_epoch, snapshot_fingerprint, snapshot_json) VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
  insertBranch:
    `INSERT INTO ${AUTHORITY_ALLOCATION_BRANCH_TABLE} (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id, budget_cents, budget_calls, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz)`,
  insertCurrent:
    `INSERT INTO ${AUTHORITY_ALLOCATION_CURRENT_TABLE} (relying_party_id, parent_id, authority_head, authority_epoch, snapshot_fingerprint) VALUES ($1, $2, $3, $4, $5)`,
  advanceCurrent:
    `UPDATE ${AUTHORITY_ALLOCATION_CURRENT_TABLE} SET authority_head = $3, authority_epoch = $4, snapshot_fingerprint = $5 WHERE relying_party_id = $1 AND parent_id = $2 AND authority_epoch < $4`,
  readSnapshot:
    `SELECT snapshot_json, snapshot_fingerprint FROM ${AUTHORITY_ALLOCATION_SNAPSHOT_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4`,
  readBranch:
    `SELECT budget_cents, budget_calls, expires_at FROM ${AUTHORITY_ALLOCATION_BRANCH_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 AND allocation_id = $5`,
  readReservation:
    `SELECT allocation_id, authority_head, authority_epoch, budget_cents, budget_calls, state, owner_digest, fencing_token FROM ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3`,
  readUsage:
    `SELECT allocation_id, state, COALESCE(sum(budget_cents), 0)::bigint AS cents, COALESCE(sum(budget_calls), 0)::bigint AS calls FROM ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 AND state IN ('reserved', 'committed') GROUP BY allocation_id, state`,
  nextFence:
    `UPDATE ${AUTHORITY_ALLOCATION_CURRENT_TABLE} SET next_fencing_token = next_fencing_token + 1 WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 RETURNING next_fencing_token - 1 AS fencing_token`,
  insertReservation:
    `INSERT INTO ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id, reservation_id, budget_cents, budget_calls, state, owner_digest, fencing_token) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'reserved', $9, $10)`,
  commitReservation:
    `UPDATE ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} SET state = 'committed', finalized_at = transaction_timestamp() WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3 AND allocation_id = $4 AND authority_head = $5 AND authority_epoch = $6 AND state = 'reserved' AND owner_digest = $7 AND fencing_token = $8`,
  releaseReservation:
    `UPDATE ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} SET state = 'released', finalized_at = transaction_timestamp() WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3 AND allocation_id = $4 AND authority_head = $5 AND authority_epoch = $6 AND state = 'reserved' AND owner_digest = $7 AND fencing_token = $8`,
  inspectReservations:
    `SELECT reservation_id, allocation_id, authority_head, authority_epoch, budget_cents, budget_calls, state, fencing_token FROM ${AUTHORITY_ALLOCATION_RESERVATION_TABLE} WHERE relying_party_id = $1 AND parent_id = $2 ORDER BY fencing_token`,
});

function row(result: AuthorityAllocationPostgresQueryResult): QueryRow | undefined {
  return result.rows[0];
}

function integerFromDatabase(value: unknown, field: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${field} returned an unsafe database integer`);
  }
  return parsed;
}

function ownerDigest(ownerToken: string): string {
  return `sha256:${crypto.createHash('sha256')
    .update(OWNER_DIGEST_DOMAIN)
    .update(ownerToken)
    .digest('hex')}`;
}

function secureOwnerToken(): string {
  return `authority-owner:v1:${crypto.randomBytes(32).toString('base64url')}`;
}

function databaseInstantMs(value: unknown): number {
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  if (!Number.isFinite(parsed)) throw new Error('PostgreSQL returned an invalid database clock');
  return parsed;
}

function currentPinMatches(
  current: QueryRow,
  head: string,
  epoch: number,
): boolean {
  return current.authority_head === head
    && integerFromDatabase(current.authority_epoch, 'authority_epoch') === epoch;
}

function reservationReason(
  reservation: QueryRow | undefined,
  request: AuthorityAllocationFinalizeRequest,
): AuthorityAllocationRefusalReason {
  if (!reservation || reservation.allocation_id !== request.allocation_id) {
    return 'reservation_not_found';
  }
  if (reservation.state === 'committed') return 'reservation_already_committed';
  if (reservation.state === 'released') return 'reservation_already_released';
  if (reservation.owner_digest !== ownerDigest(request.owner_token)
    || integerFromDatabase(reservation.fencing_token, 'fencing_token') !== request.fencing_token
    || reservation.authority_head !== request.authority_head
    || integerFromDatabase(reservation.authority_epoch, 'authority_epoch') !== request.authority_epoch) {
    return 'reservation_owner_mismatch';
  }
  return 'reservation_not_found';
}

function usageRows(
  rows: QueryRow[],
): Map<string, { reserved: AuthorityAllocationBudget; committed: AuthorityAllocationBudget }> {
  const usage = new Map<string, {
    reserved: AuthorityAllocationBudget;
    committed: AuthorityAllocationBudget;
  }>();
  for (const entry of rows) {
    const allocationId = String(entry.allocation_id);
    const current = usage.get(allocationId) ?? {
      reserved: emptyBudget(),
      committed: emptyBudget(),
    };
    const value = {
      cents: integerFromDatabase(entry.cents, 'usage.cents'),
      calls: integerFromDatabase(entry.calls, 'usage.calls'),
    };
    if (entry.state === 'reserved') current.reserved = value;
    if (entry.state === 'committed') current.committed = value;
    usage.set(allocationId, current);
  }
  return usage;
}

function aggregateUsage(
  usage: Map<string, { reserved: AuthorityAllocationBudget; committed: AuthorityAllocationBudget }>,
): { reserved: AuthorityAllocationBudget; committed: AuthorityAllocationBudget } {
  let reserved = emptyBudget();
  let committed = emptyBudget();
  for (const entry of usage.values()) {
    reserved = addBudget(reserved, entry.reserved);
    committed = addBudget(committed, entry.committed);
  }
  return { reserved, committed };
}

/**
 * Durable adapter boundary for PostgreSQL. Atomicity depends on the supplied
 * transaction callback actually using one PostgreSQL transaction; the adapter
 * additionally takes a transaction-scoped advisory lock for every parent.
 */
export function createPostgresAuthorityAllocationStore(
  options: AuthorityAllocationPostgresOptions,
): AuthorityAllocationStore {
  if (!options || typeof options.transaction !== 'function') {
    throw new TypeError('createPostgresAuthorityAllocationStore requires transaction(callback)');
  }

  const withParentLock = async <T>(
    relyingPartyId: string,
    parentId: string,
    operation: (query: AuthorityAllocationPostgresQuery) => Promise<T>,
  ): Promise<T> => options.transaction(async (query) => {
    await query(AUTHORITY_ALLOCATION_SQL.lockParent, [relyingPartyId, parentId]);
    return operation(query);
  });

  const finalize = async (
    rawRequest: AuthorityAllocationFinalizeRequest,
    state: 'committed' | 'released',
  ): Promise<AuthorityAllocationFinalizeResult> => {
    const request = validateFinalizeRequest(rawRequest);
    return withParentLock(request.relying_party_id, request.parent_id, async (query) => {
      const current = row(await query(AUTHORITY_ALLOCATION_SQL.readCurrent, [
        request.relying_party_id,
        request.parent_id,
      ]));
      if (!current) return { ok: false, reason: 'reservation_not_found' };
      if (!currentPinMatches(current, request.authority_head, request.authority_epoch)) {
        return { ok: false, reason: 'authority_pin_mismatch' };
      }
      const params = [
        request.relying_party_id,
        request.parent_id,
        request.reservation_id,
        request.allocation_id,
        request.authority_head,
        request.authority_epoch,
        ownerDigest(request.owner_token),
        request.fencing_token,
      ];
      const statement = state === 'committed'
        ? AUTHORITY_ALLOCATION_SQL.commitReservation
        : AUTHORITY_ALLOCATION_SQL.releaseReservation;
      const result = await query(statement, params);
      if (result.rowCount === 1) return { ok: true, state };
      const existing = row(await query(AUTHORITY_ALLOCATION_SQL.readReservation, [
        request.relying_party_id,
        request.parent_id,
        request.reservation_id,
      ]));
      return { ok: false, reason: reservationReason(existing, request) };
    });
  };

  return {
    durable: true,

    async installSnapshot(snapshot, pin) {
      const normalized = validateAuthorityAllocationSnapshot(snapshot, pin);
      const fingerprint = snapshotFingerprint(normalized);
      return withParentLock(
        normalized.relying_party_id,
        normalized.parent_id,
        async (query) => {
          const current = row(await query(AUTHORITY_ALLOCATION_SQL.readCurrent, [
            normalized.relying_party_id,
            normalized.parent_id,
          ]));
          if (current) {
            const currentEpoch = integerFromDatabase(current.authority_epoch, 'authority_epoch');
            if (current.authority_head === normalized.authority_head
              && currentEpoch === normalized.authority_epoch) {
              return current.snapshot_fingerprint === fingerprint
                ? { ok: true, installed: false, snapshot_fingerprint: fingerprint }
                : { ok: false, reason: 'snapshot_conflict' };
            }
            if (normalized.authority_epoch <= currentEpoch) {
              return { ok: false, reason: 'stale_authority_epoch' };
            }
            const active = row(await query(AUTHORITY_ALLOCATION_SQL.activeReservations, [
              normalized.relying_party_id,
              normalized.parent_id,
            ]));
            if (integerFromDatabase(active?.active ?? 0, 'active reservations') > 0) {
              return { ok: false, reason: 'reservations_in_flight' };
            }
          }
          await query(AUTHORITY_ALLOCATION_SQL.insertSnapshot, [
            normalized.relying_party_id,
            normalized.parent_id,
            normalized.authority_head,
            normalized.authority_epoch,
            fingerprint,
            canonicalSnapshot(normalized),
          ]);
          for (const allocation of normalized.sibling_allocations) {
            await query(AUTHORITY_ALLOCATION_SQL.insertBranch, [
              normalized.relying_party_id,
              normalized.parent_id,
              normalized.authority_head,
              normalized.authority_epoch,
              allocation.allocation_id,
              allocation.budget.cents,
              allocation.budget.calls,
              allocation.expires_at,
            ]);
          }
          if (current) {
            const advanced = await query(AUTHORITY_ALLOCATION_SQL.advanceCurrent, [
              normalized.relying_party_id,
              normalized.parent_id,
              normalized.authority_head,
              normalized.authority_epoch,
              fingerprint,
            ]);
            if (advanced.rowCount !== 1) return { ok: false, reason: 'stale_authority_epoch' };
          } else {
            await query(AUTHORITY_ALLOCATION_SQL.insertCurrent, [
              normalized.relying_party_id,
              normalized.parent_id,
              normalized.authority_head,
              normalized.authority_epoch,
              fingerprint,
            ]);
          }
          return { ok: true, installed: true, snapshot_fingerprint: fingerprint };
        },
      );
    },

    async reserve(rawRequest) {
      const request = validateReservationRequest(rawRequest);
      return withParentLock(request.relying_party_id, request.parent_id, async (query) => {
        const current = row(await query(AUTHORITY_ALLOCATION_SQL.readCurrent, [
          request.relying_party_id,
          request.parent_id,
        ]));
        if (!current) return { ok: false, reason: 'allocation_not_found' };
        if (!currentPinMatches(current, request.authority_head, request.authority_epoch)) {
          return { ok: false, reason: 'authority_pin_mismatch' };
        }
        const existing = row(await query(AUTHORITY_ALLOCATION_SQL.readReservation, [
          request.relying_party_id,
          request.parent_id,
          request.reservation_id,
        ]));
        if (existing) return { ok: false, reason: 'reservation_replayed' };
        const branch = row(await query(AUTHORITY_ALLOCATION_SQL.readBranch, [
          request.relying_party_id,
          request.parent_id,
          request.authority_head,
          request.authority_epoch,
          request.allocation_id,
        ]));
        if (!branch) return { ok: false, reason: 'allocation_not_found' };
        const snapshotRow = row(await query(AUTHORITY_ALLOCATION_SQL.readSnapshot, [
          request.relying_party_id,
          request.parent_id,
          request.authority_head,
          request.authority_epoch,
        ]));
        if (!snapshotRow || !snapshotRow.snapshot_json) {
          throw new Error('current authority allocation snapshot is missing');
        }
        const snapshot = snapshotRow.snapshot_json as AuthorityAllocationSnapshot;
        const nowMs = databaseInstantMs(current.database_now);
        if (nowMs >= strictInstantMs(snapshot.expires_at, 'snapshot.expires_at')
          || nowMs >= databaseInstantMs(branch.expires_at)) {
          return { ok: false, reason: 'allocation_expired' };
        }
        const usage = usageRows((await query(AUTHORITY_ALLOCATION_SQL.readUsage, [
          request.relying_party_id,
          request.parent_id,
          request.authority_head,
          request.authority_epoch,
        ])).rows);
        const branchUsage = usage.get(request.allocation_id) ?? {
          reserved: emptyBudget(),
          committed: emptyBudget(),
        };
        const branchCandidate = addBudget(
          addBudget(branchUsage.reserved, branchUsage.committed),
          request.budget,
        );
        const parentUsage = aggregateUsage(usage);
        const parentCandidate = addBudget(
          addBudget(parentUsage.reserved, parentUsage.committed),
          request.budget,
        );
        const branchCeiling = {
          cents: integerFromDatabase(branch.budget_cents, 'branch.budget_cents'),
          calls: integerFromDatabase(branch.budget_calls, 'branch.budget_calls'),
        };
        if (!withinBudget(branchCandidate, branchCeiling)
          || !withinBudget(parentCandidate, budget(snapshot.budget, 'snapshot.budget'))) {
          return { ok: false, reason: 'budget_exceeded' };
        }
        const fenceRow = row(await query(AUTHORITY_ALLOCATION_SQL.nextFence, [
          request.relying_party_id,
          request.parent_id,
          request.authority_head,
          request.authority_epoch,
        ]));
        if (!fenceRow) return { ok: false, reason: 'authority_pin_mismatch' };
        const fencingToken = integerFromDatabase(fenceRow.fencing_token, 'fencing_token');
        const ownerToken = secureOwnerToken();
        await query(AUTHORITY_ALLOCATION_SQL.insertReservation, [
          request.relying_party_id,
          request.parent_id,
          request.authority_head,
          request.authority_epoch,
          request.allocation_id,
          request.reservation_id,
          request.budget.cents,
          request.budget.calls,
          ownerDigest(ownerToken),
          fencingToken,
        ]);
        return {
          ok: true,
          reservation_id: request.reservation_id,
          allocation_id: request.allocation_id,
          budget: { ...request.budget },
          remaining: subtractBudget(branchCeiling, branchCandidate),
          owner: {
            owner_token: ownerToken,
            fencing_token: fencingToken,
            authority_head: request.authority_head,
            authority_epoch: request.authority_epoch,
          },
        };
      });
    },

    commit(request) {
      return finalize(request, 'committed');
    },

    release(request) {
      return finalize(request, 'released');
    },

    async inspect(rawPin) {
      const relyingPartyId = identifier(rawPin?.relying_party_id, 'pin.relying_party_id');
      const parentId = identifier(rawPin?.parent_id, 'pin.parent_id');
      const head = authorityHead(rawPin?.authority_head, 'pin.authority_head');
      const epoch = authorityEpoch(rawPin?.authority_epoch, 'pin.authority_epoch');
      return withParentLock(relyingPartyId, parentId, async (query) => {
        const current = row(await query(AUTHORITY_ALLOCATION_SQL.readCurrent, [
          relyingPartyId,
          parentId,
        ]));
        if (!current) return null;
        if (!currentPinMatches(current, head, epoch)) {
          fail('authority_pin_mismatch', 'inspection requires the exact current authority pin');
        }
        const snapshotResult = await query(AUTHORITY_ALLOCATION_SQL.readSnapshot, [
          relyingPartyId,
          parentId,
          head,
          epoch,
        ]);
        const snapshotRow = row(snapshotResult);
        if (!snapshotRow) throw new Error('current authority allocation snapshot is missing');
        const snapshot = snapshotRow.snapshot_json as AuthorityAllocationSnapshot;
        const usage = usageRows((await query(AUTHORITY_ALLOCATION_SQL.readUsage, [
          relyingPartyId,
          parentId,
          head,
          epoch,
        ])).rows);
        const parent = aggregateUsage(usage);
        const branches: AuthorityAllocationStateView['usage']['branches'] = Object.create(null);
        for (const allocation of snapshot.sibling_allocations) {
          branches[allocation.allocation_id] = usage.get(allocation.allocation_id) ?? {
            reserved: emptyBudget(),
            committed: emptyBudget(),
          };
        }
        const reservationRows = (await query(AUTHORITY_ALLOCATION_SQL.inspectReservations, [
          relyingPartyId,
          parentId,
        ])).rows;
        return {
          snapshot: cloneSnapshot(snapshot),
          snapshot_fingerprint: String(snapshotRow.snapshot_fingerprint),
          usage: { parent, branches },
          reservations: reservationRows.map((entry) => ({
            reservation_id: String(entry.reservation_id),
            allocation_id: String(entry.allocation_id),
            authority_head: String(entry.authority_head),
            authority_epoch: integerFromDatabase(entry.authority_epoch, 'authority_epoch'),
            budget: {
              cents: integerFromDatabase(entry.budget_cents, 'reservation.budget_cents'),
              calls: integerFromDatabase(entry.budget_calls, 'reservation.budget_calls'),
            },
            state: entry.state as AuthorityAllocationReservationView['state'],
            fencing_token: integerFromDatabase(entry.fencing_token, 'fencing_token'),
          })),
        };
      });
    },
  };
}

export function isDurableAuthorityAllocationStore(
  store: unknown,
): store is AuthorityAllocationStore {
  if (!store || typeof store !== 'object') return false;
  const candidate = store as Partial<AuthorityAllocationStore>;
  return candidate.durable === true
    && typeof candidate.installSnapshot === 'function'
    && typeof candidate.reserve === 'function'
    && typeof candidate.commit === 'function'
    && typeof candidate.release === 'function'
    && typeof candidate.inspect === 'function';
}
