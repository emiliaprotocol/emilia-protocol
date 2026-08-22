// SPDX-License-Identifier: Apache-2.0
/**
 * State-domain-owned aggregate consequence envelopes.
 *
 * The hard decision is a capacity reservation before provider entry. Rate,
 * entropy, velocity, correlation, and anomaly signals are deliberately absent
 * from this contract: they may tighten an outer policy but cannot mint or
 * expand capacity here.
 */
import crypto from 'node:crypto';

import {
  AGILE_SIGNATURE_ALGORITHMS,
  SIGNATURE_AGILITY_VERSION,
  signAgileSet,
  verifyAgileSignatureSet,
  type AgileSignature,
  type AgileSigningKey,
  type AgileVerificationKey,
  type AgilityOptions,
} from '@emilia-protocol/verify/pq-signature-agility';
import {
  canonicalizeAeb,
  digestAeb,
  type AebDigest,
} from '@emilia-protocol/verify/aeb-adapter-contract';

export const CONSEQUENCE_ENVELOPE_VERSION = 'EP-CONSEQUENCE-ENVELOPE-v1';
export const CONSEQUENCE_ENVELOPE_DOMAIN = `${CONSEQUENCE_ENVELOPE_VERSION}\0`;
export const CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS = Object.freeze([
  ...AGILE_SIGNATURE_ALGORITHMS,
]);
export const CONSEQUENCE_ENVELOPE_REFILL_POLICY = 'NEW_SIGNED_EPOCH_ONLY';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const UNSIGNED_DECIMAL = /^(?:0|[1-9][0-9]*)$/;

type Obj = Record<string, unknown>;

export interface ConsequenceImpactProfile {
  id: string;
  version: string;
  unit: string;
  digest: AebDigest;
  derive(action: unknown):
    | { ok: true; impact_units: bigint }
    | { ok: false; reason: string };
}

export interface ConsequenceEnvelopeParentAllocation {
  parent_envelope_id: string;
  parent_envelope_digest: AebDigest;
  parent_state_domain_id: string;
  parent_epoch: number;
  allocation_operation_id: string;
  allocation_units: string;
}

export interface ConsequenceEnvelopeBody {
  envelope_id: string;
  state_domain_id: string;
  epoch: number;
  capacity_units: string;
  impact_profile_id: string;
  impact_profile_digest: AebDigest;
  validity: { not_before: string; not_after: string };
  issuer: { id: string; key_id: string };
  parent_allocation: ConsequenceEnvelopeParentAllocation | null;
  renewable: false;
  refill_policy: typeof CONSEQUENCE_ENVELOPE_REFILL_POLICY;
  signature_profile: {
    id: typeof SIGNATURE_AGILITY_VERSION;
    required_algorithms: string[];
  };
  contract_digest: AebDigest;
}

export type ConsequenceEnvelopeDraft = Omit<
  ConsequenceEnvelopeBody,
  'signature_profile' | 'contract_digest' | 'refill_policy'
>;

export interface ConsequenceEnvelope {
  '@version': typeof CONSEQUENCE_ENVELOPE_VERSION;
  body: ConsequenceEnvelopeBody;
  signatures: AgileSignature[];
}

export interface ConsequenceEnvelopeVerification {
  verified: boolean;
  reason: string | null;
  envelope_digest: AebDigest | null;
  execution_authorizing: false;
}

declare const CONSEQUENCE_ENVELOPE_OWNER: unique symbol;
export type ConsequenceEnvelopeOwner = string & {
  readonly [CONSEQUENCE_ENVELOPE_OWNER]: true;
};

export interface ConsequenceEnvelopeReservation {
  envelope_id: string;
  envelope_digest: AebDigest;
  state_domain_id: string;
  epoch: number;
  operation_id: string;
  action_digest: AebDigest;
  impact_profile_id: string;
  impact_units: string;
  owner: ConsequenceEnvelopeOwner;
}

export interface ConsequenceEnvelopeStore {
  durable: boolean;
  /** Present only on process-local conformance stores. */
  testOnly?: true;
  ownershipFenced: true;
  atomicCapacity: true;
  epochFenced: true;
  bind(input: {
    envelope_id: string;
    envelope_digest: AebDigest;
    state_domain_id: string;
    epoch: number;
    capacity_units: string;
  }): Promise<boolean>;
  reserve(input: Omit<ConsequenceEnvelopeReservation, 'owner'>): Promise<
    | { reserved: true; owner: ConsequenceEnvelopeOwner }
    | { reserved: false; reason: string }
  >;
  transition(input: ConsequenceEnvelopeReservation & {
    expected_state: 'HELD' | 'ENTERED' | 'INDETERMINATE';
    next_state: 'ENTERED' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
  }): Promise<boolean>;
  recover(input: {
    operation_id: string;
    action_digest: AebDigest;
  }): Promise<ConsequenceEnvelopeReservation | null>;
  snapshot(): {
    capacity_units: string;
    available_units: string;
    held_units: string;
    committed_units: string;
  };
}

export type ConsequenceEnvelopeReserveResult =
  | { status: 'RESERVED'; reservation: ConsequenceEnvelopeReservation }
  | { status: 'REFUSED'; reason: string };

export interface ConsequenceEnvelopeBoundary {
  guaranteeClass: 'durable-local-atomic' | 'test-only-process-local';
  envelope: Readonly<ConsequenceEnvelopeBody>;
  envelope_digest: AebDigest;
  profile: Readonly<ConsequenceImpactProfile>;
  reserve(input: {
    operation_id: string;
    state_domain_id: string;
    expected_epoch: number;
    action: unknown;
  }): Promise<ConsequenceEnvelopeReserveResult>;
  reserveUnits(input: {
    operation_id: string;
    state_domain_id: string;
    expected_epoch: number;
    action_digest: AebDigest;
    impact_units: string;
  }): Promise<ConsequenceEnvelopeReserveResult>;
  beginProviderEntry(reservation: ConsequenceEnvelopeReservation): Promise<
    { status: 'ENTERED' } | { status: 'REFUSED'; reason: string }
  >;
  releaseNotEntered(reservation: ConsequenceEnvelopeReservation): Promise<
    { status: 'RELEASED' } | { status: 'REFUSED'; reason: string }
  >;
  settle(
    reservation: ConsequenceEnvelopeReservation,
    outcome: 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE',
  ): Promise<
    | { status: 'COMMITTED' | 'RELEASED' | 'INDETERMINATE' }
    | { status: 'REFUSED'; reason: string }
  >;
  reconcile(input: {
    operation_id: string;
    action_digest: AebDigest;
    outcome: 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
    recovery_authorization: unknown;
  }): Promise<
    | { status: 'COMMITTED' | 'RELEASED' }
    | { status: 'REFUSED'; reason: string }
  >;
  snapshot(): ReturnType<ConsequenceEnvelopeStore['snapshot']>;
  renew(): Promise<{ status: 'REFUSED'; reason: 'consequence_envelope_new_signed_epoch_required' }>;
}

function isObject(value: unknown): value is Obj {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER.test(value)
    && Buffer.byteLength(value, 'utf8') <= 256;
}

function digest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST.test(value);
}

function decimal(value: unknown, allowZero = false): value is string {
  if (typeof value !== 'string' || !UNSIGNED_DECIMAL.test(value)) return false;
  return allowZero ? true : BigInt(value) > 0n;
}

function instant(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function exactKeys(value: Obj, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function frozenClone<T>(value: T): T {
  const clone = JSON.parse(canonicalizeAeb(value));
  if (clone === null || typeof clone !== 'object') return clone;
  const stack: object[] = [clone];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === 'object') stack.push(child);
    }
    Object.freeze(current);
  }
  return clone;
}

function validParent(value: unknown): value is ConsequenceEnvelopeParentAllocation | null {
  if (value === null) return true;
  return isObject(value)
    && exactKeys(value, [
      'parent_envelope_id', 'parent_envelope_digest', 'parent_state_domain_id',
      'parent_epoch', 'allocation_operation_id', 'allocation_units',
    ])
    && identifier(value.parent_envelope_id)
    && digest(value.parent_envelope_digest)
    && identifier(value.parent_state_domain_id)
    && Number.isSafeInteger(value.parent_epoch) && Number(value.parent_epoch) > 0
    && identifier(value.allocation_operation_id)
    && decimal(value.allocation_units);
}

function validBody(value: unknown): value is ConsequenceEnvelopeBody {
  if (!isObject(value) || !exactKeys(value, [
    'envelope_id', 'state_domain_id', 'epoch', 'capacity_units',
    'impact_profile_id', 'impact_profile_digest', 'validity', 'issuer',
    'parent_allocation', 'renewable', 'refill_policy', 'signature_profile',
    'contract_digest',
  ])) return false;
  if (!identifier(value.envelope_id) || !identifier(value.state_domain_id)
      || !Number.isSafeInteger(value.epoch) || Number(value.epoch) <= 0
      || !decimal(value.capacity_units)
      || !identifier(value.impact_profile_id) || !digest(value.impact_profile_digest)
      || value.renewable !== false
      || value.refill_policy !== CONSEQUENCE_ENVELOPE_REFILL_POLICY
      || !validParent(value.parent_allocation)) return false;
  if (!isObject(value.validity) || !exactKeys(value.validity, ['not_before', 'not_after'])
      || !instant(value.validity.not_before) || !instant(value.validity.not_after)
      || Date.parse(value.validity.not_before) >= Date.parse(value.validity.not_after)) return false;
  if (!isObject(value.issuer) || !exactKeys(value.issuer, ['id', 'key_id'])
      || !identifier(value.issuer.id) || !identifier(value.issuer.key_id)) return false;
  if (!isObject(value.signature_profile)
      || !exactKeys(value.signature_profile, ['id', 'required_algorithms'])
      || value.signature_profile.id !== SIGNATURE_AGILITY_VERSION
      || !Array.isArray(value.signature_profile.required_algorithms)
      || value.signature_profile.required_algorithms.length !== CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS.length
      || value.signature_profile.required_algorithms.some(
        (algorithm, index) => algorithm !== CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS[index],
      )
      || !digest(value.contract_digest)) return false;
  return consequenceEnvelopeContractDigest(value as unknown as ConsequenceEnvelopeBody) === value.contract_digest;
}

export function consequenceEnvelopeContractDigest(
  input: Pick<ConsequenceEnvelopeBody,
    | 'envelope_id' | 'state_domain_id' | 'epoch' | 'capacity_units'
    | 'impact_profile_id' | 'impact_profile_digest' | 'validity' | 'issuer'
    | 'parent_allocation' | 'renewable' | 'refill_policy'>,
): AebDigest {
  return digestAeb({
    domain: CONSEQUENCE_ENVELOPE_VERSION,
    envelope_id: input.envelope_id,
    state_domain_id: input.state_domain_id,
    epoch: input.epoch,
    capacity_units: input.capacity_units,
    impact_profile_id: input.impact_profile_id,
    impact_profile_digest: input.impact_profile_digest,
    validity: input.validity,
    issuer: input.issuer,
    parent_allocation: input.parent_allocation,
    renewable: input.renewable,
    refill_policy: input.refill_policy,
  });
}

export function consequenceEnvelopeSignedBytes(body: ConsequenceEnvelopeBody): Uint8Array {
  return Buffer.from(`${CONSEQUENCE_ENVELOPE_DOMAIN}${canonicalizeAeb(body)}`, 'utf8');
}

export function consequenceEnvelopeDigest(body: ConsequenceEnvelopeBody): AebDigest {
  return digestAeb({ domain: `${CONSEQUENCE_ENVELOPE_VERSION}:artifact`, body });
}

export async function issueConsequenceEnvelope(
  draft: ConsequenceEnvelopeDraft,
  options: AgilityOptions & { signing_keys: AgileSigningKey[] },
): Promise<ConsequenceEnvelope> {
  const unsigned: Pick<ConsequenceEnvelopeBody,
    | 'envelope_id' | 'state_domain_id' | 'epoch' | 'capacity_units'
    | 'impact_profile_id' | 'impact_profile_digest' | 'validity' | 'issuer'
    | 'parent_allocation' | 'renewable' | 'refill_policy'> = frozenClone({
    ...draft,
    refill_policy: CONSEQUENCE_ENVELOPE_REFILL_POLICY,
  });
  const body: ConsequenceEnvelopeBody = {
    ...unsigned,
    signature_profile: {
      id: SIGNATURE_AGILITY_VERSION,
      required_algorithms: [...CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS],
    },
    contract_digest: consequenceEnvelopeContractDigest(unsigned as ConsequenceEnvelopeBody),
  };
  if (!validBody(body)) throw new TypeError('consequence_envelope_malformed');
  if (!Array.isArray(options?.signing_keys)
      || options.signing_keys.length !== CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS.length
      || options.signing_keys.some(
        (key, index) => key.alg !== CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS[index],
      )) throw new TypeError('consequence_envelope_algorithm_set_mismatch');
  const signatures = await signAgileSet(
    consequenceEnvelopeSignedBytes(body),
    options.signing_keys,
    options,
  );
  return frozenClone({ '@version': CONSEQUENCE_ENVELOPE_VERSION, body, signatures });
}

export async function verifyConsequenceEnvelope(
  value: unknown,
  options: AgilityOptions & { verification_keys: AgileVerificationKey[]; now: string },
): Promise<ConsequenceEnvelopeVerification> {
  const refuse = (reason: string): ConsequenceEnvelopeVerification => ({
    verified: false,
    reason,
    envelope_digest: null,
    execution_authorizing: false,
  });
  if (!isObject(value) || !exactKeys(value, ['@version', 'body', 'signatures'])
      || value['@version'] !== CONSEQUENCE_ENVELOPE_VERSION
      || !validBody(value.body)) return refuse('consequence_envelope_malformed');
  if (!instant(options?.now)) return refuse('consequence_envelope_clock_invalid');
  const body = value.body;
  if (Date.parse(options.now) < Date.parse(body.validity.not_before)) return refuse('consequence_envelope_not_yet_valid');
  if (Date.parse(options.now) >= Date.parse(body.validity.not_after)) return refuse('consequence_envelope_expired');
  const signatures = await verifyAgileSignatureSet(
    consequenceEnvelopeSignedBytes(body),
    value.signatures,
    options.verification_keys,
    {
      ...options,
      policy: 'hybrid_all',
      requiredAlgorithms: [...CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS],
    },
  );
  if (signatures.verified !== true) return refuse(`consequence_envelope_signature_refused:${signatures.reason ?? 'unknown'}`);
  return {
    verified: true,
    reason: null,
    envelope_digest: consequenceEnvelopeDigest(body),
    execution_authorizing: false,
  };
}

function impactProfile(
  id: string,
  version: string,
  unit: string,
  definition: Obj,
  derive: ConsequenceImpactProfile['derive'],
): ConsequenceImpactProfile {
  return Object.freeze({
    id,
    version,
    unit,
    digest: digestAeb({ id, version, unit, definition }),
    derive,
  });
}

export const FINANCE_CUMULATIVE_EXPOSURE_PROFILE = impactProfile(
  'EP-CONSEQUENCE-IMPACT-FINANCE-MINOR-UNITS-v1',
  '1',
  'currency-minor-unit',
  { action_type: 'finance.vendor-payment.1', material_field: 'amount_minor', rule: 'positive_integer' },
  (action) => {
    if (!isObject(action) || action.action_type !== 'finance.vendor-payment.1'
        || !identifier(action.currency)) return { ok: false, reason: 'consequence_impact_action_invalid' };
    const raw = action.amount_minor;
    if ((typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw <= 0)
        && (typeof raw !== 'string' || !decimal(raw))) {
      return { ok: false, reason: 'consequence_impact_amount_invalid' };
    }
    return { ok: true, impact_units: BigInt(raw) };
  },
);

export const GRID_ACTIVE_POWER_PROFILE = impactProfile(
  'EP-CONSEQUENCE-IMPACT-GRID-ACTIVE-POWER-v1',
  '1',
  'watt',
  {
    action_type: 'grid.active-power-change.1',
    material_field: 'active_power_delta_watts',
    rule: 'absolute_integer',
    telemetry_is_nonauthorizing: true,
  },
  (action) => {
    if (!isObject(action) || action.action_type !== 'grid.active-power-change.1'
        || !identifier(action.target_id)) return { ok: false, reason: 'consequence_impact_action_invalid' };
    const raw = action.active_power_delta_watts;
    if ((typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw === 0)
        && (typeof raw !== 'string' || !/^-?[1-9][0-9]*$/.test(raw))) {
      return { ok: false, reason: 'consequence_impact_amount_invalid' };
    }
    const value = BigInt(raw);
    return { ok: true, impact_units: value < 0n ? -value : value };
  },
);

/**
 * Conservative GRACE curtailment allocation. One admitted event reserves the
 * absolute requested reduction in watts. Telemetry, modeled benefit, and
 * observed delivery never increase the signed envelope.
 */
export const GRACE_CURTAILMENT_IMPACT_PROFILE = impactProfile(
  'ep:impact-profile:grace-curtailment:v1',
  '1',
  'watt',
  {
    action_type: 'grid.curtailment.1',
    material_field: 'target_delta_kw',
    transform: 'positive_decimal_kw_to_integer_watts',
    telemetry_is_nonauthorizing: true,
  },
  (action) => {
    if (!isObject(action) || action.action_type !== 'grid.curtailment.1'
        || !identifier(action.facility)) return { ok: false, reason: 'consequence_impact_action_invalid' };
    const raw = action.target_delta_kw;
    if (typeof raw !== 'string' || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?$/.test(raw)) {
      return { ok: false, reason: 'consequence_impact_amount_invalid' };
    }
    const [whole, fraction = ''] = raw.split('.');
    const watts = (BigInt(whole) * 1000n) + BigInt(fraction.padEnd(3, '0'));
    return watts > 0n
      ? { ok: true, impact_units: watts }
      : { ok: false, reason: 'consequence_impact_amount_invalid' };
  },
);

export function createMemoryConsequenceEnvelopeStore(): ConsequenceEnvelopeStore {
  let binding: {
    envelope_id: string;
    envelope_digest: AebDigest;
    state_domain_id: string;
    epoch: number;
    capacity: bigint;
  } | null = null;
  const rows = new Map<string, {
    binding: Omit<ConsequenceEnvelopeReservation, 'owner'>;
    owner: ConsequenceEnvelopeOwner;
    state: 'HELD' | 'ENTERED' | 'INDETERMINATE' | 'COMMITTED' | 'RELEASED';
  }>();
  let held = 0n;
  let committed = 0n;
  let ownerCounter = 0;
  return {
    durable: false,
    testOnly: true,
    ownershipFenced: true,
    atomicCapacity: true,
    epochFenced: true,
    async bind(input) {
      const next = {
        envelope_id: input.envelope_id,
        envelope_digest: input.envelope_digest,
        state_domain_id: input.state_domain_id,
        epoch: input.epoch,
        capacity: BigInt(input.capacity_units),
      };
      if (!binding) {
        binding = next;
        return true;
      }
      return canonicalizeAeb(binding) === canonicalizeAeb(next);
    },
    async reserve(input) {
      if (!binding || input.envelope_id !== binding.envelope_id
          || input.envelope_digest !== binding.envelope_digest
          || input.state_domain_id !== binding.state_domain_id
          || input.epoch !== binding.epoch) {
        return { reserved: false, reason: 'consequence_envelope_store_binding_mismatch' };
      }
      const prior = rows.get(input.operation_id);
      if (prior) return { reserved: false, reason: 'consequence_envelope_operation_conflict' };
      const impact = BigInt(input.impact_units);
      if (impact > binding.capacity - held - committed) {
        return { reserved: false, reason: 'consequence_envelope_capacity_exceeded' };
      }
      const owner = `owner:consequence-envelope:${++ownerCounter}:${crypto.randomBytes(12).toString('base64url')}` as ConsequenceEnvelopeOwner;
      rows.set(input.operation_id, { binding: frozenClone(input), owner, state: 'HELD' });
      held += impact;
      return { reserved: true, owner };
    },
    async transition(input) {
      const row = rows.get(input.operation_id);
      const {
        owner: _owner,
        expected_state: _expectedState,
        next_state: _nextState,
        ...presentedBinding
      } = input;
      if (!row || row.owner !== input.owner || row.state !== input.expected_state
          || canonicalizeAeb(row.binding) !== canonicalizeAeb(presentedBinding)) {
        return false;
      }
      const impact = BigInt(row.binding.impact_units);
      if (input.expected_state === 'HELD' && input.next_state === 'ENTERED') {
        held -= impact;
        committed += impact;
      } else if (input.expected_state === 'HELD' && input.next_state === 'RELEASED') {
        held -= impact;
      } else if ((input.expected_state === 'ENTERED' || input.expected_state === 'INDETERMINATE')
          && input.next_state === 'RELEASED') {
        committed -= impact;
      } else if (input.expected_state === 'ENTERED' && input.next_state === 'INDETERMINATE') {
        // Capacity stays unavailable.
      } else if ((input.expected_state === 'ENTERED' || input.expected_state === 'INDETERMINATE')
          && input.next_state === 'COMMITTED') {
        // Capacity stays committed until a new signed epoch or proven non-commitment.
      } else return false;
      row.state = input.next_state;
      return true;
    },
    async recover(input) {
      const row = rows.get(input.operation_id);
      if (!row || row.binding.action_digest !== input.action_digest
          || !['ENTERED', 'INDETERMINATE'].includes(row.state)) return null;
      return frozenClone({ ...row.binding, owner: row.owner });
    },
    snapshot() {
      const capacity = binding?.capacity ?? 0n;
      return {
        capacity_units: capacity.toString(),
        available_units: (capacity - held - committed).toString(),
        held_units: held.toString(),
        committed_units: committed.toString(),
      };
    },
  };
}

function secureStore(value: ConsequenceEnvelopeStore, allowTestStore: boolean): boolean {
  return (value?.durable === true || (allowTestStore && value?.testOnly === true))
    && value.ownershipFenced === true
    && value.atomicCapacity === true
    && value.epochFenced === true
    && typeof value.bind === 'function'
    && typeof value.reserve === 'function'
    && typeof value.transition === 'function'
    && typeof value.recover === 'function'
    && typeof value.snapshot === 'function';
}

export async function createConsequenceEnvelopeBoundary(options: {
  envelope: ConsequenceEnvelope;
  verification_keys: AgileVerificationKey[];
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  profile: ConsequenceImpactProfile;
  store: ConsequenceEnvelopeStore;
  authorize_recovery?: (input: {
    operation_id: string;
    action_digest: AebDigest;
    recovery_authorization: unknown;
  }) => boolean | Promise<boolean>;
  /** Conformance-only escape hatch. Production callers must supply a durable store. */
  allow_test_store?: true;
  now?: () => string;
}): Promise<ConsequenceEnvelopeBoundary> {
  if (!secureStore(options?.store, options?.allow_test_store === true)
      || !options?.profile || typeof options.profile.derive !== 'function') {
    throw new TypeError('consequence_envelope_boundary_configuration_invalid');
  }
  let now = options.now ?? (() => new Date().toISOString());
  const verified = await verifyConsequenceEnvelope(options.envelope, {
    verification_keys: options.verification_keys,
    mldsaBackend: options.mldsaBackend,
    now: now(),
  });
  if (!verified.verified || !verified.envelope_digest) {
    throw new TypeError(verified.reason ?? 'consequence_envelope_verification_refused');
  }
  const body = frozenClone(options.envelope.body);
  if (body.impact_profile_id !== options.profile.id
      || body.impact_profile_digest !== options.profile.digest) {
    throw new TypeError('consequence_envelope_impact_profile_mismatch');
  }
  const bound = await options.store.bind({
    envelope_id: body.envelope_id,
    envelope_digest: verified.envelope_digest,
    state_domain_id: body.state_domain_id,
    epoch: body.epoch,
    capacity_units: body.capacity_units,
  });
  if (!bound) throw new TypeError('consequence_envelope_store_binding_mismatch');

  const refuse = (reason: string) => ({ status: 'REFUSED' as const, reason });

  async function reserveUnits(input: {
    operation_id: string;
    state_domain_id: string;
    expected_epoch: number;
    action_digest: AebDigest;
    impact_units: string;
  }): Promise<ConsequenceEnvelopeReserveResult> {
    if (!identifier(input?.operation_id) || !digest(input?.action_digest)
        || !decimal(input?.impact_units)) return refuse('consequence_envelope_reservation_invalid');
    if (input.state_domain_id !== body.state_domain_id) return refuse('consequence_envelope_state_domain_mismatch');
    if (input.expected_epoch !== body.epoch) return refuse('consequence_envelope_epoch_mismatch');
    const current = now();
    if (!instant(current)) return refuse('consequence_envelope_clock_invalid');
    if (Date.parse(current) < Date.parse(body.validity.not_before)) return refuse('consequence_envelope_not_yet_valid');
    if (Date.parse(current) >= Date.parse(body.validity.not_after)) return refuse('consequence_envelope_expired');
    const binding = {
      envelope_id: body.envelope_id,
      envelope_digest: verified.envelope_digest!,
      state_domain_id: body.state_domain_id,
      epoch: body.epoch,
      operation_id: input.operation_id,
      action_digest: input.action_digest,
      impact_profile_id: body.impact_profile_id,
      impact_units: input.impact_units,
    };
    const reserved = await options.store.reserve(binding);
    return reserved.reserved
      ? { status: 'RESERVED', reservation: frozenClone({ ...binding, owner: reserved.owner }) }
      : refuse(reserved.reason);
  }

  const boundary: ConsequenceEnvelopeBoundary = {
    guaranteeClass: options.store.durable === true
      ? 'durable-local-atomic'
      : 'test-only-process-local',
    envelope: body,
    envelope_digest: verified.envelope_digest,
    profile: Object.freeze(options.profile),
    async reserve(input) {
      const actionDigest = (() => {
        try { return digestAeb(input?.action); } catch { return null; }
      })();
      if (!actionDigest) return refuse('consequence_envelope_action_invalid');
      const impact = options.profile.derive(input.action);
      if (!impact.ok || impact.impact_units <= 0n) return refuse(impact.ok ? 'consequence_impact_amount_invalid' : impact.reason);
      return reserveUnits({
        operation_id: input.operation_id,
        state_domain_id: input.state_domain_id,
        expected_epoch: input.expected_epoch,
        action_digest: actionDigest,
        impact_units: impact.impact_units.toString(),
      });
    },
    reserveUnits,
    async beginProviderEntry(reservation) {
      const transitioned = await options.store.transition({
        ...reservation,
        expected_state: 'HELD',
        next_state: 'ENTERED',
      });
      return transitioned ? { status: 'ENTERED' } : refuse('consequence_envelope_entry_conflict');
    },
    async releaseNotEntered(reservation) {
      const transitioned = await options.store.transition({
        ...reservation,
        expected_state: 'HELD',
        next_state: 'RELEASED',
      });
      return transitioned ? { status: 'RELEASED' } : refuse('consequence_envelope_release_conflict');
    },
    async settle(reservation, outcome) {
      if (outcome === 'INDETERMINATE') {
        const transitioned = await options.store.transition({
          ...reservation,
          expected_state: 'ENTERED',
          next_state: 'INDETERMINATE',
        });
        return transitioned ? { status: 'INDETERMINATE' } : refuse('consequence_envelope_settlement_conflict');
      }
      const nextState = outcome === 'COMMITTED' ? 'COMMITTED' : 'RELEASED';
      let transitioned = await options.store.transition({
        ...reservation,
        expected_state: 'ENTERED',
        next_state: nextState,
      });
      if (!transitioned) {
        transitioned = await options.store.transition({
          ...reservation,
          expected_state: 'INDETERMINATE',
          next_state: nextState,
        });
      }
      return transitioned
        ? { status: outcome === 'PROVEN_NOT_COMMITTED' ? 'RELEASED' : 'COMMITTED' }
        : refuse('consequence_envelope_settlement_conflict');
    },
    async reconcile(input) {
      if (!identifier(input?.operation_id) || !digest(input?.action_digest)
          || typeof options.authorize_recovery !== 'function') {
        return refuse('consequence_envelope_recovery_refused');
      }
      let authorized = false;
      try {
        authorized = await options.authorize_recovery({
          operation_id: input.operation_id,
          action_digest: input.action_digest,
          recovery_authorization: input.recovery_authorization,
        }) === true;
      } catch {
        authorized = false;
      }
      if (!authorized) return refuse('consequence_envelope_recovery_refused');
      const reservation = await options.store.recover({
        operation_id: input.operation_id,
        action_digest: input.action_digest,
      });
      if (!reservation) return refuse('consequence_envelope_recovery_binding_mismatch');
      const settled = await boundary.settle(reservation, input.outcome);
      if (settled.status === 'COMMITTED') return { status: 'COMMITTED' };
      if (settled.status === 'RELEASED') return { status: 'RELEASED' };
      return refuse('consequence_envelope_reconciliation_failed');
    },
    snapshot: () => options.store.snapshot(),
    async renew() {
      return { status: 'REFUSED', reason: 'consequence_envelope_new_signed_epoch_required' };
    },
  };
  return Object.freeze(boundary);
}

export async function allocateConsequenceEnvelopeSlice(options: {
  parent: ConsequenceEnvelopeBoundary;
  operation_id: string;
  child: {
    envelope_id: string;
    state_domain_id: string;
    epoch: number;
    capacity_units: string;
    validity: { not_before: string; not_after: string };
    issuer: { id: string; key_id: string };
  };
  signing_keys: AgileSigningKey[];
  mldsaBackend?: AgilityOptions['mldsaBackend'];
}): Promise<
  | { status: 'ALLOCATED'; envelope: ConsequenceEnvelope }
  | { status: 'REFUSED'; reason: string }
> {
  const child = options?.child;
  if (!child || !decimal(child.capacity_units) || !identifier(child.envelope_id)
      || !identifier(child.state_domain_id) || child.state_domain_id === options.parent.envelope.state_domain_id
      || !Number.isSafeInteger(child.epoch) || child.epoch <= 0
      || !instant(child.validity.not_before) || !instant(child.validity.not_after)
      || Date.parse(child.validity.not_before) < Date.parse(options.parent.envelope.validity.not_before)
      || Date.parse(child.validity.not_after) > Date.parse(options.parent.envelope.validity.not_after)) {
    return { status: 'REFUSED', reason: 'consequence_envelope_slice_invalid' };
  }
  const actionDigest = digestAeb({
    action_type: 'consequence-envelope.slice.issue.1',
    parent_envelope_id: options.parent.envelope.envelope_id,
    child_envelope_id: child.envelope_id,
    child_state_domain_id: child.state_domain_id,
    child_epoch: child.epoch,
    capacity_units: child.capacity_units,
  });
  const reservation = await options.parent.reserveUnits({
    operation_id: options.operation_id,
    state_domain_id: options.parent.envelope.state_domain_id,
    expected_epoch: options.parent.envelope.epoch,
    action_digest: actionDigest,
    impact_units: child.capacity_units,
  });
  if (reservation.status !== 'RESERVED') return reservation;
  let envelope: ConsequenceEnvelope;
  try {
    envelope = await issueConsequenceEnvelope({
      ...child,
      impact_profile_id: options.parent.envelope.impact_profile_id,
      impact_profile_digest: options.parent.envelope.impact_profile_digest,
      issuer: child.issuer,
      parent_allocation: {
        parent_envelope_id: options.parent.envelope.envelope_id,
        parent_envelope_digest: options.parent.envelope_digest,
        parent_state_domain_id: options.parent.envelope.state_domain_id,
        parent_epoch: options.parent.envelope.epoch,
        allocation_operation_id: options.operation_id,
        allocation_units: child.capacity_units,
      },
      renewable: false,
    }, {
      signing_keys: options.signing_keys,
      mldsaBackend: options.mldsaBackend,
      deterministic: true,
    });
  } catch {
    await options.parent.releaseNotEntered(reservation.reservation);
    return { status: 'REFUSED', reason: 'consequence_envelope_slice_signing_failed' };
  }
  const entered = await options.parent.beginProviderEntry(reservation.reservation);
  if (entered.status !== 'ENTERED') {
    await options.parent.releaseNotEntered(reservation.reservation);
    return { status: 'REFUSED', reason: 'consequence_envelope_slice_allocation_conflict' };
  }
  const committed = await options.parent.settle(reservation.reservation, 'COMMITTED');
  if (committed.status !== 'COMMITTED') {
    return { status: 'REFUSED', reason: 'consequence_envelope_slice_commit_unconfirmed' };
  }
  return { status: 'ALLOCATED', envelope };
}

export default Object.freeze({
  CONSEQUENCE_ENVELOPE_VERSION,
  CONSEQUENCE_ENVELOPE_REQUIRED_ALGORITHMS,
  CONSEQUENCE_ENVELOPE_REFILL_POLICY,
  FINANCE_CUMULATIVE_EXPOSURE_PROFILE,
  GRID_ACTIVE_POWER_PROFILE,
  GRACE_CURTAILMENT_IMPACT_PROFILE,
  issueConsequenceEnvelope,
  verifyConsequenceEnvelope,
  createMemoryConsequenceEnvelopeStore,
  createConsequenceEnvelopeBoundary,
  allocateConsequenceEnvelopeSlice,
});
