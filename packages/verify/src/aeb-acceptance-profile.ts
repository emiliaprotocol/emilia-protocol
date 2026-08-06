// SPDX-License-Identifier: Apache-2.0
/**
 * Relying-party-owned, content-addressed acceptance bar for AEB evidence.
 *
 * One immutable profile governs both deployment modes. Monitor mode is
 * deliberately non-authorizing and non-consuming. Enforce mode delegates the
 * final decision to the AEB execution boundary, including exact-record-bound
 * verification, local authority, and atomic native replay consumption.
 */
import {
  aebReservationKey,
  authorizeAebExecution,
  digestAeb,
  type AebConsumptionStore,
  type AebDigest,
  type AebEvaluationRecord,
  type AebEvaluationVerification,
} from './aeb-adapter-contract.js';

type Obj = Record<string, unknown>;

export const AEB_ACCEPTANCE_PROFILE_VERSION = 'EP-AEB-ACCEPTANCE-PROFILE-v1';

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const IDENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/;
const ROLE_RE = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
const ACTION_TYPE_RE = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*$/;
const PROFILE_KEYS = new Set([
  '@version', 'profile_id', 'version', 'authored_by', 'relying_party_id',
  'action_type', 'pinned_config_digest', 'requirement_ref', 'requirement_digest',
  'registry_digest', 'required_roles', 'accepted_inputs', 'modes', 'profile_digest',
]);
const INPUT_KEYS = new Set([
  'adapter_id', 'adapter_version', 'profile_id', 'profile_digest', 'evidence_role',
]);
const MODES_KEYS = new Set(['monitor', 'enforce']);
const MONITOR_KEYS = new Set(['authorizes_execution', 'consumes_evidence']);
const ENFORCE_KEYS = new Set([
  'requires_execution_verification', 'requires_local_authorization',
  'requires_one_time_consumption',
]);

export interface AebAcceptedInput {
  adapter_id: string;
  adapter_version: string;
  profile_id: string;
  profile_digest: AebDigest;
  evidence_role: string;
}

export interface AebAcceptanceProfile {
  '@version': typeof AEB_ACCEPTANCE_PROFILE_VERSION;
  profile_id: string;
  version: number;
  authored_by: string;
  relying_party_id: string;
  action_type: string;
  pinned_config_digest: AebDigest;
  requirement_ref: string;
  requirement_digest: AebDigest;
  registry_digest: AebDigest;
  required_roles: readonly string[];
  /** Allowlist. The AEB requirement determines which roles must be present. */
  accepted_inputs: readonly AebAcceptedInput[];
  modes: {
    monitor: {
      authorizes_execution: false;
      consumes_evidence: false;
    };
    enforce: {
      requires_execution_verification: true;
      requires_local_authorization: true;
      requires_one_time_consumption: true;
    };
  };
  profile_digest: AebDigest;
}

export type AebAcceptanceProfileInput = Omit<AebAcceptanceProfile, 'modes' | 'profile_digest'>;

export interface AebAcceptanceProfileVerification {
  valid: boolean;
  profile_digest: AebDigest | null;
  reasons: string[];
}

export interface AebAcceptanceDecision {
  state: 'MONITOR_WOULD_ACCEPT' | 'MONITOR_WOULD_REFUSE' | 'AUTHORIZED' | 'REFUSED' | 'RECONCILIATION_REQUIRED';
  allowed: boolean;
  invoke_allowed: boolean;
  would_enforce: boolean;
  reason: string;
  acceptance_profile_digest: AebDigest | null;
  program_digest: AebDigest | null;
  reservation_key?: string;
}

function isRecord(value: unknown): value is Obj {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Obj, keys: ReadonlySet<string>): boolean {
  return Object.keys(value).length === keys.size && Object.keys(value).every((key) => keys.has(key));
}

function validIdentifier(value: unknown): value is string {
  return typeof value === 'string' && IDENT_RE.test(value);
}

function validDigest(value: unknown): value is AebDigest {
  return typeof value === 'string' && DIGEST_RE.test(value);
}

function inputKey(input: AebAcceptedInput): string {
  return [input.evidence_role, input.adapter_id, input.adapter_version, input.profile_id, input.profile_digest].join('\u0000');
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function freezeDeep<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value as Obj)) freezeDeep(child);
    Object.freeze(value);
  }
  return value;
}

function unsignedProfile(profile: AebAcceptanceProfile): Omit<AebAcceptanceProfile, 'profile_digest'> {
  const copy = structuredClone(profile) as AebAcceptanceProfile;
  delete (copy as Partial<AebAcceptanceProfile>).profile_digest;
  return copy;
}

export function computeAebAcceptanceProfileDigest(profile: AebAcceptanceProfile): AebDigest {
  return digestAeb(unsignedProfile(profile));
}

function shapeReasons(profile: unknown): string[] {
  const reasons: string[] = [];
  if (!isRecord(profile) || !exactKeys(profile, PROFILE_KEYS)) return ['acceptance_profile_malformed'];
  if (profile['@version'] !== AEB_ACCEPTANCE_PROFILE_VERSION
      || !validIdentifier(profile.profile_id)
      || !Number.isSafeInteger(profile.version) || Number(profile.version) < 1
      || !validIdentifier(profile.authored_by)
      || !validIdentifier(profile.relying_party_id)
      || typeof profile.action_type !== 'string' || !ACTION_TYPE_RE.test(profile.action_type)
      || !validDigest(profile.pinned_config_digest)
      || !validIdentifier(profile.requirement_ref)
      || !validDigest(profile.requirement_digest)
      || !validDigest(profile.registry_digest)
      || !validDigest(profile.profile_digest)) reasons.push('acceptance_profile_malformed');

  if (!Array.isArray(profile.required_roles) || profile.required_roles.length === 0
      || profile.required_roles.some((role) => typeof role !== 'string' || !ROLE_RE.test(role))) {
    reasons.push('acceptance_profile_roles_invalid');
  } else if (JSON.stringify(profile.required_roles) !== JSON.stringify(sortedUnique(profile.required_roles))) {
    reasons.push('acceptance_profile_noncanonical');
  }

  const accepted = profile.accepted_inputs;
  if (!Array.isArray(accepted) || accepted.length === 0) {
    reasons.push('acceptance_profile_inputs_invalid');
  } else {
    const parsed: AebAcceptedInput[] = [];
    for (const item of accepted) {
      if (!isRecord(item) || !exactKeys(item, INPUT_KEYS)
          || !validIdentifier(item.adapter_id) || !validIdentifier(item.adapter_version)
          || !validIdentifier(item.profile_id) || !validDigest(item.profile_digest)
          || typeof item.evidence_role !== 'string' || !ROLE_RE.test(item.evidence_role)) {
        reasons.push('acceptance_profile_inputs_invalid');
        continue;
      }
      parsed.push(item as unknown as AebAcceptedInput);
    }
    const keys = parsed.map(inputKey);
    if (keys.length !== new Set(keys).size || JSON.stringify(keys) !== JSON.stringify([...keys].sort())) {
      reasons.push('acceptance_profile_noncanonical');
    }
    if (Array.isArray(profile.required_roles)) {
      const roles = new Set(parsed.map((item) => item.evidence_role));
      if (profile.required_roles.some((role) => !roles.has(role))) reasons.push('acceptance_profile_role_unmapped');
    }
  }

  if (!isRecord(profile.modes) || !exactKeys(profile.modes, MODES_KEYS)
      || !isRecord(profile.modes.monitor) || !exactKeys(profile.modes.monitor, MONITOR_KEYS)
      || profile.modes.monitor.authorizes_execution !== false
      || profile.modes.monitor.consumes_evidence !== false
      || !isRecord(profile.modes.enforce) || !exactKeys(profile.modes.enforce, ENFORCE_KEYS)
      || profile.modes.enforce.requires_execution_verification !== true
      || profile.modes.enforce.requires_local_authorization !== true
      || profile.modes.enforce.requires_one_time_consumption !== true) {
    reasons.push('acceptance_profile_modes_invalid');
  }
  return sortedUnique(reasons);
}

export function defineAebAcceptanceProfile(input: AebAcceptanceProfileInput): AebAcceptanceProfile {
  const requiredRoles = sortedUnique(input.required_roles);
  const acceptedInputs = [...structuredClone(input.accepted_inputs)]
    .sort((a, b) => inputKey(a).localeCompare(inputKey(b)));
  const profile = {
    ...structuredClone(input),
    required_roles: requiredRoles,
    accepted_inputs: acceptedInputs,
    modes: {
      monitor: { authorizes_execution: false as const, consumes_evidence: false as const },
      enforce: {
        requires_execution_verification: true as const,
        requires_local_authorization: true as const,
        requires_one_time_consumption: true as const,
      },
    },
    profile_digest: digestAeb(null),
  } as AebAcceptanceProfile;
  const reasons = shapeReasons(profile);
  if (reasons.length > 0) throw new TypeError(reasons.join(';'));
  profile.profile_digest = computeAebAcceptanceProfileDigest(profile);
  return freezeDeep(profile);
}

function verifyAebAcceptanceProfileInner(
  profile: unknown,
  expectedDigest?: AebDigest,
): AebAcceptanceProfileVerification {
  const reasons = shapeReasons(profile);
  const typed = profile as AebAcceptanceProfile;
  let computed: AebDigest | null = null;
  if (isRecord(profile)) {
    try { computed = computeAebAcceptanceProfileDigest(typed); } catch { reasons.push('acceptance_profile_malformed'); }
  }
  if (computed === null || !validDigest(typed?.profile_digest) || computed !== typed.profile_digest
      || (expectedDigest !== undefined && expectedDigest !== typed?.profile_digest)) {
    reasons.push('acceptance_profile_digest_mismatch');
  }
  return { valid: reasons.length === 0, profile_digest: computed, reasons: sortedUnique(reasons) };
}

export function verifyAebAcceptanceProfile(
  profile: unknown,
  expectedDigest?: AebDigest,
): AebAcceptanceProfileVerification {
  try {
    return verifyAebAcceptanceProfileInner(profile, expectedDigest);
  } catch {
    return { valid: false, profile_digest: null, reasons: ['acceptance_profile_verification_error'] };
  }
}

function actionTypeMatches(caid: string, actionType: string): boolean {
  return caid.startsWith(`caid:1:${actionType}:`);
}

function recordBindings(profile: AebAcceptanceProfile, record: AebEvaluationRecord): string[] {
  const reasons: string[] = [];
  if (record.evaluator?.id !== profile.relying_party_id
      || record.evaluator?.pinned_config_digest !== profile.pinned_config_digest
      || record.requirement_ref !== profile.requirement_ref
      || record.requirement_digest !== profile.requirement_digest
      || record.registry_digest !== profile.registry_digest
      || !actionTypeMatches(record.caid, profile.action_type)) {
    reasons.push('acceptance_profile_record_mismatch');
  }
  const allow = new Set(profile.accepted_inputs.map(inputKey));
  const satisfiedRoles = new Set<string>();
  for (const leg of record.legs ?? []) {
    const key = inputKey({
      adapter_id: leg.adapter_id,
      adapter_version: leg.adapter_version,
      profile_id: leg.profile_id,
      profile_digest: leg.profile_digest,
      evidence_role: leg.evidence_role,
    });
    if (!allow.has(key)) reasons.push('acceptance_profile_input_refused');
    if (leg.verdict === 'SATISFIED') satisfiedRoles.add(leg.evidence_role);
  }
  if (profile.required_roles.some((role) => !satisfiedRoles.has(role))) {
    reasons.push('acceptance_profile_required_role_missing');
  }
  return sortedUnique(reasons);
}

function decision(
  state: AebAcceptanceDecision['state'],
  reason: string,
  profileDigest: AebDigest | null,
  programDigest: AebDigest | null,
  reservationKey?: string,
): AebAcceptanceDecision {
  const authorized = state === 'AUTHORIZED';
  return {
    state,
    allowed: authorized,
    invoke_allowed: authorized,
    would_enforce: state === 'MONITOR_WOULD_ACCEPT' || authorized,
    reason,
    acceptance_profile_digest: profileDigest,
    program_digest: programDigest,
    ...(reservationKey ? { reservation_key: reservationKey } : {}),
  };
}

function applyAebAcceptanceProfileInner(
  profile: unknown,
  record: AebEvaluationRecord,
  options: {
    mode: 'monitor' | 'enforce';
    expected_profile_digest: AebDigest;
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
    local_authorization: boolean;
    store?: AebConsumptionStore;
  },
): AebAcceptanceDecision {
  const checked = verifyAebAcceptanceProfile(profile, options.expected_profile_digest);
  const profileDigest = checked.valid ? (profile as AebAcceptanceProfile).profile_digest : checked.profile_digest;
  const programDigest = validDigest(record?.evaluator?.pinned_config_digest)
    ? record.evaluator.pinned_config_digest : null;
  if (!checked.valid) return decision('REFUSED', checked.reasons[0] ?? 'acceptance_profile_invalid', profileDigest, programDigest);
  const typed = profile as AebAcceptanceProfile;
  const bindings = recordBindings(typed, record);
  if (bindings.length > 0) return decision('REFUSED', bindings[0], typed.profile_digest, programDigest);
  if (options.verification?.valid !== true) {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'evaluation_not_verified', typed.profile_digest, programDigest);
  }
  if (options.verification.execution_authorizing !== true) {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'execution_verification_required', typed.profile_digest, programDigest);
  }
  let recordDigest: AebDigest | null = null;
  try { recordDigest = digestAeb(record); } catch { /* malformed records stay unbound */ }
  if (recordDigest === null || options.verification.record_digest !== recordDigest) {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'evaluation_verification_record_mismatch', typed.profile_digest, programDigest);
  }
  if (record.verdict === 'INDETERMINATE') {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'RECONCILIATION_REQUIRED', 'evidence_indeterminate', typed.profile_digest, programDigest);
  }
  if (record.verdict !== 'SATISFIED') {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'evidence_requirement_not_satisfied', typed.profile_digest, programDigest);
  }
  if (record.authority_constraints?.one_time_consumption !== true) {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'one_time_consumption_not_required', typed.profile_digest, programDigest);
  }
  if (!options.local_authorization) {
    return decision(options.mode === 'monitor' ? 'MONITOR_WOULD_REFUSE' : 'REFUSED', 'local_authorization_denied', typed.profile_digest, programDigest);
  }
  if (options.mode === 'monitor') {
    // This is intentionally a pre-consumption result: a concurrent/native
    // replay conflict can only be decided by enforce mode's atomic reserve.
    return decision('MONITOR_WOULD_ACCEPT', 'preconsumption_checks_pass', typed.profile_digest, programDigest);
  }
  if (options.mode !== 'enforce') return decision('REFUSED', 'acceptance_mode_invalid', typed.profile_digest, programDigest);
  if (!options.store) return decision('REFUSED', 'consumption_store_required', typed.profile_digest, programDigest);
  const authorized = authorizeAebExecution(record, {
    verification: options.verification,
    local_authorization: options.local_authorization,
    store: options.store,
  });
  return decision(
    authorized.state,
    authorized.reason,
    typed.profile_digest,
    authorized.program_digest,
    authorized.reservation_key,
  );
}

export function applyAebAcceptanceProfile(
  profile: unknown,
  record: AebEvaluationRecord,
  options: {
    mode: 'monitor' | 'enforce';
    expected_profile_digest: AebDigest;
    verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
    local_authorization: boolean;
    store?: AebConsumptionStore;
  },
): AebAcceptanceDecision {
  try {
    return applyAebAcceptanceProfileInner(profile, record, options);
  } catch {
    return decision('REFUSED', 'acceptance_profile_evaluation_error', null, null);
  }
}

/** Stable key useful for monitoring diagnostics without reserving it. */
export function aebAcceptanceReservationKey(record: AebEvaluationRecord): string {
  return aebReservationKey(record);
}
