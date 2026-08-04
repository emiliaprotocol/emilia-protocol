// SPDX-License-Identifier: Apache-2.0
/**
 * Bridge one currently claimed Remedy Program action into Gate admission.
 *
 * Remedy Program state and its signed receipt are qualification evidence. They
 * never grant an execution right. Only the injected AdmissionStore may create
 * that right, and this bridge intentionally exposes no invocation, provider,
 * retry, finalization, or reconciliation operation.
 */
import {
  createAdmissionSnapshot,
  type AdmissionReserveResult,
  type AdmissionSnapshot,
  type AdmissionSnapshotInput,
  type ExecutionProgramAdmissionStore,
  type ExecutionProgramReserveInput,
  type ExecutionProgramReserveResult,
} from './admission-store.js';
import {
  expectedRemedyProgramReceiptBindings,
  verifyRemedyProgramReceipt,
} from './remedy-program-receipt.js';
import type { RemedyProgramStore } from './remedy-program.js';

type DataRecord = Record<string, any>;

export interface RecoveryAdmissionRemedyOwner {
  owner_mode: 'receipt-program' | 'action-escrow';
  owner_digest: string;
}

export interface RecoveryAdmissionRemedyBridgeOptions {
  remedyProgramStore: RemedyProgramStore;
  admissionStore: ExecutionProgramAdmissionStore;
  trustedReceiptKeys: Readonly<Record<string, unknown>>;
  expectedReceiptIssuer: Readonly<{
    issuer: string;
    tenant: string;
    environment: string;
    audience: string;
    key_id: string;
  }>;
  allowedRemedyOwners: readonly Readonly<RecoveryAdmissionRemedyOwner>[];
}

export interface RecoveryAdmissionRemedyProgramInput
  extends Omit<ExecutionProgramReserveInput, 'admission'> {}

export interface RecoveryAdmissionRemedyInput {
  tenant_id: string;
  remedy_case_instance_id: string;
  original_admission_id: string;
  receipt: unknown;
  admission: AdmissionSnapshotInput | AdmissionSnapshot;
  execution_program?: RecoveryAdmissionRemedyProgramInput;
}

export type RecoveryAdmissionRemedyRefusalReason =
  | 'recovery_admission_input_invalid'
  | 'remedy_current_state_unavailable'
  | 'remedy_case_not_found'
  | 'remedy_not_currently_claimed'
  | 'remedy_receipt_invalid'
  | 'remedy_receipt_state_mismatch'
  | 'remedy_receipt_binding_mismatch'
  | 'tenant_mismatch'
  | 'original_admission_not_found'
  | 'original_admission_binding_mismatch'
  | 'remedy_admission_binding_mismatch'
  | 'authorization_evidence_mismatch'
  | 'remedy_owner_not_allowed';

export type RecoveryAdmissionRemedyResult = {
  ok: true;
  receipt_content_digest: string;
  receipt_payload: Readonly<DataRecord>;
  reservation: Extract<AdmissionReserveResult, { ok: true }>;
} | {
  ok: false;
  reason: RecoveryAdmissionRemedyRefusalReason | string;
};

export interface RecoveryAdmissionRemedyBridge {
  reserve(input: RecoveryAdmissionRemedyInput): Promise<RecoveryAdmissionRemedyResult>;
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const OWNER_MODES = new Set(['receipt-program', 'action-escrow']);
const ISSUER_KEYS = ['issuer', 'tenant', 'environment', 'audience', 'key_id'] as const;

function dataRecord(value: unknown): value is DataRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactIssuer(value: unknown): value is RecoveryAdmissionRemedyBridgeOptions['expectedReceiptIssuer'] {
  return dataRecord(value)
    && Reflect.ownKeys(value).length === ISSUER_KEYS.length
    && ISSUER_KEYS.every((key) => typeof value[key] === 'string' && value[key].length > 0);
}

function exactInput(value: unknown): value is RecoveryAdmissionRemedyInput {
  if (!dataRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => [
    'tenant_id', 'remedy_case_instance_id', 'original_admission_id',
    'receipt', 'admission', 'execution_program',
  ].includes(key))
    && ['tenant_id', 'remedy_case_instance_id', 'original_admission_id', 'receipt', 'admission']
      .every((key) => Object.hasOwn(value, key))
    && typeof value.tenant_id === 'string' && value.tenant_id.length > 0
    && typeof value.remedy_case_instance_id === 'string'
    && value.remedy_case_instance_id.length > 0
    && typeof value.original_admission_id === 'string'
    && value.original_admission_id.length > 0;
}

function snapshotOf(
  value: AdmissionSnapshotInput | AdmissionSnapshot,
): Readonly<AdmissionSnapshot> | null {
  try {
    if (dataRecord(value) && Object.hasOwn(value, 'snapshot_digest')) {
      const body = (value as AdmissionSnapshot).body;
      return createAdmissionSnapshot(body as unknown as AdmissionSnapshotInput).snapshot_digest
          === (value as AdmissionSnapshot).snapshot_digest
        ? value as Readonly<AdmissionSnapshot>
        : null;
    }
    return createAdmissionSnapshot(value as AdmissionSnapshotInput);
  } catch {
    return null;
  }
}

function relationMatches(
  relation: AdmissionSnapshot['body']['remedy_for'],
  original: Readonly<AdmissionSnapshot>,
): boolean {
  return relation !== null
    && relation.tenant_id === original.body.tenant_id
    && relation.admission_id === original.body.admission_id
    && relation.operation_id === original.body.operation_id
    && relation.snapshot_digest === original.snapshot_digest
    && relation.caid === original.body.caid
    && relation.action_digest === original.body.action_digest;
}

function receiptReason(reason: unknown): RecoveryAdmissionRemedyRefusalReason {
  if (reason === 'receipt_state_snapshot_mismatch') return 'remedy_receipt_state_mismatch';
  if (reason === 'receipt_expected_binding_mismatch') return 'remedy_receipt_binding_mismatch';
  return 'remedy_receipt_invalid';
}

function ownerAllowed(
  owners: readonly Readonly<RecoveryAdmissionRemedyOwner>[],
  remedy: DataRecord,
): boolean {
  return owners.some((owner) => owner.owner_mode === remedy.owner_mode
    && owner.owner_digest === remedy.owner_digest);
}

/**
 * Construct a server-pinned bridge. Configuration is copied so callers cannot
 * mutate owner or issuer policy after construction.
 */
export function createRecoveryAdmissionRemedyBridge(
  options: RecoveryAdmissionRemedyBridgeOptions,
): Readonly<RecoveryAdmissionRemedyBridge> {
  if (!dataRecord(options)
      || !dataRecord(options.remedyProgramStore)
      || typeof options.remedyProgramStore.get !== 'function'
      || !dataRecord(options.admissionStore)
      || typeof options.admissionStore.read !== 'function'
      || typeof options.admissionStore.readSnapshot !== 'function'
      || typeof options.admissionStore.reserve !== 'function'
      || typeof options.admissionStore.reserveExecutionProgramAdmission !== 'function'
      || !dataRecord(options.trustedReceiptKeys)
      || !exactIssuer(options.expectedReceiptIssuer)
      || !Array.isArray(options.allowedRemedyOwners)
      || options.allowedRemedyOwners.length === 0) {
    throw new TypeError('recovery admission remedy bridge configuration is invalid');
  }
  const trustedReceiptKeys = Object.freeze({ ...options.trustedReceiptKeys });
  const expectedReceiptIssuer = Object.freeze({ ...options.expectedReceiptIssuer });
  const allowedRemedyOwners = Object.freeze(options.allowedRemedyOwners.map((owner) => {
    if (!dataRecord(owner)
        || Reflect.ownKeys(owner).length !== 2
        || !OWNER_MODES.has(owner.owner_mode)
        || typeof owner.owner_digest !== 'string'
        || !DIGEST.test(owner.owner_digest)) {
      throw new TypeError('allowed remedy owner is invalid');
    }
    return Object.freeze({
      owner_mode: owner.owner_mode as RecoveryAdmissionRemedyOwner['owner_mode'],
      owner_digest: owner.owner_digest,
    });
  }));
  const { remedyProgramStore, admissionStore } = options;

  async function reserve(
    input: RecoveryAdmissionRemedyInput,
  ): Promise<RecoveryAdmissionRemedyResult> {
    if (!exactInput(input)) return { ok: false, reason: 'recovery_admission_input_invalid' };
    const presentedAdmission = dataRecord(input.admission)
      && Object.hasOwn(input.admission, 'snapshot_digest')
      ? (input.admission as AdmissionSnapshot).body
      : input.admission as AdmissionSnapshotInput;
    const presentedInputs = dataRecord(presentedAdmission)
      ? presentedAdmission.inputs : null;
    if (!Array.isArray(presentedInputs)
        || presentedInputs.filter((entry) => dataRecord(entry)
          && entry.role === 'authorization').length !== 1) {
      return { ok: false, reason: 'authorization_evidence_mismatch' };
    }
    const admission = snapshotOf(input.admission);
    if (!admission) return { ok: false, reason: 'remedy_admission_binding_mismatch' };
    if (expectedReceiptIssuer.tenant !== input.tenant_id
        || admission.body.tenant_id !== input.tenant_id) {
      return { ok: false, reason: 'tenant_mismatch' };
    }

    let current;
    try {
      current = await remedyProgramStore.get({
        tenantId: input.tenant_id,
        instanceId: input.remedy_case_instance_id,
      });
    } catch {
      return { ok: false, reason: 'remedy_current_state_unavailable' };
    }
    if (!current || current.ok !== true || !dataRecord(current.state)) {
      return { ok: false, reason: 'remedy_case_not_found' };
    }
    const state = current.state as DataRecord;
    const active = state.active_remedy;
    if (state.tenant_id !== input.tenant_id
        || state.instance_id !== input.remedy_case_instance_id) {
      return { ok: false, reason: 'tenant_mismatch' };
    }
    if (state.status !== 'remedy_claimed'
        || !dataRecord(active)
        || active.status !== 'claimed'
        || active.remedy_operation_id !== admission.body.operation_id) {
      return { ok: false, reason: 'remedy_not_currently_claimed' };
    }

    let expected;
    try {
      expected = expectedRemedyProgramReceiptBindings(state, admission.body.operation_id);
    } catch {
      return { ok: false, reason: 'remedy_not_currently_claimed' };
    }
    const verified = verifyRemedyProgramReceipt(input.receipt, {
      trustedKeys: trustedReceiptKeys,
      expectedIssuer: expectedReceiptIssuer,
      state,
      expected,
    });
    if (!verified.valid || verified.content_digest === null || !dataRecord(verified.payload)) {
      return { ok: false, reason: receiptReason(verified.reason) };
    }
    const payload = verified.payload;
    if (!dataRecord(payload.original_effect) || !dataRecord(payload.remedy)) {
      return { ok: false, reason: 'remedy_receipt_invalid' };
    }
    if (!ownerAllowed(allowedRemedyOwners, payload.remedy)) {
      return { ok: false, reason: 'remedy_owner_not_allowed' };
    }

    const authorizationInputs = admission.body.inputs.filter(
      (entry) => entry.role === 'authorization',
    );
    if (authorizationInputs.length !== 1
        || authorizationInputs[0].payload_digest !== verified.content_digest) {
      return { ok: false, reason: 'authorization_evidence_mismatch' };
    }
    if (admission.body.supersedes_admission_id !== null
        || admission.body.operation_id !== payload.remedy.operation_id
        || admission.body.caid !== payload.remedy.caid
        || admission.body.action_digest !== payload.remedy.action_digest) {
      return { ok: false, reason: 'remedy_admission_binding_mismatch' };
    }

    const originalRecord = await admissionStore.read({
      tenant_id: input.tenant_id,
      admission_id: input.original_admission_id,
    });
    if (!originalRecord) return { ok: false, reason: 'original_admission_not_found' };
    const original = await admissionStore.readSnapshot(originalRecord.snapshot_digest);
    if (!original) return { ok: false, reason: 'original_admission_not_found' };
    if (original.body.tenant_id !== input.tenant_id
        || original.body.admission_id !== input.original_admission_id
        || !relationMatches(admission.body.remedy_for, original)
        || original.body.operation_id !== payload.original_effect.operation_id
        || original.body.caid !== payload.original_effect.caid
        || original.body.action_digest !== payload.original_effect.action_digest) {
      return { ok: false, reason: 'original_admission_binding_mismatch' };
    }

    let reserved: AdmissionReserveResult | ExecutionProgramReserveResult;
    try {
      reserved = input.execution_program === undefined
        ? await admissionStore.reserve(input.admission)
        : await admissionStore.reserveExecutionProgramAdmission({
          ...input.execution_program,
          admission: input.admission,
        });
    } catch {
      return { ok: false, reason: 'remedy_current_state_unavailable' };
    }
    if (!reserved.ok) return reserved;
    return Object.freeze({
      ok: true as const,
      receipt_content_digest: verified.content_digest,
      receipt_payload: verified.payload,
      reservation: reserved,
    });
  }

  return Object.freeze({ reserve });
}

export const createRemedyAdmissionBridge = createRecoveryAdmissionRemedyBridge;

export default createRecoveryAdmissionRemedyBridge;
