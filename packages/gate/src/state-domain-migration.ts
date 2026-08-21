// SPDX-License-Identifier: Apache-2.0
// Receipted state-domain cutover with an external credential, lease, or trust
// fence. The receipt binds what the participating components asserted. It does
// not prove a non-EMILIA destination behaves safely or that an external issuer
// reported truthfully.

import {
  RISK_DIGEST,
  riskClone,
  riskExact,
  riskFreeze,
  riskIdentifier,
  riskInstant,
  riskRecord,
  signRiskBody,
  verifyRiskBody,
  type RiskRecord,
  type TrustedRiskKeys,
} from './reliance-risk-crypto.js';

export const STATE_DOMAIN_MIGRATION_RECEIPT_VERSION = 'EP-STATE-DOMAIN-MIGRATION-RECEIPT-v1';
export const STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY =
  'receipted_source_freeze_sealed_import_external_fence_activation_and_tombstone_not_destination_safety_external_truth_or_physical_exclusivity';

const SNAPSHOT_KEYS = [
  'domain_id', 'epoch', 'final_journal_head_digest',
  'unresolved_operation_count', 'unresolved_operations_digest', 'state_digest',
] as const;
const RECEIPT_KEYS = [
  '@version', 'migration_id', 'tenant_id', 'source_domain_id',
  'destination_domain_id', 'source_epoch', 'target_epoch',
  'source_final_journal_head_digest', 'unresolved_operation_count',
  'unresolved_operations_digest', 'source_state_digest',
  'sealed_import_digest', 'target_activation_digest',
  'external_fence_evidence_digest', 'source_tombstone_digest',
  'completed_at', 'claim_boundary',
] as const;

function validDigest(value: unknown): value is string {
  return typeof value === 'string' && RISK_DIGEST.test(value);
}

function validateSnapshot(value: unknown): asserts value is RiskRecord {
  if (!riskExact(value, SNAPSHOT_KEYS)
      || !riskIdentifier(value.domain_id)
      || !Number.isSafeInteger(value.epoch) || value.epoch < 1
      || !validDigest(value.final_journal_head_digest)
      || !Number.isSafeInteger(value.unresolved_operation_count)
      || value.unresolved_operation_count < 0
      || !validDigest(value.unresolved_operations_digest)
      || !validDigest(value.state_digest)) {
    throw new TypeError('state_domain_snapshot_invalid');
  }
}

function validateReceipt(value: unknown): asserts value is RiskRecord {
  if (!riskRecord(value)) throw new TypeError('state_domain_migration_receipt_invalid');
  const { issuer, proof: _proof, ...body } = value;
  if (issuer !== undefined && (!riskExact(issuer, ['id', 'key_id'])
      || !riskIdentifier(issuer.id) || !riskIdentifier(issuer.key_id))) {
    throw new TypeError('state_domain_migration_receipt_issuer_invalid');
  }
  if (!riskExact(body, RECEIPT_KEYS)
      || body['@version'] !== STATE_DOMAIN_MIGRATION_RECEIPT_VERSION
      || !riskIdentifier(body.migration_id) || !riskIdentifier(body.tenant_id)
      || !riskIdentifier(body.source_domain_id)
      || !riskIdentifier(body.destination_domain_id)
      || body.source_domain_id === body.destination_domain_id
      || !Number.isSafeInteger(body.source_epoch) || body.source_epoch < 1
      || !Number.isSafeInteger(body.target_epoch) || body.target_epoch <= body.source_epoch
      || !validDigest(body.source_final_journal_head_digest)
      || !Number.isSafeInteger(body.unresolved_operation_count)
      || body.unresolved_operation_count < 0
      || !validDigest(body.unresolved_operations_digest)
      || !validDigest(body.source_state_digest)
      || !validDigest(body.sealed_import_digest)
      || !validDigest(body.target_activation_digest)
      || !validDigest(body.external_fence_evidence_digest)
      || !validDigest(body.source_tombstone_digest)
      || !Number.isFinite(riskInstant(body.completed_at))
      || body.claim_boundary !== STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY) {
    throw new TypeError('state_domain_migration_receipt_invalid');
  }
}

export function signStateDomainMigrationReceipt(input: RiskRecord, signer: {
  issuer_id: string;
  key_id: string;
  private_key: import('node:crypto').KeyLike;
}): RiskRecord {
  const body = {
    '@version': STATE_DOMAIN_MIGRATION_RECEIPT_VERSION,
    migration_id: input.migration_id,
    tenant_id: input.tenant_id,
    source_domain_id: input.source_domain_id,
    destination_domain_id: input.destination_domain_id,
    source_epoch: input.source_epoch,
    target_epoch: input.target_epoch,
    source_final_journal_head_digest: input.source_final_journal_head_digest,
    unresolved_operation_count: input.unresolved_operation_count,
    unresolved_operations_digest: input.unresolved_operations_digest,
    source_state_digest: input.source_state_digest,
    sealed_import_digest: input.sealed_import_digest,
    target_activation_digest: input.target_activation_digest,
    external_fence_evidence_digest: input.external_fence_evidence_digest,
    source_tombstone_digest: input.source_tombstone_digest,
    completed_at: input.completed_at,
    claim_boundary: STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY,
  };
  validateReceipt(body);
  return signRiskBody(STATE_DOMAIN_MIGRATION_RECEIPT_VERSION, body, signer);
}

export function verifyStateDomainMigrationReceipt(artifact: unknown, options: {
  trusted_keys?: TrustedRiskKeys;
  expected?: RiskRecord;
} = {}): RiskRecord {
  const refuse = (reason: string) => riskFreeze({
    accepted: false,
    reason,
    receipt: null,
    receipt_digest: null,
  });
  try { validateReceipt(artifact); } catch (error) {
    return refuse((error as Error)?.message || 'state_domain_migration_receipt_invalid');
  }
  const verified = verifyRiskBody(
    artifact,
    STATE_DOMAIN_MIGRATION_RECEIPT_VERSION,
    options.trusted_keys,
  );
  if (!verified.valid || !verified.body) return refuse(verified.reason || 'state_domain_migration_receipt_invalid');
  const body = verified.body;
  const expected = options.expected;
  if (!expected) return refuse('state_domain_migration_expected_context_required');
  if (body.migration_id !== expected.migration_id
      || body.tenant_id !== expected.tenant_id
      || body.source_domain_id !== expected.source_domain_id
      || body.destination_domain_id !== expected.destination_domain_id
      || body.target_epoch !== expected.target_epoch
      || body.issuer.id !== expected.authorizer_id) {
    return refuse('state_domain_migration_context_mismatch');
  }
  return riskFreeze({
    accepted: true,
    reason: null,
    receipt: body,
    receipt_digest: verified.artifact_digest,
    claim_boundary: STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY,
  });
}

function failed(reason: string, phase: string, state = 'REFUSED'): RiskRecord {
  return riskFreeze({ ok: false, reason, phase, state, receipt: null });
}

async function invoke(
  adapter: unknown,
  input: RiskRecord,
  phase: string,
  receiver: unknown = undefined,
): Promise<RiskRecord> {
  if (typeof adapter !== 'function') return { ok: false, reason: `${phase}_adapter_required` };
  try {
    const result = await adapter.call(receiver, riskFreeze(riskClone(input)));
    return riskRecord(result) ? result : { ok: false, reason: `${phase}_result_invalid` };
  } catch {
    return { ok: false, reason: `${phase}_failed` };
  }
}

export async function migrateStateDomain(input: RiskRecord = {}): Promise<RiskRecord> {
  if (!riskIdentifier(input.migration_id) || !riskIdentifier(input.tenant_id)
      || !riskIdentifier(input.source_domain_id)
      || !riskIdentifier(input.destination_domain_id)
      || input.source_domain_id === input.destination_domain_id
      || !Number.isSafeInteger(input.target_epoch) || input.target_epoch < 2
      || !Number.isFinite(riskInstant(input.completed_at))) {
    return failed('state_domain_migration_input_invalid', 'configure');
  }
  if (!input.source || typeof input.source.freeze !== 'function'
      || typeof input.source.readFrozenSnapshot !== 'function'
      || typeof input.source.tombstone !== 'function'
      || !input.target || typeof input.target.importSealed !== 'function'
      || typeof input.target.activate !== 'function') {
    return failed('state_domain_migration_adapter_required', 'configure');
  }

  const context = {
    migration_id: input.migration_id,
    tenant_id: input.tenant_id,
    source_domain_id: input.source_domain_id,
    destination_domain_id: input.destination_domain_id,
    target_epoch: input.target_epoch,
  };
  const freeze = await invoke(input.source.freeze, context, 'source_freeze', input.source);
  if (freeze.ok !== true) return failed(freeze.reason || 'source_freeze_refused', 'source_freeze');

  const rawSnapshot = await invoke(
    input.source.readFrozenSnapshot,
    context,
    'source_snapshot',
    input.source,
  );
  try { validateSnapshot(rawSnapshot); } catch (error) {
    return failed((error as Error)?.message || 'state_domain_snapshot_invalid', 'source_snapshot');
  }
  if (rawSnapshot.domain_id !== input.source_domain_id
      || rawSnapshot.epoch >= input.target_epoch) {
    return failed('state_domain_snapshot_context_mismatch', 'source_snapshot');
  }
  const snapshot = riskFreeze(riskClone(rawSnapshot));

  const imported = await invoke(input.target.importSealed, snapshot, 'target_import', input.target);
  if (imported.ok !== true
      || !validDigest(imported.sealed_import_digest)
      || imported.imported_state_digest !== snapshot.state_digest) {
    return failed(imported.reason || 'sealed_import_verification_failed', 'target_import');
  }

  const fenced = await invoke(input.externalFence, {
    ...context,
    source_epoch: snapshot.epoch,
    source_final_journal_head_digest: snapshot.final_journal_head_digest,
    sealed_import_digest: imported.sealed_import_digest,
  }, 'external_fence');
  const fenceVerification = await invoke(input.verifyExternalFence, {
    statement: fenced.statement,
    expected: context,
  }, 'external_fence_verification');
  if (fenceVerification.verified !== true) {
    return failed(
      fenceVerification.reason || fenced.reason || 'external_fence_unverified',
      'external_fence',
    );
  }
  if (fenceVerification.source_domain_id !== input.source_domain_id
      || fenceVerification.destination_domain_id !== input.destination_domain_id
      || fenceVerification.target_epoch !== input.target_epoch
      || fenceVerification.source_authority_revoked !== true
      || fenceVerification.destination_authority_active !== true
      || fenceVerification.exclusive !== true
      || !validDigest(fenceVerification.evidence_digest)) {
    return failed('external_fence_binding_invalid', 'external_fence');
  }

  const activated = await invoke(input.target.activate, {
    ...context,
    epoch: input.target_epoch,
    sealed_import_digest: imported.sealed_import_digest,
    external_fence_evidence_digest: fenceVerification.evidence_digest,
  }, 'target_activation', input.target);
  if (activated.ok !== true || activated.epoch !== input.target_epoch
      || !validDigest(activated.activation_digest)) {
    return failed(activated.reason || 'target_activation_failed', 'target_activation', 'INDETERMINATE');
  }

  const tombstoned = await invoke(input.source.tombstone, {
    ...context,
    source_epoch: snapshot.epoch,
    final_journal_head_digest: snapshot.final_journal_head_digest,
    target_activation_digest: activated.activation_digest,
    external_fence_evidence_digest: fenceVerification.evidence_digest,
  }, 'source_tombstone', input.source);
  if (tombstoned.ok !== true || !validDigest(tombstoned.tombstone_digest)) {
    return failed(tombstoned.reason || 'source_tombstone_failed', 'source_tombstone', 'INDETERMINATE');
  }

  let receipt;
  try {
    receipt = signStateDomainMigrationReceipt({
      ...context,
      source_epoch: snapshot.epoch,
      source_final_journal_head_digest: snapshot.final_journal_head_digest,
      unresolved_operation_count: snapshot.unresolved_operation_count,
      unresolved_operations_digest: snapshot.unresolved_operations_digest,
      source_state_digest: snapshot.state_digest,
      sealed_import_digest: imported.sealed_import_digest,
      target_activation_digest: activated.activation_digest,
      external_fence_evidence_digest: fenceVerification.evidence_digest,
      source_tombstone_digest: tombstoned.tombstone_digest,
      completed_at: input.completed_at,
    }, input.signer);
  } catch {
    return failed('migration_receipt_signing_failed', 'receipt', 'INDETERMINATE');
  }
  return riskFreeze({
    ok: true,
    reason: null,
    phase: 'complete',
    state: 'COMPLETED',
    receipt,
    claim_boundary: STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY,
  });
}

export default {
  STATE_DOMAIN_MIGRATION_RECEIPT_VERSION,
  STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY,
  signStateDomainMigrationReceipt,
  verifyStateDomainMigrationReceipt,
  migrateStateDomain,
};
