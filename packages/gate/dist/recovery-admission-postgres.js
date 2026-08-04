// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * PostgreSQL reference scaffold for one LOCAL_ATOMIC recovery admission.
 *
 * A presenter-supplied recovery decision is deliberately absent from this API.
 * The scaffold evaluates the signed artifact itself, consumes an existing
 * ordinary AdmissionStore reservation, and only then enters the local
 * transaction. No authority or PostgreSQL operation is retried.
 *
 * This module deliberately has no `pg` dependency. Callback confinement to the
 * supplied transaction client is a deployment assertion, not sandbox
 * enforcement performed by this reference scaffold.
 */
import { evaluateRecoveryAdmission, deriveRecoveryAdmissionSnapshotBindings, } from './recovery-admission.js';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const OWNER_TOKEN = /^admission-owner:v2:[A-Za-z0-9_-]{32,128}$/;
const INVOCATION_TOKEN = /^admission-invocation:v2:[A-Za-z0-9_-]{32,128}$/;
export const RECOVERY_ADMISSION_POSTGRES_BEGIN = 'BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE';
function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function digest(value) {
    return typeof value === 'string' && DIGEST.test(value);
}
function validInstant(value) {
    return typeof value === 'string' && Number.isFinite(Date.parse(value));
}
function errorValue(value, fallback) {
    return value instanceof Error ? value : new Error(fallback, { cause: value });
}
function evidenceFields(evidenceDigest) {
    return evidenceDigest === undefined ? {} : { evidence_digest: evidenceDigest };
}
function notInvoked(reason) {
    return Object.freeze({ outcome: 'NOT_INVOKED', invoked: false, reason });
}
function indeterminate(invoked, reason, evidenceDigest) {
    return Object.freeze({
        outcome: 'INDETERMINATE',
        invoked,
        reason,
        ...evidenceFields(evidenceDigest),
    });
}
function provenNotCommitted(reason, evidenceDigest) {
    return Object.freeze({
        outcome: 'PROVEN_NOT_COMMITTED',
        invoked: true,
        reason,
        evidence_digest: evidenceDigest,
    });
}
function committed(result, evidenceDigest) {
    return Object.freeze({
        outcome: 'COMMITTED',
        invoked: true,
        result,
        evidence_digest: evidenceDigest,
    });
}
function assertCallbacks(options) {
    if (!isRecord(options)
        || typeof options.perform !== 'function'
        || typeof options.validatePrecommit !== 'function'
        || typeof options.recheckCurrent !== 'function'
        || typeof options.ownerToken !== 'string'
        || !OWNER_TOKEN.test(options.ownerToken)
        || typeof options.invocationToken !== 'string'
        || !INVOCATION_TOKEN.test(options.invocationToken)
        || (options.now !== undefined && typeof options.now !== 'function')) {
        throw new TypeError('recovery-admission Postgres reference scaffold options are invalid');
    }
}
function capabilityBinding(decision) {
    if (decision.recovery_route_accepted !== true
        || decision.route !== 'LOCAL_ATOMIC'
        || decision.scope !== 'INTRA_TRANSACTION_ONLY'
        || decision.retry_permitted !== false)
        return 'route_mismatch';
    const capability = decision.capability;
    if (!isRecord(capability)
        || capability.mode !== 'LOCAL_ATOMIC'
        || !isRecord(capability.recovery)
        || capability.recovery.scope !== 'INTRA_TRANSACTION_ONLY'
        || typeof capability.tenant_id !== 'string' || capability.tenant_id.length === 0
        || typeof capability.admission_id !== 'string' || capability.admission_id.length === 0
        || !digest(capability.admission_snapshot_digest)
        || typeof capability.operation_id !== 'string' || capability.operation_id.length === 0
        || typeof capability.action_caid !== 'string' || capability.action_caid.length === 0
        || !digest(capability.action_digest)
        || !digest(capability.adapter_digest)
        || !digest(capability.recovery.adapter_digest)
        || capability.recovery.adapter_digest !== capability.adapter_digest
        || !digest(capability.recovery.state_domain_digest)
        || !Number.isSafeInteger(capability.recovery.max_transaction_ms)
        || capability.recovery.max_transaction_ms < 1
        || !validInstant(capability.expires_at)
        || !validInstant(capability.action_capability_expires_at)
        || !isRecord(decision.status)
        || !validInstant(decision.status.valid_until))
        return 'recovery_binding_invalid';
    return Object.freeze({
        capability,
        tenant_id: capability.tenant_id,
        admission_id: capability.admission_id,
        admission_snapshot_digest: capability.admission_snapshot_digest,
        operation_id: capability.operation_id,
        action_caid: capability.action_caid,
        action_digest: capability.action_digest,
        adapter_digest: capability.adapter_digest,
        state_domain_digest: capability.recovery.state_domain_digest,
        max_transaction_ms: capability.recovery.max_transaction_ms,
        deadline: Math.min(Date.parse(capability.expires_at), Date.parse(capability.action_capability_expires_at), Date.parse(decision.status.valid_until)),
    });
}
function snapshotMatches(snapshot, binding) {
    if (!(isRecord(snapshot)
        && snapshot.snapshot_digest === binding.admission_snapshot_digest
        && isRecord(snapshot.body)
        && snapshot.body.tenant_id === binding.tenant_id
        && snapshot.body.admission_id === binding.admission_id
        && snapshot.body.operation_id === binding.operation_id
        && snapshot.body.caid === binding.action_caid
        && snapshot.body.action_digest === binding.action_digest
        && isRecord(snapshot.body.provider)
        && snapshot.body.provider.provider_id === binding.capability.provider_id
        && snapshot.body.executor_adapter_digest === binding.adapter_digest))
        return false;
    try {
        const derived = deriveRecoveryAdmissionSnapshotBindings(snapshot.body);
        return derived.account_digest === binding.capability.account_digest
            && derived.environment_digest === binding.capability.environment_digest
            && derived.adapter_digest === binding.capability.adapter_digest
            && derived.trust_epoch_digest === binding.capability.trust_epoch_digest
            && derived.config_epoch_digest === binding.capability.config_epoch_digest
            && derived.resource_set_digest === binding.capability.resource_set_digest;
    }
    catch {
        return false;
    }
}
function recordMatches(record, binding) {
    return isRecord(record)
        && record.tenant_id === binding.tenant_id
        && record.admission_id === binding.admission_id
        && record.operation_id === binding.operation_id
        && record.snapshot_digest === binding.admission_snapshot_digest
        && Number.isSafeInteger(record.revision)
        && record.revision >= 0;
}
function admissionStoreUsable(value) {
    return isRecord(value)
        && value.atomic === true
        && value.compareAndSwap === true
        && value.appendOnlyJournal === true
        && value.exclusiveActuation === true
        && value.transactionalCurrentness === true
        && typeof value.read === 'function'
        && typeof value.readSnapshot === 'function'
        && typeof value.beginInvocationWithPreparedToken === 'function'
        && typeof value.recordProviderOutcome === 'function';
}
function poolFailure(pool, binding) {
    if (!isRecord(pool) || typeof pool.connect !== 'function')
        return 'pool_guarantee_mismatch';
    if (pool.localAtomic !== true
        || pool.policyBoundToSingleTransaction !== true
        || pool.externalEffectsForbidden !== true)
        return 'pool_guarantee_mismatch';
    if (pool.stateDomainDigest !== binding.state_domain_digest) {
        return 'state_domain_digest_mismatch';
    }
    if (pool.adapterDigest !== binding.adapter_digest)
        return 'adapter_digest_mismatch';
    return null;
}
/**
 * Execute at most once. The signed artifact is evaluated internally and the
 * ordinary RESERVED admission is consumed with the caller's durably custodied
 * prepared invocation token before BEGIN or `perform`. No SQLSTATE, callback,
 * outcome-recording, authority, or ambiguous COMMIT failure is retried, and
 * authority is never restored by this reference scaffold.
 */
export async function executeRecoveryAdmissionPostgresLocalAtomic(options) {
    assertCallbacks(options);
    let decision;
    try {
        decision = await evaluateRecoveryAdmission(options.artifact, options.verificationContext, options.evaluatorDependencies);
    }
    catch {
        return notInvoked('evaluation_failed');
    }
    if (decision.route === 'REFUSED')
        return notInvoked('recovery_admission_refused');
    const binding = capabilityBinding(decision);
    if (typeof binding === 'string')
        return notInvoked(binding);
    const selectedPoolFailure = poolFailure(options.pool, binding);
    if (selectedPoolFailure)
        return notInvoked(selectedPoolFailure);
    const admissionStore = options.admissionStore;
    if (!admissionStoreUsable(admissionStore)) {
        return notInvoked('admission_store_guarantee_mismatch');
    }
    const now = options.now ?? Date.now;
    let preflightNow;
    try {
        preflightNow = now();
    }
    catch {
        return notInvoked('clock_invalid');
    }
    if (!Number.isFinite(preflightNow))
        return notInvoked('clock_invalid');
    if (preflightNow >= binding.deadline)
        return notInvoked('deadline_expired');
    let reservedRecord;
    try {
        reservedRecord = await admissionStore.read({
            tenant_id: binding.tenant_id,
            admission_id: binding.admission_id,
        });
    }
    catch {
        return notInvoked('admission_read_failed');
    }
    if (reservedRecord === null)
        return notInvoked('admission_not_found');
    if (!recordMatches(reservedRecord, binding))
        return notInvoked('admission_binding_mismatch');
    let reservedSnapshot;
    try {
        reservedSnapshot = await admissionStore.readSnapshot(binding.admission_snapshot_digest);
    }
    catch {
        return notInvoked('admission_snapshot_read_failed');
    }
    if (reservedSnapshot === null)
        return notInvoked('admission_snapshot_not_found');
    if (!snapshotMatches(reservedSnapshot, binding)) {
        return notInvoked('admission_binding_mismatch');
    }
    if (reservedRecord.state !== 'RESERVED'
        || reservedRecord.execution_right !== 'RESERVED'
        || reservedRecord.provider_attempt !== 'NOT_ENTERED') {
        return notInvoked('admission_not_reserved');
    }
    let begun;
    try {
        begun = await admissionStore.beginInvocationWithPreparedToken({
            tenant_id: binding.tenant_id,
            admission_id: binding.admission_id,
            expected_revision: reservedRecord.revision,
            owner_token: options.ownerToken,
            invocation_token: options.invocationToken,
        });
    }
    catch {
        return indeterminate(false, 'begin_invocation_ambiguous');
    }
    if (!isRecord(begun) || begun.ok !== true) {
        return notInvoked('begin_invocation_refused');
    }
    if (!snapshotMatches(begun.snapshot, binding)
        || !recordMatches(begun.record, binding)
        || begun.record.revision !== reservedRecord.revision + 1
        || begun.record.state !== 'INVOKING'
        || begun.record.execution_right !== 'CONSUMED'
        || begun.record.provider_attempt !== 'INVOKING'
        || begun.invocation_token !== options.invocationToken) {
        return indeterminate(false, 'begin_invocation_ambiguous');
    }
    const invokingRecord = begun.record;
    const invocationToken = options.invocationToken;
    const invocation = Object.freeze({
        decision,
        capability: binding.capability,
        snapshot: begun.snapshot,
        record: invokingRecord,
        invocation_token: invocationToken,
    });
    const observedAt = () => {
        try {
            const value = now();
            if (Number.isFinite(value))
                return new Date(value).toISOString();
        }
        catch {
            // The evaluator already validated verificationContext.now.
        }
        return options.verificationContext.now;
    };
    const persistOutcome = async (value, evidenceDigest, result) => {
        try {
            const recorded = await admissionStore.recordProviderOutcome({
                tenant_id: binding.tenant_id,
                admission_id: binding.admission_id,
                expected_revision: invokingRecord.revision,
                owner_token: options.ownerToken,
                invocation_token: invocationToken,
                value,
                evidence_digest: evidenceDigest ?? null,
                observed_at: observedAt(),
            });
            if (!isRecord(recorded) || recorded.ok !== true
                || !recordMatches(recorded.record, binding)
                || recorded.record.revision !== invokingRecord.revision + 1
                || recorded.record.state !== value
                || recorded.record.provider_attempt !== value
                || !isRecord(recorded.record.provider_outcome)
                || recorded.record.provider_outcome.value !== value
                || recorded.record.provider_outcome.evidence_digest !== (evidenceDigest ?? null)) {
                return indeterminate(true, 'provider_outcome_recording_failed', evidenceDigest);
            }
            return result;
        }
        catch {
            return indeterminate(true, 'provider_outcome_recording_failed', evidenceDigest);
        }
    };
    const persistIndeterminate = (reason, evidenceDigest) => persistOutcome('INDETERMINATE', evidenceDigest, indeterminate(true, reason, evidenceDigest));
    let client;
    try {
        client = await options.pool.connect();
    }
    catch {
        return await persistIndeterminate('connection_failed');
    }
    if (!isRecord(client)
        || typeof client.query !== 'function'
        || typeof client.release !== 'function') {
        return await persistIndeterminate('connection_failed');
    }
    let evidenceDigest;
    let discardError;
    let transactionStartedAt = preflightNow;
    const timingFailure = () => {
        let current;
        try {
            current = now();
        }
        catch {
            return 'clock_invalid';
        }
        if (!Number.isFinite(current) || current < transactionStartedAt)
            return 'clock_invalid';
        if (current >= binding.deadline)
            return 'deadline_expired';
        if (current - transactionStartedAt > binding.max_transaction_ms) {
            return 'transaction_timeout';
        }
        return null;
    };
    const rollback = async (reason) => {
        try {
            await client.query('ROLLBACK');
        }
        catch (error) {
            discardError = errorValue(error, 'unknown PostgreSQL ROLLBACK failure');
            return await persistIndeterminate('rollback_failed', evidenceDigest);
        }
        if (!evidenceDigest)
            return await persistIndeterminate('evidence_required');
        return await persistOutcome('PROVEN_NOT_COMMITTED', evidenceDigest, provenNotCommitted(reason, evidenceDigest));
    };
    try {
        try {
            transactionStartedAt = now();
            if (!Number.isFinite(transactionStartedAt)) {
                discardError = new Error('recovery-admission clock is invalid');
                return await persistIndeterminate('clock_invalid');
            }
            await client.query(RECOVERY_ADMISSION_POSTGRES_BEGIN);
        }
        catch (error) {
            discardError = errorValue(error, 'unknown PostgreSQL BEGIN failure');
            return await persistIndeterminate('begin_failed');
        }
        let timing = timingFailure();
        if (timing)
            return await rollback(timing);
        let performed;
        try {
            const rawPerformed = await options.perform(client, invocation);
            if (isRecord(rawPerformed) && digest(rawPerformed.evidence_digest)) {
                evidenceDigest = rawPerformed.evidence_digest;
            }
            if (!isRecord(rawPerformed)
                || !Object.hasOwn(rawPerformed, 'result')
                || !digest(rawPerformed.evidence_digest)) {
                return await rollback('perform_failed');
            }
            performed = rawPerformed;
        }
        catch {
            return await rollback('perform_failed');
        }
        timing = timingFailure();
        if (timing)
            return await rollback(timing);
        try {
            if (await options.validatePrecommit(client, performed, invocation) !== true) {
                return await rollback('precommit_validation_failed');
            }
        }
        catch {
            return await rollback('precommit_validation_failed');
        }
        timing = timingFailure();
        if (timing)
            return await rollback(timing);
        try {
            if (await options.recheckCurrent(client, invocation) !== true) {
                return await rollback('currentness_recheck_failed');
            }
        }
        catch {
            return await rollback('currentness_recheck_failed');
        }
        timing = timingFailure();
        if (timing)
            return await rollback(timing);
        try {
            await client.query('COMMIT');
        }
        catch (error) {
            discardError = errorValue(error, 'unknown PostgreSQL COMMIT failure');
            return await persistIndeterminate('commit_acknowledgement_failed', evidenceDigest);
        }
        const committedEvidenceDigest = evidenceDigest;
        if (!committedEvidenceDigest) {
            return await persistIndeterminate('evidence_required');
        }
        return await persistOutcome('COMMITTED', committedEvidenceDigest, committed(performed.result, committedEvidenceDigest));
    }
    finally {
        try {
            client.release(discardError);
        }
        catch {
            // Release occurs after the outcome discriminator is established.
        }
    }
}
export default executeRecoveryAdmissionPostgresLocalAtomic;
//# sourceMappingURL=recovery-admission-postgres.js.map