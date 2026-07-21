// SPDX-License-Identifier: Apache-2.0
// Generated from runtime.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { createTrustedActionFirewall, hashCanonical, } from '../../../packages/gate/index.js';
import { parseReceiptCarrier } from '../../../packages/require-receipt/index.js';
import { normalizePrincipal } from './auth.js';
import { validateGateServiceConfig } from './config.js';
export const GITHUB_REPOSITORY_DELETE_ACTION = 'github.repo.delete';
export const GITHUB_REPOSITORY_DELETE_SELECTOR = Object.freeze({
    protocol: 'github',
    tool: 'delete_repo',
});
export const GITHUB_REPOSITORY_DELETE_MANIFEST = Object.freeze({
    '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
    actions: Object.freeze([Object.freeze({
            id: 'github.repo.delete.complete-mediation',
            label: 'GitHub repository delete',
            action_type: GITHUB_REPOSITORY_DELETE_ACTION,
            risk: 'critical',
            receipt_required: true,
            assurance_class: 'class_a',
            match: GITHUB_REPOSITORY_DELETE_SELECTOR,
            why: 'Deletes one GitHub repository after system-of-record observation and exact receipt binding.',
            execution_binding: Object.freeze({
                required_fields: Object.freeze([
                    'action_type',
                    'owner',
                    'repo',
                    'node_id',
                    'default_branch',
                    'visibility',
                ]),
            }),
        })]),
});
export const INTERRUPTED_ACTION_STATUSES = Object.freeze(['observing', 'authorizing', 'executing']);
export const EVIDENCE_EXPORT_VERSION = 'EP-GATE-EVIDENCE-EXPORT-v1';
const BODY_KEYS = Object.freeze(['action', 'owner', 'repo']);
const RESUME_BODY_KEYS = Object.freeze(['action', 'challenge_binding']);
const ACTION_ID = /^[A-Za-z0-9_-]{16,128}$/;
const RECORD_ID = /^[\x21-\x7e]{16,256}$/;
const REPOSITORY_SEGMENT = /^[A-Za-z0-9_.-]+$/;
const HEX_256 = /^[0-9a-f]{64}$/;
const VISIBILITIES = new Set(['public', 'private', 'internal']);
const MAX_EVIDENCE_PAGE = 100;
function response(status, body, headers = {}) {
    return { status, body, headers };
}
/**
 * @param {string | null} [id]
 */
function closedError(status, code, id = null, state = status >= 500 ? 'failed' : 'refused') {
    return response(status, {
        ...(id ? { id } : {}),
        status: state,
        error: { code },
    });
}
function currentTimestamp(now) {
    const value = now();
    const date = new Date(value);
    if (!Number.isFinite(date.getTime()))
        throw new Error('clock_invalid');
    return date.toISOString();
}
function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function jsonSnapshot(value) {
    const encoded = JSON.stringify(value);
    if (typeof encoded !== 'string')
        throw new Error('evidence_entry_not_json');
    const parsed = JSON.parse(encoded);
    if (!isPlainObject(parsed))
        throw new Error('evidence_entry_not_object');
    return parsed;
}
function exactKeys(value, expected) {
    if (!isPlainObject(value))
        return false;
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}
function validateLocator(locator) {
    if (!isPlainObject(locator))
        return { ok: false, code: 'target_invalid' };
    const loc = locator;
    for (const field of ['owner', 'repo']) {
        const value = loc[field];
        if (typeof value !== 'string' || value.length === 0 || value.length > 100
            || value === '.' || value === '..'
            || value !== value.trim() || !REPOSITORY_SEGMENT.test(value)) {
            return { ok: false, code: `${field}_invalid` };
        }
    }
    return { ok: true, locator: { owner: loc.owner, repo: loc.repo } };
}
function validateDeleteRequest(body) {
    const b = body;
    if (!isPlainObject(b))
        return { ok: false, code: 'request_object_required' };
    if (!exactKeys(b, BODY_KEYS))
        return { ok: false, code: 'request_fields_invalid' };
    if (b.action !== GITHUB_REPOSITORY_DELETE_ACTION) {
        return { ok: false, code: 'unsupported_action' };
    }
    return validateLocator(b);
}
function validateResumeRequest(body) {
    const b = body;
    if (!isPlainObject(b))
        return { ok: false, code: 'request_object_required' };
    if (!exactKeys(b, RESUME_BODY_KEYS))
        return { ok: false, code: 'request_fields_invalid' };
    if (b.action !== GITHUB_REPOSITORY_DELETE_ACTION) {
        return { ok: false, code: 'unsupported_action' };
    }
    if (typeof b.challenge_binding !== 'string' || !HEX_256.test(b.challenge_binding)) {
        return { ok: false, code: 'challenge_binding_invalid' };
    }
    return { ok: true, challengeBinding: b.challenge_binding };
}
function boundedObservedText(value, field, max = 256) {
    if (typeof value !== 'string' || value.length === 0 || value.length > max
        || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new Error(`github_repository_${field}_invalid`);
    }
    return value;
}
export function observedGithubRepository(repository, locator) {
    const repo = repository;
    if (!isPlainObject(repo) || !isPlainObject(repo.owner)) {
        throw new Error('github_repository_response_invalid');
    }
    const owner = boundedObservedText(repo.owner.login, 'owner', 100);
    const repoName = boundedObservedText(repo.name, 'repo', 100);
    const nodeId = boundedObservedText(repo.node_id, 'node_id', 512);
    const defaultBranch = boundedObservedText(repo.default_branch, 'default_branch', 256);
    const visibility = boundedObservedText(repo.visibility, 'visibility', 32);
    if (!VISIBILITIES.has(visibility))
        throw new Error('github_repository_visibility_invalid');
    if (owner.toLowerCase() !== locator.owner.toLowerCase()
        || repoName.toLowerCase() !== locator.repo.toLowerCase()) {
        throw new Error('github_repository_locator_mismatch');
    }
    if (repo.full_name !== undefined
        && (typeof repo.full_name !== 'string'
            || repo.full_name.toLowerCase() !== `${owner}/${repoName}`.toLowerCase())) {
        throw new Error('github_repository_full_name_invalid');
    }
    return Object.freeze({
        action_type: GITHUB_REPOSITORY_DELETE_ACTION,
        owner,
        repo: repoName,
        node_id: nodeId,
        default_branch: defaultBranch,
        visibility,
    });
}
function stableIdempotencyKey(receiptId) {
    if (typeof receiptId !== 'string' || receiptId.length === 0) {
        throw new Error('receipt_id_missing_after_authorization');
    }
    return `emilia-${crypto.createHash('sha256').update(receiptId, 'utf8').digest('base64url')}`;
}
function timeoutSignal(milliseconds) {
    return AbortSignal.timeout(milliseconds);
}
function timeoutLike(error) {
    const err = error;
    const candidate = err?.cause ?? err;
    return candidate?.timeout === true
        || candidate?.name === 'TimeoutError'
        || candidate?.name === 'AbortError';
}
function challengeBinding(id, observedAction) {
    return hashCanonical({ action_id: id, observed_action: observedAction });
}
function publicActionRecord(record, expectedId, principalId, { tenantId, gateId }) {
    const rec = record;
    if (!isPlainObject(rec) || rec.id !== expectedId
        || rec.action !== GITHUB_REPOSITORY_DELETE_ACTION
        || rec.principal_id !== principalId
        || rec.tenant_id !== tenantId || rec.gate_id !== gateId
        || typeof rec.status !== 'string')
        return null;
    const locator = validateLocator(rec.target);
    if (!locator.ok)
        return null;
    const projected = {};
    for (const field of [
        'id',
        'action',
        'status',
        'created_at',
        'updated_at',
        'outcome',
        'reason',
        'authorization_evidence_hash',
        'execution_evidence_hash',
    ]) {
        if (typeof rec[field] === 'string')
            projected[field] = rec[field];
    }
    projected.target = locator.locator;
    if (isPlainObject(rec.observed_action)) {
        const observed = {};
        for (const field of [
            'action_type',
            'owner',
            'repo',
            'node_id',
            'default_branch',
            'visibility',
        ]) {
            if (typeof rec.observed_action[field] === 'string')
                observed[field] = rec.observed_action[field];
        }
        projected.observed_action = observed;
    }
    if (isPlainObject(rec.error) && typeof rec.error.code === 'string') {
        projected.error = { code: rec.error.code };
    }
    if (typeof rec.challenge_binding_hash === 'string' && HEX_256.test(rec.challenge_binding_hash)) {
        projected.resume = {
            method: 'POST',
            path: `/v1/actions/${expectedId}/execute`,
            challenge_binding: rec.challenge_binding_hash,
        };
    }
    return projected;
}
function challengeBody(gateBody, { id, observedAction, carrierInvalid, binding }) {
    const gb = (gateBody ?? {});
    const required = isPlainObject(gb?.required) ? gb.required : {};
    return {
        ...(isPlainObject(gb) ? gb : {}),
        action_id: id,
        detail: carrierInvalid ? 'receipt_carrier_invalid' : gb?.detail,
        required: {
            ...required,
            action: GITHUB_REPOSITORY_DELETE_ACTION,
            action_hash: hashCanonical(observedAction),
            observed_action: observedAction,
        },
        resume: {
            method: 'POST',
            path: `/v1/actions/${id}/execute`,
            challenge_binding: binding,
        },
    };
}
function redactedEvidenceRecord(record, actionId, actionRecord) {
    const rec = record;
    if (!isPlainObject(rec) || !Number.isSafeInteger(rec.seq) || rec.seq < 0
        || typeof rec.record_id !== 'string' || !RECORD_ID.test(rec.record_id)
        || typeof rec.hash !== 'string' || !HEX_256.test(rec.hash)
        || (rec.prev_hash !== 'genesis' && !HEX_256.test(rec.prev_hash)))
        return null;
    const decision = rec.kind === 'decision' && rec.selector?.action_id === actionId;
    const execution = rec.kind === 'execution'
        && (rec.hash === actionRecord.execution_evidence_hash
            || rec.authorizes_decision === actionRecord.authorization_evidence_hash);
    if (!decision && !execution)
        return null;
    const projected = {
        seq: rec.seq,
        record_id: rec.record_id,
        prev_hash: rec.prev_hash,
        hash: rec.hash,
        kind: rec.kind,
    };
    for (const field of [
        'at',
        'action',
        'status',
        'reason',
        'required_tier',
        'outcome',
        'authorizes_decision',
        'observed_action_hash',
    ]) {
        if (typeof rec[field] === 'string')
            projected[field] = rec[field];
    }
    if (typeof rec.allow === 'boolean')
        projected.allow = rec.allow;
    projected.action_id = actionId;
    return projected;
}
function verificationProjection(report) {
    const rep = (report ?? {});
    if (!isPlainObject(rep) || typeof rep.ok !== 'boolean') {
        return { ok: false, reason: 'verification_report_invalid' };
    }
    if (rep.ok)
        return { ok: true };
    const projected = { ok: false, reason: 'evidence_verification_failed' };
    if (typeof rep.reason === 'string' && /^[A-Za-z0-9_:-]{1,128}$/.test(rep.reason)) {
        projected.reason = rep.reason;
    }
    if (Number.isSafeInteger(rep.at) && rep.at >= 0)
        projected.at = rep.at;
    return projected;
}
function unavailableBody() {
    return response(503, {
        status: 'unavailable',
        service: 'emilia-gate-service',
        error: { code: 'dependency_not_ready' },
    });
}
export function createGateRuntime(inputConfig) {
    const config = validateGateServiceConfig(inputConfig);
    const connector = Object.freeze({
        getRepository: config.connector.getRepository.bind(config.connector),
        deleteRepository: config.connector.deleteRepository.bind(config.connector),
    });
    const actionStore = Object.freeze({
        create: config.actionStore.create.bind(config.actionStore),
        update: config.actionStore.update.bind(config.actionStore),
        get: config.actionStore.get.bind(config.actionStore),
        transition: config.actionStore.transition.bind(config.actionStore),
        reconcileInterrupted: config.actionStore.reconcileInterrupted.bind(config.actionStore),
    });
    const consumptionStore = Object.freeze({
        durable: true,
        ownershipFenced: true,
        permanentConsumption: true,
        reserve: config.consumptionStore.reserve.bind(config.consumptionStore),
        commit: config.consumptionStore.commit.bind(config.consumptionStore),
        consume: config.consumptionStore.consume.bind(config.consumptionStore),
        has: config.consumptionStore.has.bind(config.consumptionStore),
    });
    const evidenceAdapter = Object.freeze({
        record: config.evidenceLog.record.bind(config.evidenceLog),
        head: config.evidenceLog.head.bind(config.evidenceLog),
        getRecord: config.evidenceLog.getRecord.bind(config.evidenceLog),
        history: config.evidenceLog.history.bind(config.evidenceLog),
        verify: config.evidenceLog.verify.bind(config.evidenceLog),
    });
    const counters = {
        actions_created_total: 0,
        action_authorization_denied_total: 0,
        challenges_total: 0,
        executions_succeeded_total: 0,
        executions_indeterminate_total: 0,
        readiness_checks_total: 0,
        readiness_failures_total: 0,
        startup_reconciled_total: 0,
        evidence_reads_total: 0,
        telemetry_forwarded_total: 0,
        telemetry_dropped_total: 0,
    };
    function forwardTelemetry(record) {
        if (!config.siemForwarder)
            return;
        queueMicrotask(() => {
            Promise.resolve()
                .then(() => config.siemForwarder.forward(structuredClone(record)))
                .then((result) => {
                if (result?.delivered === false)
                    counters.telemetry_dropped_total += 1;
                else
                    counters.telemetry_forwarded_total += 1;
            })
                .catch(() => { counters.telemetry_dropped_total += 1; });
        });
    }
    const evidenceLog = Object.freeze({
        durable: true,
        persisted: true,
        strict: true,
        forkAware: true,
        atomicAppend: true,
        async record(entry) {
            // JSON round-trip removes object aliases that are semantically irrelevant
            // but forbidden by the canonical evidence backend.
            const record = await evidenceAdapter.record(jsonSnapshot(entry));
            forwardTelemetry(record);
            return record;
        },
        verify: evidenceAdapter.verify,
    });
    const gate = createTrustedActionFirewall({
        manifest: GITHUB_REPOSITORY_DELETE_MANIFEST,
        trustedKeys: config.trustedKeys,
        keyRegistry: config.keyRegistry,
        approverKeys: config.approverKeys,
        verifyAssurance: config.verifyAssurance,
        rpId: config.rpId,
        allowedOrigins: config.allowedOrigins,
        maxAgeSec: config.maxAgeSec,
        store: consumptionStore,
        log: evidenceLog,
        allowInlineKey: false,
        allowEphemeralStore: false,
        strictEvidence: true,
        now: config.now,
    });
    let initialized = false;
    let accepting = false;
    let closing = false;
    let initializePromise = null;
    let closePromise = null;
    let readinessInFlight = null;
    function auditEvent(event, id, status) {
        try {
            config.logger?.info?.({
                component: 'emilia-gate-service',
                event,
                action_id: id,
                status,
            });
        }
        catch {
            // Application logging cannot participate in authorization or execution.
        }
    }
    async function initialize() {
        if (initializePromise)
            return initializePromise;
        initializePromise = (async () => {
            const patch = {
                status: 'indeterminate',
                error: { code: 'service_restart_outcome_unknown' },
                updated_at: currentTimestamp(config.now),
            };
            const updated = await actionStore.reconcileInterrupted({
                action: GITHUB_REPOSITORY_DELETE_ACTION,
                statuses: [...INTERRUPTED_ACTION_STATUSES].map(s => String(s)),
                patch: structuredClone(patch),
            });
            if (!Number.isSafeInteger(updated) || updated < 0) {
                throw new Error('action_store_reconciliation_contract_invalid');
            }
            counters.startup_reconciled_total += updated;
            initialized = true;
            if (!closing)
                accepting = true;
            return { reconciled: updated };
        })();
        return initializePromise;
    }
    function markUnready() {
        accepting = false;
    }
    async function close() {
        if (closePromise)
            return closePromise;
        closing = true;
        markUnready();
        closePromise = (async () => {
            const adapters = new Set([
                config.connector,
                config.consumptionStore,
                config.evidenceLog,
                config.actionStore,
                config.siemForwarder,
            ]);
            const hooks = [...adapters]
                .filter((adapter) => typeof adapter?.close === 'function')
                .map((adapter) => Promise.resolve().then(() => adapter.close()));
            const settled = await Promise.allSettled(hooks);
            return {
                closed: settled.filter((result) => result.status === 'fulfilled').length,
                failed: settled.filter((result) => result.status === 'rejected').length,
            };
        })();
        return closePromise;
    }
    async function authenticate(request) {
        try {
            return normalizePrincipal(await config.authenticateRequest(request));
        }
        catch {
            return null;
        }
    }
    async function actionAuthorized(principal, locator) {
        try {
            return (await config.authorizeAction(principal, GITHUB_REPOSITORY_DELETE_ACTION, locator.owner, locator.repo)) === true;
        }
        catch {
            return false;
        }
    }
    async function createAction(principal, locator) {
        for (let attempt = 0; attempt < 3; attempt += 1) {
            const id = config.idFactory();
            if (typeof id !== 'string' || !ACTION_ID.test(id))
                throw new Error('action_id_factory_invalid');
            const at = currentTimestamp(config.now);
            const record = {
                id,
                action: GITHUB_REPOSITORY_DELETE_ACTION,
                status: 'observing',
                principal_id: principal.id,
                tenant_id: config.tenantId,
                gate_id: config.gateId,
                target: { ...locator },
                created_at: at,
                updated_at: at,
            };
            const created = await actionStore.create(structuredClone(record));
            if (created === true) {
                counters.actions_created_total += 1;
                return record;
            }
            if (created !== false)
                throw new Error('action_store_create_contract_invalid');
        }
        throw new Error('action_id_collision_limit');
    }
    async function updateAction(id, principalId, patch) {
        const updated = await actionStore.update(id, principalId, structuredClone({
            ...patch,
            updated_at: currentTimestamp(config.now),
        }));
        if (updated !== true)
            throw new Error('action_store_update_failed');
    }
    async function continueDelete({ actionRecord, principal, receiptCarrier = null }) {
        const { id } = actionRecord;
        const locator = validateLocator(actionRecord.target);
        if (!locator.ok)
            return closedError(409, 'action_not_resumable', id);
        let observedAction;
        try {
            const repository = await connector.getRepository({
                ...locator.locator,
                signal: timeoutSignal(config.connectorTimeoutMs),
            });
            observedAction = observedGithubRepository(repository, locator.locator);
            await updateAction(id, principal.id, {
                status: 'authorizing',
                observed_action: observedAction,
                challenge_binding_hash: null,
            });
        }
        catch (error) {
            const code = timeoutLike(error) ? 'github_observation_timeout' : 'github_observation_failed';
            try {
                await updateAction(id, principal.id, { status: 'failed', error: { code } });
            }
            catch { /* closed below */ }
            auditEvent('observation_failed', id, 'failed');
            return closedError(timeoutLike(error) ? 504 : 502, code, id);
        }
        const carrierProvided = typeof receiptCarrier === 'string' && receiptCarrier.length > 0;
        const receipt = parseReceiptCarrier(receiptCarrier, { maxBytes: config.maxReceiptBytes });
        const carrierInvalid = carrierProvided && receipt === null;
        let deleteAttempted = false;
        let result;
        try {
            result = await gate.run({
                selector: { ...GITHUB_REPOSITORY_DELETE_SELECTOR, action_id: id },
                receipt,
                observedAction: /** @type {any} */ (observedAction),
            }, async (authorization) => {
                await updateAction(id, principal.id, { status: 'executing' });
                deleteAttempted = true;
                const deleted = await connector.deleteRepository({
                    owner: observedAction.owner,
                    repo: observedAction.repo,
                    node_id: observedAction.node_id,
                    default_branch: observedAction.default_branch,
                    visibility: observedAction.visibility,
                    idempotencyKey: stableIdempotencyKey(authorization.evidence?.receipt_id),
                    actionId: id,
                    signal: timeoutSignal(config.connectorTimeoutMs),
                });
                if (!isPlainObject(deleted) || deleted.status !== 204) {
                    throw new Error('github_delete_outcome_unknown');
                }
                return { status: 204 };
            });
        }
        catch (error) {
            const indeterminate = deleteAttempted;
            const status = indeterminate ? 'indeterminate' : 'failed';
            const code = indeterminate
                ? (timeoutLike(error) ? 'github_delete_timeout_outcome_unknown' : 'github_delete_outcome_unknown')
                : 'gate_unavailable';
            try {
                await updateAction(id, principal.id, { status, error: { code } });
            }
            catch { /* evidence remains authoritative */ }
            if (indeterminate)
                counters.executions_indeterminate_total += 1;
            auditEvent(indeterminate ? 'delete_indeterminate' : 'gate_failed', id, status);
            const httpStatus = indeterminate ? (timeoutLike(error) ? 504 : 502) : 503;
            return closedError(httpStatus, code, id, status);
        }
        if (!result.ok) {
            const reason = carrierInvalid ? 'receipt_carrier_invalid' : result.authorization.reason;
            const binding = challengeBinding(id, observedAction);
            try {
                await updateAction(id, principal.id, {
                    status: 'challenged',
                    reason,
                    challenge_binding_hash: binding,
                    authorization_evidence_hash: result.authorization.evidence?.hash ?? null,
                });
            }
            catch {
                return closedError(503, 'action_store_unavailable', id);
            }
            counters.challenges_total += 1;
            auditEvent('receipt_challenged', id, 'challenged');
            return response(428, challengeBody(result.body, {
                id,
                observedAction,
                carrierInvalid,
                binding,
            }), result.authorization.header ? { 'Receipt-Required': result.authorization.header } : {});
        }
        try {
            await updateAction(id, principal.id, {
                status: 'succeeded',
                outcome: 'deleted',
                authorization_evidence_hash: result.authorization.evidence?.hash ?? null,
                execution_evidence_hash: result.execution?.hash ?? null,
            });
        }
        catch {
            counters.executions_indeterminate_total += 1;
            auditEvent('action_record_failed_after_delete', id, 'indeterminate');
            return closedError(503, 'action_record_failed_after_delete', id, 'indeterminate');
        }
        counters.executions_succeeded_total += 1;
        auditEvent('delete_succeeded', id, 'succeeded');
        return response(200, {
            id,
            action: GITHUB_REPOSITORY_DELETE_ACTION,
            status: 'succeeded',
            outcome: 'deleted',
            observed_action: observedAction,
            evidence: {
                authorization_hash: result.authorization.evidence?.hash ?? null,
                execution_hash: result.execution?.hash ?? null,
            },
        });
    }
    /**
     * @param {{principal?: unknown, body?: unknown, receiptCarrier?: unknown}} [request]
     */
    async function executeDelete(request = {}) {
        const { principal: candidate, body, receiptCarrier = null } = request;
        const principal = normalizePrincipal(candidate);
        if (!principal)
            return closedError(401, 'authentication_required');
        const deleteRequest = validateDeleteRequest(body);
        if (!deleteRequest.ok)
            return closedError(400, deleteRequest.code);
        if (!(await actionAuthorized(principal, deleteRequest.locator))) {
            counters.action_authorization_denied_total += 1;
            return closedError(403, 'action_not_authorized');
        }
        let actionRecord;
        try {
            actionRecord = await createAction(principal, deleteRequest.locator);
        }
        catch {
            return closedError(503, 'action_store_unavailable');
        }
        return continueDelete({ actionRecord, principal, receiptCarrier });
    }
    async function ownedAction(id, principal) {
        const record = await actionStore.get(id, principal.id);
        const projected = publicActionRecord(record, id, principal.id, config);
        return projected ? { record, projected } : null;
    }
    /**
     * @param {{id?: string, principal?: unknown, body?: unknown, receiptCarrier?: unknown}} [request]
     */
    async function resumeDelete(request = {}) {
        const { id, principal: candidate, body, receiptCarrier = null } = request;
        const principal = normalizePrincipal(candidate);
        if (!principal)
            return closedError(401, 'authentication_required');
        if (typeof id !== 'string' || !ACTION_ID.test(id))
            return closedError(400, 'action_id_invalid');
        const resumeRequest = validateResumeRequest(body);
        if (!resumeRequest.ok)
            return closedError(400, resumeRequest.code, id);
        let owned;
        try {
            owned = await ownedAction(id, principal);
        }
        catch {
            return closedError(503, 'action_store_unavailable');
        }
        if (!owned)
            return closedError(404, 'action_not_found');
        const locator = validateLocator(owned.record.target);
        if (!locator.ok)
            return closedError(409, 'action_not_resumable', id);
        if (!(await actionAuthorized(principal, locator.locator))) {
            counters.action_authorization_denied_total += 1;
            return closedError(403, 'action_not_authorized');
        }
        if (owned.record.status !== 'challenged'
            || owned.record.challenge_binding_hash !== resumeRequest.challengeBinding) {
            return closedError(409, 'action_not_resumable', id);
        }
        let claimed;
        try {
            claimed = await actionStore.transition(id, principal.id, ['challenged'], {
                status: 'observing',
                updated_at: currentTimestamp(config.now),
            });
        }
        catch {
            return closedError(503, 'action_store_unavailable', id);
        }
        if (claimed !== true)
            return closedError(409, 'action_not_resumable', id);
        return continueDelete({
            actionRecord: { ...owned.record, status: 'observing' },
            principal,
            receiptCarrier,
        });
    }
    async function getAction(id, candidate) {
        const principal = normalizePrincipal(candidate);
        if (!principal)
            return closedError(401, 'authentication_required');
        if (typeof id !== 'string' || !ACTION_ID.test(id))
            return closedError(400, 'action_id_invalid');
        try {
            const owned = await ownedAction(id, principal);
            if (!owned)
                return closedError(404, 'action_not_found');
            return response(200, owned.projected);
        }
        catch {
            return closedError(503, 'action_store_unavailable');
        }
    }
    async function authorizedEvidenceScope(candidate, operation, scope, { requireAction = true } = {}) {
        const principal = normalizePrincipal(candidate);
        if (!principal)
            return { error: closedError(401, 'authentication_required') };
        if (!isPlainObject(scope) || scope.tenantId !== config.tenantId || scope.gateId !== config.gateId
            || typeof scope.actionId !== 'string' || scope.actionId.length === 0 || scope.actionId.length > 128) {
            return { error: closedError(403, 'evidence_not_authorized') };
        }
        try {
            const allowed = await config.authorizeEvidence(principal, operation, scope.tenantId, scope.gateId, scope.actionId);
            if (allowed !== true)
                return { error: closedError(403, 'evidence_not_authorized') };
        }
        catch {
            return { error: closedError(403, 'evidence_not_authorized') };
        }
        if (!requireAction)
            return { principal };
        if (!ACTION_ID.test(scope.actionId))
            return { error: closedError(400, 'action_id_invalid') };
        try {
            const owned = await ownedAction(scope.actionId, principal);
            if (!owned)
                return { error: closedError(404, 'action_not_found') };
            return { principal, actionRecord: owned.record };
        }
        catch {
            return { error: closedError(503, 'action_store_unavailable') };
        }
    }
    async function readEvidencePage(scope, actionRecord, { cursor = 0, limit = 50 } = {}) {
        if (!Number.isSafeInteger(cursor) || cursor < 0
            || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_EVIDENCE_PAGE) {
            return closedError(400, 'pagination_invalid');
        }
        try {
            const page = await evidenceAdapter.history({ ...scope, cursor, limit });
            if (!isPlainObject(page) || !Array.isArray(page.records) || page.records.length > limit
                || (page.nextCursor !== null
                    && (!Number.isSafeInteger(page.nextCursor) || page.nextCursor <= cursor))) {
                throw new Error('evidence_history_contract_invalid');
            }
            const records = page.records.map((record) => redactedEvidenceRecord(record, scope.actionId, actionRecord));
            if (records.some((record) => record === null))
                throw new Error('evidence_scope_violation');
            counters.evidence_reads_total += 1;
            return response(200, { records, next_cursor: page.nextCursor });
        }
        catch {
            return closedError(503, 'evidence_unavailable');
        }
    }
    async function evidenceHistory(candidate, scope, pagination) {
        const authorized = await authorizedEvidenceScope(candidate, 'history', scope);
        if (authorized.error)
            return authorized.error;
        return readEvidencePage(scope, authorized.actionRecord, pagination);
    }
    async function getEvidenceRecord(recordId, candidate, scope) {
        if (typeof recordId !== 'string' || !RECORD_ID.test(recordId)) {
            return closedError(400, 'evidence_record_id_invalid');
        }
        const authorized = await authorizedEvidenceScope(candidate, 'record', scope);
        if (authorized.error)
            return authorized.error;
        try {
            const raw = await evidenceAdapter.getRecord({ ...scope, recordId });
            if (raw === null)
                return closedError(404, 'evidence_record_not_found');
            const record = redactedEvidenceRecord(raw, scope.actionId, authorized.actionRecord);
            if (!record)
                return closedError(404, 'evidence_record_not_found');
            counters.evidence_reads_total += 1;
            return response(200, { record });
        }
        catch {
            return closedError(503, 'evidence_unavailable');
        }
    }
    async function evidenceHead(candidate, scope) {
        const authorized = await authorizedEvidenceScope(candidate, 'head', scope);
        if (authorized.error)
            return authorized.error;
        try {
            const head = await evidenceAdapter.head(scope);
            if (head !== null && (!isPlainObject(head) || !Number.isSafeInteger(head.seq)
                || head.seq < 0 || typeof head.hash !== 'string' || !HEX_256.test(head.hash))) {
                throw new Error('evidence_head_contract_invalid');
            }
            counters.evidence_reads_total += 1;
            return response(200, { head });
        }
        catch {
            return closedError(503, 'evidence_unavailable');
        }
    }
    async function verifyEvidence(candidate, scope) {
        const authorized = await authorizedEvidenceScope(candidate, 'verify', scope);
        if (authorized.error)
            return authorized.error;
        try {
            const verification = verificationProjection(await evidenceAdapter.verify(scope));
            counters.evidence_reads_total += 1;
            return response(verification.ok ? 200 : 409, { verification });
        }
        catch {
            return closedError(503, 'evidence_unavailable');
        }
    }
    async function exportEvidence(candidate, scope, pagination) {
        const authorized = await authorizedEvidenceScope(candidate, 'export', scope);
        if (authorized.error)
            return authorized.error;
        const history = await readEvidencePage(scope, authorized.actionRecord, pagination);
        if (history.status !== 200)
            return history;
        let verification;
        try {
            verification = verificationProjection(await evidenceAdapter.verify(scope));
        }
        catch {
            return closedError(503, 'evidence_unavailable');
        }
        return response(verification.ok ? 200 : 409, {
            version: EVIDENCE_EXPORT_VERSION,
            scope: {
                tenant_id: scope.tenantId,
                gate_id: scope.gateId,
                action_id: scope.actionId,
            },
            verification,
            ...history.body,
        });
    }
    async function metrics(candidate, scope) {
        const authorized = await authorizedEvidenceScope(candidate, 'metrics', scope, { requireAction: false });
        if (authorized.error)
            return authorized.error;
        return response(200, {
            status: 'ok',
            service: 'emilia-gate-service',
            lifecycle: {
                initialized,
                accepting,
            },
            counters: { ...counters },
        });
    }
    function live() {
        return response(200, { status: 'ok', service: 'emilia-gate-service' });
    }
    async function dependencyReadiness() {
        counters.readiness_checks_total += 1;
        const controller = new AbortController();
        let timer;
        const timeout = new Promise((_, reject) => {
            timer = setTimeout(() => {
                controller.abort();
                reject(new Error('readiness_timeout'));
            }, config.readinessTimeoutMs);
        });
        try {
            const value = await Promise.race([
                Promise.resolve().then(() => config.readiness({ signal: controller.signal })),
                timeout,
            ]);
            if (value !== true && value?.ok !== true)
                throw new Error('dependency_not_ready');
            return response(200, {
                status: 'ready',
                service: 'emilia-gate-service',
                dependencies: 'ready',
            });
        }
        catch {
            counters.readiness_failures_total += 1;
            return unavailableBody();
        }
        finally {
            clearTimeout(timer);
        }
    }
    async function ready() {
        if (!initialized || !accepting)
            return unavailableBody();
        if (!readinessInFlight) {
            const pending = dependencyReadiness();
            const shared = pending.finally(() => {
                if (readinessInFlight === shared)
                    readinessInFlight = null;
            });
            readinessInFlight = shared;
        }
        return readinessInFlight;
    }
    const maxReceiptCarrierChars = Math.ceil(config.maxReceiptBytes * 4 / 3) + 4;
    const requestTimeoutMs = Math.max(30_000, (config.connectorTimeoutMs * 2) + 5_000);
    return Object.freeze({
        initialize,
        markUnready,
        close,
        executeDelete,
        resumeDelete,
        getAction,
        authenticate,
        evidenceHead,
        getEvidenceRecord,
        evidenceHistory,
        verifyEvidence,
        exportEvidence,
        metrics,
        live,
        ready,
        limits: Object.freeze({
            maxBodyBytes: config.maxBodyBytes,
            maxReceiptBytes: config.maxReceiptBytes,
            maxReceiptCarrierChars,
            maxHeaderBytes: maxReceiptCarrierChars + 8 * 1024,
            connectorTimeoutMs: config.connectorTimeoutMs,
            readinessTimeoutMs: config.readinessTimeoutMs,
            requestTimeoutMs,
            maxEvidencePage: MAX_EVIDENCE_PAGE,
        }),
    });
}
