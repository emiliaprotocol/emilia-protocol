// SPDX-License-Identifier: Apache-2.0
// Generated from github-app.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Decision-side remote actuator client.
 *
 * The legacy filename is retained only because the standalone-runtime builder
 * already owns its Node companion. This module contains no provider
 * credentials and never invokes a provider API.
 */
import crypto from 'node:crypto';
import { canonicalize } from '@emilia-protocol/gate';
import { CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION, signConsequenceExecutionEnvelope, } from '@emilia-protocol/gate/consequence-actuator';
import { strictJsonGate } from '@emilia-protocol/require-receipt/strict-json';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';
export const CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION = 'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
export const CONSEQUENCE_ACTUATOR_RESPONSE_VERSION = 'EP-CONSEQUENCE-ACTUATOR-RESPONSE-v1';
const OBSERVATION_SIGNATURE_DOMAIN = 'EMILIA-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
const PROVIDER_ATTRIBUTION_VERSION = 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1';
const PROVIDER_ATTRIBUTION_SIGNATURE_DOMAIN = 'EP-CONSEQUENCE-PROVIDER-ATTRIBUTION-v1';
const ACTION_KEYS = Object.freeze([
    'action_type', 'owner', 'repo', 'issue_number', 'title', 'body',
]);
const OBSERVATION_KEYS = Object.freeze([
    '@version', 'payload', 'signature',
]);
const OBSERVATION_PAYLOAD_KEYS = Object.freeze([
    '@version',
    'issuer_id',
    'tenant_id',
    'request_digest',
    'environment',
    'attempt_id',
    'action_digest',
    'caid',
    'provider_id',
    'provider_account_id',
    'target_digest',
    'operation',
    'idempotency_key',
    'nonce',
    'envelope_digest',
    'provider_attribution_digest',
    'outcome',
    'observed_at',
    'reason',
    'provider_reference',
    'provider_result_digest',
]);
const SIGNATURE_KEYS = Object.freeze(['algorithm', 'key_id', 'value']);
const REQUEST_KEYS = Object.freeze([
    'action', 'action_digest', 'attempt_id', 'attribution', 'idempotency_key',
    'envelope',
]);
const RESPONSE_KEYS = Object.freeze([
    '@version', 'ok', 'outcome', 'observation',
]);
const RECONCILIATION_OBSERVATION_KEYS = Object.freeze([
    '@version',
    'evidence_id',
    'observed_at',
    'outcome',
    'reason',
    'tenant_id',
    'request_digest',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
    'operation_id',
    'caid',
    'action_digest',
    'target_digest',
    'operation',
    'nonce',
    'envelope_digest',
    'provider_attribution_digest',
    'provider_observation_digest',
    'evidence_digest',
]);
const RECONCILIATION_EXPECTED_KEYS = Object.freeze([
    'operation_id',
    'caid',
    'action_digest',
    'tenant_id',
    'request_digest',
    'provider_id',
    'provider_account_id',
    'environment',
    'attempt_id',
]);
const RECONCILIATION_SIGNATURE_DOMAIN = 'EP-CONSEQUENCE-ACTUATOR-OBSERVATION-v1';
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_RESPONSE_BYTES = 256 * 1024;
function plainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    if (!plainObject(value))
        return false;
    const actual = Object.keys(value).sort();
    const wanted = [...expected].sort();
    return actual.length === wanted.length
        && actual.every((key, index) => key === wanted[index]);
}
function requiredText(value, name, maximum = 4096) {
    if (typeof value !== 'string' || value.length < 1
        || value.length > maximum || value.includes('\0')) {
        throw new TypeError(`${name}_invalid`);
    }
    return value;
}
function requiredIdentifier(value, name) {
    const text = requiredText(value, name, 256);
    if (!IDENTIFIER.test(text))
        throw new TypeError(`${name}_invalid`);
    return text;
}
function requiredDigest(value, name) {
    const text = requiredText(value, name, 71);
    if (!DIGEST.test(text))
        throw new TypeError(`${name}_invalid`);
    return text;
}
function requiredCaid(value) {
    const text = requiredText(value, 'caid', 512);
    if (!CAID.test(text))
        throw new TypeError('caid_invalid');
    return text;
}
function normalizePrivateKey(value) {
    let key;
    try {
        key = value instanceof crypto.KeyObject ? value : crypto.createPrivateKey(value);
    }
    catch {
        throw new TypeError('actuator_envelope_private_key_invalid');
    }
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('actuator_envelope_private_key_invalid');
    }
    return key;
}
function normalizePublicKey(value) {
    let key;
    try {
        key = value instanceof crypto.KeyObject
            ? (value.type === 'private' ? crypto.createPublicKey(value) : value)
            : crypto.createPublicKey(value);
    }
    catch {
        throw new TypeError('actuator_observation_public_key_invalid');
    }
    if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('actuator_observation_public_key_invalid');
    }
    return key;
}
function endpointUrl(value, allowInsecureLoopback) {
    let url;
    try {
        url = new URL(requiredText(value, 'actuator_endpoint', 2048));
    }
    catch {
        throw new TypeError('actuator_endpoint_invalid');
    }
    const loopback = ['127.0.0.1', '::1', 'localhost'].includes(url.hostname);
    if ((url.protocol !== 'https:'
        && !(allowInsecureLoopback && loopback && url.protocol === 'http:'))
        || url.username || url.password || url.search || url.hash) {
        throw new TypeError('actuator_endpoint_invalid');
    }
    return url.href.replace(/\/$/, '');
}
function cancelBody(body) {
    try {
        Promise.resolve(body?.cancel?.()).catch(() => { });
    }
    catch { /* best effort */ }
}
async function boundedJson(response) {
    if (response?.redirected === true) {
        cancelBody(response?.body);
        throw new Error('actuator_redirect_refused');
    }
    if (!/^application\/json(?:\s*;|$)/i.test(String(response?.headers?.get?.('content-type') ?? ''))) {
        cancelBody(response?.body);
        throw new Error('actuator_response_invalid');
    }
    const announced = Number(response?.headers?.get?.('content-length'));
    if (Number.isFinite(announced) && announced > MAX_RESPONSE_BYTES) {
        cancelBody(response?.body);
        throw new Error('actuator_response_too_large');
    }
    if (!response?.body || typeof response.body.getReader !== 'function') {
        throw new Error('actuator_response_invalid');
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const chunk = await reader.read();
            if (!chunk || chunk.done === true)
                break;
            if (!(chunk.value instanceof Uint8Array))
                throw new Error('actuator_response_invalid');
            total += chunk.value.byteLength;
            if (total > MAX_RESPONSE_BYTES)
                throw new Error('actuator_response_too_large');
            chunks.push(Buffer.from(chunk.value));
        }
    }
    catch (error) {
        try {
            await reader.cancel();
        }
        catch { /* best effort */ }
        throw error;
    }
    let text;
    try {
        text = new TextDecoder('utf-8', { fatal: true })
            .decode(Buffer.concat(chunks, total));
    }
    catch {
        throw new Error('actuator_response_invalid');
    }
    if (!strictJsonGate(text).ok)
        throw new Error('actuator_response_invalid');
    const parsed = JSON.parse(text);
    if (!plainObject(parsed))
        throw new Error('actuator_response_invalid');
    return parsed;
}
function observationSignatureInput(payload) {
    return Buffer.concat([
        Buffer.from(OBSERVATION_SIGNATURE_DOMAIN, 'utf8'),
        Buffer.from([0]),
        Buffer.from(digestAeb(payload), 'utf8'),
    ]);
}
function providerAttributionSignatureInput(payload) {
    return Buffer.concat([
        Buffer.from(PROVIDER_ATTRIBUTION_SIGNATURE_DOMAIN, 'utf8'),
        Buffer.from([0]),
        Buffer.from(canonicalize(payload), 'utf8'),
    ]);
}
function githubIssueEffectDigest({ action, tenantId, providerId, providerAccountId, environment, targetDigest, }) {
    return digestAeb({
        domain: 'EP-GITHUB-ISSUE-EFFECT-v1',
        tenant_id: tenantId,
        provider_id: providerId,
        provider_account_id: providerAccountId,
        environment,
        target_digest: targetDigest,
        target: {
            owner: action.owner,
            repo: action.repo,
            issue_number: action.issue_number,
        },
        effect: {
            title: action.title,
            body: action.body,
        },
    });
}
function validObservationPayload(value) {
    if (!exactKeys(value, OBSERVATION_PAYLOAD_KEYS))
        return false;
    const observedAt = typeof value.observed_at === 'string'
        ? Date.parse(value.observed_at) : NaN;
    return value['@version'] === CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION
        && IDENTIFIER.test(value.issuer_id)
        && IDENTIFIER.test(value.tenant_id)
        && DIGEST.test(value.request_digest)
        && IDENTIFIER.test(value.environment)
        && IDENTIFIER.test(value.attempt_id)
        && DIGEST.test(value.action_digest)
        && CAID.test(value.caid)
        && IDENTIFIER.test(value.provider_id)
        && IDENTIFIER.test(value.provider_account_id)
        && DIGEST.test(value.target_digest)
        && IDENTIFIER.test(value.operation)
        && IDENTIFIER.test(value.idempotency_key)
        && typeof value.nonce === 'string'
        && value.nonce.length >= 22
        && value.nonce.length <= 128
        && BASE64URL.test(value.nonce)
        && DIGEST.test(value.envelope_digest)
        && DIGEST.test(value.provider_attribution_digest)
        && ['COMMITTED', 'INDETERMINATE'].includes(value.outcome)
        && Number.isFinite(observedAt)
        && typeof value.reason === 'string'
        && value.reason.length >= 1
        && value.reason.length <= 256
        && typeof value.provider_reference === 'string'
        && value.provider_reference.length >= 1
        && value.provider_reference.length <= 512
        && (value.provider_result_digest === null
            || DIGEST.test(value.provider_result_digest));
}
function verifyObservation(evidence, { issuerId, keyId, publicKey, }) {
    if (!exactKeys(evidence, OBSERVATION_KEYS)
        || evidence['@version'] !== CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION
        || !validObservationPayload(evidence.payload)
        || !exactKeys(evidence.signature, SIGNATURE_KEYS)
        || evidence.signature.algorithm !== 'Ed25519'
        || evidence.signature.key_id !== keyId
        || typeof evidence.signature.value !== 'string'
        || !BASE64URL.test(evidence.signature.value)) {
        return null;
    }
    let signature;
    try {
        signature = Buffer.from(evidence.signature.value, 'base64url');
    }
    catch {
        return null;
    }
    if (signature.byteLength !== 64
        || evidence.payload.issuer_id !== issuerId
        || !crypto.verify(null, observationSignatureInput(evidence.payload), publicKey, signature)) {
        return null;
    }
    return structuredClone(evidence.payload);
}
function reconciliationSignatureInput(evidence) {
    return Buffer.concat([
        Buffer.from(RECONCILIATION_SIGNATURE_DOMAIN, 'utf8'),
        Buffer.from([0]),
        Buffer.from(canonicalize(evidence), 'utf8'),
    ]);
}
function reconciliationEvidenceDigest(value) {
    const unsigned = structuredClone(value);
    delete unsigned.evidence_digest;
    return digestAeb({
        domain: RECONCILIATION_SIGNATURE_DOMAIN,
        evidence: unsigned,
    });
}
function verifyReconciliationObservation(candidate, expected, { keyId, publicKey, targetDigest, operation, }) {
    if (!exactKeys(candidate, ['evidence', 'signature'])
        || !exactKeys(candidate.signature, SIGNATURE_KEYS)
        || candidate.signature.algorithm !== 'Ed25519'
        || candidate.signature.key_id !== keyId
        || typeof candidate.signature.value !== 'string'
        || !BASE64URL.test(candidate.signature.value)
        || !exactKeys(candidate.evidence, RECONCILIATION_OBSERVATION_KEYS)) {
        return { valid: false, reason: 'provider_evidence_shape_invalid' };
    }
    let signature;
    try {
        signature = Buffer.from(candidate.signature.value, 'base64url');
    }
    catch {
        return { valid: false, reason: 'provider_evidence_signature_invalid' };
    }
    if (signature.byteLength !== 64
        || !crypto.verify(null, reconciliationSignatureInput(candidate.evidence), publicKey, signature)) {
        return { valid: false, reason: 'provider_evidence_signature_invalid' };
    }
    const evidence = candidate.evidence;
    const observedAt = typeof evidence.observed_at === 'string'
        ? Date.parse(evidence.observed_at)
        : NaN;
    if (evidence['@version'] !== CONSEQUENCE_ACTUATOR_OBSERVATION_VERSION
        || !IDENTIFIER.test(evidence.evidence_id)
        || !Number.isFinite(observedAt)
        || new Date(observedAt).toISOString() !== evidence.observed_at
        || !['COMMITTED', 'NOT_COMMITTED']
            .includes(evidence.outcome)
        || !IDENTIFIER.test(evidence.reason)
        || evidence.target_digest !== targetDigest
        || evidence.operation !== operation
        || typeof evidence.nonce !== 'string'
        || evidence.nonce.length < 22
        || evidence.nonce.length > 128
        || !BASE64URL.test(evidence.nonce)
        || !DIGEST.test(evidence.envelope_digest)
        || !DIGEST.test(evidence.provider_attribution_digest)
        || !DIGEST.test(evidence.provider_observation_digest)
        || !DIGEST.test(evidence.evidence_digest)
        || evidence.evidence_digest !== reconciliationEvidenceDigest(evidence)
        || RECONCILIATION_EXPECTED_KEYS.some((key) => evidence[key] !== expected[key])) {
        return { valid: false, reason: 'provider_evidence_binding_mismatch' };
    }
    return {
        valid: true,
        outcome: evidence.outcome,
        reason: evidence.reason,
        evidence_id: evidence.evidence_id,
        observed_at: evidence.observed_at,
        tenant_id: evidence.tenant_id,
        request_digest: evidence.request_digest,
        provider_id: evidence.provider_id,
        provider_account_id: evidence.provider_account_id,
        environment: evidence.environment,
        attempt_id: evidence.attempt_id,
        operation_id: evidence.operation_id,
        caid: evidence.caid,
        action_digest: evidence.action_digest,
        evidence_digest: evidence.evidence_digest,
    };
}
function requireAction(value, target) {
    if (!exactKeys(value, ACTION_KEYS)
        || value.action_type !== 'github.issue.update.1'
        || value.owner !== target.owner
        || value.repo !== target.repo
        || value.issue_number !== target.issueNumber
        || typeof value.title !== 'string'
        || value.title.length < 1
        || value.title.length > 256
        || typeof value.body !== 'string'
        || value.body.length > 65_536
        || value.title.includes('\0')
        || value.body.includes('\0')) {
        throw new Error('actuator_action_refused');
    }
    return structuredClone(value);
}
export function consequenceActuatorTargetDigest({ providerId, providerAccountId, owner, repo, issueNumber, }) {
    return digestAeb({
        domain: 'EP-CONSEQUENCE-ACTUATOR-TARGET-v1',
        provider_id: requiredIdentifier(providerId, 'provider_id'),
        provider_account_id: requiredIdentifier(providerAccountId, 'provider_account_id'),
        target: {
            kind: 'github.issue',
            owner: requiredIdentifier(owner, 'github_owner'),
            repo: requiredIdentifier(repo, 'github_repo'),
            issue_number: issueNumber,
        },
    });
}
export function createConsequenceActuatorClient({ endpoint, authorization, tenantId, providerId = 'github', providerAccountId, environment, owner, repo, issueNumber, operation, envelopeIssuerId, envelopeKeyId, envelopePrivateKey, observationIssuerId, observationKeyId, observationPublicKey, envelopeTtlMs = 30_000, requestTimeoutMs = 20_000, allowInsecureLoopback = false, fetchImpl = globalThis.fetch, now = Date.now, randomBytes = crypto.randomBytes, } = {}) {
    const apiEndpoint = endpointUrl(endpoint, allowInsecureLoopback);
    const bearer = requiredText(authorization, 'actuator_authorization', 4096);
    const tenant = requiredIdentifier(tenantId, 'tenant_id');
    const provider = requiredIdentifier(providerId, 'provider_id');
    const providerAccount = requiredIdentifier(providerAccountId, 'provider_account_id');
    const consequenceEnvironment = requiredIdentifier(environment, 'environment');
    const configuredOperation = requiredIdentifier(operation, 'operation');
    const issuer = requiredIdentifier(envelopeIssuerId, 'envelope_issuer_id');
    const signingKeyId = requiredIdentifier(envelopeKeyId, 'envelope_key_id');
    const signingKey = normalizePrivateKey(envelopePrivateKey);
    const observationPins = Object.freeze({
        issuerId: requiredIdentifier(observationIssuerId, 'observation_issuer_id'),
        keyId: requiredIdentifier(observationKeyId, 'observation_key_id'),
        publicKey: normalizePublicKey(observationPublicKey),
    });
    const target = Object.freeze({
        owner: requiredIdentifier(owner, 'github_owner'),
        repo: requiredIdentifier(repo, 'github_repo'),
        issueNumber: Number(issueNumber),
    });
    if (!Number.isSafeInteger(target.issueNumber) || target.issueNumber < 1
        || !Number.isSafeInteger(envelopeTtlMs)
        || envelopeTtlMs < 1 || envelopeTtlMs > 300_000
        || !Number.isSafeInteger(requestTimeoutMs)
        || requestTimeoutMs < 1 || requestTimeoutMs > 120_000
        || typeof fetchImpl !== 'function'
        || typeof now !== 'function'
        || typeof randomBytes !== 'function') {
        throw new TypeError('actuator_client_config_invalid');
    }
    const targetDigest = consequenceActuatorTargetDigest({
        providerId: provider,
        providerAccountId: providerAccount,
        ...target,
    });
    async function verifyProviderEvidence({ evidence, expected, action: candidate, } = {}) {
        let action;
        try {
            action = requireAction(candidate, target);
        }
        catch {
            return { valid: false, reason: 'provider_evidence_action_invalid' };
        }
        if (!plainObject(expected)
            || digestAeb(action) !== expected.action_digest) {
            return { valid: false, reason: 'provider_evidence_binding_mismatch' };
        }
        if (exactKeys(evidence, ['kind'])
            && evidence.kind === 'consequence-actuator-observation-v1') {
            if (!exactKeys(expected, RECONCILIATION_EXPECTED_KEYS)) {
                return { valid: false, reason: 'provider_evidence_binding_mismatch' };
            }
            try {
                const response = await fetchImpl(`${apiEndpoint}/v1/observe`, {
                    method: 'POST',
                    headers: {
                        authorization: `Bearer ${bearer}`,
                        'content-type': 'application/json',
                    },
                    body: JSON.stringify({
                        action,
                        expected: structuredClone(expected),
                        operation: configuredOperation,
                    }),
                    redirect: 'error',
                    signal: AbortSignal.timeout(requestTimeoutMs),
                });
                const body = await boundedJson(response);
                if (response?.status !== 200) {
                    return { valid: false, reason: 'provider_evidence_unavailable' };
                }
                return verifyReconciliationObservation(body, expected, {
                    keyId: observationPins.keyId,
                    publicKey: observationPins.publicKey,
                    targetDigest,
                    operation: configuredOperation,
                });
            }
            catch {
                return { valid: false, reason: 'provider_evidence_unavailable' };
            }
        }
        const payload = verifyObservation(evidence, observationPins);
        if (!payload) {
            return { valid: false, reason: 'provider_evidence_signature_invalid' };
        }
        const observedAtMs = Date.parse(payload.observed_at);
        if (payload.tenant_id !== expected.tenant_id
            || payload.request_digest !== expected.request_digest
            || payload.provider_id !== provider
            || payload.provider_account_id !== expected.provider_account_id
            || payload.provider_account_id !== providerAccount
            || payload.environment !== expected.environment
            || payload.attempt_id !== expected.attempt_id
            || payload.caid !== expected.caid
            || payload.action_digest !== expected.action_digest
            || payload.target_digest !== targetDigest
            || payload.operation !== configuredOperation
            || payload.idempotency_key !== expected.operation_id
            || (expected.nonce !== undefined
                && payload.nonce !== expected.nonce)
            || (expected.envelope_digest !== undefined
                && payload.envelope_digest !== expected.envelope_digest)
            || (expected.provider_attribution_digest !== undefined
                && payload.provider_attribution_digest
                    !== expected.provider_attribution_digest)
            || !Number.isFinite(observedAtMs)
            || observedAtMs > Number(now())) {
            return { valid: false, reason: 'provider_evidence_binding_mismatch' };
        }
        if (payload.outcome !== 'COMMITTED') {
            return { valid: false, reason: 'provider_evidence_unavailable' };
        }
        const evidenceDigest = digestAeb(evidence);
        return {
            valid: true,
            outcome: 'COMMITTED',
            reason: payload.reason,
            evidence_id: `actuator-observation:${evidenceDigest.slice('sha256:'.length)}`,
            observed_at: payload.observed_at,
            tenant_id: payload.tenant_id,
            request_digest: payload.request_digest,
            provider_id: payload.provider_id,
            provider_account_id: payload.provider_account_id,
            environment: payload.environment,
            attempt_id: payload.attempt_id,
            operation_id: payload.idempotency_key,
            caid: payload.caid,
            action_digest: payload.action_digest,
            evidence_digest: evidenceDigest,
        };
    }
    async function effect({ action: candidate, proposal, attempt, } = {}) {
        const action = requireAction(candidate, target);
        if (!plainObject(proposal)
            || !plainObject(proposal.consequence)
            || !plainObject(attempt)
            || proposal.consequence.tenant_id !== tenant
            || proposal.consequence.provider_id !== provider
            || proposal.consequence.provider_account_id !== providerAccount
            || proposal.consequence.environment !== consequenceEnvironment
            || attempt.tenant_id !== tenant
            || attempt.provider_id !== provider
            || attempt.provider_account_id !== providerAccount
            || attempt.environment !== consequenceEnvironment
            || attempt.request_digest !== proposal.consequence.request_digest) {
            throw new Error('actuator_effect_binding_refused');
        }
        const actionDigest = requiredDigest(proposal.aeb_action_digest, 'action_digest');
        if (digestAeb(action) !== actionDigest) {
            throw new Error('actuator_effect_action_digest_mismatch');
        }
        const caid = requiredCaid(proposal.caid);
        const attemptId = requiredIdentifier(attempt.attempt_id, 'attempt_id');
        const idempotencyKey = requiredIdentifier(proposal.operation_id, 'idempotency_key');
        const current = Number(now());
        if (!Number.isSafeInteger(current))
            throw new Error('actuator_clock_invalid');
        const nonceBytes = randomBytes(24);
        if (!(nonceBytes instanceof Uint8Array) || nonceBytes.byteLength !== 24) {
            throw new Error('actuator_nonce_invalid');
        }
        const payload = {
            '@version': CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
            issuer_id: issuer,
            tenant_id: tenant,
            attempt_id: attemptId,
            action_digest: actionDigest,
            caid,
            provider_account_id: providerAccount,
            target_digest: targetDigest,
            operation: configuredOperation,
            idempotency_key: idempotencyKey,
            nonce: Buffer.from(nonceBytes).toString('base64url'),
            issued_at: new Date(current).toISOString(),
            expires_at: new Date(current + envelopeTtlMs).toISOString(),
        };
        const envelope = signConsequenceExecutionEnvelope(payload, {
            keyId: signingKeyId,
            privateKey: signingKey,
        });
        const attributionPayload = JSON.parse(canonicalize({
            '@version': PROVIDER_ATTRIBUTION_VERSION,
            issuer_id: issuer,
            tenant_id: tenant,
            provider_id: provider,
            provider_account_id: providerAccount,
            environment: consequenceEnvironment,
            request_digest: requiredDigest(attempt.request_digest, 'request_digest'),
            attempt_id: attemptId,
            operation_id: idempotencyKey,
            caid,
            action_digest: actionDigest,
            target_digest: targetDigest,
            operation: configuredOperation,
            nonce: payload.nonce,
            envelope_digest: digestAeb(envelope),
            effect_digest: githubIssueEffectDigest({
                action,
                tenantId: tenant,
                providerId: provider,
                providerAccountId: providerAccount,
                environment: consequenceEnvironment,
                targetDigest,
            }),
            issued_at: payload.issued_at,
        }));
        const attribution = JSON.parse(canonicalize({
            payload: attributionPayload,
            signature: {
                algorithm: 'Ed25519',
                key_id: signingKeyId,
                value: crypto.sign(null, providerAttributionSignatureInput(attributionPayload), signingKey).toString('base64url'),
            },
        }));
        const providerAttributionDigest = digestAeb(attribution);
        const request = {
            action,
            action_digest: actionDigest,
            attempt_id: attemptId,
            attribution,
            idempotency_key: idempotencyKey,
            envelope,
        };
        if (!exactKeys(request, REQUEST_KEYS)) {
            throw new Error('actuator_request_invalid');
        }
        const response = await fetchImpl(`${apiEndpoint}/v1/execute`, {
            method: 'POST',
            headers: {
                authorization: `Bearer ${bearer}`,
                'content-type': 'application/json',
            },
            body: JSON.stringify(request),
            redirect: 'error',
            signal: AbortSignal.timeout(requestTimeoutMs),
        });
        const body = await boundedJson(response);
        if (![200, 202].includes(response?.status)
            || !exactKeys(body, RESPONSE_KEYS)
            || body['@version'] !== CONSEQUENCE_ACTUATOR_RESPONSE_VERSION
            || typeof body.ok !== 'boolean'
            || !['COMMITTED', 'INDETERMINATE'].includes(body.outcome)) {
            throw new Error('actuator_response_refused');
        }
        const executionObservation = verifyObservation(body.observation, observationPins);
        const observedAtMs = executionObservation
            ? Date.parse(executionObservation.observed_at)
            : NaN;
        if (!executionObservation
            || executionObservation.tenant_id !== tenant
            || executionObservation.request_digest
                !== proposal.consequence.request_digest
            || executionObservation.provider_id !== provider
            || executionObservation.provider_account_id !== providerAccount
            || executionObservation.environment !== consequenceEnvironment
            || executionObservation.attempt_id !== attemptId
            || executionObservation.caid !== caid
            || executionObservation.action_digest !== actionDigest
            || executionObservation.target_digest !== targetDigest
            || executionObservation.operation !== configuredOperation
            || executionObservation.idempotency_key !== idempotencyKey
            || executionObservation.nonce !== payload.nonce
            || executionObservation.envelope_digest !== digestAeb(envelope)
            || executionObservation.provider_attribution_digest
                !== providerAttributionDigest
            || executionObservation.outcome !== body.outcome
            || body.ok !== (body.outcome === 'COMMITTED')
            || response.status !== (body.outcome === 'COMMITTED' ? 200 : 202)
            || !Number.isFinite(observedAtMs)
            || observedAtMs > current) {
            throw new Error('actuator_observation_refused');
        }
        if (body.outcome === 'INDETERMINATE') {
            const error = new Error('actuator_provider_outcome_indeterminate');
            error.code = 'actuator_provider_outcome_indeterminate';
            error.providerEvidence = structuredClone(body.observation);
            throw error;
        }
        return {
            provider_status: 200,
            provider_reference: body.observation.payload.provider_reference,
            actuator_observation: structuredClone(body.observation),
        };
    }
    async function ready() {
        try {
            const response = await fetchImpl(`${apiEndpoint}/v1/ready`, {
                method: 'GET',
                headers: { authorization: `Bearer ${bearer}` },
                redirect: 'error',
                signal: AbortSignal.timeout(requestTimeoutMs),
            });
            const body = await boundedJson(response);
            return response?.status === 200
                && exactKeys(body, ['status'])
                && body.status === 'ok';
        }
        catch {
            return false;
        }
    }
    return Object.freeze({
        effect,
        ready,
        verifyProviderEvidence,
        operation: configuredOperation,
        targetDigest,
    });
}
export default Object.freeze({
    consequenceActuatorTargetDigest,
    createConsequenceActuatorClient,
});
