// SPDX-License-Identifier: Apache-2.0
//
// EP-APPROVAL-v1 — portable receipt-acquisition client and closed validation
// rules. The authorization endpoint is discovery, never authority: the
// relying service still verifies the returned EP-RECEIPT-v1 offline under its
// own pinned issuer keys and exact action binding.
import crypto from 'node:crypto';
import { strictJsonGate } from './strict-json.js';
export const EP_APPROVAL_FLOW = 'EP-APPROVAL-v1';
export const APPROVAL_REQUEST_ID_PATTERN = /^apr_[a-f0-9]{32}$/;
export const APPROVAL_POLL_TOKEN_PATTERN = /^apt_[a-f0-9]{48}$/;
export const APPROVAL_IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
export const APPROVAL_STATUSES = Object.freeze([
    'pending',
    'approved',
    'denied',
    'expired',
    'cancelled',
]);
const MAX_APPROVAL_RESPONSE_BYTES = 1024 * 1024;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CAID_PATTERN = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
const FIELD_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,127}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const REQUESTER_BEARER = /^Bearer (?:ep|ept)_[A-Za-z0-9._~-]{8,512}$/;
function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function exactKeys(value, expected) {
    const actual = Object.keys(value).sort();
    return actual.length === expected.length
        && actual.every((key, index) => key === [...expected].sort()[index]);
}
function assertClosedJson(value, path = '$', depth = 0) {
    if (depth > 32)
        throw new Error(`json_too_deep:${path}`);
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return;
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new Error(`non_json_number:${path}`);
        return;
    }
    if (Array.isArray(value)) {
        if (value.length > 64)
            throw new Error(`json_array_too_large:${path}`);
        value.forEach((entry, index) => assertClosedJson(entry, `${path}[${index}]`, depth + 1));
        return;
    }
    if (!isPlainObject(value))
        throw new Error(`non_plain_object:${path}`);
    const keys = Object.keys(value);
    if (keys.length > 64)
        throw new Error(`json_object_too_large:${path}`);
    for (const key of keys) {
        if (FORBIDDEN_KEYS.has(key))
            throw new Error(`forbidden_key:${path}.${key}`);
        assertClosedJson(value[key], `${path}.${key}`, depth + 1);
    }
}
function canonicalizeApprovalAction(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map(canonicalizeApprovalAction).join(',')}]`;
    return `{${Object.keys(value).sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalizeApprovalAction(value[key])}`)
        .join(',')}}`;
}
export function approvalActionHash(action) {
    assertClosedJson(action);
    return `sha256:${crypto.createHash('sha256').update(canonicalizeApprovalAction(action), 'utf8').digest('hex')}`;
}
export function validateApprovalAuthorization(input) {
    if (!isPlainObject(input) || !exactKeys(input, ['authorization_endpoint', 'flow'])) {
        return { ok: false, reason: 'authorization_not_closed' };
    }
    if (input.flow !== EP_APPROVAL_FLOW)
        return { ok: false, reason: 'unsupported_approval_flow' };
    if (typeof input.authorization_endpoint !== 'string') {
        return { ok: false, reason: 'authorization_endpoint_invalid' };
    }
    let endpoint;
    try {
        endpoint = new URL(input.authorization_endpoint);
    }
    catch {
        return { ok: false, reason: 'authorization_endpoint_invalid' };
    }
    if (endpoint.protocol !== 'https:'
        || endpoint.username
        || endpoint.password
        || endpoint.hash
        || endpoint.search
        || endpoint.origin === 'null') {
        return { ok: false, reason: 'authorization_endpoint_unsafe' };
    }
    return {
        ok: true,
        value: {
            authorization_endpoint: endpoint.toString(),
            flow: EP_APPROVAL_FLOW,
        },
    };
}
function requirePinnedAuthorization(discovered, trusted) {
    const candidate = validateApprovalAuthorization(discovered);
    const pin = validateApprovalAuthorization(trusted);
    if (!candidate.ok || !pin.ok
        || candidate.value.authorization_endpoint !== pin.value.authorization_endpoint
        || candidate.value.flow !== pin.value.flow) {
        // Discovery tells the client where a service would like it to POST. It is
        // never a trust root. The endpoint and flow must match configuration the
        // relying client obtained out of band before any network I/O occurs.
        throw new Error('authorization_endpoint_not_pinned');
    }
    return candidate.value;
}
async function resolveRequesterAuthorization(input) {
    // Credentials are injected by the requester from its own secret store. They
    // are never read from a challenge, manifest, authorization descriptor, or
    // response, and callers cannot add arbitrary request headers.
    const value = typeof input === 'function' ? await input() : input;
    if (typeof value !== 'string' || !REQUESTER_BEARER.test(value)) {
        throw new Error('requester_authorization_invalid');
    }
    return value;
}
export function validateRequiredFields(input) {
    if (!Array.isArray(input) || input.length === 0 || input.length > 64) {
        return { ok: false, reason: 'required_fields_invalid' };
    }
    if (input.some((field) => typeof field !== 'string' || !FIELD_PATTERN.test(field))) {
        return { ok: false, reason: 'required_fields_invalid' };
    }
    if (new Set(input).size !== input.length)
        return { ok: false, reason: 'required_fields_duplicate' };
    return { ok: true, value: [...input] };
}
export function validateCaidSelector(input) {
    if (!isPlainObject(input) || !exactKeys(input, ['field'])
        || typeof input.field !== 'string' || !FIELD_PATTERN.test(input.field)) {
        return { ok: false, reason: 'caid_selector_invalid' };
    }
    return { ok: true, value: { field: input.field } };
}
function validateChallenge(input) {
    if (!isPlainObject(input))
        throw new Error('challenge_invalid');
    const allowed = new Set(['action', 'action_hash', 'required_fields', 'caid_selector']);
    if (Object.keys(input).some((key) => !allowed.has(key)))
        throw new Error('challenge_not_closed');
    if (typeof input.action !== 'string' || !input.action)
        throw new Error('challenge_action_invalid');
    if (input.action_hash !== undefined && !SHA256_PATTERN.test(input.action_hash)) {
        throw new Error('challenge_action_hash_invalid');
    }
    const fields = validateRequiredFields(input.required_fields);
    if (!fields.ok)
        throw new Error('reason' in fields ? fields.reason : 'required_fields_invalid');
    let selector;
    if (input.caid_selector !== undefined) {
        const checked = validateCaidSelector(input.caid_selector);
        if (!checked.ok)
            throw new Error('reason' in checked ? checked.reason : 'caid_selector_invalid');
        selector = checked.value;
    }
    return {
        action: input.action,
        ...(input.action_hash ? { action_hash: input.action_hash } : {}),
        required_fields: fields.value,
        ...(selector ? { caid_selector: selector } : {}),
    };
}
function validateBoundAction(action, challenge) {
    if (!isPlainObject(action))
        throw new Error('action_invalid');
    if (action.action_type !== challenge.action)
        throw new Error('action_type_mismatch');
    for (const field of challenge.required_fields) {
        if (!Object.hasOwn(action, field) || action[field] === undefined) {
            throw new Error(`required_field_missing:${field}`);
        }
    }
    assertClosedJson(action);
    if (challenge.action_hash && approvalActionHash(action) !== challenge.action_hash) {
        throw new Error('action_hash_mismatch');
    }
    const caidField = challenge.caid_selector?.field;
    if (caidField && (!Object.hasOwn(action, caidField) || !CAID_PATTERN.test(action[caidField]))) {
        throw new Error(`caid_binding_invalid:${caidField}`);
    }
    return JSON.parse(JSON.stringify(action));
}
async function readBoundedJson(response) {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
        throw new Error('approval_response_not_json');
    }
    const advertised = Number(response.headers.get('content-length'));
    if (Number.isFinite(advertised) && advertised > MAX_APPROVAL_RESPONSE_BYTES) {
        throw new Error('approval_response_too_large');
    }
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > MAX_APPROVAL_RESPONSE_BYTES) {
        throw new Error('approval_response_too_large');
    }
    if (!strictJsonGate(text).ok)
        throw new Error('approval_response_invalid_json');
    const parsed = JSON.parse(text);
    if (!isPlainObject(parsed))
        throw new Error('approval_response_invalid');
    return parsed;
}
function validateRequestId(value) {
    if (typeof value !== 'string' || !APPROVAL_REQUEST_ID_PATTERN.test(value)) {
        throw new Error('approval_request_id_invalid');
    }
}
function validateStatus(value) {
    if (typeof value !== 'string' || !APPROVAL_STATUSES.includes(value)) {
        throw new Error('approval_status_invalid');
    }
}
function assertReceiptState(body) {
    if (body.status === 'approved') {
        if (!isPlainObject(body.receipt) || body.receipt['@version'] !== 'EP-RECEIPT-v1') {
            throw new Error('approved_receipt_missing');
        }
    }
    else if (body.receipt !== undefined) {
        throw new Error('receipt_on_nonapproved_status');
    }
}
export async function beginReceiptApproval({ authorization, trustedAuthorization, challenge, action, approver_id, idempotency_key, requesterAuthorization, fetchImpl = fetch, }) {
    const auth = requirePinnedAuthorization(authorization, trustedAuthorization);
    const normalizedChallenge = validateChallenge(challenge);
    const normalizedAction = validateBoundAction(action, normalizedChallenge);
    if (typeof approver_id !== 'string' || !/^[A-Za-z0-9:_.@-]{3,128}$/.test(approver_id)) {
        throw new Error('approver_id_invalid');
    }
    if (typeof idempotency_key !== 'string' || !APPROVAL_IDEMPOTENCY_KEY_PATTERN.test(idempotency_key)) {
        throw new Error('idempotency_key_invalid');
    }
    const requesterBearer = await resolveRequesterAuthorization(requesterAuthorization);
    const response = await fetchImpl(auth.authorization_endpoint, {
        method: 'POST',
        redirect: 'error',
        headers: {
            accept: 'application/json',
            authorization: requesterBearer,
            'content-type': 'application/json',
        },
        body: JSON.stringify({
            flow: EP_APPROVAL_FLOW,
            challenge: normalizedChallenge,
            action: normalizedAction,
            approver_id,
            idempotency_key,
        }),
    });
    if (response.status !== 201)
        throw new Error(`approval_request_failed:${response.status}`);
    const body = await readBoundedJson(response);
    validateRequestId(body.request_id);
    if (body.status !== 'pending')
        throw new Error('approval_initial_status_invalid');
    if (typeof body.poll_token !== 'string' || !APPROVAL_POLL_TOKEN_PATTERN.test(body.poll_token)) {
        throw new Error('approval_poll_token_invalid');
    }
    if (typeof body.expires_at !== 'string' || !Number.isFinite(Date.parse(body.expires_at))) {
        throw new Error('approval_expiry_invalid');
    }
    let approvalUrl;
    try {
        approvalUrl = new URL(body.approval_url);
    }
    catch {
        throw new Error('approval_url_invalid');
    }
    if (approvalUrl.protocol !== 'https:' || approvalUrl.origin !== new URL(auth.authorization_endpoint).origin
        || approvalUrl.username || approvalUrl.password || approvalUrl.hash) {
        throw new Error('approval_url_origin_mismatch');
    }
    if (body.receipt !== undefined)
        throw new Error('receipt_on_nonapproved_status');
    return body;
}
export async function pollReceiptApproval({ authorization, trustedAuthorization, request_id, poll_token, fetchImpl = fetch, }) {
    const auth = requirePinnedAuthorization(authorization, trustedAuthorization);
    validateRequestId(request_id);
    if (typeof poll_token !== 'string' || !APPROVAL_POLL_TOKEN_PATTERN.test(poll_token)) {
        throw new Error('approval_poll_token_invalid');
    }
    const endpoint = new URL(auth.authorization_endpoint);
    endpoint.pathname = `${endpoint.pathname.replace(/\/$/, '')}/${encodeURIComponent(request_id)}`;
    const response = await fetchImpl(endpoint.toString(), {
        method: 'GET',
        redirect: 'error',
        headers: {
            accept: 'application/json',
            authorization: `EP-Approval ${poll_token}`,
        },
    });
    if (!response.ok)
        throw new Error(`approval_poll_failed:${response.status}`);
    const body = await readBoundedJson(response);
    validateRequestId(body.request_id);
    if (body.request_id !== request_id)
        throw new Error('approval_request_id_mismatch');
    validateStatus(body.status);
    assertReceiptState(body);
    return body;
}
//# sourceMappingURL=acquisition.js.map