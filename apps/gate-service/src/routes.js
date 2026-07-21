// SPDX-License-Identifier: Apache-2.0
// Generated from routes.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
import { strictJsonGate } from '../../../packages/require-receipt/strict-json.js';
export const GATE_ROUTE_PATHS = Object.freeze({
    live: '/v1/live',
    ready: '/v1/ready',
    actions: '/v1/actions',
    action: '/v1/actions/{id}',
    execute: '/v1/actions/{id}/execute',
    evidenceHead: '/v1/evidence/head',
    evidenceRecord: '/v1/evidence/records/{recordId}',
    evidenceHistory: '/v1/evidence/history',
    evidenceVerify: '/v1/evidence/verify',
    evidenceExport: '/v1/evidence/export',
    metrics: '/v1/metrics',
});
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;|$)/i;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
/** @type {Set<string>} */
const EVIDENCE_PATHS = new Set([
    GATE_ROUTE_PATHS.evidenceHead,
    GATE_ROUTE_PATHS.evidenceHistory,
    GATE_ROUTE_PATHS.evidenceVerify,
    GATE_ROUTE_PATHS.evidenceExport,
]);
class HttpInputError extends Error {
    status;
    code;
    constructor(status, code) {
        super(code);
        this.status = status;
        this.code = code;
    }
}
function sendJson(response, status, body, headers = {}) {
    if (response.headersSent || response.destroyed)
        return;
    try {
        const payload = Buffer.from(JSON.stringify(body), 'utf8');
        const safeHeaders = {};
        for (const [name, value] of Object.entries(headers)) {
            if (typeof value === 'string' && !/[\r\n]/.test(value))
                safeHeaders[name] = value;
        }
        response.writeHead(status, {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': String(payload.length),
            'Cache-Control': 'no-store',
            ...safeHeaders,
        });
        response.end(payload);
    }
    catch {
        if (!response.destroyed)
            response.destroy();
    }
}
function readBody(request, maxBytes) {
    const announced = Number(request.headers['content-length']);
    if (Number.isFinite(announced) && announced > maxBytes) {
        request.on('error', () => { });
        request.resume();
        throw new HttpInputError(413, 'request_body_too_large');
    }
    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        let settled = false;
        const fail = (error) => {
            if (settled)
                return;
            settled = true;
            request.removeListener('data', onData);
            request.removeListener('end', onEnd);
            request.resume();
            reject(error);
        };
        const onData = (chunk) => {
            total += chunk.length;
            if (total > maxBytes) {
                fail(new HttpInputError(413, 'request_body_too_large'));
                return;
            }
            chunks.push(chunk);
        };
        const onEnd = () => {
            if (settled)
                return;
            settled = true;
            if (total === 0) {
                reject(new HttpInputError(400, 'request_body_required'));
                return;
            }
            resolve(Buffer.concat(chunks, total));
        };
        const onError = () => fail(new HttpInputError(400, 'request_body_read_failed'));
        request.on('data', onData);
        request.on('end', onEnd);
        request.on('error', onError);
    });
}
async function readStrictJsonBody(request, maxBytes) {
    if (!JSON_CONTENT_TYPE.test(String(request.headers['content-type'] ?? ''))) {
        throw new HttpInputError(415, 'application_json_required');
    }
    const bytes = await readBody(request, maxBytes);
    let text;
    try {
        text = UTF8.decode(bytes);
    }
    catch {
        throw new HttpInputError(400, 'request_utf8_invalid');
    }
    if (!strictJsonGate(text).ok)
        throw new HttpInputError(400, 'request_json_invalid');
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new HttpInputError(400, 'request_object_required');
    }
    return parsed;
}
function receiptCarrier(request, maxChars) {
    let count = 0;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
        if (String(request.rawHeaders[index]).toLowerCase() === 'x-emilia-receipt')
            count += 1;
    }
    const value = request.headers['x-emilia-receipt'];
    if (count > 1 || Array.isArray(value))
        return 'duplicate-receipt-carrier';
    if (value === undefined)
        return null;
    if (typeof value !== 'string' || value.length === 0 || value.length > maxChars) {
        return 'invalid-receipt-carrier';
    }
    return value;
}
function exactQuery(url, { pagination = false } = {}) {
    const allowed = new Set(['tenant_id', 'gate_id', 'action_id']);
    if (pagination) {
        allowed.add('cursor');
        allowed.add('limit');
    }
    for (const key of url.searchParams.keys()) {
        if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) {
            throw new HttpInputError(400, 'query_parameters_invalid');
        }
    }
    const required = {};
    for (const key of ['tenant_id', 'gate_id', 'action_id']) {
        const value = url.searchParams.get(key);
        if (typeof value !== 'string' || value.length === 0 || value.length > 256
            || /[\u0000-\u001f\u007f]/.test(value)) {
            throw new HttpInputError(400, 'evidence_scope_invalid');
        }
        required[key] = value;
    }
    const result = {
        scope: {
            tenantId: required.tenant_id,
            gateId: required.gate_id,
            actionId: required.action_id,
        },
    };
    if (pagination) {
        const rawCursor = url.searchParams.get('cursor') ?? '0';
        const rawLimit = url.searchParams.get('limit') ?? '50';
        if (!/^(0|[1-9][0-9]*)$/.test(rawCursor) || !/^[1-9][0-9]*$/.test(rawLimit)) {
            throw new HttpInputError(400, 'pagination_invalid');
        }
        const cursor = Number(rawCursor);
        const limit = Number(rawLimit);
        if (!Number.isSafeInteger(cursor) || !Number.isSafeInteger(limit)) {
            throw new HttpInputError(400, 'pagination_invalid');
        }
        result.pagination = { cursor, limit };
    }
    return result;
}
function decodePathSegment(value) {
    try {
        return decodeURIComponent(value);
    }
    catch {
        throw new HttpInputError(400, 'request_target_invalid');
    }
}
function unauthorized(response) {
    sendJson(response, 401, { status: 'refused', error: { code: 'authentication_required' } }, {
        'WWW-Authenticate': 'Bearer realm="emilia-gate"',
    });
}
export function createRequestHandler(runtime) {
    const required = [
        'executeDelete',
        'resumeDelete',
        'getAction',
        'authenticate',
        'live',
        'ready',
        'evidenceHead',
        'getEvidenceRecord',
        'evidenceHistory',
        'verifyEvidence',
        'exportEvidence',
        'metrics',
    ];
    if (!runtime || required.some((method) => typeof runtime[method] !== 'function')) {
        throw new TypeError('runtime contract is invalid');
    }
    return async function handleRequest(request, response) {
        try {
            let url;
            try {
                url = new URL(request.url ?? '/', 'http://emilia-gate.local');
            }
            catch {
                throw new HttpInputError(400, 'request_target_invalid');
            }
            if (url.pathname === GATE_ROUTE_PATHS.live || url.pathname === GATE_ROUTE_PATHS.ready) {
                if (url.search)
                    throw new HttpInputError(400, 'query_parameters_forbidden');
                if (request.method !== 'GET') {
                    sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, { Allow: 'GET' });
                    return;
                }
                const result = url.pathname === GATE_ROUTE_PATHS.live ? runtime.live() : await runtime.ready();
                sendJson(response, result.status, result.body, result.headers);
                return;
            }
            const actionMatch = /^\/v1\/actions\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
            const executeMatch = /^\/v1\/actions\/([A-Za-z0-9_-]+)\/execute$/.exec(url.pathname);
            const evidenceRecordMatch = /^\/v1\/evidence\/records\/([^/]+)$/.exec(url.pathname);
            const protectedRoute = url.pathname === GATE_ROUTE_PATHS.actions
                || actionMatch || executeMatch || EVIDENCE_PATHS.has(url.pathname)
                || evidenceRecordMatch || url.pathname === GATE_ROUTE_PATHS.metrics;
            if (!protectedRoute) {
                sendJson(response, 404, { status: 'refused', error: { code: 'route_not_found' } });
                return;
            }
            const principal = await runtime.authenticate(request);
            if (!principal) {
                unauthorized(response);
                return;
            }
            if (url.pathname === GATE_ROUTE_PATHS.actions || actionMatch || executeMatch) {
                if (url.search)
                    throw new HttpInputError(400, 'query_parameters_forbidden');
                if (request.method === 'POST' && url.pathname === GATE_ROUTE_PATHS.actions) {
                    const body = await readStrictJsonBody(request, runtime.limits.maxBodyBytes);
                    const result = await runtime.executeDelete({
                        principal,
                        body,
                        receiptCarrier: receiptCarrier(request, runtime.limits.maxReceiptCarrierChars),
                    });
                    sendJson(response, result.status, result.body, result.headers);
                    return;
                }
                if (request.method === 'POST' && executeMatch) {
                    const body = await readStrictJsonBody(request, runtime.limits.maxBodyBytes);
                    const result = await runtime.resumeDelete({
                        id: executeMatch[1],
                        principal,
                        body,
                        receiptCarrier: receiptCarrier(request, runtime.limits.maxReceiptCarrierChars),
                    });
                    sendJson(response, result.status, result.body, result.headers);
                    return;
                }
                if (request.method === 'GET' && actionMatch) {
                    const result = await runtime.getAction(actionMatch[1], principal);
                    sendJson(response, result.status, result.body, result.headers);
                    return;
                }
                sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, {
                    Allow: url.pathname === GATE_ROUTE_PATHS.actions || executeMatch ? 'POST' : 'GET',
                });
                return;
            }
            if (request.method !== 'GET') {
                sendJson(response, 405, { status: 'refused', error: { code: 'method_not_allowed' } }, { Allow: 'GET' });
                return;
            }
            const pagination = url.pathname === GATE_ROUTE_PATHS.evidenceHistory
                || url.pathname === GATE_ROUTE_PATHS.evidenceExport;
            const query = exactQuery(url, { pagination });
            let result;
            if (url.pathname === GATE_ROUTE_PATHS.evidenceHead) {
                result = await runtime.evidenceHead(principal, query.scope);
            }
            else if (evidenceRecordMatch) {
                result = await runtime.getEvidenceRecord(decodePathSegment(evidenceRecordMatch[1]), principal, query.scope);
            }
            else if (url.pathname === GATE_ROUTE_PATHS.evidenceHistory) {
                result = await runtime.evidenceHistory(principal, query.scope, query.pagination);
            }
            else if (url.pathname === GATE_ROUTE_PATHS.evidenceVerify) {
                result = await runtime.verifyEvidence(principal, query.scope);
            }
            else if (url.pathname === GATE_ROUTE_PATHS.evidenceExport) {
                result = await runtime.exportEvidence(principal, query.scope, query.pagination);
            }
            else {
                result = await runtime.metrics(principal, query.scope);
            }
            sendJson(response, result.status, result.body, result.headers);
        }
        catch (error) {
            if (error instanceof HttpInputError) {
                sendJson(response, error.status, { status: 'refused', error: { code: error.code } });
                return;
            }
            sendJson(response, 500, { status: 'failed', error: { code: 'internal_error' } });
        }
    };
}
