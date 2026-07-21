// SPDX-License-Identifier: Apache-2.0
// Generated from worker.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Reference / experimental. Not production audited.
/// <reference path="./cloudflare-reference.d.ts" />
import { createReceiptRequiredEdgeHandler } from '../../../packages/require-receipt/src/edge.js';
import { strictJsonGate } from '../../../packages/require-receipt/src/strict-json.js';
import { canonicalize, verifyReceipt as verifyReceiptWeb } from '../../../packages/verify/src/web.js';
const utf8 = new TextDecoder('utf-8', { fatal: true });
const caidPattern = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/;
function isCanonicalizable(value) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return true;
    if (typeof value === 'number')
        return Number.isSafeInteger(value);
    if (Array.isArray(value))
        return value.every(isCanonicalizable);
    if (value && typeof value === 'object')
        return Object.values(value).every(isCanonicalizable);
    return false;
}
async function sha256(value) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
    return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}
function parseJsonArray(value, name) {
    if (!strictJsonGate(value).ok)
        throw new Error(`${name}_invalid_json`);
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== 'string' || item.length === 0)) {
        throw new Error(`${name}_invalid`);
    }
    return parsed;
}
function parseCarrier(carrier) {
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(carrier) || carrier.length % 4 === 1)
        return null;
    const mixedAlphabets = /[-_]/.test(carrier) && /[+/]/.test(carrier);
    if (mixedAlphabets)
        return null;
    try {
        const normalized = carrier.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
        const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
        const binary = atob(padded);
        const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
        let binaryCanonical = '';
        for (const byte of bytes)
            binaryCanonical += String.fromCharCode(byte);
        const canonical = btoa(binaryCanonical).replace(/=+$/, '');
        if (canonical !== normalized)
            return null;
        const text = utf8.decode(bytes);
        if (!strictJsonGate(text).ok)
            return null;
        const parsed = JSON.parse(text);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
    }
    catch {
        return null;
    }
}
async function projectJsonAction(request) {
    const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json')
        throw new Error('observed_action_invalid');
    const text = await request.clone().text();
    if (!strictJsonGate(text).ok)
        throw new Error('observed_action_invalid');
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('observed_action_invalid');
    return value;
}
function positiveInteger(value, fallback) {
    const parsed = value === undefined ? fallback : Number(value);
    if (!Number.isSafeInteger(parsed) || parsed <= 0)
        throw new Error('positive_integer_required');
    return parsed;
}
function problemResponse(decision) {
    return new Response(JSON.stringify(decision.body), {
        status: decision.status,
        headers: decision.headers,
    });
}
export class ReceiptConsumption {
    state;
    constructor(state) {
        this.state = state;
    }
    async fetch(request) {
        if (request.method !== 'POST')
            return new Response('method not allowed', { status: 405 });
        let body;
        try {
            body = await request.json();
        }
        catch {
            return Response.json({ consumed: false }, { status: 400 });
        }
        if (typeof body.receipt_id !== 'string' || typeof body.action !== 'string') {
            return Response.json({ consumed: false }, { status: 400 });
        }
        const key = JSON.stringify([body.action, body.receipt_id]);
        let consumed = false;
        await this.state.storage.transaction(async (transaction) => {
            if (await transaction.get(key) === undefined) {
                await transaction.put(key, new Date().toISOString());
                consumed = true;
            }
        });
        return Response.json({ consumed });
    }
}
export default {
    async fetch(request, env) {
        const trustedKeys = parseJsonArray(env.EP_TRUSTED_KEYS, 'EP_TRUSTED_KEYS');
        const requiredFields = parseJsonArray(env.EP_REQUIRED_FIELDS, 'EP_REQUIRED_FIELDS');
        const maxAgeSec = positiveInteger(env.EP_MAX_AGE_SEC, 900);
        const action = env.EP_ACTION;
        const durableId = env.RECEIPT_CONSUMPTION.idFromName(action);
        const durable = env.RECEIPT_CONSUMPTION.get(durableId);
        const authorize = createReceiptRequiredEdgeHandler({
            action,
            ...(env.EP_ACTION_HASH ? { actionHash: env.EP_ACTION_HASH } : {}),
            projectAction: projectJsonAction,
            authorization: {
                authorization_endpoint: env.EP_AUTHORIZATION_ENDPOINT,
                flow: 'EP-APPROVAL-v1',
            },
            requiredFields,
            ...(env.EP_CAID_SELECTOR_FIELD ? { caidSelector: { field: env.EP_CAID_SELECTOR_FIELD } } : {}),
            maxAgeSec,
            maxBodyBytes: positiveInteger(env.EP_MAX_BODY_BYTES, 1024 * 1024),
            async verifyReceipt(carrier, context) {
                const document = parseCarrier(carrier);
                if (!document)
                    return { ok: false, reason: 'malformed_receipt' };
                const payload = document.payload;
                if (!isCanonicalizable(payload) || document.signature?.algorithm !== 'Ed25519') {
                    return { ok: false, reason: 'payload_outside_ijson_profile' };
                }
                const ageSeconds = (Date.now() - Date.parse(String(payload?.created_at || ''))) / 1000;
                if (!Number.isFinite(ageSeconds) || ageSeconds < 0 || ageSeconds > maxAgeSec) {
                    return { ok: false, reason: 'receipt_expired' };
                }
                if (payload?.expires_at !== undefined) {
                    const expiresAt = Date.parse(payload.expires_at);
                    if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) {
                        return { ok: false, reason: 'receipt_expired' };
                    }
                }
                if (payload?.claim?.action_type !== context.action)
                    return { ok: false, reason: 'action_mismatch' };
                if (!['allow', 'allow_with_signoff'].includes(String(payload.claim.outcome))) {
                    return { ok: false, reason: 'outcome_not_accepted' };
                }
                const signedAction = payload.claim.canonical_action;
                if (!signedAction || typeof signedAction !== 'object' || Array.isArray(signedAction)) {
                    return { ok: false, reason: 'signed_action_required' };
                }
                const computedHash = await sha256(canonicalize(signedAction));
                const claimedHash = typeof payload.claim.action_hash === 'string'
                    ? `sha256:${payload.claim.action_hash.replace(/^sha256:/, '').toLowerCase()}`
                    : '';
                if (claimedHash !== computedHash)
                    return { ok: false, reason: 'signed_action_hash_mismatch' };
                if (context.action_hash && context.action_hash !== computedHash) {
                    return { ok: false, reason: 'action_hash_mismatch' };
                }
                for (const field of context.required_fields) {
                    if (!Object.prototype.hasOwnProperty.call(signedAction, field) || signedAction[field] === undefined) {
                        return { ok: false, reason: 'required_field_missing' };
                    }
                }
                const caidField = context.caid_selector?.field;
                if (caidField && (typeof signedAction[caidField] !== 'string'
                    || !caidPattern.test(signedAction[caidField]))) {
                    return { ok: false, reason: 'caid_binding_invalid' };
                }
                let valid = false;
                for (const key of trustedKeys) {
                    const result = await verifyReceiptWeb(document, key);
                    if (result.valid) {
                        valid = true;
                        break;
                    }
                }
                if (!valid)
                    return { ok: false, reason: 'untrusted_or_invalid_signature' };
                return { ok: true, receipt_id: payload.receipt_id, action: context.action };
            },
            async consume(receiptId, context) {
                const response = await durable.fetch('https://receipt-consumption.internal/consume', {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ receipt_id: receiptId, action: context.action }),
                });
                if (!response.ok)
                    throw new Error('durable consumption unavailable');
                const body = await response.json();
                return body.consumed === true;
            },
        });
        const decision = await authorize(request);
        if (decision.ok === false)
            return problemResponse(decision);
        let upstreamOrigin;
        try {
            upstreamOrigin = new URL(env.UPSTREAM_ORIGIN);
        }
        catch {
            return new Response('gateway misconfigured', { status: 503 });
        }
        if (upstreamOrigin.protocol !== 'https:' || upstreamOrigin.username || upstreamOrigin.password
            || upstreamOrigin.search || upstreamOrigin.hash || upstreamOrigin.pathname !== '/') {
            return new Response('gateway misconfigured', { status: 503 });
        }
        const incoming = new URL(request.url);
        const upstream = new URL(`${incoming.pathname}${incoming.search}`, upstreamOrigin);
        const headers = new Headers(request.headers);
        for (const name of decision.upstream.remove_headers)
            headers.delete(name);
        for (const [name, value] of Object.entries(decision.upstream.set_headers))
            headers.set(name, value);
        return fetch(new Request(upstream, { method: request.method, headers, body: request.body, redirect: 'manual' }));
    },
};
