// SPDX-License-Identifier: Apache-2.0
// Generated from bounded-fetch.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { strictJsonGate } from '../../strict-json.js';
const MAX_CONFIGURED_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_CONFIGURED_TIMEOUT_MS = 60_000;
function headerValue(headers, name) {
    if (headers && typeof headers.get === 'function')
        return headers.get(name);
    if (!headers || typeof headers !== 'object')
        return null;
    const match = Object.entries(headers)
        .find(([key]) => key.toLowerCase() === name.toLowerCase());
    return match ? String(match[1]) : null;
}
function concatenate(chunks, total) {
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return output;
}
async function readBoundedBody(response, maxBytes, controller) {
    const contentLength = headerValue(response.headers, 'content-length');
    if (contentLength !== null) {
        if (!/^[0-9]+$/.test(contentLength)) {
            return { kind: 'failure', reason: 'invalid_response' };
        }
        const parsed = Number(contentLength);
        if (!Number.isSafeInteger(parsed) || parsed < 0) {
            return { kind: 'failure', reason: 'invalid_response' };
        }
        if (parsed > maxBytes) {
            controller.abort();
            return { kind: 'failure', reason: 'response_too_large' };
        }
    }
    if (response.body === null || response.body === undefined) {
        if (contentLength !== null && Number(contentLength) !== 0) {
            return { kind: 'failure', reason: 'invalid_response' };
        }
        return { kind: 'body', bytes: new Uint8Array() };
    }
    if (typeof response.body.getReader !== 'function') {
        return { kind: 'failure', reason: 'invalid_response' };
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
        const { done, value } = await reader.read();
        if (done)
            break;
        if (!(value instanceof Uint8Array)) {
            controller.abort();
            await reader.cancel().catch(() => { });
            return { kind: 'failure', reason: 'invalid_response' };
        }
        total += value.byteLength;
        if (total > maxBytes) {
            controller.abort();
            await reader.cancel().catch(() => { });
            return { kind: 'failure', reason: 'response_too_large' };
        }
        chunks.push(value);
    }
    return { kind: 'body', bytes: concatenate(chunks, total) };
}
export function validateResponseLimit(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 1 || value > MAX_CONFIGURED_RESPONSE_BYTES) {
        throw new TypeError(`${fieldName} is outside the supported range`);
    }
    return value;
}
export function validateTimeout(value, fieldName = 'timeoutMs') {
    if (!Number.isSafeInteger(value) || value < 1 || value > MAX_CONFIGURED_TIMEOUT_MS) {
        throw new TypeError(`${fieldName} is outside the supported range`);
    }
    return value;
}
/**
 * Accepts only a bare HTTPS origin. Callers construct fixed paths beneath the
 * returned value and requestBounded re-checks every final URL against it.
 */
export function validatePinnedOrigin(input, { allowedHosts, fieldName = 'apiOrigin' } = {}) {
    if (typeof input !== 'string' || input.length === 0) {
        throw new TypeError(`${fieldName} must be a non-empty HTTPS origin`);
    }
    let url;
    try {
        url = new URL(input);
    }
    catch {
        throw new TypeError(`${fieldName} must be a valid HTTPS origin`);
    }
    const hasPath = url.pathname !== '/' && url.pathname !== '';
    if (url.protocol !== 'https:'
        || url.username !== ''
        || url.password !== ''
        || hasPath
        || url.search !== ''
        || url.hash !== ''
        || (url.port !== '' && url.port !== '443')) {
        throw new TypeError(`${fieldName} must be a bare HTTPS origin on port 443`);
    }
    if (allowedHosts && !allowedHosts.has(url.hostname.toLowerCase())) {
        throw new TypeError(`${fieldName} host is not allowlisted`);
    }
    return url.origin;
}
/**
 * Fetches one exact-origin resource without redirects and bounds both the
 * response body and total wall-clock time. Error messages and response bodies
 * are intentionally not surfaced.
 */
export async function requestBounded(fetchImpl, input, init, policy) {
    if (typeof fetchImpl !== 'function')
        throw new TypeError('fetch must be a function');
    const maxBytes = validateResponseLimit(policy?.maxBytes, 'maxBytes');
    const timeoutMs = validateTimeout(policy?.timeoutMs);
    const expectedOrigin = validatePinnedOrigin(policy?.expectedOrigin);
    let target;
    try {
        target = new URL(input);
    }
    catch {
        return { kind: 'failure', reason: 'invalid_response' };
    }
    if (target.protocol !== 'https:' || target.origin !== expectedOrigin
        || target.username !== '' || target.password !== '') {
        return { kind: 'failure', reason: 'invalid_response' };
    }
    const controller = new AbortController();
    let timedOut = false;
    let timer;
    const timeout = new Promise((resolve) => {
        timer = setTimeout(() => {
            timedOut = true;
            controller.abort();
            resolve({ kind: 'failure', reason: 'timeout' });
        }, timeoutMs);
        timer.unref?.();
    });
    const operation = (async () => {
        try {
            const response = await fetchImpl(target.href, {
                ...init,
                redirect: 'error',
                signal: controller.signal,
            });
            if (!response || !Number.isInteger(response.status)
                || response.status < 100 || response.status > 599) {
                return { kind: 'failure', reason: 'invalid_response' };
            }
            if (response.redirected === true) {
                return { kind: 'failure', reason: 'invalid_response' };
            }
            if (typeof response.url === 'string' && response.url !== '') {
                let finalUrl;
                try {
                    finalUrl = new URL(response.url);
                }
                catch {
                    return { kind: 'failure', reason: 'invalid_response' };
                }
                if (finalUrl.href !== target.href
                    || finalUrl.origin !== expectedOrigin
                    || finalUrl.username !== ''
                    || finalUrl.password !== '') {
                    return { kind: 'failure', reason: 'invalid_response' };
                }
            }
            const body = await readBoundedBody(response, maxBytes, controller);
            if (body.kind === 'failure')
                return body;
            return {
                kind: 'response',
                status: response.status,
                headers: response.headers || {},
                bytes: body.bytes,
            };
        }
        catch {
            return { kind: 'failure', reason: timedOut ? 'timeout' : 'network' };
        }
    })();
    const result = await Promise.race([operation, timeout]);
    clearTimeout(timer);
    return result;
}
export function responseHeader(response, name) {
    return headerValue(response?.headers, name);
}
export function parseJsonObject(bytes, contentType, allowedProviderContentTypes = []) {
    if (typeof contentType !== 'string')
        return { ok: false };
    const mediaType = contentType.split(';', 1)[0].trim().toLowerCase();
    const allowed = new Set(allowedProviderContentTypes.map((value) => String(value).toLowerCase()));
    if (mediaType !== 'application/json' && !allowed.has(mediaType)) {
        return { ok: false };
    }
    try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!strictJsonGate(text).ok)
            return { ok: false };
        const value = JSON.parse(text);
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            return { ok: false };
        }
        return { ok: true, value };
    }
    catch {
        return { ok: false };
    }
}
