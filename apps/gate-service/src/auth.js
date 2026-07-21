// SPDX-License-Identifier: Apache-2.0
// Generated from auth.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_LENGTH = 1024;
const TOKEN_LENGTH_BYTES = 2;
const TOKEN_COMPARISON_BYTES = TOKEN_LENGTH_BYTES + MAX_TOKEN_LENGTH;
const MAX_PRINCIPAL_ID_LENGTH = 256;
function validToken(value) {
    return typeof value === 'string'
        && value.length >= MIN_TOKEN_LENGTH
        && value.length <= MAX_TOKEN_LENGTH
        && /^[\x21-\x7e]+$/.test(value);
}
function comparableToken(value) {
    if (!validToken(value))
        return null;
    const tokenBytes = Buffer.from(value, 'ascii');
    const comparison = Buffer.alloc(TOKEN_COMPARISON_BYTES);
    comparison.writeUInt16BE(tokenBytes.length, 0);
    tokenBytes.copy(comparison, TOKEN_LENGTH_BYTES);
    return comparison;
}
function oneAuthorizationHeader(request) {
    if (!request || !Array.isArray(request.rawHeaders) || request.rawHeaders.length % 2 !== 0) {
        return null;
    }
    let count = 0;
    let rawValue = null;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
        if (String(request.rawHeaders[index]).toLowerCase() === 'authorization') {
            count += 1;
            rawValue = request.rawHeaders[index + 1];
        }
    }
    const value = request.headers?.authorization;
    return count === 1 && typeof rawValue === 'string' && value === rawValue ? value : null;
}
export function normalizePrincipal(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return null;
    const obj = value;
    if (typeof obj.id !== 'string' || obj.id.length === 0
        || obj.id.length > MAX_PRINCIPAL_ID_LENGTH
        || !/^[\x21-\x7e]+$/.test(obj.id))
        return null;
    try {
        return Object.freeze(structuredClone(obj));
    }
    catch {
        return null;
    }
}
/** Create a constant-time bearer-token authenticator for a BYOC Gate service. */
export function createStaticBearerAuthenticator(token, principal) {
    const expected = comparableToken(token);
    if (!expected) {
        throw new Error(`Gate API token must be ${MIN_TOKEN_LENGTH}-${MAX_TOKEN_LENGTH} printable ASCII characters`);
    }
    const authenticatedPrincipal = normalizePrincipal(principal);
    if (!authenticatedPrincipal) {
        throw new Error('Gate API principal must be a plain object with a visible non-space id of 1-256 characters');
    }
    return async function authenticateRequest(request) {
        const header = oneAuthorizationHeader(request);
        if (!header?.startsWith('Bearer '))
            return null;
        const candidate = header.slice('Bearer '.length);
        const actual = comparableToken(candidate);
        if (!actual)
            return null;
        return crypto.timingSafeEqual(actual, expected) ? authenticatedPrincipal : null;
    };
}
export default createStaticBearerAuthenticator;
