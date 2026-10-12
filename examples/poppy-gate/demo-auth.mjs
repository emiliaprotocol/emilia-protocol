// SPDX-License-Identifier: Apache-2.0
// Generated from demo-auth.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Synthetic, in-process session authority for the offline demo. This is not
// an OAuth server, production client registration or durable DPoP replay store.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { canonicalizeStrictJson, strictJsonGate } from '../../packages/verify/dist/strict-json.js';
const digest = (input) => createHash('sha256').update(input, 'utf8').digest('base64url');
const encode = (value) => Buffer.from(canonicalizeStrictJson(value), 'utf8').toString('base64url');
const parse = (part) => {
    if (!/^[A-Za-z0-9_-]+$/.test(part) || part.length > 131072)
        throw new Error('invalid_demo_auth');
    const bytes = Buffer.from(part, 'base64url');
    if (bytes.toString('base64url') !== part)
        throw new Error('invalid_demo_auth');
    const text = bytes.toString('utf8');
    if (!strictJsonGate(text).ok)
        throw new Error('invalid_demo_auth');
    return JSON.parse(text);
};
function jwtParts(value) {
    if (typeof value !== 'string' || value.length > 262144)
        throw new Error('invalid_demo_auth');
    const parts = value.split('.');
    if (parts.length !== 3 || !/^[A-Za-z0-9_-]+$/.test(parts[2]))
        throw new Error('invalid_demo_auth');
    const header = parse(parts[0]), payload = parse(parts[1]);
    if (!header || !payload || typeof header !== 'object' || typeof payload !== 'object'
        || Array.isArray(header) || Array.isArray(payload))
        throw new Error('invalid_demo_auth');
    return { input: `${parts[0]}.${parts[1]}`, header, payload, signature: Buffer.from(parts[2], 'base64url') };
}
function header(request, name) {
    const entries = Object.entries(request.headers ?? {}).filter(([key]) => key.toLowerCase() === name.toLowerCase());
    if (entries.length !== 1 || typeof entries[0][1] !== 'string')
        throw new Error('invalid_demo_auth');
    return entries[0][1];
}
function target(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password)
        throw new Error('invalid_demo_auth');
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
}
export function createDemoSessionAuth({ companyIssuer, endpoint, owner, now = Date.now }) {
    const issuerKeys = generateKeyPairSync('ed25519');
    const sessionKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicJwk = sessionKeys.publicKey.export({ format: 'jwk' });
    const jkt = digest(canonicalizeStrictJson({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }));
    const principal = JSON.parse(canonicalizeStrictJson(owner));
    const seen = new Map();
    const resource = target(endpoint);
    const allowed = new URL(resource);
    const clock = now;
    const issued = Math.floor(clock() / 1000);
    const tokenInput = `${encode({ typ: 'at+jwt', alg: 'EdDSA', kid: 'demo-issuer' })}.${encode({
        iss: companyIssuer, aud: resource, iat: issued, exp: issued + 3600,
        cnf: { jkt }, principal,
    })}`;
    const accessToken = `${tokenInput}.${sign(null, Buffer.from(tokenInput), issuerKeys.privateKey).toString('base64url')}`;
    function request({ url, method, body }) {
        const proofInput = `${encode({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })}.${encode({
            jti: randomBytes(16).toString('hex'), htm: method, htu: target(url),
            iat: Math.floor(clock() / 1000), ath: digest(accessToken),
        })}`;
        const proof = `${proofInput}.${sign('sha256', Buffer.from(proofInput), {
            key: sessionKeys.privateKey, dsaEncoding: 'ieee-p1363',
        }).toString('base64url')}`;
        return { method, url, headers: { Authorization: `DPoP ${accessToken}`, DPoP: proof },
            ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }) };
    }
    async function authenticateRequest(input) {
        // All identity comes from the authenticated issuer token. A field such as
        // input.principal or input.accountId cannot become a trusted identity.
        const authorization = header(input, 'Authorization');
        if (!authorization.startsWith('DPoP '))
            throw new Error('invalid_demo_auth');
        const tokenValue = authorization.slice(5);
        const token = jwtParts(tokenValue), proof = jwtParts(header(input, 'DPoP'));
        const at = Math.floor(clock() / 1000);
        if (!Number.isSafeInteger(at) || token.header.alg !== 'EdDSA' || token.header.typ !== 'at+jwt'
            || token.header.kid !== 'demo-issuer' || token.payload.iss !== companyIssuer
            || token.payload.aud !== resource || !Number.isSafeInteger(token.payload.exp)
            || !Number.isSafeInteger(token.payload.iat) || at >= token.payload.exp || at < token.payload.iat
            || !verify(null, Buffer.from(token.input), issuerKeys.publicKey, token.signature))
            throw new Error('invalid_demo_auth');
        const jwk = proof.header.jwk;
        if (proof.header.typ !== 'dpop+jwt' || proof.header.alg !== 'ES256' || !jwk
            || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d !== undefined
            || typeof jwk.x !== 'string' || typeof jwk.y !== 'string')
            throw new Error('invalid_demo_auth');
        const thumbprint = digest(canonicalizeStrictJson({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
        const url = new URL(target(input.url));
        if (url.origin !== allowed.origin || !(url.pathname === allowed.pathname || url.pathname.startsWith(`${allowed.pathname}/`))
            || token.payload.cnf?.jkt !== thumbprint || proof.payload.ath !== digest(tokenValue)
            || proof.payload.htm !== input.method || proof.payload.htu !== target(input.url)
            || !Number.isSafeInteger(proof.payload.iat) || Math.abs(at - proof.payload.iat) > 60
            || typeof proof.payload.jti !== 'string' || !/^[0-9a-f]{32}$/.test(proof.payload.jti)
            || !verify('sha256', Buffer.from(proof.input), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, proof.signature))
            throw new Error('invalid_demo_auth');
        for (const [key, expiry] of seen)
            if (expiry < at)
                seen.delete(key);
        const replayKey = `${thumbprint}:${proof.payload.jti}`;
        if (seen.has(replayKey))
            throw new Error('invalid_demo_auth');
        seen.set(replayKey, proof.payload.iat + 60);
        return { ...JSON.parse(canonicalizeStrictJson(token.payload.principal)), dpop: { verified: true, jkt: thumbprint } };
    }
    return { authenticateRequest, request, fixture_kind: 'synthetic_local_session_issuer_with_ephemeral_replay_store' };
}
