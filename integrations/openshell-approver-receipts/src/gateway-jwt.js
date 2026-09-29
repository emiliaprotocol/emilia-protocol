// SPDX-License-Identifier: Apache-2.0
// Generated from gateway-jwt.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Verifies the bearer JWT an OpenShell gateway attaches to every interceptor
// call when [openshell.gateway.gateway_jwt] is configured. The algorithm is
// pinned (EdDSA over the pinned Ed25519 key); nothing about how to verify is
// read from the token itself.
import crypto from 'node:crypto';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { fromB64u } from './canonical.ts';
export const GATEWAY_JWT_TYP = 'openshell-ext+jwt';
export function loadGatewayPublicKey(pem) {
    const key = crypto.createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new Error(`gateway JWT key must be Ed25519, got ${key.asymmetricKeyType}`);
    return key;
}
function decodeJsonSegment(segment, name) {
    const bytes = fromB64u(segment);
    if (!bytes)
        throw new Error(`${name} is not canonical base64url`);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const gate = strictJsonGate(text);
    if (!gate.ok)
        throw new Error(`${name} is not strict JSON: ${gate.reason}`);
    const value = JSON.parse(text);
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        throw new Error(`${name} is not a JSON object`);
    return value;
}
export function verifyGatewayAuthorization(authorization, policy) {
    if (!policy)
        return { mode: 'not_configured' };
    try {
        if (typeof authorization !== 'string')
            throw new Error('no authorization metadata');
        if (!authorization.startsWith('Bearer '))
            throw new Error('authorization is not a Bearer credential');
        const token = authorization.slice('Bearer '.length);
        const parts = token.split('.');
        if (parts.length !== 3)
            throw new Error('JWT does not have three segments');
        const header = decodeJsonSegment(parts[0], 'JWT header');
        const claims = decodeJsonSegment(parts[1], 'JWT claims');
        const signature = fromB64u(parts[2]);
        if (!signature || signature.length !== 64)
            throw new Error('JWT signature is not a 64-byte Ed25519 signature');
        if (header.alg !== 'EdDSA')
            throw new Error(`JWT alg ${JSON.stringify(header.alg)} is not the pinned EdDSA`);
        if (header.typ !== GATEWAY_JWT_TYP)
            throw new Error(`JWT typ ${JSON.stringify(header.typ)} is not ${GATEWAY_JWT_TYP}`);
        if (header.crit !== undefined)
            throw new Error('JWT carries crit parameters this verifier does not process');
        const signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
        if (!crypto.verify(null, signed, policy.publicKey, signature))
            throw new Error('JWT signature does not verify under the pinned gateway key');
        const expectedIssuer = `openshell-gateway:${policy.gatewayId}`;
        if (claims.iss !== expectedIssuer)
            throw new Error(`JWT iss ${JSON.stringify(claims.iss)} is not ${expectedIssuer}`);
        const aud = claims.aud;
        const audOk = aud === policy.audience || (Array.isArray(aud) && aud.length > 0 && aud.every((a) => typeof a === 'string') && aud.includes(policy.audience));
        if (!audOk)
            throw new Error(`JWT aud does not name ${policy.audience}`);
        if (claims.caller_kind !== 'gateway')
            throw new Error(`JWT caller_kind ${JSON.stringify(claims.caller_kind)} is not gateway`);
        const now = Math.floor((policy.now ?? Date.now)() / 1000);
        const skew = policy.skewSeconds ?? 60;
        if (typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp))
            throw new Error('JWT exp is missing or not an integer');
        if (claims.exp + skew < now)
            throw new Error('JWT has expired');
        if (claims.iat !== undefined && (typeof claims.iat !== 'number' || claims.iat - skew > now))
            throw new Error('JWT iat is in the future');
        if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - skew > now))
            throw new Error('JWT is not yet valid');
        return { mode: 'verified', jti: typeof claims.jti === 'string' ? claims.jti : '', iss: expectedIssuer, exp: claims.exp };
    }
    catch (error) {
        return { mode: 'failed', reason: error instanceof Error ? error.message : String(error) };
    }
}
