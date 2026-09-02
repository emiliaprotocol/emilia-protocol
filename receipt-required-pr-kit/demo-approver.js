// SPDX-License-Identifier: Apache-2.0
// Generated from demo-approver.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// LOCAL DEMO ONLY. This module holds the self-contained demo's approver key
// material and the proof minter that signs on its behalf. It is deliberately
// NOT part of example-dangerous-action.ts: a template that exports its own
// Class-A proof minter hands every caller the ability to self-issue the human
// signoff the gate is supposed to demand.
//
// example-dangerous-action.ts imports this module lazily, and only when demo
// mode is explicitly on (NODE_ENV !== 'production' AND EMILIA_ALLOW_INLINE_KEY=1).
// In production you configure EMILIA_APPROVER_KEYS_JSON, EMILIA_RP_ID, and
// EMILIA_ALLOWED_ORIGINS with a real enrolled approver directory instead, and
// this file is never loaded.
import crypto from 'node:crypto';
// Refuse to load at all under a production NODE_ENV. The demo approver's
// private key lives in this process; nothing that can mint a Class-A signoff
// belongs in a production image.
if (process.env.NODE_ENV === 'production') {
    throw new Error('receipt_required_demo_approver_is_not_for_production');
}
const canonicalize = (v) => (v === null || v === undefined ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(canonicalize).join(',')}]`
        : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`
            : JSON.stringify(v));
export const DEMO_RP_ID = 'receipt-required-demo.emiliaprotocol.ai';
export const DEMO_ORIGIN = `https://${DEMO_RP_ID}`;
export const DEMO_APPROVER_ID = 'jane.doe@yourco.example';
export const DEMO_APPROVER_KEY_ID = 'receipt-required-demo-approver';
const DEMO_APPROVER = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const DEMO_APPROVER_PUBLIC_KEY = DEMO_APPROVER.publicKey
    .export({ type: 'spki', format: 'der' })
    .toString('base64url');
export const DEMO_APPROVER_KEYS = Object.freeze({
    [DEMO_APPROVER_KEY_ID]: Object.freeze({
        public_key: DEMO_APPROVER_PUBLIC_KEY,
        key_class: 'A',
        approver_id: DEMO_APPROVER_ID,
    }),
});
/** The pinned assurance context the demo gate verifies proofs against. */
export function demoAssuranceConfiguration() {
    return {
        approverKeys: DEMO_APPROVER_KEYS,
        rpId: DEMO_RP_ID,
        allowedOrigins: [DEMO_ORIGIN],
    };
}
const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
/**
 * Mint the self-contained demo's P-256 WebAuthn-shaped assurance proof.
 * Production callers run a platform passkey ceremony on the approver's own
 * device; no server-side code path can produce this signature for them.
 */
export function createDemoClassAAssuranceProof(payload) {
    const context = {
        '@version': 'EP-ASSURANCE-CONTEXT-v1',
        receipt_id: payload.receipt_id,
        claim_hash: `sha256:${sha256Hex(canonicalize(payload.claim || {}))}`,
    };
    const contextHash = `sha256:${sha256Hex(canonicalize(context))}`;
    const digest = Buffer.from(contextHash.slice('sha256:'.length), 'hex');
    const clientDataBytes = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge: digest.toString('base64url'),
        origin: DEMO_ORIGIN,
        crossOrigin: false,
    }), 'utf8');
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(1);
    const authenticatorData = Buffer.concat([
        sha256(DEMO_RP_ID),
        Buffer.from([0x05]),
        counter,
    ]);
    const signature = crypto.sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataBytes)]), DEMO_APPROVER.privateKey);
    return {
        '@version': 'EP-ASSURANCE-PROOF-v1',
        context_hash: contextHash,
        signoffs: [{
                approver_key_id: DEMO_APPROVER_KEY_ID,
                key_class: 'A',
                webauthn: {
                    authenticator_data: authenticatorData.toString('base64url'),
                    client_data_json: clientDataBytes.toString('base64url'),
                    signature: signature.toString('base64url'),
                },
            }],
    };
}
