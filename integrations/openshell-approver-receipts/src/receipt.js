// SPDX-License-Identifier: Apache-2.0
// Generated from receipt.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Approver receipts for OpenShell draft-chunk approvals.
//
// A receipt is { payload, proof }. The payload names exactly one approval:
// workspace, sandbox, chunk_id, the gateway's review_token for the reviewed
// candidate, and the digest of the canonical proposed rule. The approval
// digest is D = SHA-256(JCS(payload)). Two proof formats bind D with ES256
// (ECDSA P-256 / SHA-256):
//
//   es256     signature = ES256 over the bytes JCS(payload), which is ECDSA
//             over D; raw r||s, 64 bytes, base64url. Produced by the demo CLI
//             with a local key file.
//   webauthn  a WebAuthn assertion whose clientDataJSON.challenge is
//             base64url(D). Produced by a passkey. Verified by
//             verifyWebAuthnSignoff from @emilia-protocol/verify, which also
//             requires the user-present and user-verified flags.
//
// The approver key id is base64url(SHA-256(SPKI DER)) and is part of the
// signed payload.
import crypto from 'node:crypto';
import { verifyWebAuthnSignoff } from '@emilia-protocol/verify';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { b64u, fromB64u, jcs } from './canonical.ts';
export const APPROVAL_TYPE = 'emilia.openshell.draft-chunk-approval.v1';
const PAYLOAD_KEYS = [
    'type', 'decision', 'workspace', 'sandbox', 'chunk_id', 'review_token', 'rule_name', 'rule_digest',
    'candidate_effective_policy_hash', 'approver_kid', 'issued_at', 'nonce',
];
const ES256_PROOF_KEYS = ['format', 'public_key_spki', 'signature'];
const WEBAUTHN_PROOF_KEYS = ['format', 'public_key_spki', 'authenticator_data', 'client_data_json', 'signature'];
const HEX64 = /^[0-9a-f]{64}$/;
const RULE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
// Printable, no control characters, bounded. Names on the OpenShell API are
// much narrower; this only keeps the receipt free of ambiguous text.
const NAME = /^[\x21-\x7e]{1,253}$/;
function isPlainObject(value) {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
        return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}
function exactKeys(value, keys, what) {
    const actual = Object.keys(value);
    const extra = actual.filter((k) => !keys.includes(k));
    if (extra.length > 0)
        throw new Error(`${what} has unknown member(s): ${extra.map((k) => JSON.stringify(k)).join(', ')}`);
    const missing = keys.filter((k) => !Object.prototype.hasOwnProperty.call(value, k));
    if (missing.length > 0)
        throw new Error(`${what} is missing: ${missing.join(', ')}`);
}
function expect(condition, message) {
    if (!condition)
        throw new Error(message);
}
/** Key id: base64url(SHA-256(SPKI DER)). */
export function keyIdFromSpki(spkiDer) {
    return b64u(crypto.createHash('sha256').update(spkiDer).digest());
}
/** Parse an SPKI (base64url DER) and require an EC P-256 public key. */
export function p256PublicKey(spkiB64u) {
    const der = fromB64u(spkiB64u);
    if (!der)
        return { ok: false, reason: 'public_key_spki is not canonical base64url' };
    try {
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
            return { ok: false, reason: 'public key is not an EC P-256 key (ES256 only)' };
        }
        const canonicalDer = key.export({ format: 'der', type: 'spki' });
        if (!canonicalDer.equals(der))
            return { ok: false, reason: 'public_key_spki is not the canonical SPKI encoding of its key' };
        return { ok: true, value: { key, der, kid: keyIdFromSpki(der) } };
    }
    catch (error) {
        return { ok: false, reason: `public_key_spki does not parse: ${error instanceof Error ? error.message : String(error)}` };
    }
}
function validatePayload(value) {
    expect(isPlainObject(value), 'payload is not an object');
    const p = value;
    exactKeys(p, PAYLOAD_KEYS, 'payload');
    expect(p.type === APPROVAL_TYPE, `payload.type is not ${APPROVAL_TYPE}`);
    expect(p.decision === 'approve', 'payload.decision is not "approve"');
    for (const k of ['workspace', 'sandbox', 'chunk_id', 'rule_name']) {
        expect(typeof p[k] === 'string' && NAME.test(p[k]), `payload.${k} is not a non-empty printable name`);
    }
    expect(typeof p.review_token === 'string' && HEX64.test(p.review_token), 'payload.review_token is not 64 lowercase hex');
    expect(typeof p.rule_digest === 'string' && RULE_DIGEST.test(p.rule_digest), 'payload.rule_digest is not sha256:<64 hex>');
    expect(typeof p.candidate_effective_policy_hash === 'string' && (p.candidate_effective_policy_hash === '' || HEX64.test(p.candidate_effective_policy_hash)), 'payload.candidate_effective_policy_hash is not empty or 64 lowercase hex');
    const kid = fromB64u(p.approver_kid);
    expect(kid !== null && kid.length === 32, 'payload.approver_kid is not base64url of 32 bytes');
    expect(typeof p.issued_at === 'string' && RFC3339_UTC.test(p.issued_at) && !Number.isNaN(Date.parse(p.issued_at)), 'payload.issued_at is not an RFC 3339 UTC time');
    const nonce = fromB64u(p.nonce);
    expect(nonce !== null && nonce.length >= 16 && nonce.length <= 64, 'payload.nonce is not base64url of 16 to 64 bytes');
    return p;
}
function validateProof(value) {
    expect(isPlainObject(value), 'proof is not an object');
    const proof = value;
    if (proof.format === 'es256') {
        exactKeys(proof, ES256_PROOF_KEYS, 'proof');
        const sig = fromB64u(proof.signature);
        expect(sig !== null && sig.length === 64, 'proof.signature is not base64url of a 64-byte r||s ES256 signature');
        expect(fromB64u(proof.public_key_spki) !== null, 'proof.public_key_spki is not canonical base64url');
        return proof;
    }
    if (proof.format === 'webauthn') {
        exactKeys(proof, WEBAUTHN_PROOF_KEYS, 'proof');
        for (const k of ['public_key_spki', 'authenticator_data', 'client_data_json', 'signature']) {
            expect(fromB64u(proof[k]) !== null, `proof.${k} is not canonical base64url`);
        }
        return proof;
    }
    throw new Error('proof.format is not "es256" or "webauthn"');
}
/** Structural parse of a receipt object. Never throws. */
export function parseReceipt(value) {
    try {
        expect(isPlainObject(value), 'receipt is not an object');
        const r = value;
        exactKeys(r, ['payload', 'proof'], 'receipt');
        const payload = validatePayload(r.payload);
        const proof = validateProof(r.proof);
        jcs(payload);
        return { ok: true, value: { payload, proof } };
    }
    catch (error) {
        return { ok: false, reason: error instanceof Error ? error.message : String(error) };
    }
}
/** Parse receipts from text: a JSON array, one JSON object, or JSON lines. */
export function parseReceiptsText(text) {
    const trimmed = text.trim();
    if (trimmed === '')
        return { receipts: [] };
    const whole = strictJsonGate(trimmed);
    if (whole.ok) {
        const value = JSON.parse(trimmed);
        if (Array.isArray(value))
            return { receipts: value.map((item) => parseReceipt(item)) };
        return { receipts: [parseReceipt(value)] };
    }
    const receipts = [];
    for (const line of trimmed.split('\n')) {
        if (line.trim() === '')
            continue;
        const gate = strictJsonGate(line);
        receipts.push(gate.ok ? parseReceipt(JSON.parse(line)) : { ok: false, reason: `receipt line is not strict JSON: ${gate.reason}` });
    }
    return { receipts };
}
/** D = SHA-256(JCS(payload)); the WebAuthn challenge is base64url(D). */
export function approvalDigest(payload) {
    return crypto.createHash('sha256').update(jcs(payload), 'utf8').digest();
}
export function buildPayload(args) {
    if (!args.chunk.rule_digest)
        return { ok: false, reason: 'the chunk has no canonical rule digest; refusing to sign a rule that was not canonicalized' };
    const payload = {
        type: APPROVAL_TYPE,
        decision: 'approve',
        workspace: args.workspace,
        sandbox: args.sandbox,
        chunk_id: args.chunk.chunk_id,
        review_token: args.chunk.review_token,
        rule_name: args.chunk.rule_name,
        rule_digest: args.chunk.rule_digest,
        candidate_effective_policy_hash: args.chunk.candidate_effective_policy_hash,
        approver_kid: keyIdFromSpki(args.publicKeySpkiDer),
        issued_at: (args.issuedAt ?? new Date()).toISOString(),
        nonce: b64u(args.nonce ?? crypto.randomBytes(16)),
    };
    try {
        return { ok: true, value: validatePayload(payload) };
    }
    catch (error) {
        return { ok: false, reason: error instanceof Error ? error.message : String(error) };
    }
}
/** Demo signer: ES256 with a local P-256 private key. */
export function signEs256(payload, privateKey) {
    const publicKey = crypto.createPublicKey(privateKey);
    const spki = publicKey.export({ format: 'der', type: 'spki' });
    if (keyIdFromSpki(spki) !== payload.approver_kid)
        throw new Error('payload.approver_kid does not name this key');
    const signature = crypto.sign('sha256', Buffer.from(jcs(payload), 'utf8'), { key: privateKey, dsaEncoding: 'ieee-p1363' });
    return { payload, proof: { format: 'es256', public_key_spki: b64u(spki), signature: b64u(signature) } };
}
/**
 * Cryptographic check only: the proof is a valid ES256 signature over D by
 * the carried key, and the carried key is the one the payload names. It says
 * nothing about whether the reader trusts that key (see check.ts, ACCEPTED).
 * With `pins` on a webauthn proof it also enforces the relying-party scope.
 */
export function verifyReceiptSignature(receipt, pins) {
    const key = p256PublicKey(receipt.proof.public_key_spki);
    if (!key.ok)
        return { ok: false, reason: key.reason, format: receipt.proof.format };
    const { kid } = key.value;
    if (kid !== receipt.payload.approver_kid) {
        return { ok: false, reason: 'payload.approver_kid does not match the proof key', kid, format: receipt.proof.format };
    }
    try {
        if (receipt.proof.format === 'es256') {
            const sig = fromB64u(receipt.proof.signature);
            if (!sig || sig.length !== 64)
                return { ok: false, reason: 'signature is not 64 bytes', kid, format: 'es256' };
            const ok = crypto.verify('sha256', Buffer.from(jcs(receipt.payload), 'utf8'), { key: key.value.key, dsaEncoding: 'ieee-p1363' }, sig);
            return ok ? { ok: true, kid, format: 'es256' } : { ok: false, reason: 'ES256 signature does not verify over JCS(payload)', kid, format: 'es256' };
        }
        const proof = receipt.proof;
        const result = verifyWebAuthnSignoff({
            context: receipt.payload,
            webauthn: { authenticator_data: proof.authenticator_data, client_data_json: proof.client_data_json, signature: proof.signature },
        }, proof.public_key_spki, pins
            ? { mode: 'relying-party', rpId: pins.rp_id, allowedOrigins: pins.origins, alg: 'ES256' }
            : { mode: 'offline-integrity', alg: 'ES256' });
        if (result.valid)
            return { ok: true, kid, format: 'webauthn' };
        const failed = Object.entries(result.checks ?? {}).filter(([, v]) => v === false).map(([k]) => k);
        return { ok: false, reason: `WebAuthn assertion refused: ${result.error ?? `failed checks ${failed.join(', ')}`}`, kid, format: 'webauthn' };
    }
    catch (error) {
        return { ok: false, reason: `signature check failed: ${error instanceof Error ? error.message : String(error)}`, kid, format: receipt.proof.format };
    }
}
