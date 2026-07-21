// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ZK-RANGE-RECEIPT-v1.
 *
 * This is a genuine Bulletproof range proof adapter, not a commitment renamed
 * as zero knowledge. It proves a hidden integer v satisfies 0 <= v <= max by
 * proving ranges for v and max-v, while the second Pedersen commitment is
 * publicly linked to the first. The base EP receipt and its signature remain a
 * separate verification step; this envelope binds only its public digest.
 *
 * The cryptographic engine is intentionally injected/lazy-loaded. The main
 * Gate package does not silently add a 60 MB mobile/WASM dependency. The
 * compatible backend is @aptos-labs/confidential-asset-bindings, which exposes
 * Bulletproofs over Ristretto255. A deployment must pin and audit that optional
 * backend before enabling this path.
 */
import { createHash, randomBytes } from 'node:crypto';
import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { canonicalize } from './execution-binding.js';
export const ZK_RANGE_RECEIPT_VERSION = 'EP-ZK-RANGE-RECEIPT-v1';
export const ZK_RANGE_SCHEME = 'Bulletproofs-Ristretto255-range-v1';
export const ZK_RANGE_BACKEND_PACKAGE = '@aptos-labs/confidential-asset-bindings@1.1.2';
const ZK_RANGE_BACKEND_MODULE = '@aptos-labs/confidential-asset-bindings';
const ORDER = ristretto255.Point.Fn.ORDER;
const TEXT_ENCODER = new TextEncoder();
/**
 * @param {Uint8Array|string} value
 * @param {string} label
 * @param {number|null} [length]
 * @returns {Uint8Array}
 */
function bytes(value, label, length = null) {
    const out = value instanceof Uint8Array ? new Uint8Array(value) : Buffer.from(value, 'base64url');
    if (length !== null && out.length !== length)
        throw new TypeError(`${label} must be ${length} bytes`);
    return out;
}
function b64(value) {
    return Buffer.from(value).toString('base64url');
}
function sha256Hex(value) {
    return createHash('sha256').update(value).digest('hex');
}
function digest(value, label) {
    if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value))
        throw new TypeError(`${label} must be a sha256: digest`);
    return value;
}
function safeU64(value, label) {
    if (!Number.isSafeInteger(value) || value < 0)
        throw new TypeError(`${label} must be a non-negative safe integer`);
    return value;
}
function rangeBits(max) {
    if (max <= 0xff)
        return 8;
    if (max <= 0xffff)
        return 16;
    if (max <= 0xffffffff)
        return 32;
    return 64;
}
function bytesToBigIntLE(value) {
    let result = 0n;
    for (let i = value.length - 1; i >= 0; i -= 1)
        result = (result << 8n) | BigInt(value[i]);
    return result;
}
function bigIntToBytesLE(value, length) {
    const out = new Uint8Array(length);
    let current = value;
    for (let i = 0; i < length; i += 1) {
        out[i] = Number(current & 0xffn);
        current >>= 8n;
    }
    return out;
}
function negateScalar(value) {
    const scalar = bytesToBigIntLE(value) % ORDER;
    return bigIntToBytesLE(scalar === 0n ? 0n : ORDER - scalar, 32);
}
/** Derive independent, deterministic Pedersen bases for this proof domain. */
export function deriveZkRangeBases(domain = ZK_RANGE_RECEIPT_VERSION) {
    if (typeof domain !== 'string' || domain.length === 0)
        throw new TypeError('ZK range domain is required');
    const valBase = ristretto255.Point.BASE.toBytes();
    const randBase = ristretto255_hasher.hashToCurve(TEXT_ENCODER.encode(`${domain}:randomness-base`)).toBytes();
    if (Buffer.from(valBase).equals(Buffer.from(randBase)))
        throw new Error('ZK range bases unexpectedly collide');
    return { valBase, randBase };
}
/** Lazy-load the audited/pinned optional Bulletproof WASM binding. */
export async function loadBulletproofBackend() {
    try {
        // Keep the backend genuinely optional at bundle time. Server deployments
        // that enable ZK install the pinned module explicitly; default Gate builds
        // must not fail or pull the WASM/mobile distribution into every route.
        return await import(/* webpackIgnore: true */ ZK_RANGE_BACKEND_MODULE);
    }
    catch {
        throw new Error(`ZK range backend unavailable; install ${ZK_RANGE_BACKEND_PACKAGE} explicitly before enabling this path`);
    }
}
function requireBackend(backend) {
    if (!backend || typeof backend.batchRangeProof !== 'function' || typeof backend.batchVerifyProof !== 'function') {
        throw new TypeError('ZK range backend must implement batchRangeProof() and batchVerifyProof()');
    }
    return backend;
}
function linkedSecondCommitment(max, first, valBase) {
    const valueBase = ristretto255.Point.fromBytes(valBase);
    const firstPoint = ristretto255.Point.fromBytes(first);
    return valueBase.multiply(BigInt(max)).subtract(firstPoint).toBytes();
}
function equalBytes(left, right) {
    return left.length === right.length && Buffer.from(left).equals(Buffer.from(right));
}
function publicStatement({ policyHash, actionPredicate, max, baseReceiptDigest, issuerPublicKey, numBits }) {
    return {
        policy_hash: digest(policyHash, 'policy_hash'),
        action_predicate: actionPredicate,
        max,
        base_receipt_digest: digest(baseReceiptDigest, 'base_receipt_digest'),
        issuer_public_key: issuerPublicKey,
        num_bits: numBits,
    };
}
/**
 * Mint a hidden-amount Bulletproof range receipt.
 * @param {{ value?: any, max?: any, blindingFactor?: any, policyHash?: any, actionPredicate?: any, baseReceiptDigest?: any, issuerPublicKey?: any, nonce?: string, domain?: string, backend?: any }} [options]
 */
export async function mintZkRangeReceipt({ value, max, blindingFactor = randomBytes(32), policyHash, actionPredicate, baseReceiptDigest, issuerPublicKey, nonce = randomBytes(16).toString('base64url'), domain = ZK_RANGE_RECEIPT_VERSION, backend = null, } = {}) {
    const hiddenValue = safeU64(value, 'value');
    const upperBound = safeU64(max, 'max');
    if (hiddenValue > upperBound)
        throw new TypeError('value exceeds the public range bound');
    if (typeof actionPredicate !== 'string' || actionPredicate.length === 0)
        throw new TypeError('actionPredicate is required');
    if (typeof issuerPublicKey !== 'string' || issuerPublicKey.length === 0)
        throw new TypeError('issuerPublicKey is required');
    const normalizedBlinding = bytes(blindingFactor, 'blindingFactor', 32);
    const numBits = rangeBits(upperBound);
    const bases = deriveZkRangeBases(domain);
    const engine = requireBackend(backend || await loadBulletproofBackend());
    const result = await engine.batchRangeProof({
        v: [BigInt(hiddenValue), BigInt(upperBound - hiddenValue)],
        rs: [normalizedBlinding, negateScalar(normalizedBlinding)],
        valBase: bases.valBase,
        randBase: bases.randBase,
        numBits,
    });
    if (!result || !(result.proof instanceof Uint8Array) || !Array.isArray(result.comms) || result.comms.length !== 2)
        throw new Error('ZK range backend returned a malformed proof');
    const first = bytes(result.comms[0], 'first commitment', 32);
    const second = bytes(result.comms[1], 'second commitment', 32);
    if (!equalBytes(second, linkedSecondCommitment(upperBound, first, bases.valBase)))
        throw new Error('ZK range backend returned unlinked commitments');
    const statement = publicStatement({ policyHash, actionPredicate, max: upperBound, baseReceiptDigest, issuerPublicKey, numBits });
    const commitments = envelopeCommitments([first, second]);
    const envelope = {
        '@version': ZK_RANGE_RECEIPT_VERSION,
        scheme: ZK_RANGE_SCHEME,
        domain,
        nonce,
        statement,
        commitments,
        proof: b64(result.proof),
        binding: `sha256:${sha256Hex(canonicalize({ statement, commitments, nonce, domain }))}`,
    };
    return envelope;
}
function envelopeCommitments(commitments) {
    return commitments.map((value) => b64(value));
}
/** Verify the range proof and its public commitment relation. */
export async function verifyZkRangeReceipt(receipt, { backend = null } = {}) {
    try {
        if (!receipt || receipt['@version'] !== ZK_RANGE_RECEIPT_VERSION || receipt.scheme !== ZK_RANGE_SCHEME)
            return { ok: false, reason: 'malformed_zk_range_receipt' };
        const statement = receipt.statement;
        const max = safeU64(statement?.max, 'statement.max');
        const numBits = rangeBits(max);
        if (statement.num_bits !== numBits)
            return { ok: false, reason: 'range_bits_mismatch' };
        publicStatement({
            policyHash: statement.policy_hash,
            actionPredicate: statement.action_predicate,
            baseReceiptDigest: statement.base_receipt_digest,
            issuerPublicKey: statement.issuer_public_key,
            max,
            numBits,
        });
        const bases = deriveZkRangeBases(receipt.domain);
        const commitments = receipt.commitments?.map((value) => bytes(Buffer.from(value, 'base64url'), 'commitment', 32));
        if (!Array.isArray(commitments) || commitments.length !== 2)
            return { ok: false, reason: 'commitments_malformed' };
        if (!equalBytes(commitments[1], linkedSecondCommitment(max, commitments[0], bases.valBase)))
            return { ok: false, reason: 'commitment_relation_invalid' };
        const expectedBinding = `sha256:${sha256Hex(canonicalize({ statement, commitments: envelopeCommitments(commitments), nonce: receipt.nonce, domain: receipt.domain }))}`;
        if (expectedBinding !== receipt.binding)
            return { ok: false, reason: 'zk_binding_invalid' };
        const engine = requireBackend(backend || await loadBulletproofBackend());
        const valid = await engine.batchVerifyProof({
            proof: bytes(Buffer.from(receipt.proof || '', 'base64url'), 'proof'),
            comms: commitments,
            valBase: bases.valBase,
            randBase: bases.randBase,
            numBits,
        });
        return valid === true
            ? { ok: true, scheme: ZK_RANGE_SCHEME, statement }
            : { ok: false, reason: 'zk_range_proof_invalid' };
    }
    catch (error) {
        return { ok: false, reason: 'zk_range_receipt_invalid', detail: (error instanceof Error && error.message) || 'invalid proof' };
    }
}
export default {
    ZK_RANGE_RECEIPT_VERSION,
    ZK_RANGE_SCHEME,
    ZK_RANGE_BACKEND_PACKAGE,
    deriveZkRangeBases,
    loadBulletproofBackend,
    mintZkRangeReceipt,
    verifyZkRangeReceipt,
};
//# sourceMappingURL=zk-range-proof.js.map