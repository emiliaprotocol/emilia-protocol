/**
 * MEMORY-PROJECTION-RECORD-v1.
 *
 * Provider-neutral producer and verifier for
 * draft-ferro-schrock-memory-projection-record-00.
 *
 * The envelope verifier proves the closed record shape, adapter signature,
 * key status, freshness, and nonclaims. The full verifier additionally
 * rehashes the exact request, policy, trust snapshot, source objects,
 * fragments, and complete projection bytes, and delegates native source
 * verification to the source-profile implementation selected by the relying
 * party.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
export declare const MEMORY_PROJECTION_RECORD_VERSION = "MEMORY-PROJECTION-RECORD-v1";
export declare const MEMORY_PROJECTION_RECORD_DOMAIN = "MEMORY-PROJECTION-RECORD-v1\0";
export declare const MEMORY_PROJECTION_NONCLAIMS: Readonly<{
    model_use: "NOT_ESTABLISHED";
    action_linkage: "NOT_ESTABLISHED";
    action_authorization: "NOT_ESTABLISHED";
    execution_outcome: "NOT_ESTABLISHED";
}>;
export type MemoryProjectionTrust = 'self' | 'trusted' | 'unverified';
export type MemoryProjectionAuthorship = 'signed' | 'attested' | 'unknown';
export interface MemoryProjectionAdapterKey {
    public_key_spki_b64u: string;
    status: 'active' | 'revoked' | 'superseded';
    valid_from: string;
    valid_to: string;
    revoked_at: string | null;
}
export interface MemoryProjectionDeliveredInput {
    formatVersion: number;
    sealedObjectBytes: Uint8Array;
    contextFragmentBytes: Uint8Array;
    derivedTrust: MemoryProjectionTrust;
    authorship: MemoryProjectionAuthorship;
    authorKeyIdB64u: string | null;
    custodyPresent: boolean;
}
export interface MemoryProjectionProducerInput {
    sourceProfile: string;
    projectionId: string;
    createdAt: string;
    adapter: {
        id: string;
        keyId: string;
    };
    selectionContext: {
        recallRequestBytes: Uint8Array;
        selectionPolicyBytes: Uint8Array;
        trustSnapshotBytes: Uint8Array;
        trustEvaluatedAt: string;
        contextFrameProfile: string;
    };
    delivered: MemoryProjectionDeliveredInput[];
    exclusions: {
        authenticationFailed: number;
        schemaInvalid: number;
        policyFiltered: number;
        contextLimit: number;
    };
    privateKey: crypto.KeyLike;
}
export interface MemoryProjectionVerificationPolicy {
    adapterKeys: Record<string, MemoryProjectionAdapterKey>;
    verificationTime: string;
    maxProjectionAgeSec: number;
    maxTrustAgeSec: number;
    expectedSourceProfile?: string;
    expectedContextFrameProfile?: string;
}
export interface MemoryProjectionNativeSourceResult {
    valid: true;
    formatVersion: number;
    sealedObjectDigest: string;
    derivedTrust: MemoryProjectionTrust;
    authorship: MemoryProjectionAuthorship;
    authorKeyIdB64u: string | null;
    custodyPresent: boolean;
}
export interface MemoryProjectionVerificationMaterial {
    recallRequestBytes: Uint8Array;
    selectionPolicyBytes: Uint8Array;
    trustSnapshotBytes: Uint8Array;
    sourceObjectBytesByPosition: Uint8Array[];
    fragmentBytesByPosition: Uint8Array[];
    projectionBytes: Uint8Array;
    verifySourceEntry: (input: {
        sourceProfile: string;
        position: number;
        sourceObjectBytes: Uint8Array;
        deliveredEntry: Readonly<Obj>;
    }) => MemoryProjectionNativeSourceResult;
}
export interface MemoryProjectionIdRegistry {
    /**
     * Atomically register one projection identifier.
     * Return false when it was already registered.
     */
    register(projectionId: string): boolean;
}
export declare class MemoryProjectionVerificationError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}
/**
 * Verify the closed signed envelope without requiring plaintext memory,
 * request, policy, trust-snapshot, fragment, or projection bytes.
 *
 * This is the correct boundary for a downstream Gate that receives only the
 * adapter's signed commitments. It does not claim those commitment preimages
 * were independently rehashed.
 */
export declare function verifyMemoryProjectionRecordV1Envelope(record: unknown, policy: MemoryProjectionVerificationPolicy): {
    valid: true;
    verification_scope: 'SIGNED_ENVELOPE_ONLY';
    projection_id: string;
    projection_digest: string;
    delivered_count: number;
    excluded_count: number;
    created_at: string;
    trust_evaluated_at: string;
};
/**
 * Fully verify every commitment preimage and native source result.
 */
export declare function verifyMemoryProjectionRecordV1(record: unknown, material: MemoryProjectionVerificationMaterial, policy: MemoryProjectionVerificationPolicy, options?: {
    projectionIdRegistry?: MemoryProjectionIdRegistry;
    requireSingleUse?: boolean;
}): {
    valid: true;
    verification_scope: 'FULL_PROJECTION_AND_NATIVE_SOURCE_RESULTS';
    projection_id: string;
    projection_digest: string;
    delivered_count: number;
    excluded_count: number;
};
/**
 * Construct and sign one v1 record from exact source and projection bytes.
 */
export declare function createMemoryProjectionRecordV1(input: MemoryProjectionProducerInput): {
    record: Obj;
    verificationMaterial: Omit<MemoryProjectionVerificationMaterial, 'verifySourceEntry'>;
};
export declare function memoryProjectionRecordDigest(record: unknown): string;
declare const _default: Readonly<{
    MEMORY_PROJECTION_RECORD_VERSION: "MEMORY-PROJECTION-RECORD-v1";
    MEMORY_PROJECTION_RECORD_DOMAIN: "MEMORY-PROJECTION-RECORD-v1\0";
    createMemoryProjectionRecordV1: typeof createMemoryProjectionRecordV1;
    verifyMemoryProjectionRecordV1Envelope: typeof verifyMemoryProjectionRecordV1Envelope;
    verifyMemoryProjectionRecordV1: typeof verifyMemoryProjectionRecordV1;
    memoryProjectionRecordDigest: typeof memoryProjectionRecordDigest;
}>;
export default _default;
/**
 * THE WIRE ABOVE IS NOT EP'S TO BUMP, AND IS NOT BUMPED HERE.
 *
 * MEMORY-PROJECTION-RECORD-v1 is the wire format of
 * draft-ferro-schrock-memory-projection-record-00, co-authored with Andrea
 * Ferro. Everything above this line is byte-for-byte unchanged: the closed
 * record shape, the `proof: { alg, key_id, signature_b64u }` object, the
 * `alg: 'Ed25519'` pin, `MEMORY_PROJECTION_RECORD_DOMAIN`, the producer, and
 * both verifiers. No `@version` was bumped and no member was added, because a
 * unilateral change to a co-authored wire is not a migration, it is a fork.
 *
 * WHAT A -01 OF THE JOINT DRAFT WOULD NEED, precisely, for a real in-record
 * hybrid migration (this is the ask to take to the co-author, not something
 * this file can decide):
 *
 *   a. `proof` becomes SET-SHAPED: `{ required_algorithms: [...],
 *      signatures: [{ alg, sig, key_id }] }`. That changes the closed proof
 *      key set, so it is a wire-format change.
 *   b. The draft needs a REGISTERED value for the post-quantum `proof.alg`.
 *      The draft today admits only `Ed25519`. This repository can trace exactly
 *      one ML-DSA-65 algorithm identifier, and it is the COSE one (-49, RFC
 *      9964, see packages/verify/src/aeb-mcgraw-delegation-adapter.ts); there
 *      is no JSON/JOSE-side identifier here to reuse, so the draft must name
 *      its own or normatively reference one.
 *   c. `required_algorithms` must be a SIGNED top-level record member (inside
 *      the JCS boundary that `signingBytes` covers), not a member of `proof`,
 *      or the set is not committed and leg-stripping is only detected by
 *      relying-party policy.
 *   d. `@version` becomes `MEMORY-PROJECTION-RECORD-v2`, because (a) and (c)
 *      change the shape, and the v1 verifier must refuse a v2 record on the
 *      version marker.
 *   e. `apertomemory-context.ts` moves in lockstep: it re-checks
 *      `record.proof.alg !== 'Ed25519'` and the 64-byte signature length
 *      independently of this module.
 *
 * WHAT THIS SECTION IS INSTEAD. A purely ADDITIVE, EP-owned, DETACHED
 * co-signature. It travels beside a v1 record, never inside it. A producer that
 * emits one is still emitting an ordinary v1 record that every existing
 * ApertoMemory and EP verifier accepts unchanged; a verifier that ignores it
 * loses nothing it had.
 *
 * THE HONEST LIMIT, stated before the API rather than after it. The v1 record's
 * own signed bytes do not commit to any algorithm set, and this co-signature
 * cannot retroactively make them. So:
 *   - A relying party that requires the co-signature gets a real hybrid
 *     guarantee over the exact record bytes, because both legs sign a
 *     commitment to those bytes AND to the required set.
 *   - A relying party that does NOT ask for it sees a valid v1 record and has
 *     gained nothing. Requiring the PQ leg here is a PIN, not a property of the
 *     artifact. This profile makes the pin available; it cannot make a verifier
 *     that never asks for it.
 *   - This is the same shape and the same limit as EP-COMMIT-HYBRID-v1
 *     (lib/commit-hybrid.ts), and it is stated the same way on purpose.
 *
 * Opt-in. Not deployed, default, or certified anywhere.
 */
export declare const MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION = "EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1";
export declare const MEMORY_PROJECTION_PQ_COSIGNATURE_DOMAIN = "EP-MEMORY-PROJECTION-PQ-COSIGNATURE-v1\0";
/** The registered required algorithm set, in canonical order. */
export declare const MEMORY_PROJECTION_PQ_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface MemoryProjectionPqCosignatureBody {
    '@version': typeof MEMORY_PROJECTION_PQ_COSIGNATURE_VERSION;
    record_version: typeof MEMORY_PROJECTION_RECORD_VERSION;
    projection_id: string;
    /** sha256 over the EXACT bytes the v1 record's own Ed25519 proof covers. */
    record_signing_bytes_sha256: string;
    /** The exact v1 `proof.signature_b64u` this co-signature is bound to. */
    record_proof_signature_b64u: string;
}
export interface MemoryProjectionPqCosignature extends MemoryProjectionPqCosignatureBody {
    proof: {
        profile: string;
        required_algorithms: string[];
        key_id: string;
        /** Ed25519 base64url SPKI DER. */
        public_key: string;
        pq_key_id: string;
        /** ML-DSA-65 base64url raw 1952-byte public key. */
        pq_public_key: string;
        signatures: Array<{
            alg: string;
            sig: string;
            key_id?: string;
        }>;
    };
}
export interface MemoryProjectionPqCosignaturePin {
    key_id: string;
    public_key: string;
    pq_key_id: string;
    pq_public_key: string;
}
export interface MemoryProjectionPqCosignatureSigner {
    key_id: string;
    private_key: crypto.KeyObject;
    public_key: string;
    pq_key_id: string;
    pq_secret_key: Uint8Array | string;
    pq_public_key: string;
}
export interface MemoryProjectionPqCosignatureResult {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
}
/**
 * The bytes BOTH legs sign: the domain tag, the co-signature body, and the
 * REGISTERED algorithm set. The verifier rebuilds these from the body it
 * re-derived and the REGISTERED set, never from what the co-signature claims.
 */
export declare function memoryProjectionPqCosignatureSigningBytes(body: MemoryProjectionPqCosignatureBody, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Derive the co-signature body from an UNCHANGED v1 record. Throws a
 * MemoryProjectionVerificationError if the record is not a valid v1 record --
 * a co-signature is never minted over something that is not one.
 */
export declare function memoryProjectionPqCosignatureBody(record: unknown): MemoryProjectionPqCosignatureBody;
/**
 * Sign a detached hybrid co-signature over an unchanged v1 record. Issuer-side
 * misuse throws; an unavailable ML-DSA backend throws rather than emitting a
 * one-legged co-signature.
 */
export declare function signMemoryProjectionPqCosignature(record: unknown, signer: MemoryProjectionPqCosignatureSigner, options?: AgilityOptions): Promise<MemoryProjectionPqCosignature>;
/**
 * verifyMemoryProjectionPqCosignature -- FAIL-CLOSED. Never throws on caller
 * input. The co-signature is checked AGAINST the record the relying party
 * holds: the body is re-derived from that record, so a co-signature minted over
 * a different record cannot be presented for this one.
 *
 * This does NOT verify the v1 record itself. Run
 * verifyMemoryProjectionRecordV1Envelope (or the full verifier) for that; this
 * is strictly the additional post-quantum leg.
 */
export declare function verifyMemoryProjectionPqCosignature(record: unknown, cosignature: unknown, pin: MemoryProjectionPqCosignaturePin | null | undefined, options?: AgilityOptions): Promise<MemoryProjectionPqCosignatureResult>;
//# sourceMappingURL=memory-projection.d.ts.map