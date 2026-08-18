/**
 * The RELYING-PARTY half of the hybrid receipt spine: offline verification of
 * EP-RECEIPT-HYBRID-v1 receipts and of EP-LOG-CHECKPOINT-HYBRID-v1 checkpoint
 * proofs, using only @emilia-protocol/verify.
 *
 * WHY THIS FILE EXISTS. EP-RECEIPT-HYBRID-v1 was issuable before it was
 * verifiable by the published verifier. packages/issue/src/hybrid-issuance.ts
 * mints the receipt and carries a verifier next to the minting code, but
 * @emilia-protocol/verify -- the package a relying party actually installs to
 * check an EP artifact offline, with no issuer code and no EP backend -- had no
 * entry point for it. A portable artifact that only its issuer's package can
 * check is not portable. This module closes that gap. It is a SECOND
 * implementation only in the sense that it lives in the verifying package; the
 * signature math, the closed algorithm registry, the curve pin, the exact
 * length pins, and the "no ML-DSA backend is a refusal" rule are NOT
 * reimplemented here -- every one of them is EP-SIG-AGILITY-v1's
 * (./pq-signature-agility.js), reached through verifyAgileSignatureSet.
 *
 * BYTE COMPATIBILITY IS THE CONTRACT. hybridReceiptSignedBytes() below must
 * produce bytes identical to hybridSignedBytes() in
 * packages/issue/src/hybrid-issuance.ts, or a receipt this repository issues
 * would not verify with the verifier this repository publishes. Both sides
 * build the SAME object over the SAME canonicalization
 * (canonicalizeStrictJson, the single JCS-equivalent source of truth both
 * packages import), and the cross-package test asserts the bytes are equal
 * rather than assuming it.
 *
 * --- THE FIVE MOVES (docs/protocol/pq-hybrid-program.md) --------------------
 *
 * 1. VERSION MARKER, NOT A FIELD. EP-RECEIPT-v1's verifyReceipt() in ./index.ts
 *    is untouched and stays SYNCHRONOUS. Handed a hybrid receipt it refuses on
 *    the version marker -- `Unsupported version: EP-RECEIPT-HYBRID-v1` -- before
 *    inspecting any signature, and it does not throw. That is the required
 *    outcome for a deployed v1 verifier: never accept a hybrid receipt on the
 *    strength of the one leg it happens to understand.
 *
 * 2. SET SHAPE. `signatures` is an array of EP-SIG-AGILITY-v1 AgileSignature
 *    objects ({ alg, sig, key_id? }), one per registered algorithm, in the
 *    registered order. Ed25519 verifies under a base64url SPKI DER public key;
 *    ML-DSA-65 under raw base64url public key bytes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes. Delete the ML-DSA leg and narrow `profile.required_algorithms` to
 *    ["Ed25519"] and the surviving Ed25519 signature no longer verifies,
 *    because the bytes changed. Leave the set intact and the missing leg is a
 *    structural refusal. The verifier rebuilds the bytes from the REGISTERED
 *    set and from `doc.payload`; the presented document never chooses what it
 *    is checked against.
 *
 * 4. SEPARATE ASYNC ENTRY POINT. ML-DSA verification is asynchronous, so
 *    verifyHybridReceipt() is its own async function rather than a signature
 *    change to verifyReceipt(). verifyReceiptOfAnyProfile() routes a mixed bag
 *    on the version marker for callers that hold both.
 *
 * 5. NAMED REFUSALS. Every failure returns a named reason; nothing throws on
 *    caller input. An absent ML-DSA backend is `pq_backend_unavailable`, never
 *    a skipped check and never a pass on the classical leg.
 *
 * --- HONEST BOUNDARIES ------------------------------------------------------
 *   - OPT-IN. EP-RECEIPT-v1 remains the receipt format EP issues by default.
 *     Nothing here is on in any deployment.
 *   - The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 *     implementation: not independently audited, not a FIPS validated module.
 *     Verifying under this profile is not a certification claim.
 *   - VERIFIED is not ACCEPTED. A true verdict says both signatures check out
 *     over the receipt's own bytes under the keys the CALLER pinned. Whether
 *     those keys are trusted is the relying party's separate decision.
 *   - Merkle anchoring is out of scope for the hybrid receipt profile, exactly
 *     as the issuance module records: an EP-MERKLE-v2 anchor self-checks its
 *     leaf against `doc.payload`, which is not what a hybrid receipt commits
 *     to. An `anchor` member on a hybrid receipt is therefore refused rather
 *     than half-checked.
 *   - Neither profile retroactively protects an artifact already issued under
 *     a single algorithm.
 */
import crypto from 'node:crypto';
import { type AgilityOptions, type AgileSetResult } from './pq-signature-agility.js';
type AnyRecord = Record<string, any>;
/** The profile id, used as both `@version` and `profile.id`. */
export declare const HYBRID_RECEIPT_PROFILE = "EP-RECEIPT-HYBRID-v1";
/**
 * The registered required algorithm set, in canonical order. This exact array
 * goes into the signed bytes, so its contents AND order are part of what every
 * leg commits to. It is duplicated from packages/issue deliberately: the
 * verifying package must not need the issuing package installed to know what
 * it requires, and the cross-package test pins the two to be equal.
 */
export declare const HYBRID_RECEIPT_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** Named refusals. Every failure path returns one of these; none throw. */
export declare const HYBRID_RECEIPT_REASONS: Readonly<{
    MALFORMED_RECEIPT: "malformed_receipt";
    MALFORMED_PAYLOAD: "malformed_payload";
    UNKNOWN_PROFILE: "unknown_profile";
    ALGORITHM_SET_MISMATCH: "algorithm_set_mismatch";
    HYBRID_LEG_MISSING: "hybrid_leg_missing";
    UNEXPECTED_ALGORITHM: "unexpected_algorithm";
    DUPLICATE_ALGORITHM: "duplicate_algorithm";
    UNSUPPORTED_ANCHOR: "unsupported_anchor";
    MISSING_KEY: "missing_key";
    SIGNATURE_INVALID: "signature_invalid";
    PQ_BACKEND_UNAVAILABLE: "pq_backend_unavailable";
}>;
export interface HybridReceiptSignature {
    alg: string;
    sig: string;
    key_id?: string;
}
export interface HybridReceiptDocument {
    '@version': string;
    profile: {
        id: string;
        required_algorithms: string[];
    };
    payload: AnyRecord;
    signatures: HybridReceiptSignature[];
    metadata?: AnyRecord;
}
/** The public halves a relying party PINS to check a hybrid receipt. */
export interface HybridReceiptVerificationKeys {
    /** Ed25519: base64url SPKI DER, or a node crypto public KeyObject. */
    ed25519PublicKey: string | crypto.KeyObject | Uint8Array;
    ed25519KeyId?: string;
    /** ML-DSA-65: base64url of the raw 1952-byte public key, or the raw bytes. */
    mldsaPublicKey: string | Uint8Array;
    mldsaKeyId?: string;
}
export interface HybridReceiptChecks {
    profile: boolean;
    algorithm_set: boolean | null;
    legs_present: boolean | null;
    signatures_valid: boolean | null;
}
export interface HybridReceiptVerifyResult {
    verified: boolean;
    reason: string | null;
    /** Which algorithm's leg failed, when the failure is attributable to one. */
    failed_algorithm: string | null;
    checks: HybridReceiptChecks;
    /** The raw EP-SIG-AGILITY-v1 set result, when the set verifier ran. */
    set_result: AgileSetResult | null;
}
/**
 * Build the exact object both legs sign. The required algorithm set and the
 * profile id are INSIDE it: that is the anti-stripping commitment.
 *
 * BYTE-IDENTICAL by contract to hybridSignedMaterial() in
 * packages/issue/src/hybrid-issuance.ts. Exported so a conformance vector or an
 * independent implementation can rebuild the bytes without reading either
 * module's internals.
 *
 * @throws if the payload is outside the EP canonicalization profile, or if the
 *   algorithm set is not the registered one. Issuer-side and vector-side misuse
 *   is a programming error; verifyHybridReceipt() catches this and turns it
 *   into a named refusal, so caller input never reaches a throw.
 */
export declare function hybridReceiptSignedMaterial(payload: AnyRecord, requiredAlgorithms?: readonly string[]): AnyRecord;
/** UTF-8 canonical bytes of hybridReceiptSignedMaterial(). What every leg signs. */
export declare function hybridReceiptSignedBytes(payload: AnyRecord, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Verify an EP-RECEIPT-HYBRID-v1 receipt offline against PINNED keys.
 * FAIL-CLOSED: every malformed, unknown, or stripped input returns a named
 * refusal; nothing throws on caller input.
 *
 * Order of checks, and why:
 *   1. Structure and profile marker. An unknown `@version` or `profile.id`
 *      refuses with `unknown_profile`; this is not a general receipt verifier
 *      and never guesses at another format. The member set is CLOSED, so an
 *      unsigned member cannot ride along unnoticed.
 *   2. `profile.required_algorithms` must EXACTLY equal the registered set,
 *      order included. A narrowed set is the stripping attack's cover story, so
 *      it is refused structurally, before the (also failing) signature check.
 *   3. Exactly one signature per required algorithm: a missing leg is
 *      `hybrid_leg_missing`, an extra one `unexpected_algorithm`, a repeat
 *      `duplicate_algorithm`.
 *   4. The bytes are rebuilt from `doc.payload` and the REGISTERED set, then
 *      handed to EP-SIG-AGILITY-v1's verifyAgileSignatureSet under policy
 *      `hybrid_all` with requiredAlgorithms pinned to the FULL set. Every leg
 *      must verify over identical bytes. Verification uses the keys the CALLER
 *      pinned, never key material carried by the document.
 *
 * ON `key_id`, PRECISELY. Keys are selected by ALGORITHM, not by the `key_id` a
 * signature carries. A signature's `key_id` is a label the set verifier reports
 * back and never uses to choose a key, so a document claiming some other
 * `key_id` still verifies under the pinned key of its declared algorithm, and a
 * document claiming the RIGHT `key_id` gains nothing by it. Treat `key_id` as a
 * routing hint for finding which pin to load, never as evidence about which key
 * signed.
 */
export declare function verifyHybridReceipt(doc: unknown, keys: HybridReceiptVerificationKeys | null | undefined, options?: AgilityOptions): Promise<HybridReceiptVerifyResult>;
export interface ReceiptProfileRouteResult {
    /** Which profile the document declared, or null when it declared neither. */
    profile: string | null;
    valid: boolean;
    /** Present for both profiles; the member names differ per profile. */
    checks: AnyRecord;
    /** The named refusal reason (hybrid profile) or null. */
    reason: string | null;
    /** The human-readable error string (v1 profile) or null. */
    error: string | null;
}
/**
 * Route a receipt of EITHER profile to its verifier, for a caller holding a
 * mixed bag. EP-RECEIPT-v1 documents get the EXACT v1 verdict from the
 * unchanged synchronous verifyReceipt(); EP-RECEIPT-HYBRID-v1 documents get the
 * hybrid check. A document declaring neither refuses with `unknown_profile`,
 * which is the fail-closed answer.
 *
 * `keys` carries whichever material the presented profile needs: a v1 receipt
 * needs `ed25519PublicKey` as base64url SPKI DER, a hybrid receipt needs both
 * halves. A caller that supplies only one and is handed the other profile gets
 * a refusal, never a pass.
 *
 * verifyReceipt is imported LAZILY. ./index.ts re-exports this module, so a
 * static import here would be a cycle through the package's largest module for
 * every consumer of the hybrid verifier.
 */
export declare function verifyReceiptOfAnyProfile(doc: unknown, keys: Partial<HybridReceiptVerificationKeys> | null | undefined, options?: AgilityOptions & {
    allowLegacyMerkle?: boolean;
}): Promise<ReceiptProfileRouteResult>;
/**
 * The hybrid leg of EP-AUTHORIZATION-RECEIPT-v1, as a DETACHED proof over the
 * log checkpoint.
 *
 * WHY THE CHECKPOINT AND NOT THE WHOLE RECEIPT. An authorization receipt
 * carries two kinds of signature and EP controls only one of them:
 *
 *   - Approver signoffs. Class A is a WebAuthn assertion from a FIDO2
 *     authenticator or platform passkey (ES256, P-256). EP does not decide what
 *     that device signs or with which algorithm. Two DIFFERENT things are
 *     gated here, and they are not gated on the same parties:
 *       * A POST-QUANTUM Class A signoff is gated on the ecosystem, on three
 *         dated, checkable components: the FIDO Registry of Predefined Values
 *         v2.3 defines no ALG_SIGN constant for ML-DSA, so a certified
 *         authenticator cannot declare the capability; CTAP 2.3 carries no PQC
 *         text; and W3C WebAuthn PR 2437 (single-algorithm ML-DSA credentials)
 *         is open and unmerged. Until those move, no device emits a PQ
 *         assertion for EP to verify. Note what is NOT on that list: the
 *         relying-party VERIFICATION half is EP's own code, and it is done:
 *         verifyWebAuthnSignoff dispatches on the enrolled key's algorithm and
 *         verifies ML-DSA-65 through EP-SIG-AGILITY-v1 today.
 *       * A HYBRID Class A signoff is an EP DESIGN DECISION, not a FIDO
 *         dependency. Neither live W3C proposal specifies a hybrid assertion;
 *         both deliver single-algorithm PQ credentials and leave hybrid to the
 *         relying party. So hybrid at this layer means two enrolled
 *         credentials per approver and a policy requiring a signoff from each
 *         implemented as EP-QUORUM-v1 policy.required_algorithms, default
 *         off. Waiting for FIDO to hand EP a hybrid assertion would be waiting
 *         for something nobody is building.
 *     Class B/C signoffs are made with the APPROVER's own key, whose custody
 *     EP likewise does not hold.
 *   - The log checkpoint signature. This one IS EP's: the log operator signs
 *     `{tree_size, root_hash, log_key_id, merkle_alg}` with a key it holds, and
 *     it is the commitment that makes the receipt's inclusion checkable at all.
 *
 * So this profile hybridizes the leg EP can honestly hybridize, and says
 * plainly that it does not hybridize the other. It is a DETACHED proof, exactly
 * like EP-COMMIT-HYBRID-v1 (lib/commit-hybrid.ts): the receipt itself keeps its
 * frozen EP-AUTHORIZATION-RECEIPT-v1 shape byte for byte, no consumer has to
 * move, and no schema changes.
 *
 * WHAT A TRUE VERDICT MEANS, EXACTLY. Both legs signed the SAME checkpoint the
 * verifier independently recomputed from the receipt it holds. It does NOT mean
 * the receipt's approver signoffs are post-quantum protected (they are not), and
 * it does NOT establish inclusion on its own: the inclusion path still has to be
 * checked against `root_hash`, which is verifyTrustReceipt's job and stays
 * unchanged. This proof says the pinned log operator committed to that root
 * under both algorithms.
 *
 * THE PIN IS THE RELYING PARTY'S. The receipt remains a valid v1 artifact, so a
 * verifier that never asks for the proof gets a v1 verdict. Requiring the PQ leg
 * is a relying-party decision expressed by calling this function; the profile
 * makes the pin available and refuses without it, and cannot make a verifier
 * that never asks.
 */
export declare const LOG_CHECKPOINT_HYBRID_PROFILE = "EP-LOG-CHECKPOINT-HYBRID-v1";
/** The registered required algorithm set, in canonical order. */
export declare const LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export declare const LOG_CHECKPOINT_HYBRID_REASONS: Readonly<{
    MALFORMED_PROOF: "malformed_proof";
    MALFORMED_CHECKPOINT: "malformed_checkpoint";
    UNKNOWN_PROFILE: "unknown_profile";
    ALGORITHM_SET_MISMATCH: "algorithm_set_mismatch";
    CHECKPOINT_MISMATCH: "checkpoint_mismatch";
    UNSUPPORTED_MERKLE_ALG: "unsupported_merkle_alg";
    HYBRID_LEG_MISSING: "hybrid_leg_missing";
    UNEXPECTED_ALGORITHM: "unexpected_algorithm";
    DUPLICATE_ALGORITHM: "duplicate_algorithm";
    MISSING_KEY: "missing_key";
    SIGNATURE_INVALID: "signature_invalid";
    PQ_BACKEND_UNAVAILABLE: "pq_backend_unavailable";
}>;
/** The Merkle algorithm this profile accepts. */
export declare const LOG_CHECKPOINT_HYBRID_MERKLE_ALG = "EP-MERKLE-v2";
export interface LogCheckpointHybridProof {
    '@version': string;
    profile: {
        id: string;
        required_algorithms: string[];
    };
    checkpoint: AnyRecord;
    signatures: HybridReceiptSignature[];
}
export interface LogCheckpointHybridChecks {
    profile: boolean;
    algorithm_set: boolean | null;
    checkpoint_bound: boolean | null;
    legs_present: boolean | null;
    signatures_valid: boolean | null;
}
export interface LogCheckpointHybridVerifyResult {
    verified: boolean;
    reason: string | null;
    failed_algorithm: string | null;
    checks: LogCheckpointHybridChecks;
    set_result: AgileSetResult | null;
}
/**
 * Normalize a checkpoint to exactly the members this profile signs, dropping
 * `log_signature` if present so a caller can pass `receipt.log_proof.checkpoint`
 * verbatim. Returns null when the checkpoint is not shaped for this profile, so
 * every caller path is a named refusal rather than a throw.
 */
export declare function logCheckpointSignedFields(checkpoint: unknown): AnyRecord | null;
/**
 * Build the exact object both legs sign for a checkpoint. The required
 * algorithm set and the profile id are INSIDE it: the same anti-stripping
 * commitment EP-RECEIPT-HYBRID-v1 uses.
 *
 * @throws on a checkpoint outside the profile, or an algorithm set that is not
 *   the registered one. Verification catches this and refuses by name.
 */
export declare function logCheckpointHybridSignedMaterial(checkpoint: unknown, requiredAlgorithms?: readonly string[]): AnyRecord;
/** UTF-8 canonical bytes of logCheckpointHybridSignedMaterial(). */
export declare function logCheckpointHybridSignedBytes(checkpoint: unknown, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Verify an EP-LOG-CHECKPOINT-HYBRID-v1 proof against the checkpoint the
 * VERIFIER independently holds (normally `receipt.log_proof.checkpoint`).
 * FAIL-CLOSED; never throws on caller input.
 *
 * The proof's own `checkpoint` member is checked for byte equality against the
 * held one before any signature is examined (`checkpoint_mismatch`): a proof for
 * some other log head never speaks for this receipt. The signed bytes are then
 * rebuilt from the HELD checkpoint and the REGISTERED algorithm set.
 */
export declare function verifyLogCheckpointHybridProof(heldCheckpoint: unknown, proof: unknown, keys: HybridReceiptVerificationKeys | null | undefined, options?: AgilityOptions): Promise<LogCheckpointHybridVerifyResult>;
export {};
//# sourceMappingURL=receipt-hybrid.d.ts.map