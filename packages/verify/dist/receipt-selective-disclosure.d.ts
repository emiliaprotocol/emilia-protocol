/**
 * EP-SD-v1 — selective-disclosure presentation of EP authorization receipts.
 *
 * A holder presents a receipt to an auditor, insurer, or regulator proving
 * that an authorized approval bound one exact action (CAID intact, receipt
 * signature intact, evidence-grade fields visible) WITHOUT revealing the
 * business content of undisclosed fields.
 *
 * Construction (SD-JWT-style salted-digest disclosure; no new cryptography):
 *
 *   ISSUANCE (disclosure-ready): before signing, each designated-disclosable
 *   field's value in the payload is REPLACED by a salted commitment slot
 *   "ep-sd-commit:sha256:<hex>", and the signed payload carries a
 *   `disclosure` block naming the committed paths. The issuer's Ed25519
 *   signature is computed over the canonical bytes of THAT payload, so the
 *   signed bytes already are the redacted view. The issuer hands the holder
 *   the openings ({path, salt, value}) outside the signed body.
 *
 *   PRESENTATION: the holder forwards the signed receipt UNCHANGED plus any
 *   subset of openings and an audience/nonce binding. No signature is ever
 *   re-created; every presentation reuses the one issuer signature.
 *
 *   VERIFICATION: the verifier (a) verifies the issuer signature over the
 *   receipt exactly as any EP-RECEIPT-v1 verifier does — all signed bytes are
 *   present because undisclosed fields are commitments, not gaps — and
 *   (b) recomputes each disclosed opening's commitment and compares it to the
 *   slot embedded in the signed payload. The commitment binds the field PATH
 *   as well as the salt and value, so an opening cannot be swapped across
 *   fields.
 *
 * REAL CONSTRAINT, stated plainly: an EP-RECEIPT-v1 signature is Ed25519 over
 * the full canonical payload bytes. A verifier therefore needs every signed
 * byte. A receipt whose business fields were signed in PLAINTEXT cannot have
 * those fields hidden later while the signature still verifies — there is no
 * way around this without changing the signature scheme. Selective disclosure
 * under this profile requires DISCLOSURE-READY ISSUANCE (commitments inside
 * the signed body). Already-issued plaintext receipts remain fully verifiable
 * and fully presentable, but only in full; they are not retrofittable into
 * redacted presentations, and this module refuses them with
 * `missing_disclosure_block` rather than pretending otherwise.
 *
 * Honest residuals (see also the staged -01 prose):
 *   - STRUCTURE LEAKAGE: the verifier learns which fields exist and which
 *     were withheld (the signed `disclosure.paths` list is visible).
 *   - LINKABILITY: two presentations of the same receipt share the same
 *     signature bytes and commitment digests and are trivially linkable.
 *     This profile does not claim unlinkability (that is BBS territory).
 *   - GUESSABILITY WITHOUT SALT: a digest over a low-entropy value alone is
 *     an oracle. Salts (>= 128 bits) are therefore mandatory per field, and
 *     an opening without one is refused by construction.
 *   - Audience/nonce binding without a pinned holder key prevents a verifier
 *     from ACCEPTING a presentation bound to someone else's audience/nonce;
 *     it does not prove possession. Pin a holder key (holder_proof) where
 *     possession matters.
 *
 * VERIFIED vs ACCEPTED: every check here is cryptographic verification.
 * Whether the issuer key belongs to a trusted issuer, whether the receipt is
 * current/unrevoked, and whether the disclosure suffices for a reliance
 * purpose are ACCEPTANCE decisions that remain with the relying party.
 *
 * All failures are structured refusals with named reasons; hostile input must
 * never crash the verifier.
 */
import { type KeyObject } from 'node:crypto';
type Obj = Record<string, unknown>;
export declare const EP_SD_VERSION = "EP-SD-v1";
export declare const EP_SD_PRESENTATION_VERSION = "EP-SD-PRESENTATION-v1";
export declare const EP_SD_COMMIT_DOMAIN = "EP-SD-COMMIT-v1";
export declare const EP_SD_BINDING_DOMAIN = "EP-SD-BINDING-v1";
/** Prefix marking a committed (redacted) slot inside a signed payload. */
export declare const EP_SD_COMMIT_MARKER_PREFIX = "ep-sd-commit:";
/** Minimum salt entropy: 128 bits, per-field, mandatory. */
export declare const EP_SD_MIN_SALT_BYTES = 16;
/**
 * The closed non-redactable set. A path equal to, above, or below any of
 * these can never be designated disclosable: hiding the CAID or the
 * evidence-grade fields would turn "this exact action was approved with this
 * evidence" into "something was approved somehow", which is exactly the
 * laundered-authority failure the presentation-binding work exists to refuse.
 */
export declare const NON_REDACTABLE_PATHS: readonly string[];
export interface SdOpening {
    /** Base64url salt decoding to at least EP_SD_MIN_SALT_BYTES bytes. */
    salt: string;
    /** The original field value (strict canonical JSON domain). */
    value: unknown;
}
export type SdOpenings = Record<string, SdOpening>;
export interface SdBinding {
    audience: string;
    nonce: string;
    created_at: string;
}
export interface SdHolderProof {
    /** Holder Ed25519 public key, base64url SPKI DER. */
    public_key: string;
    /** Ed25519 signature over the 32-byte presentation binding digest. */
    signature: string;
}
export interface SdPresentation {
    '@version': typeof EP_SD_PRESENTATION_VERSION;
    /** The signed disclosure-ready receipt document, byte-for-byte unmodified. */
    receipt: Obj;
    /** Disclosed openings, sorted by path, each opening one committed slot. */
    disclosed: Array<{
        path: string;
        salt: string;
        value: unknown;
    }>;
    binding: SdBinding;
    holder_proof?: SdHolderProof;
}
export interface SdRefusal {
    ok: false;
    /** Sorted, de-duplicated named refusal reasons (never empty). */
    refusals: string[];
}
export interface SdPrepareSuccess {
    ok: true;
    /** The disclosure-ready payload to sign (commitment slots + disclosure block). */
    payload: Obj;
    /** Full opening set for the holder. Not part of the signed body. */
    openings: SdOpenings;
}
export interface SdPresentSuccess {
    ok: true;
    presentation: SdPresentation;
}
export interface SdVerifyResult {
    ok: boolean;
    refusals: string[];
    checks: {
        presentation_structure: boolean;
        receipt_signature: boolean;
        disclosure_block: boolean;
        non_redactable_set: boolean;
        commitments: boolean;
        openings: boolean;
        binding: boolean;
        /** null when no holder proof was presented and none was required. */
        holder_proof: boolean | null;
    };
    caid: string | null;
    /** path -> disclosed value; only populated on ok. */
    disclosed: Record<string, unknown> | null;
    /** Committed paths NOT opened in this presentation (structure leakage is explicit). */
    undisclosed_paths: string[];
    decision_scope: {
        establishes: string;
        does_not_establish: string;
    };
}
/**
 * Salted, path-bound, domain-separated commitment over one field value.
 * "sha256:<hex>" over the canonical bytes of the commitment structure. The
 * path inside the committed structure is what defeats swapped-opening attacks.
 */
export declare function sdCommitmentDigest(path: string, salt: string, value: unknown): string;
/**
 * The 32-byte digest a presentation binding commits to: the exact receipt
 * bytes, the exact disclosed set, and the verifier-chosen audience and nonce.
 */
export declare function sdPresentationBindingDigest(receipt: Obj, disclosed: SdPresentation['disclosed'], binding: SdBinding): Buffer;
/**
 * Prepare a payload for disclosure-ready issuance. Runs BEFORE signing: the
 * returned payload (commitment slots + signed `disclosure` block) is what the
 * issuer signs as an ordinary EP-RECEIPT-v1 payload; the returned openings go
 * to the holder outside the signed body. This function never signs and never
 * re-signs.
 *
 * `salts` may pin per-path salts (conformance vectors use fixed seeds);
 * omitted salts are drawn fresh from the CSPRNG. Salt reuse across fields is
 * refused here and again at verification.
 */
export declare function prepareSelectiveDisclosure(payload: unknown, disclosablePaths: readonly string[], salts?: Record<string, string>): SdPrepareSuccess | SdRefusal;
export interface SdHolderKey {
    privateKey: KeyObject;
    publicKeySpkiB64u: string;
}
/**
 * Build a presentation from a signed disclosure-ready receipt: forward the
 * receipt unchanged, attach the chosen subset of openings, and bind the
 * presentation to one audience and nonce. Refuses to stage a presentation
 * whose openings do not match the signed commitments, so a holder cannot
 * accidentally ship a broken or mismatched disclosure.
 */
export declare function createSelectiveDisclosurePresentation(receipt: unknown, openings: SdOpenings, disclosePaths: readonly string[], binding: SdBinding, opts?: {
    holder?: SdHolderKey;
}): SdPresentSuccess | SdRefusal;
export interface SdVerifyExpectation {
    /** The verifier's OWN audience identifier. Required. */
    audience: string;
    /** The verifier's OWN fresh nonce for this exchange. Required. */
    nonce: string;
    /** Paths that must be readable (plaintext or disclosed) for this purpose. */
    requiredPaths?: readonly string[];
    /** Pin a holder key to require and verify possession (holder_proof). */
    holderPublicKeySpkiB64u?: string;
}
/**
 * Verify a selective-disclosure presentation. Fail-closed: every failure is a
 * named refusal in `refusals`; hostile input never throws. All checks are
 * VERIFICATION; acceptance stays with the caller (see decision_scope).
 */
export declare function verifySelectiveDisclosurePresentation(presentation: unknown, issuerPublicKeySpkiB64u: string, expected: SdVerifyExpectation): SdVerifyResult;
export {};
//# sourceMappingURL=receipt-selective-disclosure.d.ts.map