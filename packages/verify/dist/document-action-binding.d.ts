/**
 * EP-DOCUMENT-ACTION-BINDING-v1
 *
 * A mapping issuer binds one final document to structured material terms, one
 * exact release action template, and the party roster a separate acceptance
 * workflow must satisfy. This artifact does NOT prove that any party accepted
 * the document. E-sign provider metadata is intentionally outside the profile;
 * EP-RESOLUTION receipts can supply acceptance evidence to a state engine.
 *
 * Verification is offline, pure, and fail-closed. The only verification key is
 * selected from the relying party's issuerKeys option. The artifact cannot
 * carry a public key.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
interface DABOptions {
    now?: number | string | Date;
    allowedMediaTypes?: string[];
    allowedPartyRoles?: string[];
    allowedActionTypes?: string[];
    requiredMaterialTermIds?: string[];
    issuerKeys?: Record<string, Obj>;
    expectedBindingId?: string;
    expectedAgreementId?: string;
    documentBytes?: Uint8Array | ArrayBuffer;
    documentMediaType?: string;
    releaseActionTemplate?: Obj;
    expectedRequiredParties?: Obj[];
    expectedSupersedesDigest?: string | null;
}
export declare const DOCUMENT_ACTION_BINDING_VERSION = "EP-DOCUMENT-ACTION-BINDING-v1";
export declare const DOCUMENT_ACTION_BINDING_DOMAIN = "EP-DOCUMENT-ACTION-BINDING-v1\0";
export declare const DOCUMENT_ACTION_MATERIAL_TERM_TYPES: readonly string[];
/**
 * SHA-256 over the final document bytes.
 *
 * @param {Uint8Array|ArrayBuffer} documentBytes
 * @returns {string|null}
 */
export declare function computeDocumentSha256(documentBytes: Uint8Array | ArrayBuffer): string | null;
/**
 * SHA-256 over the canonical release action template.
 *
 * @param {object} template
 * @returns {string|null}
 */
export declare function computeReleaseActionDigest(template: Obj): string | null;
/**
 * Compute the domain-separated digest signed by the mapping issuer.
 *
 * @param {object} binding
 * @returns {string|null}
 */
export declare function computeDocumentActionBindingDigest(binding: Obj): string | null;
/**
 * Sign a DAB mapping. The signer hashes the supplied final document bytes; it
 * never accepts a presenter-supplied document digest. This function may throw
 * on issuer-side programming errors. verifyDocumentActionBinding never throws.
 *
 * @param {object} spec
 * @param {{issuer_id:string,key_id:string,privateKey:crypto.KeyObject|string|Buffer}} signer
 * @returns {object}
 */
export declare function signDocumentActionBinding(spec: Obj, signer: Obj): Obj;
/**
 * Verify a DAB mapping under a relying-party-pinned issuer key.
 *
 * `valid:true` authenticates the mapping only. It never means that any listed
 * party accepted the document. The returned required_parties are inputs for a
 * separate acceptance/state engine.
 *
 * @param {unknown} binding
 * @param {object} [opts]
 * @returns {{
 *   valid:boolean,
 *   reason:string,
 *   binding_id:string|null,
 *   agreement_id:string|null,
 *   supersedes_digest:string|null,
 *   binding_digest:string|null,
 *   document_digest:string|null,
 *   action_digest:string|null,
 *   required_parties:Array<{party_id:string,role:string}>
 * }}
 */
export declare function verifyDocumentActionBinding(binding: unknown, opts?: DABOptions): {
    valid: boolean;
    reason: string;
    binding_id: null;
    agreement_id: null;
    supersedes_digest: null;
    binding_digest: null;
    document_digest: null;
    action_digest: null;
    required_parties: never[];
} | {
    valid: boolean;
    reason: string;
    binding_id: any;
    agreement_id: any;
    supersedes_digest: any;
    binding_digest: string;
    document_digest: any;
    action_digest: any;
    required_parties: Obj;
};
/**
 * Reference hybrid migration for this surface, copying the five moves from
 * EP-REVOCATION-v2 (packages/verify/src/revocation.ts) verbatim:
 *
 * 1. VERSION BUMP. `profile` (this artifact's `@version` field) moves from
 *    -v1 to -v2; verifyDocumentActionBinding above is UNCHANGED and refuses a
 *    v2 mapping cleanly on the profile marker before inspecting any signature
 *    (validateCore rejects `unsupported_profile` first).
 * 2. SET SHAPE. `issuer_signatures` carries exactly the two AgileSignature
 *    entries ({alg, sig, key_id?}) for Ed25519 and ML-DSA-65, in that order,
 *    reusing EP-SIG-AGILITY-v1's shape verbatim.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is a CORE field (inside the
 *    signed bytes), independently recomputed by the verifier from the
 *    registered set, never read off the presented mapping.
 * 4. V1 COMPATIBILITY. v1 mappings keep verifying through the unchanged sync
 *    verifyDocumentActionBinding. v2 verification is a separate ASYNC entry
 *    point (ML-DSA verification is async); verifyDocumentActionBindingStatement
 *    routes on `profile` for callers holding a mixed bag.
 * 5. NAMED REFUSALS. Every failure returns a `reason` string; nothing throws
 *    on caller input. An absent ML-DSA backend refuses via the agility
 *    module's own `pq_backend_unavailable`, never a pass on the Ed25519 leg
 *    alone.
 */
export declare const DOCUMENT_ACTION_BINDING_V2_VERSION = "EP-DOCUMENT-ACTION-BINDING-v2";
export declare const DOCUMENT_ACTION_BINDING_V2_DOMAIN = "EP-DOCUMENT-ACTION-BINDING-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const DOCUMENT_ACTION_BINDING_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface DABv2Signer {
    issuer_id: string;
    key_id: string;
    privateKey: crypto.KeyObject | string | Buffer;
    pq_key_id: string;
    /** ML-DSA-65 secret key: raw bytes or base64url, 4032 bytes. */
    pqPrivateKey: Uint8Array | string;
}
export interface DABv2IssuerPin {
    issuer_id: string;
    /** Ed25519: base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65: base64url of the raw 1952-byte public key. */
    pq_public_key: string;
}
interface DABv2Options extends AgilityOptions {
    now?: number | string | Date;
    allowedMediaTypes?: string[];
    allowedPartyRoles?: string[];
    allowedActionTypes?: string[];
    requiredMaterialTermIds?: string[];
    issuerKeys?: Record<string, DABv2IssuerPin>;
    expectedBindingId?: string;
    expectedAgreementId?: string;
    documentBytes?: Uint8Array | ArrayBuffer;
    documentMediaType?: string;
    releaseActionTemplate?: Obj;
    expectedRequiredParties?: Obj[];
    expectedSupersedesDigest?: string | null;
}
/**
 * Sign a DAB mapping under EP-DOCUMENT-ACTION-BINDING-v2 (hybrid). Throws on
 * issuer-side misuse; never silently downgrades to a single algorithm.
 */
export declare function signDocumentActionBindingV2(spec: Obj, signer: DABv2Signer): Promise<Obj>;
/**
 * Verify a hybrid DAB mapping. Async because ML-DSA-65 verification is
 * async; a v2 mapping never verifies on one leg alone (FAIL-CLOSED).
 */
export declare function verifyDocumentActionBindingV2(binding: unknown, opts?: DABv2Options): Promise<{
    valid: boolean;
    reason: string;
    binding_id: null;
    agreement_id: null;
    supersedes_digest: null;
    binding_digest: null;
    document_digest: null;
    action_digest: null;
    required_parties: never[];
} | {
    valid: boolean;
    reason: string;
    binding_id: any;
    agreement_id: any;
    supersedes_digest: any;
    binding_digest: string;
    document_digest: any;
    action_digest: any;
    required_parties: Obj;
}>;
/**
 * Route a mapping of EITHER version to its verifier. A `profile` naming
 * neither version refuses through the v1 (sync) verifier's `malformed_binding`
 * / `unsupported_profile` path, which is the fail-closed answer.
 */
export declare function verifyDocumentActionBindingStatement(binding: unknown, opts?: DABv2Options): Promise<{
    valid: boolean;
    reason: string;
    binding_id: null;
    agreement_id: null;
    supersedes_digest: null;
    binding_digest: null;
    document_digest: null;
    action_digest: null;
    required_parties: never[];
} | {
    valid: boolean;
    reason: string;
    binding_id: any;
    agreement_id: any;
    supersedes_digest: any;
    binding_digest: string;
    document_digest: any;
    action_digest: any;
    required_parties: Obj;
}>;
declare const documentActionBinding: {
    DOCUMENT_ACTION_BINDING_VERSION: string;
    DOCUMENT_ACTION_BINDING_DOMAIN: string;
    DOCUMENT_ACTION_MATERIAL_TERM_TYPES: readonly string[];
    DOCUMENT_ACTION_BINDING_V2_VERSION: string;
    DOCUMENT_ACTION_BINDING_V2_DOMAIN: string;
    DOCUMENT_ACTION_BINDING_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    computeDocumentSha256: typeof computeDocumentSha256;
    computeReleaseActionDigest: typeof computeReleaseActionDigest;
    computeDocumentActionBindingDigest: typeof computeDocumentActionBindingDigest;
    signDocumentActionBinding: typeof signDocumentActionBinding;
    verifyDocumentActionBinding: typeof verifyDocumentActionBinding;
    signDocumentActionBindingV2: typeof signDocumentActionBindingV2;
    verifyDocumentActionBindingV2: typeof verifyDocumentActionBindingV2;
    verifyDocumentActionBindingStatement: typeof verifyDocumentActionBindingStatement;
};
export default documentActionBinding;
//# sourceMappingURL=document-action-binding.d.ts.map