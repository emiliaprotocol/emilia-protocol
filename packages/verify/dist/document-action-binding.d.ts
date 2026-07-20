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
declare const documentActionBinding: {
    DOCUMENT_ACTION_BINDING_VERSION: string;
    DOCUMENT_ACTION_BINDING_DOMAIN: string;
    DOCUMENT_ACTION_MATERIAL_TERM_TYPES: readonly string[];
    computeDocumentSha256: typeof computeDocumentSha256;
    computeReleaseActionDigest: typeof computeReleaseActionDigest;
    computeDocumentActionBindingDigest: typeof computeDocumentActionBindingDigest;
    signDocumentActionBinding: typeof signDocumentActionBinding;
    verifyDocumentActionBinding: typeof verifyDocumentActionBinding;
};
export default documentActionBinding;
//# sourceMappingURL=document-action-binding.d.ts.map