/**
 * Validated, sorted shape of the caller-supplied expected-binding context
 * returned by {@link exactExpected}.
 * @typedef {Object} ExpectedActionBindingContext
 * @property {string} agreement_digest
 * @property {string} document_action_binding_digest
 * @property {string} release_action_digest
 * @property {string} milestone_id
 * @property {Array<{party_id: string, role: string}>} parties
 * @property {string} parties_digest
 * @property {string} profile_digest
 * @property {string|null} supersedes_document_action_binding_digest
 */
/**
 * Validated release-action template shape produced by
 * {@link validateActionEscrowReleaseTemplate}.
 * @typedef {Object} ActionEscrowReleaseTemplate
 * @property {string} action_type
 * @property {string} action_escrow_profile_digest
 * @property {string} agreement_id
 * @property {string} agreement_digest
 * @property {string} milestone_id
 * @property {string} amount
 * @property {string} currency
 * @property {string} destination_id
 * @property {string} payee_id
 * @property {string} custodian_provider
 * @property {'sandbox'|'production'} custodian_environment
 * @property {string} custodian_transaction_id
 * @property {string} custodian_milestone_id
 * @property {string} document_sha256
 * @property {string} material_terms_sha256
 * @property {string} completion_evidence_sha256
 * @property {number} amendment_version
 * @property {string} [project_record_snapshot_digest]
 * @property {string} [action_escrow_template_profile]
 */
export declare const ACTION_ESCROW_AGREEMENT_DIGEST_VERSION = "EP-ACTION-ESCROW-AGREEMENT-DIGEST-v1";
export declare const ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION = "EP-ACTION-ESCROW-CONTRACTOR-TEMPLATE-v1";
export declare const ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS: readonly string[];
export declare const ACTION_ESCROW_CONTRACTOR_REQUIRED_MATERIAL_TERM_IDS: readonly string[];
export declare function computeActionEscrowAgreementDigest(agreementId: any): string | null;
export declare function validateActionEscrowReleaseTemplate(template: any, { profileDigest, agreementId, agreementDigest, milestoneId, documentDigest, materialTerms, contractorProjectSource, }?: {
    profileDigest?: any;
    agreementId?: any;
    agreementDigest?: any;
    milestoneId?: any;
    documentDigest?: any;
    materialTerms?: any;
    contractorProjectSource?: boolean;
}): any;
export declare function createActionEscrowDocumentBindingVerifier(options?: {}): (binding: any, untrustedExpected: any) => Promise<any>;
export declare function createActionEscrowContractorDocumentBindingVerifier(options?: {}): (binding: any, untrustedExpected: any) => Promise<any>;
declare const _default: Readonly<{
    ACTION_ESCROW_AGREEMENT_DIGEST_VERSION: "EP-ACTION-ESCROW-AGREEMENT-DIGEST-v1";
    ACTION_ESCROW_CONTRACTOR_TEMPLATE_VERSION: "EP-ACTION-ESCROW-CONTRACTOR-TEMPLATE-v1";
    ACTION_ESCROW_CONTRACTOR_REQUIRED_MATERIAL_TERM_IDS: readonly string[];
    ACTION_ESCROW_REQUIRED_MATERIAL_TERM_IDS: readonly string[];
    computeActionEscrowAgreementDigest: typeof computeActionEscrowAgreementDigest;
    createActionEscrowContractorDocumentBindingVerifier: typeof createActionEscrowContractorDocumentBindingVerifier;
    createActionEscrowDocumentBindingVerifier: typeof createActionEscrowDocumentBindingVerifier;
    validateActionEscrowReleaseTemplate: typeof validateActionEscrowReleaseTemplate;
}>;
export default _default;
//# sourceMappingURL=action-escrow-verifiers.d.ts.map