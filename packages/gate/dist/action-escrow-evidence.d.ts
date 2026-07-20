export declare const ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION = "EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1";
export declare const ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION = "EP-ACTION-ESCROW-CONTRACTOR-EVIDENCE-PACKAGE-v1";
export declare const ACTION_ESCROW_EVIDENCE_STAGES: readonly string[];
/**
 * Strict raw parser for security-bearing package transport.
 * @param {*} raw
 * @param {{ maxBytes?: number }} [options]
 */
export declare function parseActionEscrowEvidencePackage(raw: any, { maxBytes, }?: {
    maxBytes?: number | undefined;
}): {
    ok: boolean;
    reason: string | undefined;
    value: null;
} | {
    ok: boolean;
    reason: string;
    value: any;
};
/**
 * Build a portable evidence manifest. The final document bytes are hashed but
 * not embedded; transport them beside the JSON manifest.
 *
 * @param {{ now?: number, maxDocumentBytes?: number, maxProjectRecordBytes?: number }} [limits]
 */
export declare function buildActionEscrowEvidencePackage({ agreementId, stage, binding, documentBytes: rawDocumentBytes, documentFileName, documentExecution, agreementAcceptances, releaseApprovals, fundingStatement, milestones, release, stateRecord, amendments, verificationProfile, projectRecordBytes: rawProjectRecordBytes, projectRecordFileName, projectRecordProvider, projectRecordSnapshotDigest, }?: {
    agreementId?: string;
    stage?: string;
    binding?: unknown;
    documentBytes?: unknown;
    documentFileName?: string | null;
    documentExecution?: unknown;
    agreementAcceptances?: any[];
    releaseApprovals?: any[];
    fundingStatement?: unknown;
    milestones?: any[];
    release?: unknown;
    stateRecord?: unknown;
    amendments?: any[];
    verificationProfile?: unknown;
    projectRecordBytes?: unknown;
    projectRecordFileName?: string | null;
    projectRecordProvider?: string | null;
    projectRecordSnapshotDigest?: string | null;
}, { now, maxDocumentBytes, maxProjectRecordBytes, }?: {
    now?: number;
    maxDocumentBytes?: number;
    maxProjectRecordBytes?: number;
}): any;
/**
 * Shape of every pluggable relying-party-owned component verifier accepted
 * below: caller-supplied, arbitrary in signature beyond (value, context).
 */
type EvidenceVerifierFn = (value: any, context: any) => any;
/**
 * Re-perform every package join using relying-party-owned component verifiers.
 *
 * Component verifiers are configuration, never read from the package. Their
 * returned binding fields are checked again here so a valid artifact for one
 * agreement, document, party, or action cannot be relabeled into another slot.
 *
 * @param {*} pkg
 */
export declare function verifyActionEscrowEvidencePackage(pkg: any, { documentBytes: rawDocumentBytes, projectRecordBytes: rawProjectRecordBytes, verifyBinding, verifyProjectRecord, verifyProfile, verifyDocumentExecution, verifyAgreementAcceptance, verifyReleaseApproval, verifyFunding, verifyMilestone, verifyRelease, verifyAmendment, verifyState, expectedAgreementId, now, maxDocumentBytes, maxProjectRecordBytes, }?: {
    documentBytes?: unknown;
    projectRecordBytes?: unknown;
    verifyBinding?: EvidenceVerifierFn;
    verifyProjectRecord?: EvidenceVerifierFn;
    verifyProfile?: EvidenceVerifierFn;
    verifyDocumentExecution?: EvidenceVerifierFn;
    verifyAgreementAcceptance?: EvidenceVerifierFn;
    verifyReleaseApproval?: EvidenceVerifierFn;
    verifyFunding?: EvidenceVerifierFn;
    verifyMilestone?: EvidenceVerifierFn;
    verifyRelease?: EvidenceVerifierFn;
    verifyAmendment?: EvidenceVerifierFn;
    verifyState?: EvidenceVerifierFn;
    expectedAgreementId?: string;
    now?: Date | number | string;
    maxDocumentBytes?: number;
    maxProjectRecordBytes?: number;
}): Promise<{
    valid: boolean;
    reason: any;
    checks: any;
} | {
    valid: boolean;
    reason: string;
    checks: {
        structure: boolean;
        package_digest: boolean;
        time: boolean;
        document: boolean;
        project_record: boolean;
        binding: boolean;
        profile: boolean;
        document_execution: boolean;
        agreement_acceptances: boolean;
        amendments: boolean;
        state: boolean;
        release_approvals: boolean;
        funding: boolean;
        milestones: boolean;
        release: boolean;
    };
    package_digest: any;
    agreement_id: any;
    binding_digest: any;
    action_digest: any;
    profile_digest: any;
    project_record_snapshot_digest: any;
    required_parties: {
        party_id: string;
        role: string | null;
    }[] | null;
    required_release_parties: {
        party_id: string;
        role: string | null;
    }[] | null;
}>;
declare const _default: {
    ACTION_ESCROW_CONTRACTOR_EVIDENCE_PACKAGE_VERSION: string;
    ACTION_ESCROW_EVIDENCE_PACKAGE_VERSION: string;
    ACTION_ESCROW_EVIDENCE_STAGES: readonly string[];
    parseActionEscrowEvidencePackage: typeof parseActionEscrowEvidencePackage;
    buildActionEscrowEvidencePackage: typeof buildActionEscrowEvidencePackage;
    verifyActionEscrowEvidencePackage: typeof verifyActionEscrowEvidencePackage;
};
export default _default;
//# sourceMappingURL=action-escrow-evidence.d.ts.map