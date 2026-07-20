type Obj = Record<string, any>;
interface ProvenanceOptions {
    humanKeyClasses?: string[];
    allowUnsignedDelegations?: boolean;
    now?: number;
    requireActionApprovalAlways?: boolean;
    rootVerification?: Obj;
    root_verification?: Obj;
    actionVerification?: Obj;
    action_verification?: Obj;
    delegationKeys?: Record<string, Obj>;
    reversibilityAsserted?: (execution: Obj) => boolean;
}
export declare const PROVENANCE_VERSION = "EP-PROVENANCE-CHAIN-v1";
/**
 * Verify an EP-PROVENANCE-CHAIN-v1 document fully offline. FAIL CLOSED.
 * See lib/provenance/chain.js for the full contract; opts mirror it
 * (humanKeyClasses, delegationKeys, reversibilityAsserted, allowUnsignedDelegations,
 * now, requireActionApprovalAlways).
 */
export declare function verifyProvenanceOffline(doc: Obj, opts?: ProvenanceOptions): {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    links: Obj[];
    agent_identity: {
        agent_id: any;
        claimed_by: any;
        claim_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
    liability: {
        owner: any;
        owner_name: any;
        evidence_only: boolean;
        attestation_signature_valid: boolean | null;
    } | null;
};
export {};
//# sourceMappingURL=provenance.d.ts.map