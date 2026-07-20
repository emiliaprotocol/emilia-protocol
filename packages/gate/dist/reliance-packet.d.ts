export declare const RELIANCE_PACKET_VERSION = "EP-GATE-RELIANCE-PACKET-v1";
export declare const ADMISSIBILITY_VERDICTS: readonly string[];
type Obj = Record<string, any>;
/**
 * @param {{ decision?: any, execution?: any, evidence?: any, manifest?: any, binding?: any, admissibility?: any, verifier?: string }} [o]
 */
export declare function buildReliancePacket({ decision, execution, evidence, manifest, binding, admissibility, verifier, }?: {
    decision?: Obj | null;
    execution?: Obj | null;
    evidence?: Obj | null;
    manifest?: Obj | null;
    binding?: Obj | null;
    admissibility?: Obj | null;
    verifier?: string;
}): Promise<{
    '@version': string;
    product: string;
    verifier: string;
    verdict: string;
    summary: {
        action: any;
        receipt_id: any;
        subject: any;
        policy_id: any;
        policy_hash: any;
        tenant_id: any;
        approvers: any;
        required_tier: any;
        observed_tier: any;
        decision_hash: any;
        execution_hash: any;
        evidence_head: any;
        admissibility_verdict: string | null;
        admissibility_profile: {
            id: any;
            version: any;
        } | null;
        admissibility_profile_hash: string | null;
    };
    admissibility: {
        admissibility_profile: {
            id: any;
            version: any;
        } | null;
        profile_hash: string | null;
        verdict: string | null;
        verdict_recognized: boolean;
        admissible: boolean;
        replay_digest: string | null;
        challenge_id: any;
        challenge_digest: string | null;
    } | null;
    checks: {
        detail?: string | Obj | undefined;
        id: any;
        ok: any;
    }[];
    manifest_version: any;
    limitations: string[];
}>;
declare const _default: {
    RELIANCE_PACKET_VERSION: string;
    ADMISSIBILITY_VERDICTS: readonly string[];
    buildReliancePacket: typeof buildReliancePacket;
};
export default _default;
//# sourceMappingURL=reliance-packet.d.ts.map