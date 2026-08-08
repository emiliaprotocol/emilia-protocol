/**
 * Signed local-policy decision evidence for AEB composition.
 *
 * This module does not implement a policy engine and does not convert a
 * machine-policy ALLOW into human authorization. It lets an OPA or Cerbos
 * integration sign the exact decision it observed, then exposes that result as
 * one relying-party-pinned AEB evidence leg. A consequential Gate policy can
 * require this leg together with independent human authorization evidence.
 */
import { type KeyObject } from 'node:crypto';
import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
type Obj = Record<string, unknown>;
export declare const POLICY_DECISION_EVIDENCE_VERSION = "EP-POLICY-DECISION-EVIDENCE-v1";
export declare const POLICY_DECISION_EVIDENCE_TYP = "ep-policy-decision-evidence+jwt";
export declare const POLICY_DECISION_EVIDENCE_ADAPTER_ID = "native:policy-decision-evidence";
export declare const POLICY_DECISION_EVIDENCE_ADAPTER_VERSION = "1";
export declare const POLICY_DECISION_EVIDENCE_CONFIG_VERSION = "EP-POLICY-DECISION-EVIDENCE-CONFIG-v1";
export declare const POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION = "EP-POLICY-DECISION-EVIDENCE-ROOT-v1";
export declare const POLICY_DECISION_EVIDENCE_MAPPING_VERSION = "EP-POLICY-DECISION-CAID-MAPPING-v1";
export declare const POLICY_DECISION_EVIDENCE_MAPPER_ID = "mapper:policy-decision-exact-action-v1";
export type PolicyEngineKind = 'opa' | 'cerbos';
export type MachinePolicyDecision = 'ALLOW' | 'DENY' | 'INDETERMINATE';
export interface PolicyDecisionEvidenceClaims {
    ep_version: typeof POLICY_DECISION_EVIDENCE_VERSION;
    iss: string;
    sub: string;
    aud: string;
    iat: number;
    exp: number;
    jti: string;
    engine: PolicyEngineKind;
    policy_id: string;
    policy_digest: AebDigest;
    policy_decision: MachinePolicyDecision;
    action: Obj;
    action_digest: AebDigest;
    native_decision_ref: string;
    native_result_digest: AebDigest;
}
export interface PolicyDecisionEvidenceSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface PolicyDecisionEvidenceTrustRoot {
    '@version': typeof POLICY_DECISION_EVIDENCE_TRUST_ROOT_VERSION;
    issuer: string;
    key_id: string;
    algorithm: 'EdDSA';
    public_key: string;
}
export interface PolicyDecisionEvidenceAdapterConfig {
    '@version': typeof POLICY_DECISION_EVIDENCE_CONFIG_VERSION;
    evidence_role: string;
    subject: {
        id: string;
        kind: 'workload' | 'system';
    };
    issuer: string;
    audience: string;
    action_type: string;
    allowed_engines: PolicyEngineKind[];
    allowed_policy_digests: AebDigest[];
    clock_skew_seconds: number;
    max_decision_age_seconds: number;
}
export interface PolicyDecisionProjectionInput {
    issuer: string;
    subject: string;
    audience: string;
    issued_at: number;
    expires_at: number;
    decision_id: string;
    policy_id: string;
    policy_digest: AebDigest;
    action: unknown;
    native_decision_ref: string;
}
export interface OpaPolicyDecisionProjectionInput extends PolicyDecisionProjectionInput {
    result: unknown;
}
export interface CerbosPolicyDecisionProjectionInput extends PolicyDecisionProjectionInput {
    effect: unknown;
}
/** Project an OPA boolean result. Non-boolean results are explicitly indeterminate. */
export declare function projectOpaPolicyDecision(input: OpaPolicyDecisionProjectionInput): PolicyDecisionEvidenceClaims;
/** Project a Cerbos CheckResources effect. Unknown effects are explicitly indeterminate. */
export declare function projectCerbosPolicyDecision(input: CerbosPolicyDecisionProjectionInput): PolicyDecisionEvidenceClaims;
/** Sign a normalized policy-engine observation with the local bridge key. */
export declare function signPolicyDecisionEvidence(claims: PolicyDecisionEvidenceClaims, signer: PolicyDecisionEvidenceSigner): string;
export declare function createPolicyDecisionEvidenceActionDefinition(actionType: string): Obj;
/**
 * Build the AEB adapter under relying-party-pinned config and bridge keys.
 * The bridge key proves only what this local integration observed. It does not
 * prove complete mediation, policy correctness, human intent, or authorization.
 */
export declare function createPolicyDecisionEvidenceAdapter(constructorPins: {
    config: PolicyDecisionEvidenceAdapterConfig;
    trust_roots: readonly PolicyDecisionEvidenceTrustRoot[];
}): AebAdapter;
export {};
//# sourceMappingURL=policy-decision-evidence.d.ts.map