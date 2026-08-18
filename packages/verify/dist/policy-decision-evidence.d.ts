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
import { type AgilityOptions } from './pq-signature-agility.js';
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
/**
 * Same five-move migration as EP-REVOCATION-v2, and the same reason the JOSE
 * `alg` header disappears in v2 as in EP-AUTHORIZATION-SERVER-CONFIRMATION-v2:
 * this repository carries no traceable JOSE algorithm identifier for ML-DSA-65
 * (the only in-tree ML-DSA algorithm identifier is the COSE one, RFC 9964, in
 * packages/verify/src/aeb-mcgraw-delegation-adapter.ts), and
 * docs/protocol/pq-hybrid-program.md records the JOSE registration as unfinished
 * draft work. Rather than squat on the JOSE registry with an invented value,
 * the v2 protected header carries no `alg` at all: each signature carries its
 * own label from EP's own closed registry (EP-SIG-AGILITY-v1), and the header
 * commits to the required SET.
 *
 *   1. VERSION BUMP. `ep_version` becomes the v2 marker and `typ` changes, so
 *      the unchanged v1 parser (signableClaims / verifyStatement) refuses a v2
 *      statement on the version marker before touching a signature, without
 *      throwing. Asserted by test.
 *   2. SET SHAPE. `signatures: [{ alg, sig, key_id }]`, the EP-SIG-AGILITY-v1
 *      AgileSignature shape, one entry per registered algorithm.
 *   3. ANTI-STRIPPING BYTES. `required_algorithms` is a member of the protected
 *      header, which is inside the ASCII `<protected>.<payload>` signing input
 *      both legs cover. The verifier rebuilds the expected header from the PIN
 *      and the REGISTERED set and requires byte equality.
 *   4. V1 COMPATIBILITY. signPolicyDecisionEvidence() and the synchronous
 *      AebAdapter path are unchanged and stay synchronous. ML-DSA verification
 *      is async and AebAdapter.verifyNative() is synchronous by contract, so v2
 *      is a separate async entry point; there is no hybrid adapter here.
 *   5. NAMED REFUSALS. Nothing throws on caller input; a missing ML-DSA backend
 *      is `pq_backend_unavailable` and never a pass on the classical leg.
 *
 * COORDINATION BOUNDARY. The signer is an OPA or Cerbos integration that
 * vendored this helper. Shipping the v2 verifier does not make any policy-engine
 * integration emit v2 statements: each one must deploy an ML-DSA-65 key and the
 * v2 signer first. Opt-in; not deployed, default, or certified.
 *
 * UNCHANGED BOUNDARY. v2 changes the signature algebra and nothing else. A
 * verified statement still proves only that a pinned integration observed and
 * signed this machine-policy decision. A machine ALLOW is still not human
 * authorization.
 */
export declare const POLICY_DECISION_EVIDENCE_V2_VERSION = "EP-POLICY-DECISION-EVIDENCE-v2";
export declare const POLICY_DECISION_EVIDENCE_V2_TYP = "ep-policy-decision-evidence+hybrid";
/** The registered required algorithm set, in canonical order. */
export declare const POLICY_DECISION_EVIDENCE_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface PolicyDecisionEvidenceV2Claims extends Omit<PolicyDecisionEvidenceClaims, 'ep_version'> {
    ep_version: typeof POLICY_DECISION_EVIDENCE_V2_VERSION;
}
export interface PolicyDecisionEvidenceHybridStatement {
    protected: string;
    payload: string;
    signatures: Array<{
        alg: string;
        sig: string;
        key_id: string;
    }>;
}
export interface PolicyDecisionEvidenceV2KeyPin {
    key_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    pq_key_id: string;
    /** ML-DSA-65 base64url raw 1952-byte public key. */
    pq_public_key: string;
}
export interface PolicyDecisionEvidenceV2Signer {
    key_id: string;
    private_key: KeyObject;
    pq_key_id: string;
    /** ML-DSA-65 raw 4032-byte secret key (Uint8Array or base64url). */
    pq_secret_key: Uint8Array | string;
}
export interface PolicyDecisionEvidenceV2Result {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    claims?: PolicyDecisionEvidenceV2Claims;
}
/** The v2 protected header; `required_algorithms` is a signed member of it. */
export declare function policyDecisionEvidenceV2ProtectedHeader(keyId: string, pqKeyId: string, requiredAlgorithms?: readonly string[]): Obj;
/** ASCII `<protected>.<payload>`: the exact v1 signing-input convention. */
export declare function policyDecisionEvidenceV2SigningInput(protectedB64u: string, payloadB64u: string): Buffer;
/** Sign a v2 policy decision statement under BOTH registered algorithms. */
export declare function signPolicyDecisionEvidenceV2(claims: PolicyDecisionEvidenceV2Claims, signer: PolicyDecisionEvidenceV2Signer, options?: AgilityOptions): Promise<PolicyDecisionEvidenceHybridStatement>;
/**
 * verifyPolicyDecisionEvidenceV2 -- FAIL-CLOSED hybrid check against a pinned
 * key pair and a pinned adapter config. Never throws on caller input; a v2
 * statement NEVER verifies on one leg alone.
 *
 * SCOPE. Header shape, committed algorithm set, both legs under pinned keys,
 * and closed claim validity against the config. Freshness, engine/policy
 * allow-lists beyond the closed claim check, status, and AEB acceptance stay
 * with the unchanged synchronous v1 adapter.
 */
export declare function verifyPolicyDecisionEvidenceV2(statement: unknown, pin: PolicyDecisionEvidenceV2KeyPin | null | undefined, config: PolicyDecisionEvidenceAdapterConfig | null | undefined, options?: AgilityOptions): Promise<PolicyDecisionEvidenceV2Result>;
export {};
//# sourceMappingURL=policy-decision-evidence.d.ts.map