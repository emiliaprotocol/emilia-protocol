import type { AebAdapter, AebDigest } from './aeb-adapter-contract.js';
export declare const PSEA_SOURCE_REVISION = "draft-yossif-psea-02";
export declare const PSEA_EAT_PROFILE = "urn:ietf:params:psea:eat-profile:1";
export declare const PSEA_PROOF_VERSION = "1";
export declare const PSEA_AEB_ADAPTER_ID = "native:psea-eat-jws";
export declare const PSEA_AEB_ADAPTER_VERSION = "1";
export declare const PSEA_AEB_CONFIG_VERSION = "AEB-PSEA-CONFIG-v1";
export declare const PSEA_AEB_TRUST_ROOT_VERSION = "AEB-PSEA-ES256-ROOT-v1";
export declare const PSEA_AEB_CAID_MAPPING_VERSION = "AEB-PSEA-CAID-MAPPING-v1";
export declare const PSEA_AEB_CAID_MAPPER_ID = "mapper:psea-jcs-action-v1";
type Obj = Record<string, unknown>;
export type PseaAttestationStatus = 'verified-hardware-uv' | 'verified-key-only' | 'not-appraised' | 'rejected';
export interface PseaAebConfig {
    '@version': typeof PSEA_AEB_CONFIG_VERSION;
    source_revision: typeof PSEA_SOURCE_REVISION;
    evidence_role: string;
    subject: {
        id: string;
        kind: 'human';
        native_id: string;
    };
    action_type: string;
    issuer: string;
    audience: string;
    operation: string;
    tier: number;
    expected_nonce: string | null;
    max_token_lifetime_seconds: number;
    max_clock_skew_seconds: number;
    max_status_age_seconds: number;
    required_attestation_statuses: readonly PseaAttestationStatus[];
    replay_mode: 'gate-atomic-consumption-required';
}
export interface PseaTrustRoot {
    '@version': typeof PSEA_AEB_TRUST_ROOT_VERSION;
    source_revision: typeof PSEA_SOURCE_REVISION;
    issuer: string;
    kid: string;
    public_key_spki: string;
    ueid: string;
    subject_native_id: string;
    enrollment_status: 'active' | 'revoked';
    attestation_status: PseaAttestationStatus;
    counter_scope: string;
}
export interface PseaArtifact {
    proof: string;
    actionPayload: unknown;
    integrityEvidence?: unknown;
}
export interface PseaClaims {
    jti: string;
    aud: string;
    iss: string;
    iat: number;
    exp: number;
    ueid: string;
    eat_profile: typeof PSEA_EAT_PROFILE;
    psea_tier: number;
    psea_op: string;
    psea_counter: number;
    psea_payload_hash: string;
    psea_uv: {
        verified: true;
        method: string;
    };
    psea_proof_version: typeof PSEA_PROOF_VERSION;
    eat_nonce?: string;
    submods?: {
        'psea-device-state': Obj;
    };
    psea_chain_prev?: string;
    psea_caller_package?: string;
    psea_sdk_version?: string;
    psea_user_hash?: string;
    psea_chain_pending?: unknown;
    psea_last_confirmed_head?: unknown;
    psea_rp_context_hash?: unknown;
}
export interface PseaReplayCandidate {
    scope: string;
    counter: number;
    jti: string;
    replay_unit: AebDigest;
}
export interface PseaReplaySnapshot {
    highest_counter: number | null;
    seen_jtis: ReadonlySet<string> | readonly string[];
}
export type PseaReplayCommitResult = {
    committed: true;
} | {
    committed: false;
    reason: 'jti_replay' | 'counter_rollback';
};
/** Implement this as one durable compare-and-update transaction in production. */
export interface PseaReplayStore {
    inspect(scope: string): Promise<PseaReplaySnapshot>;
    commit(candidate: PseaReplayCandidate): Promise<PseaReplayCommitResult>;
}
export interface PseaInspectionResult {
    verified: boolean;
    reasons: string[];
    proof_digest: AebDigest;
    action_digest: AebDigest;
    claims: PseaClaims | null;
    root: PseaTrustRoot | null;
    replay_candidate: PseaReplayCandidate | null;
}
export interface PseaCommittedVerification extends PseaInspectionResult {
    replay_committed: boolean;
}
/** RFC 8785-compatible JSON canonicalization for I-JSON data. */
export declare function canonicalizePsea(value: unknown, seen?: WeakSet<object>): string;
/**
 * Pure native inspection.  Optional replaySnapshot permits deterministic
 * historical checks.  It does not mutate replay state.
 */
export declare function inspectPseaProof(input: {
    artifact: unknown;
    config: unknown;
    trust_roots: readonly unknown[];
    now: string;
    replay_snapshot?: PseaReplaySnapshot;
}): PseaInspectionResult;
/** Verify and atomically finalize counter+jti before Gate admission. */
export declare function verifyAndCommitPseaProof(input: {
    artifact: unknown;
    config: unknown;
    trust_roots: readonly unknown[];
    now: string;
    replay_store: PseaReplayStore;
}): Promise<PseaCommittedVerification>;
/** Reference only. Production must use a durable transaction/fence. */
export declare class InMemoryPseaReplayStore implements PseaReplayStore {
    private readonly counters;
    private readonly jtis;
    inspect(scope: string): Promise<PseaReplaySnapshot>;
    commit(candidate: PseaReplayCandidate): Promise<PseaReplayCommitResult>;
}
/** Pure PSEA-to-AEB adapter. Gate must consume replay_unit atomically. */
export declare function createPseaAebAdapter(): AebAdapter;
export {};
//# sourceMappingURL=aeb-psea-adapter.d.ts.map