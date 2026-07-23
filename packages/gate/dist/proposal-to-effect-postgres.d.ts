/**
 * PostgreSQL custody for Proposal-to-Effect consequence attempts.
 *
 * The application issues an opaque owner capability and sends only its keyed
 * digest to PostgreSQL. The database owns state-transition atomicity, terminal
 * immutability, and the exact attempt/provider-evidence join.
 */
import type { ConsequenceAttemptBinding, ConsequenceAttemptOwnerHandle, ConsequenceAttemptReference, ConsequenceAttemptState, ProposalToEffectConsequenceAttemptStore } from './proposal-to-effect.js';
type AebDigest = ConsequenceAttemptBinding['request_digest'];
export interface ProposalToEffectPostgresQueryResult {
    rowCount: number | null;
    rows: unknown[];
}
export interface ProposalToEffectPostgresClient {
    query(text: string, params?: readonly unknown[]): Promise<ProposalToEffectPostgresQueryResult>;
    /** Passing an error discards an ambiguously committed pooled connection. */
    release(error?: Error): void;
}
export interface ProposalToEffectPostgresPool {
    connect(): Promise<ProposalToEffectPostgresClient>;
}
export interface ProposalToEffectAttemptDigests {
    operation_digest: AebDigest;
    action_digest: AebDigest;
    config_digest: AebDigest;
}
export interface ProposalToEffectPostgresAttemptLookup {
    tenant_id: string;
    provider_id: string;
    provider_account_id: string;
    environment: string;
    request_digest: AebDigest;
}
export interface ProposalToEffectPostgresAttemptReference {
    tenant_id: string;
    provider_id: string;
    provider_account_id: string;
    environment: string;
    attempt_id: string;
    request_digest: AebDigest;
}
export interface ProposalToEffectPostgresAttemptSnapshot extends ProposalToEffectPostgresAttemptReference, ProposalToEffectAttemptDigests {
    attempt_digest: AebDigest;
    state: ConsequenceAttemptState;
    evidence_digest: AebDigest | null;
    last_heartbeat_at: string;
    lease_expires_at: string;
    lease_stale: boolean;
}
export interface ProposalToEffectPostgresRecoveryAuthorization extends ProposalToEffectPostgresAttemptSnapshot {
    owner_generation: number;
}
export type ProposalToEffectPostgresRecoveryResult = {
    recovered: true;
    owner: ConsequenceAttemptOwnerHandle;
    state: 'RESERVED' | 'INDETERMINATE';
} | {
    recovered: false;
    reason: 'attempt_not_found' | 'attempt_not_stale' | 'recovery_not_authorized' | 'recovery_conflict' | 'terminal_state_immutable';
};
export interface ProposalToEffectPostgresStore extends ProposalToEffectConsequenceAttemptStore {
    /**
     * Rediscover an attempt after a lost response using only the exact,
     * server-derived provider tuple and request digest. This neither executes
     * nor rotates custody and returns no owner or operational state.
     */
    lookup(input: ProposalToEffectPostgresAttemptLookup): Promise<ProposalToEffectPostgresAttemptReference | null>;
    /**
     * Read operational saga state by its complete durable namespace and request
     * digest. Owner material is deliberately absent.
     */
    read(input: ProposalToEffectPostgresAttemptReference): Promise<ProposalToEffectPostgresAttemptSnapshot | null>;
    /**
     * Renew nonterminal custody. The owner digest and database lease jointly
     * fence stale workers; the opaque owner never crosses the SQL boundary.
     */
    heartbeat(input: ConsequenceAttemptReference): Promise<boolean>;
    /**
     * Rotate ownership after restart only after the configured server callback
     * authorizes the exact stored tenant/attempt/request binding. INVOKING is
     * conservatively claimed as INDETERMINATE.
     */
    recover(input: ProposalToEffectPostgresAttemptReference): Promise<ProposalToEffectPostgresRecoveryResult>;
}
export interface CreateProposalToEffectPostgresStoreOptions {
    /** Least-privilege executor connection; it must not hold the recovery role. */
    pool: ProposalToEffectPostgresPool;
    /** Separately credentialed recovery connection; must differ from pool. */
    recovery_pool: ProposalToEffectPostgresPool;
    /** Server-held key copied at construction; minimum 256 bits. */
    owner_hmac_sha256_key: Uint8Array;
    /**
     * Resolve the digests not carried by ConsequenceAttemptBinding from
     * server-controlled canonical request custody.
     */
    resolve_binding_digests(binding: Readonly<ConsequenceAttemptBinding>): Promise<ProposalToEffectAttemptDigests> | ProposalToEffectAttemptDigests;
    /**
     * Explicit server authorization for restart ownership rotation. This
     * callback never receives the old owner token or its keyed digest.
     */
    authorize_recovery(authorization: Readonly<ProposalToEffectPostgresRecoveryAuthorization>): Promise<boolean> | boolean;
    /** Injectable only for deterministic tests; production defaults to crypto.randomBytes. */
    random_bytes?: (size: number) => Uint8Array;
    /** Database-enforced lease duration. Defaults to 30 seconds, max 5 minutes. */
    lease_seconds?: number;
}
/**
 * Install under a dedicated non-login owner. Runtime roles should receive only
 * schema USAGE plus EXECUTE on the RPCs they need; no table privilege is
 * required or intended. Keep recover_attempt limited to the server role that
 * runs authorize_recovery.
 */
export declare const PROPOSAL_TO_EFFECT_POSTGRES_DDL: string;
export declare const PROPOSAL_TO_EFFECT_POSTGRES_SQL: Readonly<{
    reserve: "SELECT * FROM proposal_to_effect_private.reserve_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12\n  )";
    transition: "SELECT * FROM proposal_to_effect_private.transition_attempt(\n    $1, $2, $3, $4, $5, $6\n  )";
    heartbeat: "SELECT * FROM proposal_to_effect_private.heartbeat_attempt(\n    $1, $2, $3, $4\n  )";
    reconcile: "SELECT * FROM proposal_to_effect_private.reconcile_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9,\n    $10, $11, $12, $13, $14, $15, $16, $17, $18, $19\n  )";
    lookup: "SELECT * FROM proposal_to_effect_private.lookup_attempt(\n    $1, $2, $3, $4, $5\n  )";
    read: "SELECT * FROM proposal_to_effect_private.read_attempt(\n    $1, $2, $3, $4, $5, $6\n  )";
    recover: "SELECT * FROM proposal_to_effect_private.recover_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12\n  )";
}>;
export declare function proposalToEffectAttemptDigest(binding: ConsequenceAttemptBinding, digests: ProposalToEffectAttemptDigests): AebDigest;
/**
 * Build the owner-fenced store consumed by createProposalToEffect(), plus
 * operational read/recovery methods for restart-safe saga repair.
 */
export declare function createProposalToEffectPostgresStore(options: CreateProposalToEffectPostgresStoreOptions): ProposalToEffectPostgresStore;
declare const _default: {
    PROPOSAL_TO_EFFECT_POSTGRES_DDL: string;
    PROPOSAL_TO_EFFECT_POSTGRES_SQL: Readonly<{
        reserve: "SELECT * FROM proposal_to_effect_private.reserve_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12\n  )";
        transition: "SELECT * FROM proposal_to_effect_private.transition_attempt(\n    $1, $2, $3, $4, $5, $6\n  )";
        heartbeat: "SELECT * FROM proposal_to_effect_private.heartbeat_attempt(\n    $1, $2, $3, $4\n  )";
        reconcile: "SELECT * FROM proposal_to_effect_private.reconcile_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9,\n    $10, $11, $12, $13, $14, $15, $16, $17, $18, $19\n  )";
        lookup: "SELECT * FROM proposal_to_effect_private.lookup_attempt(\n    $1, $2, $3, $4, $5\n  )";
        read: "SELECT * FROM proposal_to_effect_private.read_attempt(\n    $1, $2, $3, $4, $5, $6\n  )";
        recover: "SELECT * FROM proposal_to_effect_private.recover_attempt(\n    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12\n  )";
    }>;
    proposalToEffectAttemptDigest: typeof proposalToEffectAttemptDigest;
    createProposalToEffectPostgresStore: typeof createProposalToEffectPostgresStore;
};
export default _default;
//# sourceMappingURL=proposal-to-effect-postgres.d.ts.map