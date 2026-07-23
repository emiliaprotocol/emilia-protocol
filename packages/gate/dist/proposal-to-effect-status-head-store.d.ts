/**
 * Durable relying-party custody for accepted EP-STATUS-v1 heads.
 *
 * The presenter supplies only a candidate status artifact. The store loads the
 * authenticated predecessor, passes that predecessor to trusted verification
 * code, and advances the exact tenant/relying-party/target head only when one
 * database-side compare-and-advance still observes that predecessor. This
 * keeps cryptographic work outside database transactions without opening a
 * time-of-check/time-of-use acceptance race.
 */
import { type StatusTarget, type StatusVerification } from '@emilia-protocol/verify/status';
export declare const PROPOSAL_TO_EFFECT_STATUS_HEAD_STORE_VERSION = "EP-GATE-PTE-STATUS-HEAD-PG-v1";
export declare const PROPOSAL_TO_EFFECT_STATUS_HEAD_TABLE = "ep_aeb_status_heads";
export declare const PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL: Readonly<{
    get: "SELECT status_digest, sequence, status_state, previous_status_digest,\n  issued_at, next_update, status_json, predecessor_status_json\nFROM ep_aeb_private.get_status_head(\n  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text\n)";
    compareAndAdvance: "SELECT accepted, reason\nFROM ep_aeb_private.compare_and_advance_status_head(\n  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,\n  $7::text, $8::text, $9::bigint, $10::text, $11::text,\n  $12::timestamptz, $13::timestamptz, $14::text\n)";
}>;
type MaybePromise<T> = T | Promise<T>;
type QueryResult = {
    rowCount: number | null;
    rows?: Record<string, unknown>[];
};
export type ProposalToEffectStatusHeadPgClient = {
    query: (text: string, params?: any[]) => Promise<QueryResult>;
    release: () => void;
};
export type ProposalToEffectStatusHeadPgPool = {
    connect: () => Promise<ProposalToEffectStatusHeadPgClient>;
};
export interface ProposalToEffectStatusHeadAcceptance {
    accepted: boolean;
    source: 'advanced' | 'existing' | null;
    reason: string | null;
    verification: StatusVerification;
}
export interface ProposalToEffectStatusHeadAcceptanceInput {
    target: Readonly<StatusTarget>;
    status: unknown;
    /**
     * Trusted verification callback. Its argument is loaded from durable
     * relying-party custody; no presenter-provided predecessor is accepted.
     */
    verify(previousStatus: unknown | undefined): MaybePromise<StatusVerification>;
}
export interface ProposalToEffectStatusHeadStore {
    durable: true;
    readonly tenantId: string;
    readonly relyingPartyId: string;
    accept(input: ProposalToEffectStatusHeadAcceptanceInput): Promise<ProposalToEffectStatusHeadAcceptance>;
}
export interface PostgresProposalToEffectStatusHeadStoreOptions {
    /** Pool authenticated as a tenant-bound member of ep_aeb_executor. */
    pool?: ProposalToEffectStatusHeadPgPool;
    tenantId?: string;
    relyingPartyId?: string;
}
/**
 * Create a durable accepted-head store. The PostgreSQL principal must be bound
 * to tenantId in ep_aeb_private.tenant_principals and inherit ep_aeb_executor.
 */
export declare function createPostgresProposalToEffectStatusHeadStore({ pool, tenantId, relyingPartyId, }?: PostgresProposalToEffectStatusHeadStoreOptions): ProposalToEffectStatusHeadStore;
declare const _default: {
    PROPOSAL_TO_EFFECT_STATUS_HEAD_STORE_VERSION: string;
    PROPOSAL_TO_EFFECT_STATUS_HEAD_TABLE: string;
    PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL: Readonly<{
        get: "SELECT status_digest, sequence, status_state, previous_status_digest,\n  issued_at, next_update, status_json, predecessor_status_json\nFROM ep_aeb_private.get_status_head(\n  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text\n)";
        compareAndAdvance: "SELECT accepted, reason\nFROM ep_aeb_private.compare_and_advance_status_head(\n  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,\n  $7::text, $8::text, $9::bigint, $10::text, $11::text,\n  $12::timestamptz, $13::timestamptz, $14::text\n)";
    }>;
    createPostgresProposalToEffectStatusHeadStore: typeof createPostgresProposalToEffectStatusHeadStore;
};
export default _default;
//# sourceMappingURL=proposal-to-effect-status-head-store.d.ts.map