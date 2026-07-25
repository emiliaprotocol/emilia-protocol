/**
 * Runtime counterpart for Conservation of Authority.
 *
 * This module keeps path containment and aggregate sibling conservation
 * separate. A relying party pins one complete parent allocation snapshot to an
 * exact authority head and epoch. Every sibling is checked against that parent,
 * both resource dimensions are summed independently, and reservations cross a
 * single atomic store boundary before they can be committed.
 *
 * The memory store is deterministic conformance infrastructure, not durable
 * custody. The PostgreSQL adapter requires a real transaction callback and
 * serializes every mutation for one relying-party/parent pair.
 */
export declare const AUTHORITY_ALLOCATION_VERSION = "EP-AUTHORITY-ALLOCATION-v1";
export declare const AUTHORITY_ALLOCATION_CURRENT_TABLE = "ep_authority_allocation_current";
export declare const AUTHORITY_ALLOCATION_SNAPSHOT_TABLE = "ep_authority_allocation_snapshots";
export declare const AUTHORITY_ALLOCATION_BRANCH_TABLE = "ep_authority_allocation_branches";
export declare const AUTHORITY_ALLOCATION_RESERVATION_TABLE = "ep_authority_allocation_reservations";
export interface AuthorityAllocationBudget {
    cents: number;
    calls: number;
}
export interface AuthorityAllocationPin {
    relying_party_id: string;
    authority_head: string;
    authority_epoch: number;
}
export interface AuthorityBranchAllocation {
    allocation_id: string;
    parent_id: string;
    actions: readonly string[];
    audiences: readonly string[];
    budget: AuthorityAllocationBudget;
    expires_at: string;
}
export interface AuthorityAllocationSnapshot {
    version: typeof AUTHORITY_ALLOCATION_VERSION;
    relying_party_id: string;
    parent_id: string;
    authority_head: string;
    authority_epoch: number;
    actions: readonly string[];
    audiences: readonly string[];
    budget: AuthorityAllocationBudget;
    expires_at: string;
    sibling_allocations: readonly AuthorityBranchAllocation[];
}
export interface AuthorityAllocationReservationRequest {
    relying_party_id: string;
    parent_id: string;
    allocation_id: string;
    reservation_id: string;
    authority_head: string;
    authority_epoch: number;
    budget: AuthorityAllocationBudget;
    /** Used by the deterministic memory adapter. PostgreSQL uses database time. */
    now?: string | number | Date;
}
export interface AuthorityAllocationOwner {
    owner_token: string;
    fencing_token: number;
    authority_head: string;
    authority_epoch: number;
}
export interface AuthorityAllocationFinalizeRequest {
    relying_party_id: string;
    parent_id: string;
    allocation_id: string;
    reservation_id: string;
    authority_head: string;
    authority_epoch: number;
    owner_token: string;
    fencing_token: number;
}
export type AuthorityAllocationRefusalReason = 'allocation_not_found' | 'allocation_expired' | 'authority_pin_mismatch' | 'budget_exceeded' | 'reservation_replayed' | 'reservation_not_found' | 'reservation_owner_mismatch' | 'reservation_already_committed' | 'reservation_already_released' | 'snapshot_conflict' | 'stale_authority_epoch' | 'reservations_in_flight';
export type AuthorityAllocationInstallResult = {
    ok: true;
    installed: boolean;
    snapshot_fingerprint: string;
} | {
    ok: false;
    reason: AuthorityAllocationRefusalReason;
};
export type AuthorityAllocationReservationResult = {
    ok: true;
    reservation_id: string;
    allocation_id: string;
    budget: AuthorityAllocationBudget;
    remaining: AuthorityAllocationBudget;
    owner: AuthorityAllocationOwner;
} | {
    ok: false;
    reason: AuthorityAllocationRefusalReason;
};
export type AuthorityAllocationFinalizeResult = {
    ok: true;
    state: 'committed' | 'released';
} | {
    ok: false;
    reason: AuthorityAllocationRefusalReason;
};
export interface AuthorityAllocationReservationView {
    reservation_id: string;
    allocation_id: string;
    authority_head: string;
    authority_epoch: number;
    budget: AuthorityAllocationBudget;
    state: 'reserved' | 'committed' | 'released';
    fencing_token: number;
}
export interface AuthorityAllocationStateView {
    snapshot: AuthorityAllocationSnapshot;
    snapshot_fingerprint: string;
    usage: {
        parent: {
            reserved: AuthorityAllocationBudget;
            committed: AuthorityAllocationBudget;
        };
        branches: Record<string, {
            reserved: AuthorityAllocationBudget;
            committed: AuthorityAllocationBudget;
        }>;
    };
    reservations: AuthorityAllocationReservationView[];
}
export interface AuthorityAllocationStore {
    readonly durable: boolean;
    installSnapshot(snapshot: AuthorityAllocationSnapshot, pin: AuthorityAllocationPin): Promise<AuthorityAllocationInstallResult>;
    reserve(request: AuthorityAllocationReservationRequest): Promise<AuthorityAllocationReservationResult>;
    commit(request: AuthorityAllocationFinalizeRequest): Promise<AuthorityAllocationFinalizeResult>;
    release(request: AuthorityAllocationFinalizeRequest): Promise<AuthorityAllocationFinalizeResult>;
    inspect(pin: AuthorityAllocationPin & {
        parent_id: string;
    }): Promise<AuthorityAllocationStateView | null>;
}
export declare class AuthorityAllocationValidationError extends TypeError {
    readonly code: string;
    constructor(code: string, message: string);
}
type QueryRow = Record<string, unknown>;
export interface AuthorityAllocationPostgresQueryResult {
    rowCount: number | null;
    rows: QueryRow[];
}
export type AuthorityAllocationPostgresQuery = (text: string, params?: readonly unknown[]) => Promise<AuthorityAllocationPostgresQueryResult>;
export interface AuthorityAllocationPostgresOptions {
    /**
     * Must run the callback in one PostgreSQL transaction. Database errors must
     * reject the callback so the transaction is rolled back.
     */
    transaction<T>(callback: (query: AuthorityAllocationPostgresQuery) => Promise<T>): Promise<T>;
}
/**
 * Validate and normalize a complete authoritative allocation snapshot.
 * Throws AuthorityAllocationValidationError on every malformed or widening
 * condition and returns a detached, deterministically ordered snapshot.
 */
export declare function validateAuthorityAllocationSnapshot(input: AuthorityAllocationSnapshot, pin: AuthorityAllocationPin): AuthorityAllocationSnapshot;
/**
 * Deterministic linearizable in-memory implementation for conformance tests.
 * Owner capabilities and fences are deterministic and therefore unsuitable
 * for production. The store is explicitly marked non-durable.
 */
export declare function createMemoryAuthorityAllocationStore(): AuthorityAllocationStore;
/**
 * PostgreSQL schema contract. Historical snapshots are append-only;
 * ep_authority_allocation_current identifies the one exact head+epoch that can
 * accept reservations. Reservation IDs are replay-fenced across all epochs for
 * one relying-party/parent pair, and owner capabilities are stored only as
 * domain-separated SHA-256 digests.
 */
export declare const AUTHORITY_ALLOCATION_DDL = "CREATE TABLE IF NOT EXISTS ep_authority_allocation_snapshots (\n  relying_party_id    TEXT NOT NULL CHECK (octet_length(relying_party_id) BETWEEN 1 AND 512),\n  parent_id           TEXT NOT NULL CHECK (octet_length(parent_id) BETWEEN 1 AND 512),\n  authority_head      TEXT NOT NULL CHECK (authority_head ~ '^sha256:[0-9a-f]{64}$'),\n  authority_epoch     BIGINT NOT NULL CHECK (authority_epoch >= 0),\n  snapshot_fingerprint TEXT NOT NULL CHECK (snapshot_fingerprint ~ '^sha256:[0-9a-f]{64}$'),\n  snapshot_json       JSONB NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),\n  installed_at        TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  PRIMARY KEY (relying_party_id, parent_id, authority_head, authority_epoch)\n);\nCREATE TABLE IF NOT EXISTS ep_authority_allocation_current (\n  relying_party_id    TEXT NOT NULL,\n  parent_id           TEXT NOT NULL,\n  authority_head      TEXT NOT NULL,\n  authority_epoch     BIGINT NOT NULL,\n  snapshot_fingerprint TEXT NOT NULL,\n  next_fencing_token  BIGINT NOT NULL DEFAULT 1 CHECK (next_fencing_token > 0),\n  PRIMARY KEY (relying_party_id, parent_id),\n  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch)\n    REFERENCES ep_authority_allocation_snapshots\n      (relying_party_id, parent_id, authority_head, authority_epoch)\n);\nCREATE TABLE IF NOT EXISTS ep_authority_allocation_branches (\n  relying_party_id TEXT NOT NULL,\n  parent_id        TEXT NOT NULL,\n  authority_head   TEXT NOT NULL,\n  authority_epoch  BIGINT NOT NULL,\n  allocation_id    TEXT NOT NULL CHECK (octet_length(allocation_id) BETWEEN 1 AND 512),\n  budget_cents     BIGINT NOT NULL CHECK (budget_cents >= 0),\n  budget_calls     BIGINT NOT NULL CHECK (budget_calls >= 0),\n  expires_at       TIMESTAMPTZ NOT NULL,\n  PRIMARY KEY (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id),\n  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch)\n    REFERENCES ep_authority_allocation_snapshots\n      (relying_party_id, parent_id, authority_head, authority_epoch)\n);\nCREATE TABLE IF NOT EXISTS ep_authority_allocation_reservations (\n  relying_party_id TEXT NOT NULL,\n  parent_id        TEXT NOT NULL,\n  authority_head   TEXT NOT NULL,\n  authority_epoch  BIGINT NOT NULL,\n  allocation_id    TEXT NOT NULL,\n  reservation_id   TEXT NOT NULL CHECK (octet_length(reservation_id) BETWEEN 1 AND 512),\n  budget_cents     BIGINT NOT NULL CHECK (budget_cents >= 0),\n  budget_calls     BIGINT NOT NULL CHECK (budget_calls >= 0),\n  state            TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'released')),\n  owner_digest     TEXT NOT NULL CHECK (owner_digest ~ '^sha256:[0-9a-f]{64}$'),\n  fencing_token    BIGINT NOT NULL CHECK (fencing_token > 0),\n  reserved_at      TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\n  finalized_at     TIMESTAMPTZ NULL,\n  PRIMARY KEY (relying_party_id, parent_id, reservation_id),\n  UNIQUE (relying_party_id, parent_id, fencing_token),\n  FOREIGN KEY (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id)\n    REFERENCES ep_authority_allocation_branches\n      (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id),\n  CHECK (\n    (state = 'reserved' AND finalized_at IS NULL)\n    OR (state IN ('committed', 'released') AND finalized_at IS NOT NULL)\n  )\n);\nREVOKE ALL ON ep_authority_allocation_snapshots FROM PUBLIC;\nREVOKE ALL ON ep_authority_allocation_current FROM PUBLIC;\nREVOKE ALL ON ep_authority_allocation_branches FROM PUBLIC;\nREVOKE ALL ON ep_authority_allocation_reservations FROM PUBLIC;";
/** Exact statements used by createPostgresAuthorityAllocationStore(). */
export declare const AUTHORITY_ALLOCATION_SQL: Readonly<{
    lockParent: "SELECT pg_advisory_xact_lock(pg_catalog.hashtextextended(pg_catalog.jsonb_build_array($1::text, $2::text)::text, 0))";
    readCurrent: "SELECT authority_head, authority_epoch, snapshot_fingerprint, next_fencing_token, clock_timestamp() AS database_now FROM ep_authority_allocation_current WHERE relying_party_id = $1 AND parent_id = $2 FOR UPDATE";
    activeReservations: "SELECT count(*)::bigint AS active FROM ep_authority_allocation_reservations WHERE relying_party_id = $1 AND parent_id = $2 AND state = 'reserved'";
    insertSnapshot: "INSERT INTO ep_authority_allocation_snapshots (relying_party_id, parent_id, authority_head, authority_epoch, snapshot_fingerprint, snapshot_json) VALUES ($1, $2, $3, $4, $5, $6::jsonb)";
    insertBranch: "INSERT INTO ep_authority_allocation_branches (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id, budget_cents, budget_calls, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz)";
    insertCurrent: "INSERT INTO ep_authority_allocation_current (relying_party_id, parent_id, authority_head, authority_epoch, snapshot_fingerprint) VALUES ($1, $2, $3, $4, $5)";
    advanceCurrent: "UPDATE ep_authority_allocation_current SET authority_head = $3, authority_epoch = $4, snapshot_fingerprint = $5 WHERE relying_party_id = $1 AND parent_id = $2 AND authority_epoch < $4";
    readSnapshot: "SELECT snapshot_json, snapshot_fingerprint FROM ep_authority_allocation_snapshots WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4";
    readBranch: "SELECT budget_cents, budget_calls, expires_at FROM ep_authority_allocation_branches WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 AND allocation_id = $5";
    readReservation: "SELECT allocation_id, authority_head, authority_epoch, budget_cents, budget_calls, state, owner_digest, fencing_token FROM ep_authority_allocation_reservations WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3";
    readUsage: "SELECT allocation_id, state, COALESCE(sum(budget_cents), 0)::bigint AS cents, COALESCE(sum(budget_calls), 0)::bigint AS calls FROM ep_authority_allocation_reservations WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 AND state IN ('reserved', 'committed') GROUP BY allocation_id, state";
    nextFence: "UPDATE ep_authority_allocation_current SET next_fencing_token = next_fencing_token + 1 WHERE relying_party_id = $1 AND parent_id = $2 AND authority_head = $3 AND authority_epoch = $4 RETURNING next_fencing_token - 1 AS fencing_token";
    insertReservation: "INSERT INTO ep_authority_allocation_reservations (relying_party_id, parent_id, authority_head, authority_epoch, allocation_id, reservation_id, budget_cents, budget_calls, state, owner_digest, fencing_token) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'reserved', $9, $10)";
    commitReservation: "UPDATE ep_authority_allocation_reservations SET state = 'committed', finalized_at = transaction_timestamp() WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3 AND allocation_id = $4 AND authority_head = $5 AND authority_epoch = $6 AND state = 'reserved' AND owner_digest = $7 AND fencing_token = $8";
    releaseReservation: "UPDATE ep_authority_allocation_reservations SET state = 'released', finalized_at = transaction_timestamp() WHERE relying_party_id = $1 AND parent_id = $2 AND reservation_id = $3 AND allocation_id = $4 AND authority_head = $5 AND authority_epoch = $6 AND state = 'reserved' AND owner_digest = $7 AND fencing_token = $8";
    inspectReservations: "SELECT reservation_id, allocation_id, authority_head, authority_epoch, budget_cents, budget_calls, state, fencing_token FROM ep_authority_allocation_reservations WHERE relying_party_id = $1 AND parent_id = $2 ORDER BY fencing_token";
}>;
/**
 * Durable adapter boundary for PostgreSQL. Atomicity depends on the supplied
 * transaction callback actually using one PostgreSQL transaction; the adapter
 * additionally takes a transaction-scoped advisory lock for every parent.
 */
export declare function createPostgresAuthorityAllocationStore(options: AuthorityAllocationPostgresOptions): AuthorityAllocationStore;
export declare function isDurableAuthorityAllocationStore(store: unknown): store is AuthorityAllocationStore;
export {};
//# sourceMappingURL=authority-allocation.d.ts.map