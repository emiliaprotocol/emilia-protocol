/**
 * @emilia-protocol/gate — consumption store (replay defense).
 * @license Apache-2.0
 *
 * A receipt authorizes ONE action, once. The gate consumes a receipt's
 * identifier the first time it is used; any later presentation of the same
 * receipt is a replay and is refused. The in-memory store is an explicit
 * test/demo opt-in; security-bearing gates use the durable contract below.
 */
export declare class MemoryConsumptionStore {
    durable: boolean;
    ownershipFenced: boolean;
    permanentConsumption: boolean;
    seen: Set<string>;
    reserved: Set<string>;
    constructor();
    /** Returns true the FIRST time a key is seen, false on every replay. */
    consume(key: any): Promise<boolean>;
    /** Reserve an id while an action is in flight; blocks concurrent replay. */
    reserve(key: any): Promise<boolean>;
    /** Commit a reserved id after an external-effect attempt begins. */
    commit(key: any): Promise<boolean>;
    /** Release only when the caller can prove the external effect never began. */
    release(key: any): Promise<boolean>;
    has(key: any): Promise<boolean>;
    get size(): number;
}
export declare const DURABLE_CONSUMPTION_VERSION = "EP-GATE-DURABLE-CONSUMPTION-v2";
/** Capability contract required by security-bearing Gate execution paths. */
export declare function isSecureConsumptionStore(store: any): boolean;
/**
 * Production custody for replay defense: a durable consumption store backed by
 * any shared key-value backend (Redis, Postgres, DynamoDB, ...), so a receipt
 * consumed on one pod/lambda cannot be replayed on another.
 *
 * The backend MUST provide atomic insert-if-absent plus atomic conditional
 * transition and delete. Together they make replay defense and reservation
 * ownership sound under concurrency:
 *
 *   backend = {
 *     async addIfAbsent(key, value): boolean
 *     async compareAndSet(key, expected, replacement): boolean
 *     async deleteIfValue(key, expected): boolean
 *     async has(key): boolean
 *   }
 *
 * State per receipt id is a single ownership-fenced value. A reservation is
 * `reserved:v2:<random token>` and only the store instance holding that token
 * can commit or release it. This prevents a delayed worker from deleting or
 * committing a newer worker's reservation after timeout/failover.
 *
 * Reservations deliberately receive NO TTL. A crash after an external effect
 * has begun is an indeterminate outcome, and automatically reopening the key
 * would permit a duplicate effect. Operators must reconcile abandoned
 * reservations. `ttlSeconds` applies only after a value is committed, when the
 * receipt's own freshness window independently prevents reuse.
 */
/**
 * @param {any} backend
 * @param {{ ttlSeconds?: number, reservationTokenFactory?: () => string }} [options]
 */
export declare function createDurableConsumptionStore(backend: any, { ttlSeconds, reservationTokenFactory }?: {
    ttlSeconds?: number | null;
    reservationTokenFactory?: () => string;
}): {
    durable: boolean;
    ownershipFenced: boolean;
    permanentConsumption: boolean;
    retentionSeconds: number | null;
    health(): Promise<any>;
    reserve(key: any): Promise<boolean>;
    commit(key: any): Promise<boolean>;
    release(key: any): Promise<boolean>;
    consume(key: any): Promise<boolean>;
    has(key: any): Promise<boolean>;
};
/** In-memory reference backend (for tests/single-process). addIfAbsent is atomic in a single thread. */
export declare function createMemoryBackend(): {
    durable: boolean;
    addIfAbsent(key: any, value: any): Promise<boolean>;
    compareAndSet(key: any, expected: any, replacement: any): Promise<boolean>;
    deleteIfValue(key: any, expected: any): Promise<boolean>;
    has(key: any): Promise<boolean>;
    get(key: any): Promise<any>;
    readonly size: number;
};
declare const _default: {
    MemoryConsumptionStore: typeof MemoryConsumptionStore;
    createDurableConsumptionStore: typeof createDurableConsumptionStore;
    createMemoryBackend: typeof createMemoryBackend;
    isSecureConsumptionStore: typeof isSecureConsumptionStore;
    DURABLE_CONSUMPTION_VERSION: string;
};
export default _default;
//# sourceMappingURL=store.d.ts.map