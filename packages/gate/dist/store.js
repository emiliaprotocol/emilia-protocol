// @ts-nocheck
/**
 * @emilia-protocol/gate — consumption store (replay defense).
 * @license Apache-2.0
 *
 * A receipt authorizes ONE action, once. The gate consumes a receipt's
 * identifier the first time it is used; any later presentation of the same
 * receipt is a replay and is refused. The in-memory store is an explicit
 * test/demo opt-in; security-bearing gates use the durable contract below.
 */
export class MemoryConsumptionStore {
    durable;
    ownershipFenced;
    permanentConsumption;
    seen;
    reserved;
    constructor() {
        this.durable = false;
        this.ownershipFenced = false;
        this.permanentConsumption = false;
        this.seen = new Set();
        this.reserved = new Set();
    }
    /** Returns true the FIRST time a key is seen, false on every replay. */
    async consume(key) {
        if (this.seen.has(key) || this.reserved.has(key))
            return false;
        this.seen.add(key);
        return true;
    }
    /** Reserve an id while an action is in flight; blocks concurrent replay. */
    async reserve(key) {
        if (this.seen.has(key) || this.reserved.has(key))
            return false;
        this.reserved.add(key);
        return true;
    }
    /** Commit a reserved id after an external-effect attempt begins. */
    async commit(key) {
        this.reserved.delete(key);
        this.seen.add(key);
        return true;
    }
    /** Release only when the caller can prove the external effect never began. */
    async release(key) {
        this.reserved.delete(key);
        return true;
    }
    async has(key) {
        return this.seen.has(key) || this.reserved.has(key);
    }
    get size() {
        return this.seen.size;
    }
}
export const DURABLE_CONSUMPTION_VERSION = 'EP-GATE-DURABLE-CONSUMPTION-v2';
/** Capability contract required by security-bearing Gate execution paths. */
export function isSecureConsumptionStore(store) {
    if (!store || typeof store !== 'object')
        return false;
    return store.durable === true
        && store.ownershipFenced === true
        && store.permanentConsumption === true
        && typeof store.consume === 'function'
        && typeof store.reserve === 'function'
        && typeof store.commit === 'function';
}
const COMMITTED_VALUE = 'committed:v2';
const RESERVED_PREFIX = 'reserved:v2:';
function defaultReservationToken() {
    if (typeof globalThis.crypto?.randomUUID !== 'function') {
        throw new Error('secure crypto.randomUUID() is required for durable reservation fencing');
    }
    return globalThis.crypto.randomUUID();
}
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
export function createDurableConsumptionStore(backend, { ttlSeconds, reservationTokenFactory = defaultReservationToken } = {}) {
    for (const m of ['addIfAbsent', 'compareAndSet', 'deleteIfValue', 'has']) {
        if (typeof backend?.[m] !== 'function') {
            throw new Error(`createDurableConsumptionStore: backend must implement async ${m}(). `
                + 'addIfAbsent and conditional transitions MUST be atomic or replay defense is not fleet-safe.');
        }
    }
    if (typeof reservationTokenFactory !== 'function') {
        throw new Error('createDurableConsumptionStore: reservationTokenFactory must be a function');
    }
    if (ttlSeconds !== undefined && ttlSeconds !== null
        && (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0)) {
        throw new Error('createDurableConsumptionStore: ttlSeconds must be a positive safe integer when supplied');
    }
    const opt = ttlSeconds ? { ttlSeconds } : undefined;
    const ownedReservations = new Map();
    function ownedValue(key) {
        const token = ownedReservations.get(key);
        if (!token) {
            throw new Error(`durable consumption transition refused: this store does not own reservation ${key}`);
        }
        return `${RESERVED_PREFIX}${token}`;
    }
    return {
        durable: backend.durable === true,
        ownershipFenced: true,
        permanentConsumption: ttlSeconds === undefined || ttlSeconds === null,
        retentionSeconds: ttlSeconds ?? null,
        async health() {
            if (typeof backend.health !== 'function')
                return { ok: false, reason: 'backend_health_unavailable' };
            return backend.health();
        },
        async reserve(key) {
            const token = reservationTokenFactory();
            if (typeof token !== 'string' || token.length < 16) {
                throw new Error('reservationTokenFactory must return an unpredictable string of at least 16 characters');
            }
            const inserted = (await backend.addIfAbsent(key, `${RESERVED_PREFIX}${token}`)) === true;
            if (inserted)
                ownedReservations.set(key, token);
            return inserted;
        },
        async commit(key) {
            const expected = ownedValue(key);
            const changed = await backend.compareAndSet(key, expected, COMMITTED_VALUE, opt);
            if (changed !== true) {
                throw new Error(`durable consumption commit refused: reservation ownership was lost for ${key}`);
            }
            ownedReservations.delete(key);
            return true;
        },
        async release(key) {
            const expected = ownedValue(key);
            const deleted = await backend.deleteIfValue(key, expected);
            ownedReservations.delete(key);
            if (deleted !== true) {
                throw new Error(`durable consumption release refused: reservation ownership was lost for ${key}`);
            }
            return true;
        },
        async consume(key) { return (await backend.addIfAbsent(key, COMMITTED_VALUE, opt)) === true; },
        async has(key) { return (await backend.has(key)) === true; },
    };
}
/** In-memory reference backend (for tests/single-process). addIfAbsent is atomic in a single thread. */
export function createMemoryBackend() {
    const map = new Map();
    return {
        durable: false,
        async addIfAbsent(key, value) { if (map.has(key))
            return false; map.set(key, value); return true; },
        async compareAndSet(key, expected, replacement) {
            if (map.get(key) !== expected)
                return false;
            map.set(key, replacement);
            return true;
        },
        async deleteIfValue(key, expected) {
            if (map.get(key) !== expected)
                return false;
            return map.delete(key);
        },
        async has(key) { return map.has(key); },
        async get(key) { return map.get(key); },
        get size() { return map.size; },
    };
}
export default {
    MemoryConsumptionStore,
    createDurableConsumptionStore,
    createMemoryBackend,
    isSecureConsumptionStore,
    DURABLE_CONSUMPTION_VERSION,
};
//# sourceMappingURL=store.js.map