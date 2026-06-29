/**
 * @emilia-protocol/gate — consumption store (replay defense).
 * @license Apache-2.0
 *
 * A receipt authorizes ONE action, once. The gate consumes a receipt's
 * identifier the first time it is used; any later presentation of the same
 * receipt is a replay and is refused. The default store is in-memory; swap in a
 * Redis/DB-backed store with the same `consume(key)` contract for a fleet.
 */
export class MemoryConsumptionStore {
  constructor() {
    this.seen = new Set();
    this.reserved = new Set();
  }

  /** Returns true the FIRST time a key is seen, false on every replay. */
  async consume(key) {
    if (this.seen.has(key) || this.reserved.has(key)) return false;
    this.seen.add(key);
    return true;
  }

  /** Reserve an id while an action is in flight; blocks concurrent replay. */
  async reserve(key) {
    if (this.seen.has(key) || this.reserved.has(key)) return false;
    this.reserved.add(key);
    return true;
  }

  /** Commit a reserved id after the action succeeds. */
  async commit(key) {
    this.reserved.delete(key);
    this.seen.add(key);
    return true;
  }

  /** Release a reserved id after the action fails; approval stays retryable. */
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

/**
 * Production custody for replay defense: a durable consumption store backed by
 * any shared key-value backend (Redis, Postgres, DynamoDB, ...), so a receipt
 * consumed on one pod/lambda cannot be replayed on another.
 *
 * The backend MUST provide an ATOMIC insert-if-absent — this is the single
 * correctness primitive that makes replay defense sound under concurrency:
 *
 *   backend = {
 *     async addIfAbsent(key, value): boolean  // true iff it inserted (Redis SET NX,
 *                                             // Postgres INSERT .. ON CONFLICT DO NOTHING)
 *     async set(key, value): void             // overwrite
 *     async delete(key): void
 *     async has(key): boolean
 *   }
 *
 * State per receipt id is a single key: 'reserved' while in flight, 'committed'
 * once the action succeeded. reserve() is the atomic gate; a second reserve()
 * (concurrent replay) loses the race and is refused. Optional `ttlSeconds` is
 * passed through to the backend so consumed ids can expire after the receipt's
 * own max age (the gate already rejects stale receipts on freshness).
 */
export function createDurableConsumptionStore(backend, { ttlSeconds } = {}) {
  for (const m of ['addIfAbsent', 'set', 'delete', 'has']) {
    if (typeof backend?.[m] !== 'function') {
      throw new Error(`createDurableConsumptionStore: backend must implement async ${m}(). `
        + 'addIfAbsent MUST be atomic (e.g. Redis SET NX) or replay defense is not fleet-safe.');
    }
  }
  const opt = ttlSeconds ? { ttlSeconds } : undefined;
  return {
    async reserve(key) { return (await backend.addIfAbsent(key, 'reserved', opt)) === true; },
    async commit(key) { await backend.set(key, 'committed', opt); return true; },
    async release(key) { await backend.delete(key); return true; },
    async consume(key) { return (await backend.addIfAbsent(key, 'committed', opt)) === true; },
    async has(key) { return (await backend.has(key)) === true; },
  };
}

/** In-memory reference backend (for tests/single-process). addIfAbsent is atomic in a single thread. */
export function createMemoryBackend() {
  const map = new Map();
  return {
    async addIfAbsent(key, value) { if (map.has(key)) return false; map.set(key, value); return true; },
    async set(key, value) { map.set(key, value); },
    async delete(key) { map.delete(key); },
    async has(key) { return map.has(key); },
    get size() { return map.size; },
  };
}

export default { MemoryConsumptionStore, createDurableConsumptionStore, createMemoryBackend };
