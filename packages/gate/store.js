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
  }

  /** Returns true the FIRST time a key is seen, false on every replay. */
  async consume(key) {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    return true;
  }

  async has(key) {
    return this.seen.has(key);
  }

  get size() {
    return this.seen.size;
  }
}

export default { MemoryConsumptionStore };
