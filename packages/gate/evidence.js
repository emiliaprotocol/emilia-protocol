/**
 * @emilia-protocol/gate — evidence log (tamper-detecting audit of decisions).
 * @license Apache-2.0
 *
 * Every gate decision — allow or deny — appends a hash-chained record. Each
 * record commits to the previous one, so removing or altering any decision
 * breaks the chain and `verify()` catches it. This is the compliance and
 * insurance artifact: a provable account of exactly which consequential actions
 * were authorized, refused, and why. Default sink is in-memory; pass `sink` to
 * stream records to storage. This local chain detects alteration only when the
 * verifier receives its complete history from genesis; a sink alone cannot
 * prevent truncation, restart-from-genesis, or cross-replica forks. Use
 * createAtomicEvidenceLog for a shared production head.
 *
 * Hashing is over CANONICAL JSON (sorted keys) so the same logical record hashes
 * identically across systems and languages — a plain JSON.stringify is
 * insertion-order dependent and would make cross-system verification fragile.
 *
 * `strict` mode makes the log fail CLOSED: if a durable `sink` write fails, the
 * record is NOT appended and `record()` throws. The gate uses this so it never
 * authorizes an action it cannot durably account for. In non-strict (observe)
 * mode a sink failure is best-effort and swallowed.
 */
import crypto from 'node:crypto';

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

/** Canonical JSON (recursive sorted keys) — matches @emilia-protocol/verify. */
function canonical(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',')}}`;
  }
  return JSON.stringify(v);
}

export function createEvidenceLog({ sink, strict = false } = {}) {
  const records = [];
  let prev = 'genesis';

  return {
    // A sink can persist this process-local chain, but it cannot make the head
    // atomic across replicas or continue it after restart. Never advertise the
    // local logger as a fleet-safe production ledger.
    durable: false,
    persisted: typeof sink === 'function' && strict === true,
    strict: strict === true,
    forkAware: false,
    atomicAppend: false,
    async record(entry) {
      // Deep-copy the caller's entry: a shallow spread embeds live references to
      // nested objects, so a caller mutating them after record() would silently
      // corrupt the hash-chained evidence record (and anything a sink persisted).
      const snapshot = entry && typeof entry === 'object' ? structuredClone(entry) : entry;
      const body = { seq: records.length, prev_hash: prev, ...snapshot };
      const hash = sha256hex(canonical(body));
      const rec = { ...body, hash };
      if (sink) {
        try {
          await sink(rec);
        } catch (e) {
          // Fail closed in strict mode: do NOT advance the chain, surface the
          // failure so the caller (the gate) can refuse the action. The seq is
          // left unconsumed so a retry produces a consistent chain.
          if (strict) {
            const err = new Error('evidence_sink_failed');
            err.cause = e;
            throw err;
          }
          /* non-strict (observe): best-effort, swallow — never break the gate */
        }
      }
      records.push(rec);
      prev = hash;
      return rec;
    },

    all() {
      return records.slice();
    },

    /** Recompute the chain; detects any altered or removed record. */
    verify() {
      let p = 'genesis';
      for (const r of records) {
        const { hash, ...body } = r;
        if (body.prev_hash !== p) return { ok: false, at: r.seq, reason: 'prev_hash_mismatch' };
        if (sha256hex(canonical(body)) !== hash) return { ok: false, at: r.seq, reason: 'hash_mismatch' };
        p = hash;
      }
      return { ok: true, length: records.length, head: p === 'genesis' ? null : p };
    },
  };
}

const LOG_HEX_256 = /^[0-9a-f]{64}$/;
const LOG_RESERVED_FIELDS = new Set(['seq', 'prev_hash', 'record_id', 'hash']);

/** Verify one logger acknowledgement independently of the logger that emitted it. */
export function verifyEvidenceRecord(record, { atomicRequired = false, expectedEntry } = {}) {
  try {
    if (!record || typeof record !== 'object' || Array.isArray(record)
        || !Number.isSafeInteger(record.seq) || record.seq < 0
        || (record.prev_hash !== 'genesis' && !LOG_HEX_256.test(record.prev_hash))
        || !LOG_HEX_256.test(record.hash)) return false;
    const hasRecordId = Object.prototype.hasOwnProperty.call(record, 'record_id');
    if ((atomicRequired && !hasRecordId)
        || (hasRecordId && (typeof record.record_id !== 'string'
          || record.record_id.length < 16 || record.record_id.length > 256))) return false;
    const { hash, ...body } = record;
    if (sha256hex(canonical(body)) !== hash) return false;
    if (expectedEntry !== undefined) {
      if (!expectedEntry || typeof expectedEntry !== 'object' || Array.isArray(expectedEntry)) return false;
      const entry = Object.fromEntries(
        Object.entries(record).filter(([key]) => !LOG_RESERVED_FIELDS.has(key)),
      );
      if (canonical(entry) !== canonical(expectedEntry)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function assertLogEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('atomic evidence entry must be an object');
  }
  for (const field of LOG_RESERVED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new Error(`atomic evidence entry must not supply reserved field ${field}`);
    }
  }
  const stack = [{ value: entry, depth: 0 }];
  const seen = new WeakSet();
  let nodes = 0;
  let stringBytes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop();
    if (++nodes > 50000 || depth > 64) throw new Error('atomic evidence entry exceeds resource limits');
    if (value === null || typeof value === 'boolean') continue;
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) throw new Error('atomic evidence entry contains a non-safe integer');
      continue;
    }
    if (typeof value === 'string') {
      stringBytes += Buffer.byteLength(value, 'utf8');
      if (stringBytes > 1024 * 1024) throw new Error('atomic evidence entry exceeds string limit');
      continue;
    }
    if (typeof value !== 'object') throw new Error('atomic evidence entry is not canonical JSON');
    if (seen.has(value)) throw new Error('atomic evidence entry contains a cycle or alias');
    seen.add(value);
    if (Array.isArray(value)) {
      for (const child of value) stack.push({ value: child, depth: depth + 1 });
    } else {
      for (const [key, child] of Object.entries(value)) {
        stringBytes += Buffer.byteLength(key, 'utf8');
        if (stringBytes > 1024 * 1024) throw new Error('atomic evidence entry exceeds string limit');
        stack.push({ value: child, depth: depth + 1 });
      }
    }
  }
}

function validateAtomicRecord(record, expectedId, expectedEntry, expectedRecord = null) {
  return record?.record_id === expectedId
    && verifyEvidenceRecord(record, { atomicRequired: true, expectedEntry })
    && (expectedRecord === null || canonical(record) === canonical(expectedRecord));
}

function validHead(head) {
  return head === null || Boolean(head && Number.isSafeInteger(head.seq) && head.seq >= 0 && LOG_HEX_256.test(head.hash));
}

/**
 * Fleet-safe, fail-closed evidence log over an atomic shared-head backend.
 *
 * Backend contract (all operations are scoped by streamId):
 *   readHead(streamId) -> null | { seq, hash }
 *   getById(streamId, recordId) -> null | record
 *   appendIfHead(streamId, expectedHeadHash|null, record) -> boolean
 *   readAll(streamId) -> record[]                    // optional, for verify/all
 *
 * appendIfHead MUST atomically compare the current head, append the immutable
 * record, reject duplicate record_id, and advance the head in one durable
 * transaction. A true return MUST provide immediate read-after-write visibility
 * through getById. `backend.durable === true` is a deployment capability
 * assertion; this module tests the protocol but cannot prove storage hardware
 * semantics.
 */
export function createAtomicEvidenceLog(backend, {
  streamId = 'emilia-gate',
  maxRetries = 32,
  recordIdFactory = () => crypto.randomUUID(),
} = {}) {
  for (const method of ['readHead', 'getById', 'appendIfHead']) {
    if (typeof backend?.[method] !== 'function') {
      throw new Error(`createAtomicEvidenceLog: backend must implement async ${method}()`);
    }
  }
  if (typeof streamId !== 'string' || !streamId || streamId.length > 256) {
    throw new Error('createAtomicEvidenceLog: streamId must be a non-empty string of at most 256 characters');
  }
  if (!Number.isSafeInteger(maxRetries) || maxRetries < 1 || maxRetries > 1024) {
    throw new Error('createAtomicEvidenceLog: maxRetries must be an integer from 1 to 1024');
  }
  if (typeof recordIdFactory !== 'function') {
    throw new Error('createAtomicEvidenceLog: recordIdFactory must be a function');
  }

  async function recover(recordId, snapshot, expectedRecord = null) {
    const existing = await backend.getById(streamId, recordId);
    if (existing === null || existing === undefined) return null;
    if (!validateAtomicRecord(existing, recordId, snapshot, expectedRecord)) {
      throw new Error('atomic evidence backend returned a conflicting record_id');
    }
    return structuredClone(existing);
  }

  return {
    durable: backend.durable === true,
    persisted: backend.durable === true,
    strict: true,
    forkAware: true,
    atomicAppend: true,
    streamId,

    async record(entry) {
      const snapshot = structuredClone(entry);
      assertLogEntry(snapshot);
      const recordId = recordIdFactory();
      if (typeof recordId !== 'string' || recordId.length < 16 || recordId.length > 256) {
        throw new Error('atomic evidence record id must be a string of 16 to 256 characters');
      }

      for (let attempt = 0; attempt < maxRetries; attempt++) {
        const recovered = await recover(recordId, snapshot);
        if (recovered) return recovered;

        const head = await backend.readHead(streamId);
        if (!validHead(head)) throw new Error('atomic evidence backend returned a malformed head');
        const seq = head === null ? 0 : head.seq + 1;
        const prevHash = head === null ? 'genesis' : head.hash;
        const body = { seq, prev_hash: prevHash, record_id: recordId, ...snapshot };
        const record = { ...body, hash: sha256hex(canonical(body)) };
        try {
          if ((await backend.appendIfHead(streamId, head?.hash ?? null, record)) === true) {
            const persisted = await recover(recordId, snapshot, record);
            if (persisted) return persisted;
            throw new Error('atomic_evidence_append_not_observable');
          }
        } catch (error) {
          // The append may have linearized before its response was lost. Recover
          // by stable id; if no record is visible, fail closed and let the caller
          // retain/freeze its execution reservation.
          const afterError = await recover(recordId, snapshot, record);
          if (afterError) return afterError;
          const wrapped = new Error('atomic_evidence_append_indeterminate');
          wrapped.cause = error;
          throw wrapped;
        }
      }
      throw new Error('atomic_evidence_contention_limit');
    },

    async all() {
      if (typeof backend.readAll !== 'function') throw new Error('atomic evidence backend does not expose readAll()');
      const records = await backend.readAll(streamId);
      if (!Array.isArray(records)) throw new Error('atomic evidence backend returned malformed history');
      return structuredClone(records);
    },

    async verify() {
      try {
        if (typeof backend.readAll !== 'function') return { ok: false, reason: 'read_all_unavailable' };
        const records = await backend.readAll(streamId);
        if (!Array.isArray(records)) return { ok: false, reason: 'malformed_history' };
        let prev = 'genesis';
        const ids = new Set();
        for (let index = 0; index < records.length; index++) {
          const record = records[index];
          if (!record || typeof record !== 'object' || Array.isArray(record)
              || record.seq !== index || record.prev_hash !== prev
              || typeof record.record_id !== 'string' || ids.has(record.record_id)) {
            return { ok: false, at: index, reason: 'sequence_or_predecessor_mismatch' };
          }
          const { hash, ...body } = record;
          if (!LOG_HEX_256.test(hash) || sha256hex(canonical(body)) !== hash) {
            return { ok: false, at: index, reason: 'hash_mismatch' };
          }
          ids.add(record.record_id);
          prev = hash;
        }
        const head = await backend.readHead(streamId);
        const expectedHead = records.length === 0 ? null : { seq: records.length - 1, hash: prev };
        if (canonical(head) !== canonical(expectedHead)) return { ok: false, reason: 'head_mismatch' };
        return { ok: true, length: records.length, head: expectedHead?.hash ?? null };
      } catch {
        return { ok: false, reason: 'backend_read_failed_or_malformed' };
      }
    },
  };
}

/** In-memory contract model for tests. It is intentionally not durable. */
export function createMemoryAtomicEvidenceBackend() {
  const streams = new Map();
  const state = (streamId) => {
    if (!streams.has(streamId)) streams.set(streamId, { records: [], byId: new Map() });
    return streams.get(streamId);
  };
  return {
    durable: false,
    async readHead(streamId) {
      const records = state(streamId).records;
      const record = records[records.length - 1];
      return record ? { seq: record.seq, hash: record.hash } : null;
    },
    async getById(streamId, recordId) {
      return structuredClone(state(streamId).byId.get(recordId) ?? null);
    },
    async appendIfHead(streamId, expectedHeadHash, record) {
      const s = state(streamId);
      const head = s.records[s.records.length - 1] ?? null;
      const actual = head?.hash ?? null;
      if (actual !== expectedHeadHash || s.byId.has(record.record_id)
          || record.seq !== s.records.length || record.prev_hash !== (head?.hash ?? 'genesis')) return false;
      const snapshot = structuredClone(record);
      s.records.push(snapshot);
      s.byId.set(snapshot.record_id, snapshot);
      return true;
    },
    async readAll(streamId) { return structuredClone(state(streamId).records); },
  };
}

export const __atomicEvidenceSecurityInternals = Object.freeze({
  canonical,
  assertLogEntry,
  validateAtomicRecord,
  validHead,
});

export default {
  createEvidenceLog,
  verifyEvidenceRecord,
  createAtomicEvidenceLog,
  createMemoryAtomicEvidenceBackend,
};
