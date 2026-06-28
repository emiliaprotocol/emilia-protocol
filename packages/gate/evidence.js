/**
 * @emilia-protocol/gate — evidence log (tamper-evident audit of decisions).
 * @license Apache-2.0
 *
 * Every gate decision — allow or deny — appends a hash-chained record. Each
 * record commits to the previous one, so removing or altering any decision
 * breaks the chain and `verify()` catches it. This is the compliance and
 * insurance artifact: a provable account of exactly which consequential actions
 * were authorized, refused, and why. Default sink is in-memory; pass `sink` to
 * stream records to durable/append-only storage.
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
    async record(entry) {
      const body = { seq: records.length, prev_hash: prev, ...entry };
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

export default { createEvidenceLog };
