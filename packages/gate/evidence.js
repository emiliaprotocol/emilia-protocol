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
 */
import crypto from 'node:crypto';

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

export function createEvidenceLog({ sink } = {}) {
  const records = [];
  let prev = 'genesis';

  return {
    async record(entry) {
      const body = { seq: records.length, prev_hash: prev, ...entry };
      const hash = sha256hex(JSON.stringify(body));
      const rec = { ...body, hash };
      records.push(rec);
      prev = hash;
      if (sink) { try { await sink(rec); } catch { /* sink must never break the gate */ } }
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
        if (sha256hex(JSON.stringify(body)) !== hash) return { ok: false, at: r.seq, reason: 'hash_mismatch' };
        p = hash;
      }
      return { ok: true, length: records.length, head: p === 'genesis' ? null : p };
    },
  };
}

export default { createEvidenceLog };
