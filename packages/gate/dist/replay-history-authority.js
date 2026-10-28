// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Independent-store replay authority. The pool MUST target a separately
 * administered durability domain, never Gate's operational database. Code
 * cannot establish administrative independence. External-store loss/rollback
 * together with its separate checkpoint witness is outside this profile;
 * operational rollback and authority-DB rollback with witness retained are inside it.
 * No deletion, compaction, epoch reset, refund or automatic bootstrap exists.
 */
import { createHash, randomBytes } from 'node:crypto';
const hash = (v) => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const id = (v) => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/.test(v);
const digest = (v) => `sha256:${createHash('sha256').update(JSON.stringify(v)).digest('hex')}`;
export const replayHistoryGenesis = (authorityId, prefix) => digest(['EP-REPLAY-HISTORY-GENESIS-v1', authorityId, prefix]);
function receiptDigest(r) {
    return digest([r.version, r.authority_id, r.native_replay_identity, r.native_authorization_id, r.action_digest, r.sequence, r.previous_digest]);
}
/** Structural integrity only; authenticity requires the trusted live authority. */
export function validReplayHistoryReceiptShape(value) {
    if (!value || typeof value !== 'object')
        return false;
    const r = value;
    return Object.keys(r).length === 8 && r.version === 'EP-REPLAY-HISTORY-CONSUME-v1'
        && id(r.authority_id) && hash(r.native_replay_identity) && hash(r.action_digest)
        && typeof r.native_authorization_id === 'string' && r.native_authorization_id.length > 0
        && r.native_authorization_id.length <= 256 && hash(r.previous_digest) && hash(r.checkpoint_digest)
        && Number.isSafeInteger(r.sequence) && r.sequence > 0 && receiptDigest(r) === r.checkpoint_digest;
}
export function validReplayHistoryReceipt(value, request) {
    return validReplayHistoryReceiptShape(value) && value.authority_id === request.authority_id
        && value.native_replay_identity === request.native_replay_identity
        && value.native_authorization_id === request.native_authorization_id && value.action_digest === request.action_digest;
}
export const REPLAY_HISTORY_DDL = `
CREATE TABLE ep_external_replay_heads (
  authority_id text PRIMARY KEY,
  fresh_authorization_prefix text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  checkpoint_digest text NOT NULL
);
CREATE TABLE ep_external_replay_entries (
  authority_id text NOT NULL REFERENCES ep_external_replay_heads(authority_id),
  sequence bigint NOT NULL CHECK (sequence > 0),
  native_replay_identity text NOT NULL,
  native_authorization_id text NOT NULL,
  action_digest text NOT NULL,
  previous_digest text NOT NULL,
  checkpoint_digest text NOT NULL,
  PRIMARY KEY (authority_id, sequence),
  UNIQUE (authority_id, native_replay_identity)
);
CREATE FUNCTION ep_external_replay_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'replay history is retained and immutable'; END $$;
CREATE TRIGGER ep_external_replay_entries_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
ON ep_external_replay_entries FOR EACH STATEMENT EXECUTE FUNCTION ep_external_replay_reject_mutation();
CREATE TRIGGER ep_external_replay_heads_retained BEFORE DELETE OR TRUNCATE
ON ep_external_replay_heads FOR EACH STATEMENT EXECUTE FUNCTION ep_external_replay_reject_mutation();
CREATE FUNCTION ep_external_replay_advance_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.authority_id <> OLD.authority_id OR NEW.fresh_authorization_prefix <> OLD.fresh_authorization_prefix
     OR NEW.sequence <> OLD.sequence + 1 OR NOT EXISTS (
       SELECT 1 FROM ep_external_replay_entries WHERE authority_id = OLD.authority_id
         AND sequence = NEW.sequence AND checkpoint_digest = NEW.checkpoint_digest
         AND previous_digest = OLD.checkpoint_digest
     ) THEN RAISE EXCEPTION 'replay history head must advance one retained fact'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER ep_external_replay_heads_monotone BEFORE UPDATE ON ep_external_replay_heads
FOR EACH ROW EXECUTE FUNCTION ep_external_replay_advance_only();
REVOKE ALL ON ep_external_replay_heads, ep_external_replay_entries FROM PUBLIC;`;
export const REPLAY_HISTORY_SQL = Object.freeze({
    head: 'SELECT sequence::text, checkpoint_digest, fresh_authorization_prefix FROM ep_external_replay_heads WHERE authority_id = $1 FOR UPDATE',
    history: 'SELECT sequence::text, native_replay_identity, native_authorization_id, action_digest, previous_digest, checkpoint_digest FROM ep_external_replay_entries WHERE authority_id = $1 ORDER BY sequence LIMIT $2',
    append: 'INSERT INTO ep_external_replay_entries (authority_id, sequence, native_replay_identity, native_authorization_id, action_digest, previous_digest, checkpoint_digest) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    advance: 'UPDATE ep_external_replay_heads SET sequence = $2, checkpoint_digest = $3 WHERE authority_id = $1 AND sequence = $4 AND checkpoint_digest = $5',
});
/** Explicit operator bootstrap SQL: execute ONCE on the separate authority store. */
export function replayHistoryBootstrap(authorityId) {
    if (!id(authorityId))
        throw new TypeError('replay_history_authority_id_invalid');
    const prefix = `ep-fresh-${randomBytes(32).toString('hex')}:`;
    return { fresh_authorization_prefix: prefix, genesis: replayHistoryGenesis(authorityId, prefix),
        text: 'INSERT INTO ep_external_replay_heads (authority_id, fresh_authorization_prefix, sequence, checkpoint_digest) VALUES ($1,$2,0,$3)',
        values: [authorityId, prefix, replayHistoryGenesis(authorityId, prefix)] };
}
export function createPostgresReplayHistoryAuthority({ pool, authority_id, checkpoint, max_entries = 10000 }) {
    if (!pool || typeof pool.connect !== 'function' || !checkpoint || typeof checkpoint.read !== 'function'
        || typeof checkpoint.advance !== 'function' || !id(authority_id)
        || !Number.isSafeInteger(max_entries) || max_entries < 1 || max_entries > 1000000)
        throw new TypeError('replay_history_configuration_invalid');
    const connect = pool.connect.bind(pool);
    const readCheckpoint = checkpoint.read.bind(checkpoint);
    const advanceCheckpoint = checkpoint.advance.bind(checkpoint);
    async function access(input, write) {
        const request = structuredClone(input);
        if (Object.keys(request).length !== 4 || request.authority_id !== authority_id || typeof request.native_authorization_id !== 'string' || request.native_authorization_id.length > 256 || !hash(request.native_replay_identity) || !hash(request.action_digest))
            throw Error('replay_history_request_invalid');
        const client = await connect();
        let began = false;
        try {
            await client.query('BEGIN');
            began = true;
            await client.query('SET LOCAL synchronous_commit = on');
            const head = await client.query(REPLAY_HISTORY_SQL.head, [authority_id]);
            if (head.rowCount !== 1 || head.rows.length !== 1)
                throw Error('replay_history_head_missing');
            const prefix = head.rows[0].fresh_authorization_prefix;
            if (typeof prefix !== 'string' || !/^ep-fresh-[a-f0-9]{64}:$/.test(prefix))
                throw Error('replay_history_cutover_invalid');
            if (!request.native_authorization_id.startsWith(prefix) || request.native_authorization_id.length <= prefix.length)
                throw Error('replay_history_legacy_namespace_refused');
            const sequence = Number(head.rows[0].sequence);
            if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > max_entries
                || String(sequence) !== head.rows[0].sequence || !hash(head.rows[0].checkpoint_digest))
                throw Error('replay_history_head_invalid_or_full');
            const anchored = structuredClone(await readCheckpoint());
            if (anchored.sequence !== sequence || anchored.checkpoint_digest !== head.rows[0].checkpoint_digest)
                throw Error('replay_history_anchor_rollback_or_gap');
            const history = await client.query(REPLAY_HISTORY_SQL.history, [authority_id, max_entries + 1]);
            if (history.rowCount !== sequence || history.rows.length !== sequence)
                throw Error('replay_history_coverage_gap');
            let previous = replayHistoryGenesis(authority_id, prefix);
            const identities = new Set();
            let existing = null;
            for (let i = 0; i < history.rows.length; i++) {
                const row = history.rows[i];
                const receipt = { version: 'EP-REPLAY-HISTORY-CONSUME-v1', authority_id,
                    native_replay_identity: row.native_replay_identity, native_authorization_id: row.native_authorization_id, action_digest: row.action_digest,
                    sequence: Number(row.sequence), previous_digest: row.previous_digest, checkpoint_digest: row.checkpoint_digest };
                if (String(i + 1) !== row.sequence || receipt.previous_digest !== previous
                    || typeof receipt.native_authorization_id !== 'string' || !receipt.native_authorization_id.startsWith(prefix)
                    || !hash(receipt.native_replay_identity) || !hash(receipt.action_digest)
                    || identities.has(receipt.native_replay_identity) || !validReplayHistoryReceipt(receipt, receipt))
                    throw Error('replay_history_chain_invalid');
                identities.add(receipt.native_replay_identity);
                previous = receipt.checkpoint_digest;
                if (receipt.native_replay_identity === request.native_replay_identity)
                    existing = receipt;
            }
            if (head.rows[0].checkpoint_digest !== previous)
                throw Error('replay_history_root_mismatch');
            if (!write || existing) {
                await client.query('ROLLBACK');
                began = false;
                return write ? null : existing;
            }
            if (sequence === max_entries)
                throw Error('replay_history_capacity_exhausted');
            const body = { version: 'EP-REPLAY-HISTORY-CONSUME-v1', ...request, sequence: sequence + 1, previous_digest: previous };
            const receipt = Object.freeze({ ...body, checkpoint_digest: receiptDigest(body) });
            const append = await client.query(REPLAY_HISTORY_SQL.append, [authority_id, receipt.sequence, request.native_replay_identity, request.native_authorization_id, request.action_digest, previous, receipt.checkpoint_digest]);
            const advance = await client.query(REPLAY_HISTORY_SQL.advance, [authority_id, receipt.sequence, receipt.checkpoint_digest, sequence, previous]);
            if (append.rowCount !== 1 || advance.rowCount !== 1)
                throw Error('replay_history_advance_failed');
            // Never return an accepted receipt before acknowledged durable COMMIT.
            await client.query('COMMIT');
            began = false;
            // Synchronous stronger profile: no accepted consume receipt until the
            // separately retained witness confirms the exact new frontier. A crash
            // between stores burns the identity and fails closed on the next read.
            const anchoredReceipt = structuredClone(await advanceCheckpoint(anchored, {
                sequence: receipt.sequence, checkpoint_digest: receipt.checkpoint_digest,
            }));
            if (anchoredReceipt.sequence !== receipt.sequence || anchoredReceipt.checkpoint_digest !== receipt.checkpoint_digest)
                throw Error('replay_history_anchor_advance_unconfirmed');
            return receipt;
        }
        catch (error) {
            if (began) {
                try {
                    await client.query('ROLLBACK');
                }
                catch { /* uncertainty remains */ }
            }
            throw error;
        }
        finally {
            client.release();
        }
    }
    return Object.freeze({ authority_id, consume: (input) => access(input, true),
        lookup: (input) => access(input, false) });
}
//# sourceMappingURL=replay-history-authority.js.map