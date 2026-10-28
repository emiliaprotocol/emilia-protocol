// SPDX-License-Identifier: Apache-2.0
/** Fresh-only v2 authority: exact anchored membership compaction, never an import
 * of an unproved legacy operational history. Separate witness/admin assumptions
 * are identical to replay-history-authority.ts. Full exact-set reads are bounded;
 * this is not a Merkle point-proof implementation or a WORM/admin-compromise claim.
 */
import { createHash } from 'node:crypto';
import { replayHistoryBootstrap, replayHistoryGenesis, validReplayHistoryReceipt,
  type ReplayHistoryRequest, type ReplayHistoryReceipt, type ReplayHistoryAuthority,
  type ReplayHistoryPool } from './replay-history-authority.js';
import type { ReplayHistoryCheckpointStore } from './replay-history-checkpoint.js';
const digest = (v: unknown) => `sha256:${createHash('sha256').update(JSON.stringify(v)).digest('hex')}`;
const hash = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const integer = (v: unknown): number => {
  const n = Number(v);
  if (typeof v !== 'string' || String(n) !== v || !Number.isSafeInteger(n) || n < 0) throw Error('compaction_frontier_invalid');
  return n;
};
type Member = [string, string];
const membershipRoot = (members: Member[]) => digest(['EP-REPLAY-MEMBERSHIP-v2', members]);
const snapshotRoot = (authority: string, prefix: string, base: number, witness: number, previous: string, membership: string) =>
  digest(['EP-REPLAY-COMPACTION-v2', authority, prefix, base, witness, previous, membership]);
export const COMPACTING_REPLAY_HISTORY_DDL = `
CREATE TABLE ep_replay_v2_heads (
 authority_id text PRIMARY KEY, fresh_authorization_prefix text NOT NULL,
 sequence bigint NOT NULL CHECK(sequence >= 0), witness_sequence bigint NOT NULL DEFAULT 0,
 checkpoint_digest text NOT NULL, compacted_through bigint NOT NULL DEFAULT 0,
 compaction_digest text
);
CREATE TABLE ep_replay_v2_entries (
 authority_id text NOT NULL REFERENCES ep_replay_v2_heads(authority_id), sequence bigint NOT NULL CHECK(sequence > 0),
 native_replay_identity text NOT NULL, native_authorization_id text NOT NULL, action_digest text NOT NULL,
 previous_digest text NOT NULL, checkpoint_digest text NOT NULL,
 PRIMARY KEY(authority_id,sequence), UNIQUE(authority_id,native_replay_identity)
);
CREATE TABLE ep_replay_v2_snapshots (
 authority_id text NOT NULL REFERENCES ep_replay_v2_heads(authority_id), base_sequence bigint NOT NULL CHECK(base_sequence > 0),
 witness_sequence bigint NOT NULL, previous_digest text NOT NULL, membership_root text NOT NULL,
 checkpoint_digest text NOT NULL, members jsonb NOT NULL, PRIMARY KEY(authority_id,base_sequence)
);
CREATE FUNCTION ep_replay_v2_reject_statement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'replay history is immutable'; END $$;
CREATE FUNCTION ep_replay_v2_retain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE h ep_replay_v2_heads%ROWTYPE; owner_name text;
BEGIN
 SELECT pg_get_userbyid(relowner) INTO owner_name FROM pg_class WHERE oid = TG_RELID;
 IF TG_OP = 'DELETE' AND current_user = owner_name THEN
  SELECT * INTO h FROM ep_replay_v2_heads WHERE authority_id = OLD.authority_id;
  IF h.compaction_digest IS NOT NULL AND current_setting('ep.replay.prune_root',true) = h.compaction_digest THEN
   IF (TG_TABLE_NAME = 'ep_replay_v2_entries' AND (to_jsonb(OLD)->>'sequence')::bigint <= h.compacted_through)
      OR (TG_TABLE_NAME = 'ep_replay_v2_snapshots' AND (to_jsonb(OLD)->>'base_sequence')::bigint < h.compacted_through)
   THEN RETURN OLD; END IF;
  END IF;
 END IF;
 RAISE EXCEPTION 'replay history is immutable';
END $$;
CREATE TRIGGER ep_replay_v2_entries_retained BEFORE UPDATE OR DELETE ON ep_replay_v2_entries
 FOR EACH ROW EXECUTE FUNCTION ep_replay_v2_retain();
CREATE TRIGGER ep_replay_v2_snapshots_retained BEFORE UPDATE OR DELETE ON ep_replay_v2_snapshots
 FOR EACH ROW EXECUTE FUNCTION ep_replay_v2_retain();
CREATE TRIGGER ep_replay_v2_entries_no_truncate BEFORE TRUNCATE ON ep_replay_v2_entries
 FOR EACH STATEMENT EXECUTE FUNCTION ep_replay_v2_reject_statement();
CREATE TRIGGER ep_replay_v2_snapshots_no_truncate BEFORE TRUNCATE ON ep_replay_v2_snapshots
 FOR EACH STATEMENT EXECUTE FUNCTION ep_replay_v2_reject_statement();
CREATE TRIGGER ep_replay_v2_heads_retained BEFORE DELETE OR TRUNCATE ON ep_replay_v2_heads
 FOR EACH STATEMENT EXECUTE FUNCTION ep_replay_v2_reject_statement();
CREATE FUNCTION ep_replay_v2_advance_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.authority_id <> OLD.authority_id OR NEW.fresh_authorization_prefix <> OLD.fresh_authorization_prefix
  OR NEW.witness_sequence <> OLD.witness_sequence + 1 THEN RAISE EXCEPTION 'invalid replay head advance'; END IF;
 IF NEW.sequence = OLD.sequence + 1 AND NEW.compacted_through = OLD.compacted_through
  AND NEW.compaction_digest IS NOT DISTINCT FROM OLD.compaction_digest AND EXISTS (
   SELECT 1 FROM ep_replay_v2_entries WHERE authority_id=OLD.authority_id AND sequence=NEW.sequence
    AND previous_digest=OLD.checkpoint_digest AND checkpoint_digest=NEW.checkpoint_digest
  ) THEN RETURN NEW; END IF;
 IF NEW.sequence = OLD.sequence AND NEW.compacted_through = OLD.sequence AND NEW.compacted_through > OLD.compacted_through
  AND NEW.compaction_digest = NEW.checkpoint_digest AND EXISTS (
   SELECT 1 FROM ep_replay_v2_snapshots WHERE authority_id=OLD.authority_id AND base_sequence=NEW.sequence
    AND witness_sequence=NEW.witness_sequence AND previous_digest=OLD.checkpoint_digest AND checkpoint_digest=NEW.checkpoint_digest
  ) THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'invalid replay head advance';
END $$;
CREATE TRIGGER ep_replay_v2_heads_monotone BEFORE UPDATE ON ep_replay_v2_heads
 FOR EACH ROW EXECUTE FUNCTION ep_replay_v2_advance_only();
CREATE FUNCTION ep_replay_v2_prune(a text, root text) RETURNS bigint
 LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE h ep_replay_v2_heads%ROWTYPE; removed bigint;
BEGIN
 SELECT * INTO h FROM ep_replay_v2_heads WHERE authority_id=a FOR UPDATE;
 IF NOT FOUND OR h.compaction_digest IS NULL OR h.compaction_digest <> root OR NOT EXISTS (
  SELECT 1 FROM ep_replay_v2_snapshots WHERE authority_id=a AND base_sequence=h.compacted_through AND checkpoint_digest=root
 ) THEN RAISE EXCEPTION 'no current installed compaction'; END IF;
 PERFORM set_config('ep.replay.prune_root',root,true);
 DELETE FROM ep_replay_v2_entries WHERE authority_id=a AND sequence <= h.compacted_through;
 GET DIAGNOSTICS removed = ROW_COUNT;
 DELETE FROM ep_replay_v2_snapshots WHERE authority_id=a AND base_sequence < h.compacted_through;
 RETURN removed;
END $$;
REVOKE ALL ON ep_replay_v2_heads,ep_replay_v2_entries,ep_replay_v2_snapshots FROM PUBLIC;
REVOKE ALL ON FUNCTION ep_replay_v2_prune(text,text) FROM PUBLIC;`;
export const COMPACTING_REPLAY_HISTORY_SQL = Object.freeze({
 head: 'SELECT authority_id,fresh_authorization_prefix,sequence::text,witness_sequence::text,checkpoint_digest,compacted_through::text,compaction_digest FROM ep_replay_v2_heads WHERE authority_id=$1 FOR UPDATE',
 snapshot: 'SELECT base_sequence::text,witness_sequence::text,previous_digest,membership_root,checkpoint_digest,members FROM ep_replay_v2_snapshots WHERE authority_id=$1 AND base_sequence=$2',
 entries: 'SELECT sequence::text,native_replay_identity,native_authorization_id,action_digest,previous_digest,checkpoint_digest FROM ep_replay_v2_entries WHERE authority_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3',
 append: 'INSERT INTO ep_replay_v2_entries VALUES ($1,$2,$3,$4,$5,$6,$7)',
 consumeHead: 'UPDATE ep_replay_v2_heads SET sequence=$2,witness_sequence=$3,checkpoint_digest=$4 WHERE authority_id=$1',
 snapshotInsert: 'INSERT INTO ep_replay_v2_snapshots VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)',
 compactHead: 'UPDATE ep_replay_v2_heads SET witness_sequence=$2,checkpoint_digest=$3,compacted_through=sequence,compaction_digest=$3 WHERE authority_id=$1',
 prune: 'SELECT ep_replay_v2_prune($1,$2)::text AS removed',
});
export function compactingReplayHistoryBootstrap(authorityId: string) {
 const bootstrap = replayHistoryBootstrap(authorityId);
 return { ...bootstrap, text: 'INSERT INTO ep_replay_v2_heads(authority_id,fresh_authorization_prefix,sequence,checkpoint_digest) VALUES ($1,$2,0,$3)' };
}
export interface ReplayHistoryCompactionResult {
 status: 'ANCHORED_AND_PRUNED'; covered_through: number; witness_sequence: number;
 checkpoint_digest: string; membership_root: string; removed_raw_entries: number;
}
export interface CompactingReplayHistoryAuthority extends ReplayHistoryAuthority {
 /** Requires separately provisioned operator/compactor credentials. */
 compact(): Promise<ReplayHistoryCompactionResult>;
}
export function createPostgresCompactingReplayHistoryAuthority({ pool, compaction_pool, authority_id, checkpoint, max_entries = 10000 }: {
 pool: ReplayHistoryPool; compaction_pool?: ReplayHistoryPool; authority_id: string;
 checkpoint: ReplayHistoryCheckpointStore; max_entries?: number;
}): CompactingReplayHistoryAuthority {
 if (!pool || typeof pool.connect !== 'function' || !checkpoint || typeof checkpoint.read !== 'function'
  || typeof checkpoint.advance !== 'function' || typeof authority_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/.test(authority_id)
  || !Number.isSafeInteger(max_entries) || max_entries<1 || max_entries>1000000
  || (compaction_pool !== undefined && typeof compaction_pool.connect !== 'function')) throw Error('compaction_configuration_invalid');
 const connect = pool.connect.bind(pool), operatorConnect = compaction_pool?.connect.bind(compaction_pool);
 const readCheckpoint = checkpoint.read.bind(checkpoint), advanceCheckpoint = checkpoint.advance.bind(checkpoint);
 async function access(input: Readonly<ReplayHistoryRequest> | null, mode: 'consume'|'lookup'|'compact', supplied?: Readonly<ReplayHistoryReceipt>): Promise<ReplayHistoryReceipt|null|ReplayHistoryCompactionResult> {
  const request = input === null ? null : structuredClone(input);
  if (mode !== 'compact' && (!request || Object.keys(request).length!==4 || request.authority_id!==authority_id
   || !hash(request.native_replay_identity) || !hash(request.action_digest) || typeof request.native_authorization_id!=='string'
   || request.native_authorization_id.length>256)) throw Error('replay_history_request_invalid');
  if (mode==='compact' && !operatorConnect) throw Error('compaction_operator_required');
  const client = await (mode==='compact' ? operatorConnect!() : connect()); let began=false;
  try {
   await client.query('BEGIN'); began=true; await client.query('SET LOCAL synchronous_commit=on');
   const headResult=await client.query(COMPACTING_REPLAY_HISTORY_SQL.head,[authority_id]);
   if (headResult.rowCount!==1 || headResult.rows.length!==1) throw Error('replay_history_head_missing');
   const head=headResult.rows[0], prefix=head.fresh_authorization_prefix;
   if (typeof prefix!=='string' || !/^ep-fresh-[a-f0-9]{64}:$/.test(prefix)) throw Error('replay_history_cutover_invalid');
   if (request && (!request.native_authorization_id.startsWith(prefix) || request.native_authorization_id.length<=prefix.length)) throw Error('replay_history_legacy_namespace_refused');
   const sequence=integer(head.sequence), witnessSequence=integer(head.witness_sequence), base=integer(head.compacted_through);
   if (sequence>max_entries || base>sequence || !hash(head.checkpoint_digest)) throw Error('replay_history_frontier_invalid');
   const anchored=structuredClone(await readCheckpoint());
   if (anchored.sequence!==witnessSequence || anchored.checkpoint_digest!==head.checkpoint_digest) throw Error('replay_history_anchor_rollback_or_gap');
   const members=new Map<string,string>(); let previous=replayHistoryGenesis(authority_id,prefix);
   let currentMembershipRoot=membershipRoot([]);
   if (base>0) {
    const snapshotResult=await client.query(COMPACTING_REPLAY_HISTORY_SQL.snapshot,[authority_id,base]);
    if (snapshotResult.rowCount!==1 || snapshotResult.rows.length!==1) throw Error('compaction_snapshot_missing');
    const s=snapshotResult.rows[0], snapshotWitness=integer(s.witness_sequence);
    if (integer(s.base_sequence)!==base || witnessSequence-snapshotWitness!==sequence-base
     || !hash(s.previous_digest) || !hash(s.membership_root) || !Array.isArray(s.members) || s.members.length!==base) throw Error('compaction_coverage_invalid');
    let prior='';
    for (const member of s.members) {
     if (!Array.isArray(member) || member.length!==2 || !hash(member[0]) || !hash(member[1]) || member[0]<=prior) throw Error('compaction_membership_invalid');
     members.set(member[0],member[1]); prior=member[0];
    }
    currentMembershipRoot=membershipRoot([...members]);
    previous=snapshotRoot(authority_id,prefix,base,snapshotWitness,s.previous_digest,currentMembershipRoot);
    if (s.membership_root!==currentMembershipRoot || s.checkpoint_digest!==previous || head.compaction_digest!==previous) throw Error('compaction_root_mismatch');
   } else if (head.compaction_digest!==null || witnessSequence!==sequence) throw Error('compaction_frontier_invalid');
   const raw=await client.query(COMPACTING_REPLAY_HISTORY_SQL.entries,[authority_id,base,max_entries+1]);
   if (raw.rowCount!==sequence-base || raw.rows.length!==sequence-base) throw Error('replay_history_coverage_gap');
   let existing:ReplayHistoryReceipt|null=null;
   for (let i=0;i<raw.rows.length;i++) {
    const r=raw.rows[i];
    const receipt={ version:'EP-REPLAY-HISTORY-CONSUME-v1' as const,authority_id,sequence:integer(r.sequence),
     native_replay_identity:r.native_replay_identity,native_authorization_id:r.native_authorization_id,
     action_digest:r.action_digest,previous_digest:r.previous_digest,checkpoint_digest:r.checkpoint_digest } as ReplayHistoryReceipt;
    if (receipt.sequence!==base+i+1 || receipt.previous_digest!==previous || !validReplayHistoryReceipt(receipt,receipt)
     || !receipt.native_authorization_id.startsWith(prefix) || members.has(receipt.native_replay_identity)) throw Error('replay_history_chain_invalid');
    members.set(receipt.native_replay_identity,receipt.checkpoint_digest); previous=receipt.checkpoint_digest;
    if (request?.native_replay_identity===receipt.native_replay_identity) existing=receipt;
   }
   if (previous!==head.checkpoint_digest || members.size!==sequence) throw Error('replay_history_root_mismatch');
   if (mode==='lookup' && existing && !validReplayHistoryReceipt(existing,request!)) throw Error('replay_history_lookup_binding_mismatch');
   if (mode==='lookup' || (mode==='consume' && members.has(request!.native_replay_identity))) {
    if (mode==='lookup' && !existing && members.has(request!.native_replay_identity)) {
     const original=structuredClone(supplied);
     if (!original || !validReplayHistoryReceipt(original,request!) || original.checkpoint_digest!==members.get(request!.native_replay_identity)
      || original.sequence>base) throw Error('compacted_receipt_required_or_mismatched');
     existing=original;
    }
    await client.query('ROLLBACK'); began=false; return mode==='consume'?null:existing;
   }
   if (mode==='compact') {
    let root=head.compaction_digest as string, newWitness=witnessSequence;
    if (base===0 && sequence===0) throw Error('compaction_empty_history');
    if (base<sequence) {
     const sorted=[...members].sort((a,b)=>a[0]<b[0]?-1:1) as Member[];
     currentMembershipRoot=membershipRoot(sorted); newWitness=witnessSequence+1;
     root=snapshotRoot(authority_id,prefix,sequence,newWitness,previous,currentMembershipRoot);
     if ((await client.query(COMPACTING_REPLAY_HISTORY_SQL.snapshotInsert,[authority_id,sequence,newWitness,previous,currentMembershipRoot,root,JSON.stringify(sorted)])).rowCount!==1
      || (await client.query(COMPACTING_REPLAY_HISTORY_SQL.compactHead,[authority_id,newWitness,root])).rowCount!==1) throw Error('compaction_install_failed');
     await client.query('COMMIT'); began=false;
     const confirmed=structuredClone(await advanceCheckpoint(anchored,{sequence:newWitness,checkpoint_digest:root}));
     if (confirmed.sequence!==newWitness || confirmed.checkpoint_digest!==root) throw Error('compaction_anchor_unconfirmed');
    } else { await client.query('ROLLBACK'); began=false; }
    // The operator-only function locks the head again and can reclaim ONLY
    // rows covered by the current installed snapshot. No reset/truncate path.
    // Re-read live witness before reclamation; uncertainty never deletes.
    const latest=structuredClone(await readCheckpoint());
    if (latest.sequence!==newWitness || latest.checkpoint_digest!==root) throw Error('compaction_anchor_changed_before_prune');
    // This call already owns an operator client, and its source transaction
    // ended before anchoring. Reuse it for the new locked pruning transaction:
    // acquiring another lease here deadlocks a correctly configured max=1 pool.
    // The outer finally owns the sole release on every path.
    const pruning=client;
    try {
     await pruning.query('BEGIN'); await pruning.query('SET LOCAL synchronous_commit=on');
     const removed=await pruning.query(COMPACTING_REPLAY_HISTORY_SQL.prune,[authority_id,root]);
     if (removed.rowCount!==1 || removed.rows.length!==1) throw Error('compaction_prune_unconfirmed');
     const count=integer(removed.rows[0].removed);
     await pruning.query('COMMIT');
     return Object.freeze({status:'ANCHORED_AND_PRUNED',covered_through:sequence,witness_sequence:newWitness,
      checkpoint_digest:root,membership_root:currentMembershipRoot,removed_raw_entries:count});
    } catch(error) { try{await pruning.query('ROLLBACK');}catch{} throw error; }
   }
   if (sequence===max_entries) throw Error('replay_history_capacity_exhausted');
   const body={version:'EP-REPLAY-HISTORY-CONSUME-v1' as const,...request!,sequence:sequence+1,previous_digest:previous};
   const receipt=Object.freeze({...body,checkpoint_digest:digest([body.version,body.authority_id,body.native_replay_identity,
    body.native_authorization_id,body.action_digest,body.sequence,body.previous_digest])});
   if ((await client.query(COMPACTING_REPLAY_HISTORY_SQL.append,[authority_id,receipt.sequence,receipt.native_replay_identity,receipt.native_authorization_id,receipt.action_digest,previous,receipt.checkpoint_digest])).rowCount!==1
    || (await client.query(COMPACTING_REPLAY_HISTORY_SQL.consumeHead,[authority_id,receipt.sequence,witnessSequence+1,receipt.checkpoint_digest])).rowCount!==1) throw Error('replay_history_advance_failed');
   await client.query('COMMIT'); began=false;
   const confirmed=structuredClone(await advanceCheckpoint(anchored,{sequence:witnessSequence+1,checkpoint_digest:receipt.checkpoint_digest}));
   if (confirmed.sequence!==witnessSequence+1 || confirmed.checkpoint_digest!==receipt.checkpoint_digest) throw Error('replay_history_anchor_unconfirmed');
   return receipt;
  } catch(error) { if(began){try{await client.query('ROLLBACK');}catch{}} throw error; }
  finally{client.release();}
 }
 return Object.freeze({authority_id,
  consume:request=>access(request,'consume') as Promise<ReplayHistoryReceipt|null>,
  lookup:(request,original)=>access(request,'lookup',original) as Promise<ReplayHistoryReceipt|null>,
  compact:()=>access(null,'compact') as Promise<ReplayHistoryCompactionResult>});
}
