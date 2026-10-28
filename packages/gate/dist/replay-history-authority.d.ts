import type { ReplayHistoryCheckpointStore } from './replay-history-checkpoint.js';
export interface ReplayHistoryRequest {
    authority_id: string;
    native_replay_identity: string;
    native_authorization_id: string;
    action_digest: string;
}
export interface ReplayHistoryReceipt extends ReplayHistoryRequest {
    version: 'EP-REPLAY-HISTORY-CONSUME-v1';
    sequence: number;
    previous_digest: string;
    checkpoint_digest: string;
}
export interface ReplayHistoryAuthority {
    authority_id: string;
    consume(request: Readonly<ReplayHistoryRequest>): Promise<ReplayHistoryReceipt | null>;
    lookup(request: Readonly<ReplayHistoryRequest>, original_receipt?: Readonly<ReplayHistoryReceipt>): Promise<ReplayHistoryReceipt | null>;
}
export declare const replayHistoryGenesis: (authorityId: string, prefix: string) => string;
/** Structural integrity only; authenticity requires the trusted live authority. */
export declare function validReplayHistoryReceiptShape(value: unknown): value is ReplayHistoryReceipt;
export declare function validReplayHistoryReceipt(value: unknown, request: ReplayHistoryRequest): value is ReplayHistoryReceipt;
export declare const REPLAY_HISTORY_DDL = "\nCREATE TABLE ep_external_replay_heads (\n  authority_id text PRIMARY KEY,\n  fresh_authorization_prefix text NOT NULL,\n  sequence bigint NOT NULL CHECK (sequence >= 0),\n  checkpoint_digest text NOT NULL\n);\nCREATE TABLE ep_external_replay_entries (\n  authority_id text NOT NULL REFERENCES ep_external_replay_heads(authority_id),\n  sequence bigint NOT NULL CHECK (sequence > 0),\n  native_replay_identity text NOT NULL,\n  native_authorization_id text NOT NULL,\n  action_digest text NOT NULL,\n  previous_digest text NOT NULL,\n  checkpoint_digest text NOT NULL,\n  PRIMARY KEY (authority_id, sequence),\n  UNIQUE (authority_id, native_replay_identity)\n);\nCREATE FUNCTION ep_external_replay_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN RAISE EXCEPTION 'replay history is retained and immutable'; END $$;\nCREATE TRIGGER ep_external_replay_entries_immutable BEFORE UPDATE OR DELETE OR TRUNCATE\nON ep_external_replay_entries FOR EACH STATEMENT EXECUTE FUNCTION ep_external_replay_reject_mutation();\nCREATE TRIGGER ep_external_replay_heads_retained BEFORE DELETE OR TRUNCATE\nON ep_external_replay_heads FOR EACH STATEMENT EXECUTE FUNCTION ep_external_replay_reject_mutation();\nCREATE FUNCTION ep_external_replay_advance_only() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n  IF NEW.authority_id <> OLD.authority_id OR NEW.fresh_authorization_prefix <> OLD.fresh_authorization_prefix\n     OR NEW.sequence <> OLD.sequence + 1 OR NOT EXISTS (\n       SELECT 1 FROM ep_external_replay_entries WHERE authority_id = OLD.authority_id\n         AND sequence = NEW.sequence AND checkpoint_digest = NEW.checkpoint_digest\n         AND previous_digest = OLD.checkpoint_digest\n     ) THEN RAISE EXCEPTION 'replay history head must advance one retained fact'; END IF;\n  RETURN NEW;\nEND $$;\nCREATE TRIGGER ep_external_replay_heads_monotone BEFORE UPDATE ON ep_external_replay_heads\nFOR EACH ROW EXECUTE FUNCTION ep_external_replay_advance_only();\nREVOKE ALL ON ep_external_replay_heads, ep_external_replay_entries FROM PUBLIC;";
export declare const REPLAY_HISTORY_SQL: Readonly<{
    head: "SELECT sequence::text, checkpoint_digest, fresh_authorization_prefix FROM ep_external_replay_heads WHERE authority_id = $1 FOR UPDATE";
    history: "SELECT sequence::text, native_replay_identity, native_authorization_id, action_digest, previous_digest, checkpoint_digest FROM ep_external_replay_entries WHERE authority_id = $1 ORDER BY sequence LIMIT $2";
    append: "INSERT INTO ep_external_replay_entries (authority_id, sequence, native_replay_identity, native_authorization_id, action_digest, previous_digest, checkpoint_digest) VALUES ($1,$2,$3,$4,$5,$6,$7)";
    advance: "UPDATE ep_external_replay_heads SET sequence = $2, checkpoint_digest = $3 WHERE authority_id = $1 AND sequence = $4 AND checkpoint_digest = $5";
}>;
interface QueryResult {
    rows: Record<string, unknown>[];
    rowCount: number | null;
}
interface Client {
    query(sql: string, values?: unknown[]): Promise<QueryResult>;
    release(): void;
}
export interface ReplayHistoryPool {
    connect(): Promise<Client>;
}
/** Explicit operator bootstrap SQL: execute ONCE on the separate authority store. */
export declare function replayHistoryBootstrap(authorityId: string): {
    fresh_authorization_prefix: string;
    genesis: string;
    text: string;
    values: string[];
};
export declare function createPostgresReplayHistoryAuthority({ pool, authority_id, checkpoint, max_entries }: {
    pool: ReplayHistoryPool;
    authority_id: string;
    checkpoint: ReplayHistoryCheckpointStore;
    max_entries?: number;
}): ReplayHistoryAuthority;
export {};
//# sourceMappingURL=replay-history-authority.d.ts.map