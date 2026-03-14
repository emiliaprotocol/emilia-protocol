-- =============================================================================
-- EMILIA Protocol — Migration 003: Blockchain Anchoring
-- Merkle tree batching + Base L2 verification
-- =============================================================================

-- Merkle batches — each batch is a tree of receipt hashes
create table merkle_batches (
  id              uuid primary key default gen_random_uuid(),
  merkle_root     text not null,
  leaf_count      integer not null,
  receipt_ids     uuid[] not null,                          -- ordered list of receipt UUIDs in this batch
  layers_json     text not null,                            -- full Merkle tree layers for proof generation
  
  -- On-chain anchoring
  tx_hash         text,                                     -- Base L2 transaction hash
  block_number    bigint,                                   -- Base L2 block number
  
  -- Lifecycle
  status          text not null default 'pending'
                  check (status in ('pending', 'anchored', 'failed')),
  error_message   text,
  
  created_at      timestamptz not null default now(),
  anchored_at     timestamptz
);

create index idx_merkle_batches_status on merkle_batches (status);
create index idx_merkle_batches_root on merkle_batches (merkle_root);
create index idx_merkle_batches_tx on merkle_batches (tx_hash) where tx_hash is not null;

-- Add merkle_batch_id to receipts
alter table receipts add column merkle_batch_id uuid references merkle_batches(id);
create index idx_receipts_batch on receipts (merkle_batch_id) where merkle_batch_id is not null;
create index idx_receipts_unanchored on receipts (created_at) where merkle_batch_id is null;
