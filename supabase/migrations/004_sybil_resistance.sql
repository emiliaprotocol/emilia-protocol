-- =============================================================================
-- EMILIA Protocol — Migration 004: Sybil Resistance
-- Fraud flags table, unique submitter tracking, behavioral agent satisfaction
-- =============================================================================

-- Fraud flags — logged by the sybil resistance layer
create table fraud_flags (
  id              uuid primary key default gen_random_uuid(),
  entity_id       uuid not null references entities(id),
  submitted_by    uuid not null references entities(id),
  flags           text[] not null,                          -- ['closed_loop', 'velocity_spike', etc.]
  detail          jsonb not null default '{}',
  blocked         boolean not null default false,           -- was the receipt rejected?
  reviewed        boolean not null default false,           -- has a human reviewed this?
  reviewed_at     timestamptz,
  created_at      timestamptz not null default now()
);

create index idx_fraud_flags_entity on fraud_flags (entity_id, created_at desc);
create index idx_fraud_flags_unreviewed on fraud_flags (reviewed, created_at desc) where reviewed = false;

-- Track unique submitters per entity for thin-graph detection
alter table entities add column if not exists unique_submitters integer not null default 0;

-- Function to update unique_submitters count after each receipt
create or replace function update_unique_submitters()
returns trigger as $$
begin
  update entities set
    unique_submitters = (
      select count(distinct submitted_by)
      from receipts
      where entity_id = new.entity_id
    )
  where id = new.entity_id;
  return new;
end;
$$ language plpgsql;

create trigger trg_receipt_update_submitters
  after insert on receipts
  for each row execute function update_unique_submitters();

-- Add agent_behavior field to receipts for behavioral satisfaction signal
alter table receipts add column if not exists agent_behavior text
  check (agent_behavior in (
    'completed', 'retried_same', 'retried_different', 'abandoned', 'disputed'
  ));
