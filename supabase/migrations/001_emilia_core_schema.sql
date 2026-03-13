-- =============================================================================
-- EMILIA Protocol — Migration 001: Core Schema
-- Entity Measurement Infrastructure for Ledgered Interaction Accountability
-- =============================================================================

-- Enable pgvector for semantic matching
create extension if not exists vector with schema extensions;

-- =============================================================================
-- ENTITIES — every commercial actor in the agent economy
-- Merchants, agents, service providers, anything that transacts
-- =============================================================================
create table entities (
  id              uuid primary key default gen_random_uuid(),
  entity_id       text unique not null,                -- human-readable slug: "rex-booking-v2"
  owner_id        text not null,                       -- who owns this entity (API key holder)
  
  -- Identity
  display_name    text not null,
  entity_type     text not null check (entity_type in ('agent', 'merchant', 'service_provider')),
  description     text not null,
  website_url     text,
  
  -- Capabilities (for agents)
  capabilities    jsonb not null default '[]',          -- ["inbound_booking", "sentiment_analysis"]
  input_schema    jsonb,                                -- JSON Schema: what this entity accepts
  output_schema   jsonb,                                -- JSON Schema: what it returns
  
  -- Commerce details (for merchants)
  category        text,                                 -- "furniture", "salon", "legal"
  service_area    text,                                 -- geographic or "global"
  
  -- Pricing
  pricing_model   text check (pricing_model in ('per_task', 'per_transaction', 'subscription', 'free')),
  pricing_amount_cents integer default 0,
  
  -- Embedding for semantic matching
  capability_embedding extensions.vector(1536),         -- from text-embedding-3-small
  
  -- EMILIA Score (computed, NEVER self-reported)
  emilia_score        float not null default 50.0,      -- 0-100, starts at 50 (unproven)
  total_receipts      integer not null default 0,
  successful_receipts integer not null default 0,
  avg_delivery_accuracy float default 0,
  avg_product_accuracy  float default 0,
  avg_price_integrity   float default 0,
  avg_return_processing float default 0,
  avg_agent_satisfaction float default 0,
  score_consistency     float default 0,
  
  -- Verification
  verified        boolean not null default false,       -- EMILIA-verified status
  verified_at     timestamptz,
  
  -- A2A / UCP compatibility
  a2a_endpoint    text,                                 -- A2A Agent Card endpoint
  ucp_profile_url text,                                 -- UCP merchant profile
  
  -- Metadata
  status          text not null default 'active' check (status in ('active', 'inactive', 'suspended')),
  api_key_hash    text not null,                        -- hashed API key for auth
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

-- Indexes
create index idx_entities_embedding on entities
  using ivfflat (capability_embedding extensions.vector_cosine_ops) with (lists = 100);
create index idx_entities_active on entities (status) where status = 'active';
create index idx_entities_score on entities (emilia_score desc) where status = 'active';
create index idx_entities_type on entities (entity_type, emilia_score desc);
create index idx_entities_category on entities (category, emilia_score desc);
create index idx_entities_api_key on entities (api_key_hash);

-- =============================================================================
-- RECEIPTS — the immutable ledger
-- Every transaction produces a receipt. This is the core of EMILIA.
-- Append-only. No updates. No deletes. Ever.
-- =============================================================================
create table receipts (
  id                  uuid primary key default gen_random_uuid(),
  receipt_id          text unique not null,              -- deterministic ID from transaction hash
  
  -- Who was involved
  entity_id           uuid not null references entities(id),  -- the entity being scored
  submitted_by        uuid not null references entities(id),  -- the entity submitting the receipt
  
  -- Transaction reference
  transaction_ref     text,                              -- external transaction ID (UCP order, A2A task)
  transaction_type    text not null check (transaction_type in (
    'purchase', 'service', 'task_completion', 'delivery', 'return'
  )),
  
  -- What was promised vs what happened (all 0-100 scores)
  delivery_accuracy   float check (delivery_accuracy between 0 and 100),    -- promised vs actual timing
  product_accuracy    float check (product_accuracy between 0 and 100),     -- listing vs reality
  price_integrity     float check (price_integrity between 0 and 100),      -- quoted vs charged
  return_processing   float check (return_processing between 0 and 100),    -- policy honored?
  agent_satisfaction  float check (agent_satisfaction between 0 and 100),    -- purchasing agent signal
  
  -- Raw evidence (structured, not opinions)
  evidence            jsonb not null default '{}',       -- {promised_delivery: "2d", actual_delivery: "3d", ...}
  
  -- Computed at write time
  composite_score     float not null,                    -- weighted average of all signals
  
  -- Cryptographic integrity
  receipt_hash        text not null,                     -- SHA-256 of receipt contents
  previous_hash       text,                              -- hash of previous receipt for this entity (chain)
  
  -- Metadata
  created_at          timestamptz not null default now()
);

-- Append-only enforcement: no updates, no deletes via RLS
-- (RLS policies applied in migration 002)
create index idx_receipts_entity on receipts (entity_id, created_at desc);
create index idx_receipts_submitted_by on receipts (submitted_by, created_at desc);
create index idx_receipts_type on receipts (transaction_type, created_at desc);
create index idx_receipts_created on receipts (created_at desc);

-- =============================================================================
-- NEEDS — the need feed
-- Agents broadcast what they need. The network matches them.
-- =============================================================================
create table needs (
  id                uuid primary key default gen_random_uuid(),
  need_id           text unique not null,
  
  -- Who needs it
  from_entity_id    uuid not null references entities(id),
  
  -- What's needed
  capability_needed text not null,                       -- "sentiment_analysis", "price_comparison"
  context           text,                                -- additional context
  input_data        jsonb,                               -- the actual input payload
  
  -- Constraints
  budget_cents      integer,                             -- max willing to pay
  deadline_ms       integer,                             -- max time to complete
  min_emilia_score  float not null default 0,            -- minimum EMILIA Score to qualify
  
  -- Embedding for matching
  need_embedding    extensions.vector(1536),
  
  -- Lifecycle
  status            text not null default 'open' check (status in (
    'open', 'claimed', 'in_progress', 'completed', 'failed', 'expired', 'cancelled'
  )),
  claimed_by        uuid references entities(id),
  claimed_at        timestamptz,
  completed_at      timestamptz,
  
  -- Result
  output_data       jsonb,
  
  created_at        timestamptz not null default now(),
  expires_at        timestamptz
);

create index idx_needs_open on needs (status, created_at desc) where status = 'open';
create index idx_needs_embedding on needs
  using ivfflat (need_embedding extensions.vector_cosine_ops) with (lists = 100);
create index idx_needs_from on needs (from_entity_id, created_at desc);
create index idx_needs_claimed on needs (claimed_by, created_at desc);

-- =============================================================================
-- SCORE HISTORY — track how scores change over time
-- =============================================================================
create table score_history (
  id              uuid primary key default gen_random_uuid(),
  entity_id       uuid not null references entities(id),
  score           float not null,
  total_receipts  integer not null,
  receipt_id      uuid references receipts(id),          -- the receipt that triggered this change
  created_at      timestamptz not null default now()
);

create index idx_score_history on score_history (entity_id, created_at desc);

-- =============================================================================
-- API KEYS — authentication for entities
-- =============================================================================
create table api_keys (
  id              uuid primary key default gen_random_uuid(),
  entity_id       uuid not null references entities(id),
  key_hash        text not null unique,                  -- SHA-256 of the API key
  key_prefix      text not null,                         -- first 8 chars for identification: "ep_live_"
  label           text,                                  -- "Production key", "Test key"
  permissions     jsonb not null default '["read", "write"]',
  last_used_at    timestamptz,
  created_at      timestamptz not null default now(),
  revoked_at      timestamptz
);

create index idx_api_keys_hash on api_keys (key_hash) where revoked_at is null;
create index idx_api_keys_entity on api_keys (entity_id);

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Compute EMILIA Score from recent receipts
-- This is the scoring algorithm. It is open source. Anyone can audit it.
create or replace function compute_emilia_score(p_entity_id uuid)
returns float as $$
declare
  v_score float;
  v_count integer;
begin
  select
    count(*),
    -- Weighted composite: delivery 30%, product 25%, price 15%, returns 15%, satisfaction 10%, consistency 5%
    coalesce(
      avg(delivery_accuracy)  * 0.30 +
      avg(product_accuracy)   * 0.25 +
      avg(price_integrity)    * 0.15 +
      avg(return_processing)  * 0.15 +
      avg(agent_satisfaction) * 0.10 +
      -- Consistency bonus: low stddev = high consistency
      greatest(0, 100 - coalesce(stddev(composite_score), 0) * 2) * 0.05
    , 50.0)
  into v_count, v_score
  from (
    select *
    from receipts
    where entity_id = p_entity_id
    order by created_at desc
    limit 200  -- rolling window of last 200 receipts
  ) recent;

  -- New entities with < 5 receipts get dampened toward 50
  if v_count < 5 then
    v_score := 50.0 + (v_score - 50.0) * (v_count::float / 5.0);
  end if;

  return round(greatest(0, least(100, v_score))::numeric, 1);
end;
$$ language plpgsql stable;

-- Auto-update entity score when a new receipt is inserted
create or replace function update_entity_score()
returns trigger as $$
declare
  v_new_score float;
begin
  v_new_score := compute_emilia_score(new.entity_id);
  
  update entities set
    emilia_score = v_new_score,
    total_receipts = total_receipts + 1,
    successful_receipts = successful_receipts + case when new.composite_score >= 70 then 1 else 0 end,
    updated_at = now()
  where id = new.entity_id;
  
  -- Record score history
  insert into score_history (entity_id, score, total_receipts, receipt_id)
  select new.entity_id, v_new_score, total_receipts, new.id
  from entities where id = new.entity_id;
  
  return new;
end;
$$ language plpgsql;

create trigger trg_receipt_update_score
  after insert on receipts
  for each row execute function update_entity_score();

-- Auto-set expires_at on needs if not provided
create or replace function set_need_expiry()
returns trigger as $$
begin
  if new.expires_at is null then
    new.expires_at := new.created_at + interval '24 hours';
  end if;
  return new;
end;
$$ language plpgsql;

create trigger trg_need_set_expiry
  before insert on needs
  for each row execute function set_need_expiry();
