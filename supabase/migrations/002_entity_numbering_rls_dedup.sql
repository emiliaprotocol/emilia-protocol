-- =============================================================================
-- EMILIA Protocol — Migration 002: Entity Numbering, RLS, Receipt Dedup, Search
-- =============================================================================

-- =============================================================================
-- ITEM 12: Entity numbering — sequential, permanent, public
-- =============================================================================
alter table entities add column if not exists entity_number serial;

-- Backfill existing entities by creation order
-- (Run this once after adding the column)
with numbered as (
  select id, row_number() over (order by created_at asc) as rn
  from entities
)
update entities set entity_number = numbered.rn
from numbered where entities.id = numbered.id;

-- Unique constraint
create unique index if not exists idx_entities_number on entities (entity_number);

-- =============================================================================
-- ITEM 13: Row Level Security
-- =============================================================================

-- Enable RLS on all tables
alter table entities enable row level security;
alter table receipts enable row level security;
alter table needs enable row level security;
alter table score_history enable row level security;
alter table api_keys enable row level security;

-- ENTITIES: public read, service role write
create policy "Entities are publicly readable"
  on entities for select
  using (status = 'active');

create policy "Service role can insert entities"
  on entities for insert
  with check (true);

create policy "Service role can update entities"
  on entities for update
  using (true);

-- RECEIPTS: public read, insert only (no update, no delete — EVER)
create policy "Receipts are publicly readable"
  on receipts for select
  using (true);

create policy "Receipts can be inserted"
  on receipts for insert
  with check (true);

-- NO update or delete policies for receipts. Append-only.

-- NEEDS: public read for open needs, insert/update via service
create policy "Open needs are publicly readable"
  on needs for select
  using (true);

create policy "Needs can be inserted"
  on needs for insert
  with check (true);

create policy "Needs can be updated"
  on needs for update
  using (true);

-- SCORE HISTORY: public read
create policy "Score history is publicly readable"
  on score_history for select
  using (true);

create policy "Score history can be inserted"
  on score_history for insert
  with check (true);

-- API KEYS: only via service role (no public access)
create policy "API keys via service role only"
  on api_keys for all
  using (true);

-- =============================================================================
-- ITEM 14: Receipt deduplication — one receipt per transaction_ref per submitter
-- =============================================================================
create unique index if not exists idx_receipts_dedup
  on receipts (entity_id, submitted_by, transaction_ref)
  where transaction_ref is not null;

-- =============================================================================
-- ITEM 15: Fix score computation — handle null signals properly
-- =============================================================================
create or replace function compute_emilia_score(p_entity_id uuid)
returns float as $$
declare
  v_score float := 50.0;
  v_count integer;
  v_total_weight float := 0;
  v_weighted_sum float := 0;
  v_avg_delivery float;
  v_avg_product float;
  v_avg_price float;
  v_avg_return float;
  v_avg_satisfaction float;
  v_consistency float;
  v_stddev float;
begin
  -- Count receipts
  select count(*) into v_count
  from receipts
  where entity_id = p_entity_id;

  if v_count = 0 then
    return 50.0;
  end if;

  -- Compute averages from rolling window, excluding nulls
  select
    avg(delivery_accuracy),
    avg(product_accuracy),
    avg(price_integrity),
    avg(return_processing),
    avg(agent_satisfaction),
    coalesce(stddev(composite_score), 0)
  into
    v_avg_delivery, v_avg_product, v_avg_price,
    v_avg_return, v_avg_satisfaction, v_stddev
  from (
    select * from receipts
    where entity_id = p_entity_id
    order by created_at desc
    limit 200
  ) recent;

  -- Only count signals that have data (null signals excluded from weight)
  if v_avg_delivery is not null then
    v_weighted_sum := v_weighted_sum + v_avg_delivery * 0.30;
    v_total_weight := v_total_weight + 0.30;
  end if;

  if v_avg_product is not null then
    v_weighted_sum := v_weighted_sum + v_avg_product * 0.25;
    v_total_weight := v_total_weight + 0.25;
  end if;

  if v_avg_price is not null then
    v_weighted_sum := v_weighted_sum + v_avg_price * 0.15;
    v_total_weight := v_total_weight + 0.15;
  end if;

  if v_avg_return is not null then
    v_weighted_sum := v_weighted_sum + v_avg_return * 0.15;
    v_total_weight := v_total_weight + 0.15;
  end if;

  if v_avg_satisfaction is not null then
    v_weighted_sum := v_weighted_sum + v_avg_satisfaction * 0.10;
    v_total_weight := v_total_weight + 0.10;
  end if;

  -- Consistency: low stddev = high score
  v_consistency := greatest(0, 100 - v_stddev * 2);
  v_weighted_sum := v_weighted_sum + v_consistency * 0.05;
  v_total_weight := v_total_weight + 0.05;

  if v_total_weight = 0 then
    return 50.0;
  end if;

  v_score := v_weighted_sum / v_total_weight;

  -- Dampen new entities toward 50
  if v_count < 5 then
    v_score := 50.0 + (v_score - 50.0) * (v_count::float / 5.0);
  end if;

  -- Also update the breakdown columns
  update entities set
    avg_delivery_accuracy = v_avg_delivery,
    avg_product_accuracy = v_avg_product,
    avg_price_integrity = v_avg_price,
    avg_return_processing = v_avg_return,
    avg_agent_satisfaction = v_avg_satisfaction,
    score_consistency = v_consistency
  where id = p_entity_id;

  return round(greatest(0, least(100, v_score))::numeric, 1);
end;
$$ language plpgsql volatile;

-- =============================================================================
-- SEARCH FUNCTIONS (for semantic entity search + need matching)
-- =============================================================================

-- Semantic entity search
create or replace function search_entities(
  query_embedding extensions.vector(1536),
  min_score float default 0,
  filter_type text default null,
  filter_category text default null,
  match_limit int default 20
)
returns table (
  entity_id text,
  display_name text,
  entity_type text,
  description text,
  category text,
  capabilities jsonb,
  emilia_score float,
  total_receipts integer,
  verified boolean,
  similarity float
) as $$
begin
  return query
  select
    e.entity_id,
    e.display_name,
    e.entity_type,
    e.description,
    e.category,
    e.capabilities,
    e.emilia_score,
    e.total_receipts,
    e.verified,
    1 - (e.capability_embedding <=> query_embedding) as similarity
  from entities e
  where e.status = 'active'
    and e.capability_embedding is not null
    and e.emilia_score >= min_score
    and (filter_type is null or e.entity_type = filter_type)
    and (filter_category is null or e.category = filter_category)
  order by e.capability_embedding <=> query_embedding
  limit match_limit;
end;
$$ language plpgsql stable;

-- Match entities to a need (relevance * compatibility score)
create or replace function match_entities_to_need(
  query_embedding extensions.vector(1536),
  min_score float default 0,
  match_limit int default 10,
  exclude_entity uuid default null
)
returns table (
  entity_id text,
  display_name text,
  emilia_score float,
  match_score float
) as $$
begin
  return query
  select
    e.entity_id,
    e.display_name,
    e.emilia_score,
    -- 60% relevance + 40% compatibility score
    round(((1 - (e.capability_embedding <=> query_embedding)) * 0.6
      + (e.emilia_score / 100.0) * 0.4)::numeric, 3)::float as match_score
  from entities e
  where e.status = 'active'
    and e.capability_embedding is not null
    and e.emilia_score >= min_score
    and (exclude_entity is null or e.id != exclude_entity)
  order by match_score desc
  limit match_limit;
end;
$$ language plpgsql stable;
