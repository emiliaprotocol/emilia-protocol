-- SPDX-License-Identifier: Apache-2.0
-- Durable state for the EMILIA native approval platform.

create extension if not exists pgcrypto;

create or replace function mobile_presentation_is_valid(p_value jsonb)
returns boolean
language sql
immutable
set search_path = public, pg_temp
as $$
  select coalesce(
    jsonb_typeof(p_value) = 'object'
    and p_value ->> '@version' = 'EP-MOBILE-PRESENTATION-v1'
    and p_value ?& array['@version', 'title', 'summary', 'risk', 'consequence', 'material_fields']
    and p_value - array['@version', 'title', 'summary', 'risk', 'consequence', 'material_fields'] = '{}'::jsonb
    and jsonb_typeof(p_value -> 'title') = 'string'
    and char_length(p_value ->> 'title') between 1 and 200
    and jsonb_typeof(p_value -> 'summary') = 'string'
    and char_length(p_value ->> 'summary') between 1 and 2000
    and jsonb_typeof(p_value -> 'risk') = 'string'
    and char_length(p_value ->> 'risk') between 1 and 128
    and jsonb_typeof(p_value -> 'consequence') = 'string'
    and char_length(p_value ->> 'consequence') between 0 and 2000
    and jsonb_typeof(p_value -> 'material_fields') = 'object'
    and (
      select count(*)
      from jsonb_each(
        case when jsonb_typeof(p_value -> 'material_fields') = 'object'
          then p_value -> 'material_fields' else '{}'::jsonb end
      )
    ) between 1 and 64
    and not exists (
      select 1
      from jsonb_each(
        case when jsonb_typeof(p_value -> 'material_fields') = 'object'
          then p_value -> 'material_fields' else '{}'::jsonb end
      ) field(name, value)
      where field.name !~ '^[A-Za-z0-9][A-Za-z0-9_. -]{0,127}$'
         or jsonb_typeof(field.value) <> 'string'
         or char_length(field.value #>> '{}') > 4096
    ),
    false
  );
$$;

create table if not exists mobile_kv_state (
  state_key text primary key check (char_length(state_key) between 16 and 512),
  state_value text not null check (char_length(state_value) between 1 and 512),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists mobile_pairings (
  code_hash text primary key check (code_hash ~ '^[0-9a-f]{64}$'),
  entity_ref text not null references entities(entity_id) on delete cascade,
  approver_id text not null check (char_length(approver_id) between 3 and 128),
  profile_id text not null check (char_length(profile_id) between 3 and 128),
  allowed_apps jsonb not null,
  expires_at timestamptz not null,
  session_expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  constraint mobile_pairings_expiry_order check (session_expires_at > expires_at),
  constraint mobile_pairings_allowed_apps_object check (jsonb_typeof(allowed_apps) = 'object')
);

create index if not exists mobile_pairings_entity_created_idx
  on mobile_pairings (entity_ref, created_at desc);

create table if not exists mobile_sessions (
  session_id uuid primary key default gen_random_uuid(),
  token_hash text unique not null check (token_hash ~ '^[0-9a-f]{64}$'),
  entity_ref text not null references entities(entity_id) on delete cascade,
  approver_id text not null check (char_length(approver_id) between 3 and 128),
  profile_id text not null check (char_length(profile_id) between 3 and 128),
  platform text not null check (platform in ('ios', 'android')),
  app_id text not null check (char_length(app_id) between 3 and 256),
  device_key_id text,
  expires_at timestamptz not null,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists mobile_sessions_entity_approver_idx
  on mobile_sessions (entity_ref, approver_id, created_at desc)
  where revoked_at is null;

create table if not exists mobile_enrollments (
  device_key_id text primary key check (char_length(device_key_id) between 16 and 256),
  entity_ref text not null references entities(entity_id) on delete cascade,
  credential_id text unique not null check (char_length(credential_id) between 8 and 4096),
  public_key_spki text not null check (char_length(public_key_spki) between 32 and 8192),
  approver_id text not null check (char_length(approver_id) between 3 and 128),
  platform text not null check (platform in ('ios', 'android')),
  app_id text not null check (char_length(app_id) between 3 and 256),
  attestation_key_id text not null check (char_length(attestation_key_id) between 3 and 512),
  platform_public_key text,
  status text not null default 'active' check (status in ('active', 'revoked', 'expired')),
  valid_from timestamptz not null,
  valid_to timestamptz not null,
  sign_count bigint not null default 0 check (sign_count >= 0),
  attestation_format text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint mobile_enrollments_validity check (valid_to > valid_from),
  constraint mobile_enrollments_entity_device_unique unique (entity_ref, device_key_id),
  constraint mobile_enrollments_platform_key check (
    (platform = 'ios' and platform_public_key like '%BEGIN PUBLIC KEY%'
      and char_length(platform_public_key) between 64 and 8192)
    or (platform = 'android' and platform_public_key ~ '^[A-Za-z0-9_-]+$'
      and char_length(platform_public_key) between 80 and 8192)
  )
);

drop index if exists mobile_enrollments_active_attestation_key_idx;
create unique index if not exists mobile_enrollments_active_apple_attest_key_idx
  on mobile_enrollments (app_id, attestation_key_id)
  where platform = 'ios' and status = 'active';
create unique index if not exists mobile_enrollments_active_android_device_key_idx
  on mobile_enrollments (attestation_key_id)
  where platform = 'android' and status = 'active';

alter table mobile_sessions
  add constraint mobile_sessions_device_key_fk
  foreign key (entity_ref, device_key_id)
  references mobile_enrollments(entity_ref, device_key_id);

create index if not exists mobile_enrollments_entity_approver_idx
  on mobile_enrollments (entity_ref, approver_id, status, valid_to);

create table if not exists mobile_counters (
  counter_key text primary key check (char_length(counter_key) between 3 and 512),
  counter_value bigint not null check (counter_value >= 0),
  updated_at timestamptz not null default now()
);

create table if not exists mobile_audit_records (
  sequence_id bigint generated always as identity primary key,
  record_id text unique not null check (record_id ~ '^mar_[0-9a-f]{32}$'),
  entity_ref text not null references entities(entity_id) on delete cascade,
  event jsonb not null check (jsonb_typeof(event) = 'object'),
  previous_hash text check (previous_hash is null or previous_hash ~ '^[0-9a-f]{64}$'),
  record_hash text unique not null check (record_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);

create index if not exists mobile_audit_entity_sequence_idx
  on mobile_audit_records (entity_ref, sequence_id desc);

-- Portable decision evidence uses the same canonical record contract as the
-- offline verifier. Operational enrollment/revocation events remain in
-- mobile_audit_records so they cannot perturb a relying party's evidence head.
create table if not exists mobile_evidence_records (
  sequence_id bigint generated always as identity primary key,
  record_id text unique not null check (record_id ~ '^mar_[0-9a-f]{32}$'),
  entity_ref text not null references entities(entity_id) on delete cascade,
  record jsonb not null check (jsonb_typeof(record) = 'object'),
  previous_hash text not null check (previous_hash = 'genesis' or previous_hash ~ '^[0-9a-f]{64}$'),
  record_hash text unique not null check (record_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  constraint mobile_evidence_record_id_match check (record ->> 'record_id' = record_id),
  constraint mobile_evidence_previous_hash_match check (record ->> 'prev_hash' = previous_hash),
  constraint mobile_evidence_hash_match check (record ->> 'hash' = record_hash)
);

create index if not exists mobile_evidence_entity_sequence_idx
  on mobile_evidence_records (entity_ref, sequence_id desc);
create unique index if not exists mobile_evidence_entity_record_seq_idx
  on mobile_evidence_records (entity_ref, ((record ->> 'seq')::bigint));

create table if not exists mobile_actions (
  action_reference text not null check (char_length(action_reference) between 8 and 256),
  entity_ref text not null references entities(entity_id) on delete cascade,
  approver_id text not null check (char_length(approver_id) between 3 and 128),
  initiator_id text not null check (char_length(initiator_id) between 3 and 256),
  action jsonb not null check (jsonb_typeof(action) = 'object'),
  presentation jsonb not null constraint mobile_actions_presentation_v1
    check (mobile_presentation_is_valid(presentation)),
  policy jsonb,
  policy_id text,
  status text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'expired', 'cancelled')),
  decision_challenge_id text,
  decision_verdict text,
  decision_evidence jsonb,
  decided_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (entity_ref, action_reference)
);

create index if not exists mobile_actions_inbox_idx
  on mobile_actions (entity_ref, approver_id, status, created_at desc);
create unique index if not exists mobile_actions_entity_action_approver_idx
  on mobile_actions (entity_ref, (action ->> 'action_id'), approver_id);

create table if not exists mobile_action_challenges (
  challenge_id text primary key check (char_length(challenge_id) between 8 and 256),
  session_id uuid not null references mobile_sessions(session_id) on delete cascade,
  action_reference text not null,
  entity_ref text not null references entities(entity_id) on delete cascade,
  approver_id text not null check (char_length(approver_id) between 3 and 128),
  decision text not null check (decision in ('approved', 'denied')),
  action_hash text not null check (action_hash ~ '^sha256:[0-9a-f]{64}$'),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  foreign key (entity_ref, action_reference)
    references mobile_actions(entity_ref, action_reference) on delete cascade
);

create index if not exists mobile_action_challenges_action_idx
  on mobile_action_challenges (entity_ref, action_reference, created_at desc);
create index if not exists mobile_action_challenges_session_idx
  on mobile_action_challenges (session_id, consumed_at, expires_at);

create or replace function mobile_state_add_if_absent(
  p_state_key text,
  p_state_value text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  inserted_count integer;
begin
  if p_state_key is null
     or char_length(p_state_key) not between 16 and 512
     or p_state_value is null
     or char_length(p_state_value) not between 1 and 512 then
    return false;
  end if;

  insert into mobile_kv_state(state_key, state_value)
  values (p_state_key, p_state_value)
  on conflict (state_key) do nothing;
  get diagnostics inserted_count = row_count;
  return inserted_count = 1;
exception when check_violation then
  return false;
end;
$$;

create or replace function mobile_state_compare_and_set(
  p_state_key text,
  p_expected text,
  p_replacement text,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  updated_count integer;
begin
  if p_state_key is null
     or char_length(p_state_key) not between 16 and 512
     or p_expected is null
     or char_length(p_expected) not between 1 and 512
     or p_replacement is null
     or char_length(p_replacement) not between 1 and 512
     or p_now is null then
    return false;
  end if;

  update mobile_kv_state
  set state_value = p_replacement, updated_at = p_now
  where state_key = p_state_key
    and state_value = p_expected;
  get diagnostics updated_count = row_count;
  return updated_count = 1;
end;
$$;

create or replace function create_mobile_pairing(
  p_code_hash text,
  p_entity_ref text,
  p_approver_id text,
  p_profile_id text,
  p_allowed_apps jsonb,
  p_expires_at timestamptz,
  p_session_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_code_hash is null
     or p_code_hash !~ '^[0-9a-f]{64}$'
     or p_entity_ref is null
     or p_approver_id is null
     or char_length(p_approver_id) not between 3 and 128
     or p_profile_id is null
     or char_length(p_profile_id) not between 3 and 128
     or p_allowed_apps is null
     or jsonb_typeof(p_allowed_apps) <> 'object'
     or p_expires_at is null
     or p_session_expires_at is null
     or p_now is null
     or p_expires_at <= p_now
     or p_session_expires_at <= p_expires_at then
    return false;
  end if;
  if p_allowed_apps - 'ios' - 'android' <> '{}'::jsonb
     or jsonb_typeof(p_allowed_apps -> 'ios') <> 'array'
     or jsonb_typeof(p_allowed_apps -> 'android') <> 'array' then
    return false;
  end if;
  if jsonb_array_length(p_allowed_apps -> 'ios') < 1
     or jsonb_array_length(p_allowed_apps -> 'ios') > 8
     or jsonb_array_length(p_allowed_apps -> 'android') > 8
     or exists (
       select 1 from jsonb_array_elements((p_allowed_apps -> 'ios') || (p_allowed_apps -> 'android')) app
       where jsonb_typeof(app) <> 'string'
          or char_length(app #>> '{}') not between 3 and 256
     ) then
    return false;
  end if;

  insert into mobile_pairings(
    code_hash, entity_ref, approver_id, profile_id, allowed_apps, expires_at, session_expires_at
  ) values (
    p_code_hash, p_entity_ref, p_approver_id, p_profile_id, p_allowed_apps,
    p_expires_at, p_session_expires_at
  );
  return true;
exception when unique_violation or check_violation or foreign_key_violation or not_null_violation then
  return false;
end;
$$;

create or replace function touch_mobile_session(
  p_session_id uuid,
  p_token_hash text,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  updated_count integer;
begin
  if p_session_id is null
     or p_token_hash is null
     or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_now is null then
    return false;
  end if;

  update mobile_sessions
  set last_used_at = p_now
  where session_id = p_session_id
    and token_hash = p_token_hash
    and revoked_at is null
    and expires_at > p_now;
  get diagnostics updated_count = row_count;
  return updated_count = 1;
end;
$$;

create or replace function create_mobile_demo_action(
  p_action_reference text,
  p_entity_ref text,
  p_approver_id text,
  p_initiator_id text,
  p_action jsonb,
  p_presentation jsonb,
  p_policy jsonb,
  p_policy_id text,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_action_reference is null
     or p_action_reference !~ '^mobact_[0-9a-f]{32}$'
     or p_entity_ref is null
     or p_approver_id is null
     or char_length(p_approver_id) not between 3 and 128
     or p_initiator_id is null
     or char_length(p_initiator_id) not between 3 and 256
     or p_action is null
     or jsonb_typeof(p_action) <> 'object'
     or p_presentation is null
     or not mobile_presentation_is_valid(p_presentation)
     or p_policy is null
     or jsonb_typeof(p_policy) <> 'object'
     or p_policy_id is null
     or char_length(p_policy_id) not between 3 and 128
     or p_expires_at is null
     or p_now is null
     or p_expires_at <= p_now then
    return false;
  end if;
  if p_policy ->> 'policy_id' <> p_policy_id
     or octet_length(p_action::text) > 65536
     or octet_length(p_presentation::text) > 65536
     or octet_length(p_policy::text) > 16384 then
    return false;
  end if;

  insert into mobile_actions(
    action_reference, entity_ref, approver_id, initiator_id, action, presentation,
    policy, policy_id, expires_at
  ) values (
    p_action_reference, p_entity_ref, p_approver_id, p_initiator_id, p_action,
    p_presentation, p_policy, p_policy_id, p_expires_at
  );
  return true;
exception when unique_violation or check_violation or foreign_key_violation or not_null_violation then
  return false;
end;
$$;

create or replace function create_grace_mobile_action_group(
  p_assignments jsonb,
  p_entity_ref text,
  p_initiator_id text,
  p_action jsonb,
  p_presentation jsonb,
  p_policy jsonb,
  p_policy_id text,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  assignment_count integer;
  required_count integer;
  assignment_approvers jsonb;
  target_delta_kw numeric;
  hard_cut_threshold_kw numeric;
begin
  if p_assignments is null
     or jsonb_typeof(p_assignments) <> 'array'
     or p_entity_ref is null
     or p_initiator_id is null
     or char_length(p_initiator_id) not between 3 and 256
     or p_action is null
     or jsonb_typeof(p_action) <> 'object'
     or p_action ->> '@version' is distinct from 'EP-GRACE-CURTAILMENT-ACTION-v1'
     or p_action ->> 'action_type' is distinct from 'grid.curtailment'
     or p_action ->> 'effect_class' is distinct from 'power_reduction'
     or p_action ->> 'control_mode' not in ('human_on_the_loop', 'human_in_the_loop')
     or char_length(coalesce(p_action ->> 'action_id', '')) not between 3 and 256
     or char_length(coalesce(p_action ->> 'facility', '')) not between 3 and 256
     or coalesce(p_action ->> 'target_delta_kw', '') !~ '^(0|[1-9][0-9]*)(\.[0-9]{1,3})?$'
     or coalesce(p_action ->> 'baseline_method_hash', '') !~ '^sha256:[0-9a-f]{64}$'
     or char_length(coalesce(p_action ->> 'envelope_id', '')) not between 3 and 256
     or char_length(coalesce(p_action ->> 'requested_by', '')) not between 3 and 256
     or p_action - array[
       '@version', 'action_id', 'action_type', 'effect_class', 'facility',
       'target_delta_kw', 'window', 'issued_at', 'expires_at',
       'baseline_method_hash', 'control_mode', 'envelope_id', 'requested_by'
     ] <> '{}'::jsonb
     or p_presentation is null
     or not mobile_presentation_is_valid(p_presentation)
     or p_policy is null
     or jsonb_typeof(p_policy) <> 'object'
     or p_policy_id is null
     or char_length(p_policy_id) not between 3 and 128
     or p_policy ->> 'policy_id' is distinct from p_policy_id
     or p_policy ->> 'action_family' is distinct from 'grid.curtailment'
     or p_policy ->> 'human_approval' is distinct from 'class_a'
     or jsonb_typeof(p_policy -> 'approvers') <> 'array'
     or coalesce(p_policy ->> 'required_approvals', '') !~ '^[1-9][0-9]*$'
     or char_length(coalesce(p_policy ->> 'required_approvals', '')) > 2
     or coalesce(p_policy ->> 'hard_cut_threshold_kw', '') !~ '^[1-9][0-9]*$'
     or p_policy - array[
       'policy_id', 'action_family', 'human_approval', 'required_approvals',
       'approvers', 'hard_cut_threshold_kw'
     ] <> '{}'::jsonb
     or p_expires_at is null
     or p_now is null
     or p_expires_at <= p_now
     or octet_length(p_action::text) > 65536
     or octet_length(p_presentation::text) > 65536
     or octet_length(p_policy::text) > 16384 then
    return false;
  end if;

  assignment_count := jsonb_array_length(p_assignments);
  begin
    required_count := (p_policy ->> 'required_approvals')::integer;
    target_delta_kw := (p_action ->> 'target_delta_kw')::numeric;
    hard_cut_threshold_kw := (p_policy ->> 'hard_cut_threshold_kw')::numeric;
  exception when others then
    return false;
  end;

  if assignment_count not between 1 and 16
     or required_count > assignment_count
     or target_delta_kw <= 0
     or (target_delta_kw >= hard_cut_threshold_kw and required_count < 2)
     or jsonb_array_length(p_policy -> 'approvers') <> assignment_count
     or exists (
       select 1 from jsonb_array_elements(p_assignments) item
       where jsonb_typeof(item) <> 'object'
          or item - 'action_reference' - 'approver_id' <> '{}'::jsonb
          or coalesce(item ->> 'action_reference', '') !~ '^mobact_[0-9a-f]{32}$'
          or char_length(coalesce(item ->> 'approver_id', '')) not between 3 and 128
     )
     or exists (
       select 1
       from jsonb_array_elements(p_assignments) item
       group by item ->> 'action_reference'
       having count(*) > 1
     )
     or exists (
       select 1
       from jsonb_array_elements(p_assignments) item
       group by item ->> 'approver_id'
       having count(*) > 1
     ) then
    return false;
  end if;

  select jsonb_agg(item ->> 'approver_id' order by ordinal)
    into assignment_approvers
    from jsonb_array_elements(p_assignments) with ordinality a(item, ordinal);
  if assignment_approvers is distinct from p_policy -> 'approvers' then
    return false;
  end if;

  insert into mobile_actions(
    action_reference, entity_ref, approver_id, initiator_id, action, presentation,
    policy, policy_id, expires_at
  )
  select
    item ->> 'action_reference', p_entity_ref, item ->> 'approver_id', p_initiator_id,
    p_action, p_presentation, p_policy, p_policy_id, p_expires_at
  from jsonb_array_elements(p_assignments) item;
  return true;
exception when unique_violation or check_violation or foreign_key_violation or not_null_violation then
  return false;
end;
$$;

create or replace function exchange_mobile_pairing(
  p_code_hash text,
  p_token_hash text,
  p_platform text,
  p_app_id text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  pairing mobile_pairings%rowtype;
  created mobile_sessions%rowtype;
begin
  if p_code_hash !~ '^[0-9a-f]{64}$' or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_platform not in ('ios', 'android') or char_length(p_app_id) not between 3 and 256 then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;

  select * into pairing from mobile_pairings where code_hash = p_code_hash for update;
  if not found or pairing.consumed_at is not null or pairing.expires_at < p_now then
    return jsonb_build_object('ok', false, 'reason', 'invalid_or_expired');
  end if;
  if not coalesce(pairing.allowed_apps -> p_platform, '[]'::jsonb) ? p_app_id then
    return jsonb_build_object('ok', false, 'reason', 'app_not_allowed');
  end if;

  update mobile_pairings set consumed_at = p_now where code_hash = p_code_hash;
  insert into mobile_sessions (
    token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
  ) values (
    p_token_hash, pairing.entity_ref, pairing.approver_id, pairing.profile_id,
    p_platform, p_app_id, pairing.session_expires_at
  ) returning * into created;

  return jsonb_build_object(
    'ok', true,
    'session_id', created.session_id,
    'entity_ref', created.entity_ref,
    'approver_id', created.approver_id,
    'profile_id', created.profile_id,
    'expires_at', created.expires_at
  );
end;
$$;

create or replace function advance_mobile_counter(
  p_counter_key text,
  p_next bigint
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  touched text;
begin
  if char_length(p_counter_key) not between 3 and 512 or p_next < 0 then
    return false;
  end if;
  insert into mobile_counters (counter_key, counter_value)
  values (p_counter_key, p_next)
  on conflict (counter_key) do update
    set counter_value = excluded.counter_value, updated_at = now()
    where mobile_counters.counter_value < excluded.counter_value
  returning counter_key into touched;
  return touched is not null;
end;
$$;

create or replace function append_mobile_audit_event(
  p_entity_ref text,
  p_event jsonb
) returns table(record_id text, hash text, previous_hash text, recorded_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  prior text;
  rid text;
  digest_hex text;
  stamp timestamptz := clock_timestamp();
begin
  if p_entity_ref is null or jsonb_typeof(p_event) <> 'object' then
    raise exception 'invalid mobile audit event';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_entity_ref, 74219));
  select mar.record_hash into prior
    from mobile_audit_records mar
    where mar.entity_ref = p_entity_ref
    order by mar.sequence_id desc
    limit 1;
  rid := 'mar_' || replace(gen_random_uuid()::text, '-', '');
  digest_hex := encode(digest(
    convert_to(coalesce(prior, '') || '|' || rid || '|' || stamp::text || '|' || p_event::text, 'UTF8'),
    'sha256'
  ), 'hex');
  insert into mobile_audit_records(record_id, entity_ref, event, previous_hash, record_hash, created_at)
    values (rid, p_entity_ref, p_event, prior, digest_hex, stamp);
  return query select rid, digest_hex, prior, stamp;
end;
$$;

create or replace function append_mobile_evidence_record(
  p_entity_ref text,
  p_expected_hash text,
  p_record jsonb,
  p_canonical_body text
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  prior_hash text;
  prior_seq bigint;
  proposed_seq bigint;
  expected_previous text;
  parsed_body jsonb;
begin
  if p_entity_ref is null
     or jsonb_typeof(p_record) <> 'object'
     or p_canonical_body is null
     or octet_length(p_canonical_body) > 1048576
     or coalesce(p_record ->> 'record_id', '') !~ '^mar_[0-9a-f]{32}$'
     or coalesce(p_record ->> 'hash', '') !~ '^[0-9a-f]{64}$'
     or coalesce(p_record ->> 'prev_hash', '') !~ '^(genesis|[0-9a-f]{64})$'
     or jsonb_typeof(p_record -> 'seq') <> 'number'
     or coalesce(p_record ->> 'seq', '') !~ '^(0|[1-9][0-9]*)$' then
    return false;
  end if;

  begin
    parsed_body := p_canonical_body::jsonb;
    proposed_seq := (p_record ->> 'seq')::bigint;
  exception when others then
    return false;
  end;

  if parsed_body is distinct from (p_record - 'hash')
     or encode(digest(convert_to(p_canonical_body, 'UTF8'), 'sha256'), 'hex')
        <> p_record ->> 'hash' then
    return false;
  end if;

  perform pg_advisory_xact_lock(hashtextextended('mobile-evidence:' || p_entity_ref, 74219));
  select mer.record_hash, (mer.record ->> 'seq')::bigint
    into prior_hash, prior_seq
    from mobile_evidence_records mer
    where mer.entity_ref = p_entity_ref
    order by mer.sequence_id desc
    limit 1;

  if prior_hash is distinct from p_expected_hash then
    return false;
  end if;
  expected_previous := coalesce(prior_hash, 'genesis');
  if proposed_seq <> coalesce(prior_seq + 1, 0)
     or p_record ->> 'prev_hash' <> expected_previous then
    return false;
  end if;

  insert into mobile_evidence_records(
    record_id, entity_ref, record, previous_hash, record_hash
  ) values (
    p_record ->> 'record_id', p_entity_ref, p_record,
    p_record ->> 'prev_hash', p_record ->> 'hash'
  );
  return true;
exception when unique_violation then
  return false;
end;
$$;

create or replace function enroll_mobile_device(
  p_entity_ref text,
  p_session_id uuid,
  p_enrollment jsonb,
  p_event jsonb
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  pairing_session mobile_sessions%rowtype;
begin
  select * into pairing_session
  from mobile_sessions
  where session_id = p_session_id
    and entity_ref = p_entity_ref
  for update;
  if not found
     or pairing_session.revoked_at is not null
     or pairing_session.expires_at <= now()
     or pairing_session.device_key_id is not null
     or pairing_session.approver_id <> p_enrollment->>'approver_id'
     or pairing_session.platform <> p_enrollment->>'platform'
     or pairing_session.app_id <> p_enrollment->>'app_id' then
    return false;
  end if;
  if p_enrollment is null
     or jsonb_typeof(p_enrollment) <> 'object'
     or coalesce(p_enrollment ->> 'device_key_id', '') !~ '^ep:key:mobile-[A-Za-z0-9_-]{20,128}$'
     or coalesce(p_enrollment ->> 'credential_id', '') !~ '^[A-Za-z0-9_-]+$'
     or char_length(coalesce(p_enrollment ->> 'credential_id', '')) not between 8 and 4096
     or coalesce(p_enrollment ->> 'public_key_spki', '') !~ '^[A-Za-z0-9_-]+$'
     or char_length(coalesce(p_enrollment ->> 'public_key_spki', '')) not between 32 and 8192
     or coalesce(p_enrollment ->> 'status', '') <> 'active'
     or coalesce(p_enrollment ->> 'sign_count', '') !~ '^(0|[1-9][0-9]*)$'
     or char_length(coalesce(p_enrollment ->> 'sign_count', '')) > 16
     or (p_enrollment ->> 'sign_count')::numeric > 9007199254740991
     or coalesce(p_enrollment ->> 'valid_from', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
     or coalesce(p_enrollment ->> 'valid_to', '') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
     or (p_enrollment ->> 'platform' = 'android' and (
       coalesce(p_enrollment ->> 'attestation_key_id', '') !~ '^android-keystore:sha256:[A-Za-z0-9_-]{43}$'
       or coalesce(p_enrollment ->> 'platform_public_key', '') !~ '^[A-Za-z0-9_-]+$'
       or char_length(coalesce(p_enrollment ->> 'platform_public_key', '')) not between 80 and 8192
     ))
     or (p_enrollment ->> 'platform' = 'ios' and (
       coalesce(p_enrollment ->> 'attestation_key_id', '') !~ '^[A-Za-z0-9+/_=-]{3,512}$'
       or coalesce(p_enrollment ->> 'platform_public_key', '') not like '%BEGIN PUBLIC KEY%'
     )) then
    return false;
  end if;

  insert into mobile_enrollments (
    device_key_id, entity_ref, credential_id, public_key_spki, approver_id,
    platform, app_id, attestation_key_id, platform_public_key, status,
    valid_from, valid_to, sign_count, attestation_format
  ) values (
    p_enrollment->>'device_key_id', p_entity_ref, p_enrollment->>'credential_id',
    p_enrollment->>'public_key_spki', p_enrollment->>'approver_id',
    p_enrollment->>'platform', p_enrollment->>'app_id',
    p_enrollment->>'attestation_key_id', nullif(p_enrollment->>'platform_public_key', ''),
    p_enrollment->>'status', (p_enrollment->>'valid_from')::timestamptz,
    (p_enrollment->>'valid_to')::timestamptz, (p_enrollment->>'sign_count')::bigint,
    nullif(p_enrollment->>'attestation_format', '')
  );
  insert into mobile_counters(counter_key, counter_value)
  values (
    'mobile:webauthn:' || (p_enrollment ->> 'device_key_id'),
    (p_enrollment ->> 'sign_count')::bigint
  );
  update mobile_sessions
  set device_key_id = p_enrollment->>'device_key_id',
      last_used_at = now()
  where session_id = p_session_id
    and device_key_id is null;
  if not found then
    raise exception 'mobile session binding changed concurrently';
  end if;
  perform * from append_mobile_audit_event(p_entity_ref, p_event);
  return true;
exception when unique_violation or check_violation or foreign_key_violation or not_null_violation
  or invalid_text_representation or numeric_value_out_of_range
  or invalid_datetime_format or datetime_field_overflow then
  return false;
end;
$$;

create or replace function revoke_mobile_session(
  p_entity_ref text,
  p_session_id uuid,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  active_session mobile_sessions%rowtype;
begin
  select * into active_session
  from mobile_sessions
  where session_id = p_session_id
    and entity_ref = p_entity_ref
  for update;

  if not found or active_session.revoked_at is not null then
    return false;
  end if;

  if active_session.device_key_id is not null then
    update mobile_enrollments
    set status = 'revoked', updated_at = p_now
    where entity_ref = p_entity_ref
      and device_key_id = active_session.device_key_id
      and status = 'active';
  end if;

  update mobile_sessions
  set revoked_at = p_now, last_used_at = p_now
  where session_id = p_session_id
    and entity_ref = p_entity_ref;

  perform append_mobile_audit_event(
    p_entity_ref,
    jsonb_build_object(
      'event_type', 'mobile.session_revoked',
      'session_id', p_session_id,
      'device_key_id', active_session.device_key_id,
      'revoked_at', p_now
    )
  );
  return true;
end;
$$;

create or replace function register_mobile_action_challenge(
  p_entity_ref text,
  p_session_id uuid,
  p_action_reference text,
  p_approver_id text,
  p_challenge_id text,
  p_action_hash text,
  p_decision text,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  inserted_count integer;
begin
  if p_entity_ref is null
     or p_session_id is null
     or char_length(p_action_reference) not between 8 and 256
     or char_length(p_approver_id) not between 3 and 128
     or char_length(p_challenge_id) not between 8 and 256
     or p_action_hash !~ '^sha256:[0-9a-f]{64}$'
     or p_decision not in ('approved', 'denied')
     or p_expires_at <= p_now then
    return false;
  end if;

  insert into mobile_action_challenges (
    challenge_id, session_id, action_reference, entity_ref, approver_id, decision, action_hash, expires_at
  )
  select
    p_challenge_id, p_session_id, action.action_reference, action.entity_ref,
    action.approver_id, p_decision, p_action_hash, p_expires_at
  from mobile_actions action
  join mobile_sessions session
    on session.session_id = p_session_id
   and session.entity_ref = action.entity_ref
   and session.approver_id = action.approver_id
  where action.action_reference = p_action_reference
    and action.entity_ref = p_entity_ref
    and action.approver_id = p_approver_id
    and action.status = 'pending'
    and action.expires_at > p_now
    and action.expires_at >= p_expires_at
    and session.revoked_at is null
    and session.expires_at >= p_expires_at
    and session.device_key_id is not null;

  get diagnostics inserted_count = row_count;
  return inserted_count = 1;
exception when unique_violation or check_violation or foreign_key_violation then
  return false;
end;
$$;

drop function if exists commit_mobile_action_decision(text, text, text, text, text, timestamptz);
drop function if exists commit_mobile_action_decision(text, uuid, text, text, text, text, text, jsonb, text, timestamptz);

create or replace function commit_mobile_action_decision(
  p_entity_ref text,
  p_session_id uuid,
  p_challenge_id text,
  p_action_hash text,
  p_decision text,
  p_verdict text,
  p_decision_evidence jsonb,
  p_expected_hash text,
  p_record jsonb,
  p_canonical_body text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  mapping mobile_action_challenges%rowtype;
  active_session mobile_sessions%rowtype;
  updated_count integer;
  prior_hash text;
  prior_seq bigint;
  proposed_seq bigint;
  expected_previous text;
  parsed_body jsonb;
begin
  if p_entity_ref is null
     or p_session_id is null
     or p_challenge_id is null
     or char_length(p_challenge_id) not between 8 and 256
     or coalesce(p_action_hash, '') !~ '^sha256:[0-9a-f]{64}$'
     or p_decision is null
     or p_decision not in ('approved', 'denied')
     or p_verdict is distinct from 'verified'
     or p_now is null
     or jsonb_typeof(p_record) <> 'object'
     or p_canonical_body is null
     or octet_length(p_canonical_body) > 1048576
     or coalesce(p_record ->> 'record_id', '') !~ '^mar_[0-9a-f]{32}$'
     or coalesce(p_record ->> 'hash', '') !~ '^[0-9a-f]{64}$'
     or coalesce(p_record ->> 'prev_hash', '') !~ '^(genesis|[0-9a-f]{64})$'
     or jsonb_typeof(p_record -> 'seq') <> 'number'
     or coalesce(p_record ->> 'seq', '') !~ '^(0|[1-9][0-9]*)$'
     or p_record ->> 'event_type' is distinct from 'mobile.ceremony.decision'
     or p_record ->> 'session_id' is distinct from p_session_id::text
     or p_record ->> 'challenge_id' is distinct from p_challenge_id
     or p_record ->> 'action_hash' is distinct from p_action_hash
     or p_record ->> 'decision' is distinct from p_decision
     or p_record ->> 'verdict' is distinct from p_verdict
     or char_length(coalesce(p_record ->> 'approver_id', '')) not between 3 and 128
     or coalesce(p_record ->> 'context_hash', '') !~ '^sha256:[0-9a-f]{64}$'
     or p_decision_evidence is null
     or jsonb_typeof(p_decision_evidence) is distinct from 'object'
     or p_decision_evidence - array['context', 'signoff']::text[] is distinct from '{}'::jsonb
     or jsonb_typeof(p_decision_evidence -> 'context') is distinct from 'object'
     or jsonb_typeof(p_decision_evidence -> 'context' -> 'mobile_binding') is distinct from 'object'
     or jsonb_typeof(p_decision_evidence -> 'signoff') is distinct from 'object'
     or jsonb_typeof(p_decision_evidence -> 'signoff' -> 'webauthn') is distinct from 'object'
     or p_decision_evidence -> 'context' ->> 'action_hash' is distinct from p_action_hash
     or p_decision_evidence -> 'context' ->> 'decision' is distinct from p_decision
     or p_decision_evidence -> 'context' ->> 'approver' is distinct from p_record ->> 'approver_id'
     or p_decision_evidence -> 'context' -> 'mobile_binding' ->> 'profile_hash'
        is distinct from p_record ->> 'profile_hash'
     or p_decision_evidence -> 'context' -> 'mobile_binding' ->> 'device_key_id'
        is distinct from p_record ->> 'device_key_id'
     or p_decision_evidence -> 'signoff' ->> 'key_class' is distinct from 'A'
     or p_decision_evidence -> 'signoff' ->> 'approver_key_id'
        is distinct from p_record ->> 'device_key_id'
     or p_decision_evidence -> 'signoff' ->> 'context_hash'
        is distinct from p_record ->> 'context_hash'
     or p_decision_evidence -> 'signoff' ->> 'signed_at'
        is distinct from p_decision_evidence -> 'context' ->> 'issued_at'
     or p_record -> 'decision_evidence' is distinct from p_decision_evidence
     or octet_length(p_decision_evidence::text) > 262144 then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;

  begin
    parsed_body := p_canonical_body::jsonb;
    proposed_seq := (p_record ->> 'seq')::bigint;
  exception when others then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end;
  if parsed_body is distinct from (p_record - 'hash')
     or encode(digest(convert_to(p_canonical_body, 'UTF8'), 'sha256'), 'hex')
        <> p_record ->> 'hash' then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;

  select * into active_session
  from mobile_sessions
  where session_id = p_session_id
    and entity_ref = p_entity_ref
  for update;
  if not found
     or active_session.revoked_at is not null
     or active_session.expires_at <= p_now
     or active_session.device_key_id is null then
    return jsonb_build_object('ok', false, 'reason', 'session_inactive');
  end if;

  perform pg_advisory_xact_lock(hashtextextended('mobile-evidence:' || p_entity_ref, 74219));
  select mer.record_hash, (mer.record ->> 'seq')::bigint
    into prior_hash, prior_seq
    from mobile_evidence_records mer
    where mer.entity_ref = p_entity_ref
    order by mer.sequence_id desc
    limit 1;
  if prior_hash is distinct from p_expected_hash then
    return jsonb_build_object('ok', false, 'reason', 'head_changed');
  end if;
  expected_previous := coalesce(prior_hash, 'genesis');
  if proposed_seq <> coalesce(prior_seq + 1, 0)
     or p_record ->> 'prev_hash' <> expected_previous then
    return jsonb_build_object('ok', false, 'reason', 'head_changed');
  end if;

  select * into mapping
  from mobile_action_challenges
  where challenge_id = p_challenge_id
    and entity_ref = p_entity_ref
  for update;

  if not found
     or mapping.session_id <> p_session_id
     or mapping.consumed_at is not null
     or mapping.expires_at < p_now
     or mapping.action_hash <> p_action_hash
     or mapping.decision <> p_decision
     or mapping.approver_id <> active_session.approver_id
     or p_verdict <> 'verified' then
    return jsonb_build_object('ok', false, 'reason', 'action_conflict');
  end if;

  update mobile_actions
  set status = p_decision,
      decision_challenge_id = p_challenge_id,
      decision_verdict = p_verdict,
      decision_evidence = p_decision_evidence,
      decided_at = p_now,
      updated_at = p_now
  where action_reference = mapping.action_reference
    and entity_ref = p_entity_ref
    and approver_id = mapping.approver_id
    and status = 'pending'
    and expires_at > p_now;

  get diagnostics updated_count = row_count;
  if updated_count <> 1 then
    return jsonb_build_object('ok', false, 'reason', 'action_conflict');
  end if;

  update mobile_action_challenges
  set consumed_at = p_now
  where challenge_id = p_challenge_id;
  insert into mobile_evidence_records(
    record_id, entity_ref, record, previous_hash, record_hash
  ) values (
    p_record ->> 'record_id', p_entity_ref, p_record,
    p_record ->> 'prev_hash', p_record ->> 'hash'
  );
  return jsonb_build_object('ok', true);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'reason', 'record_conflict');
end;
$$;

alter table mobile_kv_state enable row level security;
alter table mobile_pairings enable row level security;
alter table mobile_sessions enable row level security;
alter table mobile_enrollments enable row level security;
alter table mobile_counters enable row level security;
alter table mobile_audit_records enable row level security;
alter table mobile_evidence_records enable row level security;
alter table mobile_actions enable row level security;
alter table mobile_action_challenges enable row level security;

revoke all on mobile_kv_state, mobile_pairings, mobile_sessions, mobile_enrollments,
  mobile_counters, mobile_audit_records, mobile_evidence_records, mobile_actions, mobile_action_challenges
  from anon, authenticated, public;
revoke all on function mobile_state_add_if_absent(text, text) from anon, authenticated, public;
revoke all on function mobile_presentation_is_valid(jsonb) from anon, authenticated, public;
revoke all on function mobile_state_compare_and_set(text, text, text, timestamptz) from anon, authenticated, public;
revoke all on function create_mobile_pairing(text, text, text, text, jsonb, timestamptz, timestamptz, timestamptz)
  from anon, authenticated, public;
revoke all on function touch_mobile_session(uuid, text, timestamptz) from anon, authenticated, public;
revoke all on function create_mobile_demo_action(text, text, text, text, jsonb, jsonb, jsonb, text, timestamptz, timestamptz)
  from anon, authenticated, public;
revoke all on function create_grace_mobile_action_group(jsonb, text, text, jsonb, jsonb, jsonb, text, timestamptz, timestamptz)
  from anon, authenticated, public;
revoke all on function exchange_mobile_pairing(text, text, text, text, timestamptz) from anon, authenticated, public;
revoke all on function advance_mobile_counter(text, bigint) from anon, authenticated, public;
revoke all on function append_mobile_audit_event(text, jsonb) from anon, authenticated, public;
revoke all on function append_mobile_evidence_record(text, text, jsonb, text) from anon, authenticated, public;
revoke all on function enroll_mobile_device(text, uuid, jsonb, jsonb) from anon, authenticated, public;
revoke all on function revoke_mobile_session(text, uuid, timestamptz) from anon, authenticated, public;
revoke all on function register_mobile_action_challenge(text, uuid, text, text, text, text, text, timestamptz, timestamptz)
  from anon, authenticated, public;
revoke all on function commit_mobile_action_decision(text, uuid, text, text, text, text, jsonb, text, jsonb, text, timestamptz)
  from anon, authenticated, public;

revoke insert, update, delete, truncate, references, trigger on mobile_kv_state, mobile_pairings, mobile_sessions,
  mobile_enrollments, mobile_counters, mobile_audit_records, mobile_evidence_records, mobile_actions,
  mobile_action_challenges from service_role;
grant select on mobile_kv_state, mobile_pairings, mobile_sessions,
  mobile_enrollments, mobile_counters, mobile_audit_records, mobile_evidence_records, mobile_actions,
  mobile_action_challenges to service_role;
grant execute on function mobile_presentation_is_valid(jsonb) to service_role;
revoke all on sequence mobile_audit_records_sequence_id_seq from service_role;
revoke all on sequence mobile_evidence_records_sequence_id_seq from service_role;
grant execute on function mobile_state_add_if_absent(text, text) to service_role;
grant execute on function mobile_state_compare_and_set(text, text, text, timestamptz) to service_role;
grant execute on function create_mobile_pairing(text, text, text, text, jsonb, timestamptz, timestamptz, timestamptz)
  to service_role;
grant execute on function touch_mobile_session(uuid, text, timestamptz) to service_role;
grant execute on function create_mobile_demo_action(text, text, text, text, jsonb, jsonb, jsonb, text, timestamptz, timestamptz)
  to service_role;
grant execute on function create_grace_mobile_action_group(jsonb, text, text, jsonb, jsonb, jsonb, text, timestamptz, timestamptz)
  to service_role;
grant execute on function exchange_mobile_pairing(text, text, text, text, timestamptz) to service_role;
grant execute on function advance_mobile_counter(text, bigint) to service_role;
grant execute on function append_mobile_audit_event(text, jsonb) to service_role;
grant execute on function append_mobile_evidence_record(text, text, jsonb, text) to service_role;
grant execute on function enroll_mobile_device(text, uuid, jsonb, jsonb) to service_role;
grant execute on function revoke_mobile_session(text, uuid, timestamptz) to service_role;
grant execute on function register_mobile_action_challenge(text, uuid, text, text, text, text, text, timestamptz, timestamptz)
  to service_role;
grant execute on function commit_mobile_action_decision(text, uuid, text, text, text, text, jsonb, text, jsonb, text, timestamptz)
  to service_role;
