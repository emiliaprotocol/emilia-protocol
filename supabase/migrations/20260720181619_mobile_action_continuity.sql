-- EMILIA mobile Action Evidence Boundary continuity.
-- Forward-only: the deployed 20260715180000 mobile migration remains immutable.

create table if not exists mobile_action_groups (
  group_id text not null check (group_id ~ '^mag_[0-9a-f]{32}$'),
  entity_ref text not null references entities(entity_id) on delete cascade,
  active_revision integer not null default 1 check (active_revision >= 1),
  required_approvals integer not null check (required_approvals between 1 and 16),
  state text not null default 'open' check (
    state in (
      'open', 'authorized', 'denied', 'withdrawn', 'cancelled', 'expired',
      'consumed', 'indeterminate', 'executed', 'refused'
    )
  ),
  current_action_caid text not null check (
    current_action_caid ~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (entity_ref, group_id)
);

create table if not exists mobile_action_revisions (
  entity_ref text not null,
  group_id text not null,
  revision integer not null check (revision >= 1),
  action_caid text not null check (
    action_caid ~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ),
  action_digest text not null check (action_digest ~ '^sha256:[0-9a-f]{64}$'),
  action jsonb not null check (jsonb_typeof(action) = 'object'),
  presentation jsonb not null check (mobile_presentation_is_valid(presentation)),
  material_fields jsonb not null check (jsonb_typeof(material_fields) = 'object'),
  supersedes_revision integer,
  supersedes_action_caid text,
  change_set jsonb not null default '[]'::jsonb check (jsonb_typeof(change_set) = 'array'),
  created_at timestamptz not null default now(),
  primary key (entity_ref, group_id, revision),
  foreign key (entity_ref, group_id)
    references mobile_action_groups(entity_ref, group_id) on delete cascade,
  constraint mobile_action_revision_supersession check (
    (supersedes_revision is null and supersedes_action_caid is null and revision = 1)
    or (
      supersedes_revision is not null
      and supersedes_revision >= 1
      and supersedes_revision < revision
      and supersedes_action_caid ~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
    )
  )
);

create index if not exists mobile_action_revisions_caid_idx
  on mobile_action_revisions (entity_ref, action_caid, created_at desc);

alter table mobile_actions
  add column if not exists group_id text,
  add column if not exists revision integer;

drop index if exists mobile_actions_entity_action_approver_idx;
create unique index if not exists mobile_actions_legacy_entity_action_approver_idx
  on mobile_actions (entity_ref, (action ->> 'action_id'), approver_id)
  where group_id is null;
create unique index if not exists mobile_actions_revision_approver_idx
  on mobile_actions (entity_ref, group_id, revision, approver_id)
  where group_id is not null;

alter table mobile_actions
  drop constraint if exists mobile_actions_group_revision_fk;
alter table mobile_actions
  add constraint mobile_actions_group_revision_fk
  foreign key (entity_ref, group_id, revision)
  references mobile_action_revisions(entity_ref, group_id, revision);

alter table mobile_actions
  drop constraint if exists mobile_actions_status_check;
alter table mobile_actions
  add constraint mobile_actions_status_check
  check (status in ('pending', 'approved', 'denied', 'withdrawn', 'expired', 'cancelled'));

alter table mobile_action_challenges
  add column if not exists group_id text,
  add column if not exists revision integer,
  add column if not exists action_caid text;

alter table mobile_action_challenges
  drop constraint if exists mobile_action_challenges_group_revision_fk;
alter table mobile_action_challenges
  add constraint mobile_action_challenges_group_revision_fk
  foreign key (entity_ref, group_id, revision)
  references mobile_action_revisions(entity_ref, group_id, revision);
alter table mobile_action_challenges
  drop constraint if exists mobile_action_challenges_action_caid_check;
alter table mobile_action_challenges
  add constraint mobile_action_challenges_action_caid_check
  check (
    action_caid is null
    or action_caid ~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  );

create table if not exists mobile_action_events (
  event_id text primary key check (event_id ~ '^mae_[0-9a-f]{32}$'),
  entity_ref text not null,
  group_id text not null,
  revision integer not null,
  event_type text not null check (
    event_type in (
      'declared', 'decision_recorded', 'quorum_progressed', 'authorized',
      'superseded', 'withdrawn', 'denied', 'cancelled', 'expired',
      'consumed', 'execution_indeterminate', 'executed', 'execution_refused',
      'alignment_recorded'
    )
  ),
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  evidence_digest text check (evidence_digest is null or evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  foreign key (entity_ref, group_id, revision)
    references mobile_action_revisions(entity_ref, group_id, revision) on delete cascade
);

create index if not exists mobile_action_events_timeline_idx
  on mobile_action_events (entity_ref, group_id, revision, created_at, event_id);

create table if not exists mobile_action_operations (
  operation_id text primary key check (char_length(operation_id) between 8 and 256),
  entity_ref text not null,
  group_id text not null,
  revision integer not null,
  action_caid text not null check (
    action_caid ~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
  ),
  consumption_nonce text unique not null check (char_length(consumption_nonce) between 16 and 256),
  status text not null check (status in ('consumed', 'indeterminate', 'executed', 'refused')),
  provider_evidence_digest text check (
    provider_evidence_digest is null or provider_evidence_digest ~ '^sha256:[0-9a-f]{64}$'
  ),
  provider_reference text,
  consumed_at timestamptz not null,
  indeterminate_at timestamptz,
  reconciled_at timestamptz,
  updated_at timestamptz not null default now(),
  unique (entity_ref, group_id, revision),
  foreign key (entity_ref, group_id, revision)
    references mobile_action_revisions(entity_ref, group_id, revision)
);

create table if not exists mobile_executor_keys (
  entity_ref text not null references entities(entity_id) on delete cascade,
  executor_id text not null check (char_length(executor_id) between 3 and 256),
  key_id text not null check (key_id ~ '^ep:executor-key:sha256:[0-9a-f]{64}$'),
  public_key text not null check (
    public_key ~ '^[A-Za-z0-9_-]+$' and char_length(public_key) between 40 and 4096
  ),
  status text not null default 'active' check (status in ('active', 'revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (entity_ref, executor_id),
  unique (entity_ref, key_id)
);

create table if not exists mobile_action_alignments (
  entity_ref text not null,
  group_id text not null,
  revision integer not null,
  system_name text not null check (char_length(system_name) between 1 and 128),
  verdict text not null check (
    verdict in ('EQUIVALENT_UNDER_PROFILE', 'NOT_EQUIVALENT', 'INDETERMINATE')
  ),
  profile_id text,
  profile_hash text,
  native_verified boolean not null default false,
  evidence_digest text,
  reason text,
  created_at timestamptz not null default now(),
  primary key (entity_ref, group_id, revision, system_name),
  foreign key (entity_ref, group_id, revision)
    references mobile_action_revisions(entity_ref, group_id, revision) on delete cascade,
  constraint mobile_action_alignment_positive_proof check (
    verdict <> 'EQUIVALENT_UNDER_PROFILE'
    or (
      native_verified
      and char_length(profile_id) between 1 and 256
      and profile_hash ~ '^sha256:[0-9a-f]{64}$'
      and evidence_digest ~ '^sha256:[0-9a-f]{64}$'
    )
  )
);

create or replace function mobile_action_event(
  p_entity_ref text,
  p_group_id text,
  p_revision integer,
  p_event_type text,
  p_details jsonb default '{}'::jsonb,
  p_evidence_digest text default null,
  p_now timestamptz default now()
) returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  created_id text := 'mae_' || replace(gen_random_uuid()::text, '-', '');
begin
  insert into mobile_action_events(
    event_id, entity_ref, group_id, revision, event_type, details,
    evidence_digest, created_at
  ) values (
    created_id, p_entity_ref, p_group_id, p_revision, p_event_type,
    coalesce(p_details, '{}'::jsonb), p_evidence_digest, p_now
  );
  perform append_mobile_audit_event(
    p_entity_ref,
    jsonb_build_object(
      'event_type', 'mobile.action.' || p_event_type,
      'event_id', created_id,
      'group_id', p_group_id,
      'revision', p_revision,
      'details', coalesce(p_details, '{}'::jsonb),
      'evidence_digest', p_evidence_digest,
      'created_at', p_now
    )
  );
  return created_id;
end;
$$;

create or replace function mobile_action_challenge_identity()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  select action.group_id, action.revision, revision.action_caid
    into new.group_id, new.revision, new.action_caid
  from mobile_actions action
  join mobile_action_revisions revision
    on revision.entity_ref = action.entity_ref
   and revision.group_id = action.group_id
   and revision.revision = action.revision
  where action.entity_ref = new.entity_ref
    and action.action_reference = new.action_reference;
  return new;
end;
$$;

drop trigger if exists mobile_action_challenge_identity_trigger on mobile_action_challenges;
create trigger mobile_action_challenge_identity_trigger
before insert on mobile_action_challenges
for each row execute function mobile_action_challenge_identity();

create or replace function mobile_action_decision_identity_guard()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  bound_revision mobile_action_revisions%rowtype;
  bound_challenge mobile_action_challenges%rowtype;
begin
  if new.group_id is null or new.revision is null
     or old.status <> 'pending' or new.status not in ('approved', 'denied') then
    return new;
  end if;
  select * into bound_revision
  from mobile_action_revisions
  where entity_ref = new.entity_ref
    and group_id = new.group_id
    and revision = new.revision;
  select * into bound_challenge
  from mobile_action_challenges
  where challenge_id = new.decision_challenge_id
    and entity_ref = new.entity_ref;
  if not found
     or bound_challenge.group_id is distinct from new.group_id
     or bound_challenge.revision is distinct from new.revision
     or bound_challenge.action_caid is distinct from bound_revision.action_caid
     or new.decision_evidence -> 'context' ->> 'action_reference'
        is distinct from new.action_reference
     or new.decision_evidence -> 'context' ->> 'action_caid'
        is distinct from bound_revision.action_caid
     or new.decision_evidence -> 'context' ->> 'action_digest'
        is distinct from bound_revision.action_digest then
    raise exception 'mobile action identity mismatch';
  end if;
  return new;
end;
$$;

drop trigger if exists mobile_action_decision_identity_guard_trigger on mobile_actions;
create trigger mobile_action_decision_identity_guard_trigger
before update of status, decision_challenge_id, decision_evidence on mobile_actions
for each row execute function mobile_action_decision_identity_guard();

create or replace function mobile_action_decision_projection()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  current_group mobile_action_groups%rowtype;
  approvals integer;
  denials integer;
  withdrawals integer;
  pending_count integer;
  next_state text;
begin
  if new.group_id is null or new.revision is null or new.status is not distinct from old.status then
    return new;
  end if;
  select * into current_group
  from mobile_action_groups
  where entity_ref = new.entity_ref and group_id = new.group_id
  for update;
  if not found or current_group.active_revision <> new.revision
     or current_group.state in ('consumed', 'indeterminate', 'executed', 'refused') then
    return new;
  end if;

  select
    count(*) filter (where status = 'approved'),
    count(*) filter (where status = 'denied'),
    count(*) filter (where status = 'withdrawn'),
    count(*) filter (where status = 'pending')
  into approvals, denials, withdrawals, pending_count
  from mobile_actions
  where entity_ref = new.entity_ref
    and group_id = new.group_id
    and revision = new.revision;

  next_state := case
    when approvals >= current_group.required_approvals then 'authorized'
    when approvals + pending_count < current_group.required_approvals and denials > 0 then 'denied'
    when approvals + pending_count < current_group.required_approvals and withdrawals > 0 then 'withdrawn'
    else 'open'
  end;
  update mobile_action_groups
  set state = next_state, updated_at = coalesce(new.updated_at, now())
  where entity_ref = new.entity_ref and group_id = new.group_id;

  perform mobile_action_event(
    new.entity_ref,
    new.group_id,
    new.revision,
    case
      when new.status = 'approved' then 'decision_recorded'
      when new.status = 'denied' then 'denied'
      when new.status = 'withdrawn' then 'withdrawn'
      else new.status
    end,
    jsonb_build_object(
      'approver_id', new.approver_id,
      'decision', new.status,
      'approved', approvals,
      'required', current_group.required_approvals,
      'remaining', greatest(current_group.required_approvals - approvals, 0)
    ),
    null,
    coalesce(new.updated_at, now())
  );
  if next_state = 'authorized' and current_group.state <> 'authorized' then
    perform mobile_action_event(
      new.entity_ref, new.group_id, new.revision, 'authorized',
      jsonb_build_object('approved', approvals, 'required', current_group.required_approvals),
      null, coalesce(new.updated_at, now())
    );
  elsif next_state = 'open' and new.status = 'approved' then
    perform mobile_action_event(
      new.entity_ref, new.group_id, new.revision, 'quorum_progressed',
      jsonb_build_object(
        'approved', approvals,
        'required', current_group.required_approvals,
        'remaining', greatest(current_group.required_approvals - approvals, 0)
      ),
      null, coalesce(new.updated_at, now())
    );
  end if;
  return new;
end;
$$;

drop trigger if exists mobile_action_decision_projection_trigger on mobile_actions;
create trigger mobile_action_decision_projection_trigger
after update of status on mobile_actions
for each row execute function mobile_action_decision_projection();

create or replace function create_mobile_demo_action_v2(
  p_group_id text,
  p_action_reference text,
  p_entity_ref text,
  p_approver_id text,
  p_initiator_id text,
  p_action jsonb,
  p_presentation jsonb,
  p_policy jsonb,
  p_policy_id text,
  p_action_caid text,
  p_action_digest text,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  created boolean;
begin
  if p_group_id !~ '^mag_[0-9a-f]{32}$'
     or p_action_caid !~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
     or p_action_digest !~ '^sha256:[0-9a-f]{64}$' then
    return false;
  end if;
  insert into mobile_action_groups(
    group_id, entity_ref, required_approvals, current_action_caid, created_at, updated_at
  ) values (p_group_id, p_entity_ref, 1, p_action_caid, p_now, p_now);
  insert into mobile_action_revisions(
    entity_ref, group_id, revision, action_caid, action_digest, action,
    presentation, material_fields, created_at
  ) values (
    p_entity_ref, p_group_id, 1, p_action_caid, p_action_digest, p_action,
    p_presentation, p_presentation -> 'material_fields', p_now
  );
  created := create_mobile_demo_action(
    p_action_reference, p_entity_ref, p_approver_id, p_initiator_id,
    p_action, p_presentation, p_policy, p_policy_id, p_expires_at, p_now
  );
  if not created then raise exception 'legacy mobile action insertion refused'; end if;
  update mobile_actions
  set group_id = p_group_id, revision = 1
  where entity_ref = p_entity_ref and action_reference = p_action_reference;
  perform mobile_action_event(
    p_entity_ref, p_group_id, 1, 'declared',
    jsonb_build_object('action_caid', p_action_caid, 'action_digest', p_action_digest),
    p_action_digest, p_now
  );
  return true;
exception when others then
  return false;
end;
$$;

create or replace function create_grace_mobile_action_group_v2(
  p_group_id text,
  p_assignments jsonb,
  p_entity_ref text,
  p_initiator_id text,
  p_action jsonb,
  p_presentation jsonb,
  p_policy jsonb,
  p_policy_id text,
  p_action_caid text,
  p_action_digest text,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  created boolean;
  required_count integer;
begin
  if p_group_id !~ '^mag_[0-9a-f]{32}$'
     or p_action_caid !~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
     or p_action_digest !~ '^sha256:[0-9a-f]{64}$'
     or coalesce(p_policy ->> 'required_approvals', '') !~ '^[1-9][0-9]*$' then
    return false;
  end if;
  required_count := (p_policy ->> 'required_approvals')::integer;
  insert into mobile_action_groups(
    group_id, entity_ref, required_approvals, current_action_caid, created_at, updated_at
  ) values (p_group_id, p_entity_ref, required_count, p_action_caid, p_now, p_now);
  insert into mobile_action_revisions(
    entity_ref, group_id, revision, action_caid, action_digest, action,
    presentation, material_fields, created_at
  ) values (
    p_entity_ref, p_group_id, 1, p_action_caid, p_action_digest, p_action,
    p_presentation, p_presentation -> 'material_fields', p_now
  );
  created := create_grace_mobile_action_group(
    p_assignments, p_entity_ref, p_initiator_id, p_action, p_presentation,
    p_policy, p_policy_id, p_expires_at, p_now
  );
  if not created then raise exception 'legacy GRACE action insertion refused'; end if;
  update mobile_actions
  set group_id = p_group_id, revision = 1
  where entity_ref = p_entity_ref
    and action_reference in (
      select item ->> 'action_reference' from jsonb_array_elements(p_assignments) item
    );
  perform mobile_action_event(
    p_entity_ref, p_group_id, 1, 'declared',
    jsonb_build_object(
      'action_caid', p_action_caid,
      'action_digest', p_action_digest,
      'required_approvals', required_count
    ),
    p_action_digest, p_now
  );
  return true;
exception when others then
  return false;
end;
$$;

create or replace function supersede_mobile_action(
  p_entity_ref text,
  p_current_action_reference text,
  p_assignments jsonb,
  p_initiator_id text,
  p_action jsonb,
  p_presentation jsonb,
  p_policy jsonb,
  p_policy_id text,
  p_action_caid text,
  p_action_digest text,
  p_change_set jsonb,
  p_expires_at timestamptz,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  current_action mobile_actions%rowtype;
  current_group mobile_action_groups%rowtype;
  next_revision integer;
  required_count integer;
begin
  select * into current_action
  from mobile_actions
  where entity_ref = p_entity_ref and action_reference = p_current_action_reference
  for update;
  if not found or current_action.group_id is null or jsonb_typeof(p_assignments) <> 'array'
     or jsonb_array_length(p_assignments) not between 1 and 16
     or not mobile_presentation_is_valid(p_presentation)
     or p_action_caid !~ '^caid:1:[a-z][a-z0-9.-]*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$'
     or p_action_digest !~ '^sha256:[0-9a-f]{64}$'
     or jsonb_typeof(p_change_set) <> 'array'
     or p_expires_at <= p_now
     or coalesce(p_policy ->> 'required_approvals', '1') !~ '^[1-9][0-9]*$' then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;
  select * into current_group
  from mobile_action_groups
  where entity_ref = p_entity_ref and group_id = current_action.group_id
  for update;
  if current_group.state in ('consumed', 'indeterminate', 'executed', 'refused') then
    return jsonb_build_object('ok', false, 'reason', 'already_consumed');
  end if;
  next_revision := current_group.active_revision + 1;
  required_count := coalesce((p_policy ->> 'required_approvals')::integer, 1);
  if required_count > jsonb_array_length(p_assignments) then
    return jsonb_build_object('ok', false, 'reason', 'invalid_quorum');
  end if;
  if exists (
    select 1 from jsonb_array_elements(p_assignments) item
    where item - 'action_reference' - 'approver_id' <> '{}'::jsonb
       or coalesce(item ->> 'action_reference', '') !~ '^mobact_[0-9a-f]{32}$'
       or char_length(coalesce(item ->> 'approver_id', '')) not between 3 and 128
  ) then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;

  update mobile_actions
  set status = 'cancelled', updated_at = p_now
  where entity_ref = p_entity_ref
    and group_id = current_group.group_id
    and revision = current_group.active_revision
    and status in ('pending', 'approved');
  insert into mobile_action_revisions(
    entity_ref, group_id, revision, action_caid, action_digest, action,
    presentation, material_fields, supersedes_revision, supersedes_action_caid,
    change_set, created_at
  ) values (
    p_entity_ref, current_group.group_id, next_revision, p_action_caid,
    p_action_digest, p_action, p_presentation, p_presentation -> 'material_fields',
    current_group.active_revision, current_group.current_action_caid, p_change_set, p_now
  );
  insert into mobile_actions(
    action_reference, entity_ref, approver_id, initiator_id, action, presentation,
    policy, policy_id, expires_at, group_id, revision
  )
  select
    item ->> 'action_reference', p_entity_ref, item ->> 'approver_id', p_initiator_id,
    p_action, p_presentation, p_policy, p_policy_id, p_expires_at,
    current_group.group_id, next_revision
  from jsonb_array_elements(p_assignments) item;
  update mobile_action_groups
  set active_revision = next_revision,
      required_approvals = required_count,
      state = 'open',
      current_action_caid = p_action_caid,
      updated_at = p_now
  where entity_ref = p_entity_ref and group_id = current_group.group_id;
  perform mobile_action_event(
    p_entity_ref, current_group.group_id, current_group.active_revision, 'superseded',
    jsonb_build_object('successor_revision', next_revision, 'successor_caid', p_action_caid),
    p_action_digest, p_now
  );
  perform mobile_action_event(
    p_entity_ref, current_group.group_id, next_revision, 'declared',
    jsonb_build_object(
      'action_caid', p_action_caid,
      'action_digest', p_action_digest,
      'change_set', p_change_set
    ),
    p_action_digest, p_now
  );
  return jsonb_build_object('ok', true, 'revision', next_revision, 'group_id', current_group.group_id);
exception when unique_violation or check_violation or foreign_key_violation or not_null_violation then
  return jsonb_build_object('ok', false, 'reason', 'conflict');
end;
$$;

create or replace function withdraw_mobile_action(
  p_entity_ref text,
  p_session_id uuid,
  p_action_reference text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  active_session mobile_sessions%rowtype;
  target mobile_actions%rowtype;
  current_group mobile_action_groups%rowtype;
begin
  select * into active_session
  from mobile_sessions
  where session_id = p_session_id and entity_ref = p_entity_ref
  for update;
  if not found or active_session.revoked_at is not null or active_session.expires_at <= p_now then
    return jsonb_build_object('ok', false, 'reason', 'session_inactive');
  end if;
  select * into target
  from mobile_actions
  where entity_ref = p_entity_ref
    and action_reference = p_action_reference
    and approver_id = active_session.approver_id
  for update;
  if not found or target.status <> 'approved' or target.group_id is null then
    return jsonb_build_object('ok', false, 'reason', 'not_withdrawable');
  end if;
  select * into current_group
  from mobile_action_groups
  where entity_ref = p_entity_ref and group_id = target.group_id
  for update;
  if current_group.active_revision <> target.revision
     or current_group.state in ('consumed', 'indeterminate', 'executed', 'refused') then
    return jsonb_build_object('ok', false, 'reason', 'already_consumed');
  end if;
  update mobile_actions
  set status = 'withdrawn', updated_at = p_now
  where entity_ref = p_entity_ref and action_reference = p_action_reference and status = 'approved';
  return jsonb_build_object('ok', true, 'state', 'withdrawn');
end;
$$;

create or replace function consume_mobile_action(
  p_entity_ref text,
  p_action_reference text,
  p_operation_id text,
  p_consumption_nonce text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  target mobile_actions%rowtype;
  current_group mobile_action_groups%rowtype;
begin
  if char_length(p_operation_id) not between 8 and 256
     or char_length(p_consumption_nonce) not between 16 and 256 then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;
  select * into target
  from mobile_actions
  where entity_ref = p_entity_ref and action_reference = p_action_reference
  for update;
  if not found or target.group_id is null then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;
  select * into current_group
  from mobile_action_groups
  where entity_ref = p_entity_ref and group_id = target.group_id
  for update;
  if current_group.active_revision <> target.revision then
    return jsonb_build_object('ok', false, 'reason', 'superseded');
  end if;
  if target.expires_at <= p_now then
    update mobile_actions
    set status = 'expired', updated_at = p_now
    where entity_ref = p_entity_ref
      and group_id = current_group.group_id
      and revision = target.revision
      and status in ('pending', 'approved');
    update mobile_action_groups
    set state = 'expired', updated_at = p_now
    where entity_ref = p_entity_ref and group_id = current_group.group_id;
    perform mobile_action_event(
      p_entity_ref, current_group.group_id, target.revision, 'expired',
      jsonb_build_object('action_reference', p_action_reference),
      null, p_now
    );
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  if current_group.state <> 'authorized' then
    return jsonb_build_object(
      'ok', false,
      'reason', case
        when current_group.state in ('consumed', 'indeterminate', 'executed', 'refused')
          then 'already_consumed'
        else 'not_authorized'
      end
    );
  end if;
  insert into mobile_action_operations(
    operation_id, entity_ref, group_id, revision, action_caid,
    consumption_nonce, status, consumed_at, updated_at
  ) values (
    p_operation_id, p_entity_ref, current_group.group_id, target.revision,
    current_group.current_action_caid, p_consumption_nonce, 'consumed', p_now, p_now
  );
  update mobile_action_groups
  set state = 'consumed', updated_at = p_now
  where entity_ref = p_entity_ref and group_id = current_group.group_id;
  perform mobile_action_event(
    p_entity_ref, current_group.group_id, target.revision, 'consumed',
    jsonb_build_object('operation_id', p_operation_id, 'consumption_nonce', p_consumption_nonce),
    null, p_now
  );
  return jsonb_build_object(
    'ok', true,
    'operation_id', p_operation_id,
    'action_caid', current_group.current_action_caid,
    'consumption_nonce', p_consumption_nonce,
    'state', 'consumed'
  );
exception when unique_violation then
  return jsonb_build_object('ok', false, 'reason', 'already_consumed');
end;
$$;

create or replace function mark_mobile_action_indeterminate(
  p_entity_ref text,
  p_operation_id text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  operation mobile_action_operations%rowtype;
begin
  select * into operation
  from mobile_action_operations
  where entity_ref = p_entity_ref and operation_id = p_operation_id
  for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if operation.status <> 'consumed' then
    return jsonb_build_object('ok', false, 'reason', 'already_terminal');
  end if;
  update mobile_action_operations
  set status = 'indeterminate', indeterminate_at = p_now, updated_at = p_now
  where operation_id = p_operation_id;
  update mobile_action_groups
  set state = 'indeterminate', updated_at = p_now
  where entity_ref = p_entity_ref and group_id = operation.group_id;
  perform mobile_action_event(
    p_entity_ref, operation.group_id, operation.revision, 'execution_indeterminate',
    jsonb_build_object('operation_id', p_operation_id, 'retry_safe', false),
    null, p_now
  );
  return jsonb_build_object('ok', true, 'state', 'indeterminate', 'retry_safe', false);
end;
$$;

create or replace function reconcile_mobile_action_operation(
  p_entity_ref text,
  p_operation_id text,
  p_outcome text,
  p_provider_reference text,
  p_evidence_digest text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  operation mobile_action_operations%rowtype;
begin
  if p_outcome not in ('executed', 'refused')
     or char_length(p_provider_reference) not between 1 and 256
     or p_evidence_digest !~ '^sha256:[0-9a-f]{64}$' then
    return jsonb_build_object('ok', false, 'reason', 'malformed');
  end if;
  select * into operation
  from mobile_action_operations
  where entity_ref = p_entity_ref and operation_id = p_operation_id
  for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if operation.status not in ('consumed', 'indeterminate') then
    return jsonb_build_object('ok', false, 'reason', 'already_terminal');
  end if;
  update mobile_action_operations
  set status = p_outcome,
      provider_reference = p_provider_reference,
      provider_evidence_digest = p_evidence_digest,
      reconciled_at = p_now,
      updated_at = p_now
  where operation_id = p_operation_id;
  update mobile_action_groups
  set state = p_outcome, updated_at = p_now
  where entity_ref = p_entity_ref and group_id = operation.group_id;
  perform mobile_action_event(
    p_entity_ref, operation.group_id, operation.revision,
    case when p_outcome = 'executed' then 'executed' else 'execution_refused' end,
    jsonb_build_object(
      'operation_id', p_operation_id,
      'provider_reference', p_provider_reference,
      'provider_evidence_verified', true
    ),
    p_evidence_digest, p_now
  );
  return jsonb_build_object('ok', true, 'state', p_outcome, 'retry_safe', false);
end;
$$;

create or replace function register_mobile_executor_key(
  p_entity_ref text,
  p_executor_id text,
  p_key_id text,
  p_public_key text,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if char_length(p_executor_id) not between 3 and 256
     or p_key_id !~ '^ep:executor-key:sha256:[0-9a-f]{64}$'
     or p_public_key !~ '^[A-Za-z0-9_-]+$'
     or char_length(p_public_key) not between 40 and 4096 then
    return false;
  end if;
  insert into mobile_executor_keys(
    entity_ref, executor_id, key_id, public_key, created_at, updated_at
  ) values (p_entity_ref, p_executor_id, p_key_id, p_public_key, p_now, p_now)
  on conflict (entity_ref, executor_id) do update
  set key_id = excluded.key_id,
      public_key = excluded.public_key,
      status = 'active',
      updated_at = excluded.updated_at;
  perform append_mobile_audit_event(
    p_entity_ref,
    jsonb_build_object(
      'event_type', 'mobile.executor_key_registered',
      'executor_id', p_executor_id,
      'key_id', p_key_id,
      'registered_at', p_now
    )
  );
  return true;
exception when unique_violation or check_violation or foreign_key_violation then
  return false;
end;
$$;

create or replace function record_mobile_action_alignment(
  p_entity_ref text,
  p_action_reference text,
  p_system_name text,
  p_verdict text,
  p_profile_id text,
  p_profile_hash text,
  p_native_verified boolean,
  p_evidence_digest text,
  p_reason text,
  p_now timestamptz default now()
) returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  target mobile_actions%rowtype;
begin
  select * into target
  from mobile_actions
  where entity_ref = p_entity_ref and action_reference = p_action_reference;
  if not found or target.group_id is null
     or char_length(p_system_name) not between 1 and 128
     or p_verdict not in ('EQUIVALENT_UNDER_PROFILE', 'NOT_EQUIVALENT', 'INDETERMINATE')
     or (
       p_verdict = 'EQUIVALENT_UNDER_PROFILE'
       and (
         not coalesce(p_native_verified, false)
         or char_length(p_profile_id) not between 1 and 256
         or p_profile_hash !~ '^sha256:[0-9a-f]{64}$'
         or p_evidence_digest !~ '^sha256:[0-9a-f]{64}$'
       )
     ) then
    return false;
  end if;
  insert into mobile_action_alignments(
    entity_ref, group_id, revision, system_name, verdict, profile_id,
    profile_hash, native_verified, evidence_digest, reason, created_at
  ) values (
    p_entity_ref, target.group_id, target.revision, p_system_name, p_verdict,
    p_profile_id, p_profile_hash, coalesce(p_native_verified, false),
    p_evidence_digest, p_reason, p_now
  )
  on conflict (entity_ref, group_id, revision, system_name) do update
  set verdict = excluded.verdict,
      profile_id = excluded.profile_id,
      profile_hash = excluded.profile_hash,
      native_verified = excluded.native_verified,
      evidence_digest = excluded.evidence_digest,
      reason = excluded.reason,
      created_at = excluded.created_at;
  perform mobile_action_event(
    p_entity_ref, target.group_id, target.revision, 'alignment_recorded',
    jsonb_build_object('system', p_system_name, 'verdict', p_verdict),
    p_evidence_digest, p_now
  );
  return true;
exception when unique_violation or check_violation or foreign_key_violation then
  return false;
end;
$$;

create or replace function list_mobile_action_continuity(
  p_entity_ref text,
  p_approver_id text,
  p_pending_only boolean default true,
  p_now timestamptz default now()
) returns jsonb
language sql
security definer
set search_path = public, pg_temp
stable
as $$
  select coalesce(jsonb_agg(snapshot order by snapshot ->> 'created_at' desc), '[]'::jsonb)
  from (
    select jsonb_build_object(
      'action_reference', action.action_reference,
      'action', action.action,
      'presentation', action.presentation,
      'policy', action.policy,
      'policy_id', action.policy_id,
      'status', action.status,
      'expires_at', action.expires_at,
      'created_at', action.created_at,
      'decided_at', action.decided_at,
      'decision_challenge_id', action.decision_challenge_id,
      'decision_verdict', action.decision_verdict,
      'decision_evidence', action.decision_evidence,
      'group_id', action.group_id,
      'revision', action.revision,
      'action_caid', revision.action_caid,
      'action_digest', revision.action_digest,
      'supersedes_action_caid', revision.supersedes_action_caid,
      'change_set', revision.change_set,
      'group_state', coalesce(action_group.state, action.status),
      'required_approvals', coalesce(action_group.required_approvals, 1),
      'approved_count', case when action.group_id is null
        then case when action.status = 'approved' then 1 else 0 end
        else (
          select count(*) from mobile_actions member
          where member.entity_ref = action.entity_ref
            and member.group_id = action.group_id
            and member.revision = action.revision
            and member.status = 'approved'
        )
      end,
      'denied_count', case when action.group_id is null
        then case when action.status = 'denied' then 1 else 0 end
        else (
          select count(*) from mobile_actions member
          where member.entity_ref = action.entity_ref
            and member.group_id = action.group_id
            and member.revision = action.revision
            and member.status = 'denied'
        )
      end,
      'withdrawn_count', case when action.group_id is null
        then case when action.status = 'withdrawn' then 1 else 0 end
        else (
          select count(*) from mobile_actions member
          where member.entity_ref = action.entity_ref
            and member.group_id = action.group_id
            and member.revision = action.revision
            and member.status = 'withdrawn'
        )
      end,
      'operation', (
        select jsonb_build_object(
          'operation_id', operation.operation_id,
          'consumption_nonce', operation.consumption_nonce,
          'status', operation.status,
          'provider_evidence_digest', operation.provider_evidence_digest,
          'provider_reference', operation.provider_reference,
          'consumed_at', operation.consumed_at,
          'indeterminate_at', operation.indeterminate_at,
          'reconciled_at', operation.reconciled_at
        )
        from mobile_action_operations operation
        where operation.entity_ref = action.entity_ref
          and operation.group_id = action.group_id
          and operation.revision = action.revision
      ),
      'events', (
        select coalesce(jsonb_agg(jsonb_build_object(
          'event_id', event.event_id,
          'type', event.event_type,
          'details', event.details,
          'evidence_digest', event.evidence_digest,
          'created_at', event.created_at
        ) order by event.created_at, event.event_id), '[]'::jsonb)
        from mobile_action_events event
        where event.entity_ref = action.entity_ref
          and event.group_id = action.group_id
          and event.revision = action.revision
      ),
      'alignments', (
        select coalesce(jsonb_agg(jsonb_build_object(
          'system', alignment.system_name,
          'verdict', alignment.verdict,
          'profile_id', alignment.profile_id,
          'profile_hash', alignment.profile_hash,
          'native_verified', alignment.native_verified,
          'evidence_digest', alignment.evidence_digest,
          'reason', alignment.reason
        ) order by alignment.system_name), '[]'::jsonb)
        from mobile_action_alignments alignment
        where alignment.entity_ref = action.entity_ref
          and alignment.group_id = action.group_id
          and alignment.revision = action.revision
      )
    ) as snapshot
    from mobile_actions action
    left join mobile_action_groups action_group
      on action_group.entity_ref = action.entity_ref
     and action_group.group_id = action.group_id
    left join mobile_action_revisions revision
      on revision.entity_ref = action.entity_ref
     and revision.group_id = action.group_id
     and revision.revision = action.revision
    where action.entity_ref = p_entity_ref
      and action.approver_id = p_approver_id
      and (
        not p_pending_only
        or (
          action.status = 'pending'
          and action.expires_at > p_now
          and (
            action.group_id is null
            or action.revision = action_group.active_revision
          )
        )
      )
    order by action.created_at desc, action.action_reference desc
    limit 100
  ) rows;
$$;

alter table mobile_action_groups enable row level security;
alter table mobile_action_revisions enable row level security;
alter table mobile_action_events enable row level security;
alter table mobile_action_operations enable row level security;
alter table mobile_executor_keys enable row level security;
alter table mobile_action_alignments enable row level security;

revoke all on table
  mobile_action_groups, mobile_action_revisions, mobile_action_events,
  mobile_action_operations, mobile_executor_keys, mobile_action_alignments
from public, anon, authenticated, service_role;
grant select on table
  mobile_action_groups, mobile_action_revisions, mobile_action_events,
  mobile_action_operations, mobile_executor_keys, mobile_action_alignments
to service_role;

revoke all on function mobile_action_event(text, text, integer, text, jsonb, text, timestamptz)
  from public, anon, authenticated, service_role;
revoke all on function create_mobile_demo_action_v2(
  text, text, text, text, text, jsonb, jsonb, jsonb, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function create_mobile_demo_action_v2(
  text, text, text, text, text, jsonb, jsonb, jsonb, text, text, text, timestamptz, timestamptz
) to service_role;
revoke all on function create_grace_mobile_action_group_v2(
  text, jsonb, text, text, jsonb, jsonb, jsonb, text, text, text, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function create_grace_mobile_action_group_v2(
  text, jsonb, text, text, jsonb, jsonb, jsonb, text, text, text, timestamptz, timestamptz
) to service_role;
revoke all on function supersede_mobile_action(
  text, text, jsonb, text, jsonb, jsonb, jsonb, text, text, text, jsonb, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function supersede_mobile_action(
  text, text, jsonb, text, jsonb, jsonb, jsonb, text, text, text, jsonb, timestamptz, timestamptz
) to service_role;
revoke all on function withdraw_mobile_action(text, uuid, text, timestamptz)
  from public, anon, authenticated;
grant execute on function withdraw_mobile_action(text, uuid, text, timestamptz)
  to service_role;
revoke all on function consume_mobile_action(text, text, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function consume_mobile_action(text, text, text, text, timestamptz)
  to service_role;
revoke all on function mark_mobile_action_indeterminate(text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function mark_mobile_action_indeterminate(text, text, timestamptz)
  to service_role;
revoke all on function reconcile_mobile_action_operation(text, text, text, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function reconcile_mobile_action_operation(text, text, text, text, text, timestamptz)
  to service_role;
revoke all on function register_mobile_executor_key(text, text, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function register_mobile_executor_key(text, text, text, text, timestamptz)
  to service_role;
revoke all on function record_mobile_action_alignment(
  text, text, text, text, text, text, boolean, text, text, timestamptz
) from public, anon, authenticated;
grant execute on function record_mobile_action_alignment(
  text, text, text, text, text, text, boolean, text, text, timestamptz
) to service_role;
revoke all on function list_mobile_action_continuity(text, text, boolean, timestamptz)
  from public, anon, authenticated;
grant execute on function list_mobile_action_continuity(text, text, boolean, timestamptz)
  to service_role;
