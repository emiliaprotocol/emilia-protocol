-- SPDX-License-Identifier: Apache-2.0
-- Forward-only hardening for durable mobile execution:
--   * operation identifiers are tenant scoped;
--   * every consumption is bound to the active executor key used for reconciliation;
--   * reconciliation rechecks that pin under lock and retains the signed evidence.

alter table mobile_action_operations
  add column if not exists executor_id text,
  add column if not exists executor_key_id text,
  add column if not exists provider_evidence jsonb;

-- Existing operations predate executor binding. Keep their history, but make them
-- deliberately unreconcilable instead of guessing which executor/key was intended.
update mobile_action_operations
set executor_id = 'legacy:unbound'
where executor_id is null;

update mobile_action_operations
set executor_key_id = 'ep:executor-key:sha256:' || repeat('0', 64)
where executor_key_id is null;

alter table mobile_action_operations
  alter column executor_id set not null,
  alter column executor_key_id set not null,
  drop constraint if exists mobile_action_operations_executor_id_check,
  add constraint mobile_action_operations_executor_id_check
    check (char_length(executor_id) between 3 and 256),
  drop constraint if exists mobile_action_operations_executor_key_id_check,
  add constraint mobile_action_operations_executor_key_id_check
    check (executor_key_id ~ '^ep:executor-key:sha256:[0-9a-f]{64}$'),
  drop constraint if exists mobile_action_operations_provider_evidence_check,
  add constraint mobile_action_operations_provider_evidence_check
    check (provider_evidence is null or jsonb_typeof(provider_evidence) = 'object');

alter table mobile_action_operations
  drop constraint if exists mobile_action_operations_pkey;

alter table mobile_action_operations
  add constraint mobile_action_operations_pkey primary key (entity_ref, operation_id);

drop function if exists consume_mobile_action(text, text, text, text, timestamptz);

create or replace function consume_mobile_action(
  p_entity_ref text,
  p_action_reference text,
  p_operation_id text,
  p_consumption_nonce text,
  p_executor_id text,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  target mobile_actions%rowtype;
  current_group mobile_action_groups%rowtype;
  executor_key mobile_executor_keys%rowtype;
begin
  if char_length(p_operation_id) not between 8 and 256
     or char_length(p_consumption_nonce) not between 16 and 256
     or char_length(p_executor_id) not between 3 and 256 then
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

  -- The row lock makes key rotation serialize with consumption. The exact key ID
  -- is copied into the operation and becomes part of the immutable execution intent.
  select * into executor_key
  from mobile_executor_keys
  where entity_ref = p_entity_ref
    and executor_id = p_executor_id
    and status = 'active'
  for share;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'executor_key_not_pinned');
  end if;

  insert into mobile_action_operations(
    operation_id, entity_ref, group_id, revision, action_caid,
    consumption_nonce, executor_id, executor_key_id, status, consumed_at, updated_at
  ) values (
    p_operation_id, p_entity_ref, current_group.group_id, target.revision,
    current_group.current_action_caid, p_consumption_nonce,
    executor_key.executor_id, executor_key.key_id, 'consumed', p_now, p_now
  );
  update mobile_action_groups
  set state = 'consumed', updated_at = p_now
  where entity_ref = p_entity_ref and group_id = current_group.group_id;
  perform mobile_action_event(
    p_entity_ref, current_group.group_id, target.revision, 'consumed',
    jsonb_build_object(
      'operation_id', p_operation_id,
      'consumption_nonce', p_consumption_nonce,
      'executor_id', executor_key.executor_id,
      'executor_key_id', executor_key.key_id
    ),
    null, p_now
  );
  return jsonb_build_object(
    'ok', true,
    'operation_id', p_operation_id,
    'action_caid', current_group.current_action_caid,
    'consumption_nonce', p_consumption_nonce,
    'executor_id', executor_key.executor_id,
    'executor_key_id', executor_key.key_id,
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
  where entity_ref = p_entity_ref and operation_id = p_operation_id;
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

drop function if exists reconcile_mobile_action_operation(
  text, text, text, text, text, timestamptz
);

create or replace function reconcile_mobile_action_operation(
  p_entity_ref text,
  p_operation_id text,
  p_executor_id text,
  p_executor_key_id text,
  p_outcome text,
  p_provider_reference text,
  p_evidence_digest text,
  p_provider_evidence jsonb,
  p_now timestamptz default now()
) returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  operation mobile_action_operations%rowtype;
  executor_key mobile_executor_keys%rowtype;
  expected_action_digest text;
begin
  if p_outcome is null or p_outcome not in ('executed', 'refused')
     or p_provider_reference is null
     or char_length(p_provider_reference) not between 1 and 256
     or p_evidence_digest is null
     or p_evidence_digest !~ '^sha256:[0-9a-f]{64}$'
     or jsonb_typeof(p_provider_evidence) is distinct from 'object'
     or p_provider_evidence ->> '@version' is distinct from 'EP-MOBILE-PROVIDER-OUTCOME-v1'
     or jsonb_typeof(p_provider_evidence -> 'proof') is distinct from 'object' then
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

  select action_digest into expected_action_digest
  from mobile_action_revisions
  where entity_ref = p_entity_ref
    and group_id = operation.group_id
    and revision = operation.revision;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'revision_not_found');
  end if;

  if p_executor_id is distinct from operation.executor_id
     or p_executor_key_id is distinct from operation.executor_key_id
     or p_provider_evidence ->> 'operation_id' is distinct from operation.operation_id
     or p_provider_evidence ->> 'action_caid' is distinct from operation.action_caid
     or p_provider_evidence ->> 'action_digest' is distinct from expected_action_digest
     or p_provider_evidence ->> 'consumption_nonce' is distinct from operation.consumption_nonce
     or p_provider_evidence ->> 'executor_id' is distinct from operation.executor_id
     or p_provider_evidence ->> 'outcome' is distinct from p_outcome
     or p_provider_evidence ->> 'provider_reference' is distinct from p_provider_reference
     or p_provider_evidence -> 'proof' ->> 'key_id' is distinct from operation.executor_key_id then
    return jsonb_build_object('ok', false, 'reason', 'provider_evidence_mismatch');
  end if;

  -- Recheck the exact active pin in the same transaction that commits the outcome.
  -- Rotation/revocation therefore cannot race between application verification and SQL.
  select * into executor_key
  from mobile_executor_keys
  where entity_ref = p_entity_ref
    and executor_id = operation.executor_id
    and key_id = operation.executor_key_id
    and status = 'active'
  for share;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'executor_key_not_active');
  end if;

  update mobile_action_operations
  set status = p_outcome,
      provider_reference = p_provider_reference,
      provider_evidence_digest = p_evidence_digest,
      provider_evidence = p_provider_evidence,
      reconciled_at = p_now,
      updated_at = p_now
  where entity_ref = p_entity_ref and operation_id = p_operation_id;
  update mobile_action_groups
  set state = p_outcome, updated_at = p_now
  where entity_ref = p_entity_ref and group_id = operation.group_id;
  perform mobile_action_event(
    p_entity_ref, operation.group_id, operation.revision,
    case when p_outcome = 'executed' then 'executed' else 'execution_refused' end,
    jsonb_build_object(
      'operation_id', p_operation_id,
      'executor_id', operation.executor_id,
      'executor_key_id', operation.executor_key_id,
      'provider_reference', p_provider_reference,
      'provider_evidence_verified', true
    ),
    p_evidence_digest, p_now
  );
  return jsonb_build_object('ok', true, 'state', p_outcome, 'retry_safe', false);
end;
$$;

revoke all on function consume_mobile_action(
  text, text, text, text, text, timestamptz
) from public, anon, authenticated;
grant execute on function consume_mobile_action(
  text, text, text, text, text, timestamptz
) to service_role;

revoke all on function mark_mobile_action_indeterminate(
  text, text, timestamptz
) from public, anon, authenticated;
grant execute on function mark_mobile_action_indeterminate(
  text, text, timestamptz
) to service_role;

revoke all on function reconcile_mobile_action_operation(
  text, text, text, text, text, text, text, jsonb, timestamptz
) from public, anon, authenticated;
grant execute on function reconcile_mobile_action_operation(
  text, text, text, text, text, text, text, jsonb, timestamptz
) to service_role;
