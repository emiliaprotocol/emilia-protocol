-- SPDX-License-Identifier: Apache-2.0
-- Execute only against a disposable database, after the mobile migrations.

insert into entities(entity_id) values ('entity-mobile-continuity');
insert into entities(entity_id) values ('entity-mobile-continuity-peer');
insert into mobile_sessions(
  session_id, token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
) values (
  '00000000-0000-0000-0000-000000000101', repeat('1', 64), 'entity-mobile-continuity',
  'approver-continuity', 'profile-continuity', 'ios', 'ai.emiliaprotocol.approver',
  now() + interval '1 day'
);

do $$
declare
  caid_one constant text :=
    'caid:1:emilia.mobile.authorized-action.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  caid_two constant text :=
    'caid:1:emilia.mobile.authorized-action.1:jcs-sha256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
  digest_one constant text := 'sha256:' || repeat('a', 64);
  digest_two constant text := 'sha256:' || repeat('b', 64);
  executor_id constant text := 'provider-continuity';
  executor_key_id constant text := 'ep:executor-key:sha256:' || repeat('d', 64);
  presentation_one constant jsonb :=
    '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release exact funds.","risk":"high","consequence":"Funds move.","material_fields":{"amount":"10.00","currency":"USD"}}';
  presentation_two constant jsonb :=
    '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release corrected funds.","risk":"high","consequence":"Funds move.","material_fields":{"amount":"11.00","currency":"USD"}}';
  created boolean;
  consumed jsonb;
  replayed jsonb;
  uncertain jsonb;
  stale_key_reconciliation jsonb;
  reconciled jsonb;
  withdrawn jsonb;
  consume_withdrawn jsonb;
  consume_expired jsonb;
  refused_supersession jsonb;
  successful_supersession jsonb;
  listed jsonb;
  provider_evidence jsonb;
begin
  created := create_mobile_demo_action_v2(
    'mag_11111111111111111111111111111111',
    'mobact_11111111111111111111111111111111',
    'entity-mobile-continuity',
    'approver-continuity',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"10.00","currency":"USD"}',
    presentation_one,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_one,
    digest_one,
    now() + interval '1 day',
    now()
  );
  if created is not true then raise exception 'v2 action creation failed'; end if;
  if (select count(*) from mobile_action_groups
      where entity_ref = 'entity-mobile-continuity'
        and group_id = 'mag_11111111111111111111111111111111'
        and state = 'open' and current_action_caid = caid_one) <> 1
     or (select count(*) from mobile_action_revisions
      where entity_ref = 'entity-mobile-continuity'
        and group_id = 'mag_11111111111111111111111111111111'
        and revision = 1 and action_digest = digest_one) <> 1 then
    raise exception 'group or immutable revision projection missing';
  end if;

  insert into mobile_action_challenges(
    challenge_id, session_id, action_reference, entity_ref, approver_id,
    decision, action_hash, expires_at
  ) values (
    'mobile-challenge-continuity-0001',
    '00000000-0000-0000-0000-000000000101',
    'mobact_11111111111111111111111111111111',
    'entity-mobile-continuity',
    'approver-continuity',
    'approved',
    'sha256:' || repeat('1', 64),
    now() + interval '1 hour'
  );
  update mobile_actions
  set status = 'approved',
      decision_challenge_id = 'mobile-challenge-continuity-0001',
      decision_evidence = jsonb_build_object('context', jsonb_build_object(
        'action_reference', 'mobact_11111111111111111111111111111111',
        'action_caid', caid_one,
        'action_digest', digest_one
      )),
      updated_at = now()
  where entity_ref = 'entity-mobile-continuity'
    and action_reference = 'mobact_11111111111111111111111111111111';
  if (select state from mobile_action_groups
      where entity_ref = 'entity-mobile-continuity'
        and group_id = 'mag_11111111111111111111111111111111') <> 'authorized' then
    raise exception 'quorum did not project to authorized';
  end if;

  if register_mobile_executor_key(
    'entity-mobile-continuity',
    executor_id,
    executor_key_id,
    repeat('A', 64),
    now()
  ) is not true then
    raise exception 'executor key registration failed';
  end if;

  consumed := consume_mobile_action(
    'entity-mobile-continuity',
    'mobact_11111111111111111111111111111111',
    'mobile-operation-0001',
    'mobile-consumption-nonce-0001',
    executor_id,
    now()
  );
  replayed := consume_mobile_action(
    'entity-mobile-continuity',
    'mobact_11111111111111111111111111111111',
    'mobile-operation-0002',
    'mobile-consumption-nonce-0002',
    executor_id,
    now()
  );
  if consumed ->> 'ok' <> 'true'
     or consumed ->> 'state' <> 'consumed'
     or replayed ->> 'ok' <> 'false'
     or replayed ->> 'reason' <> 'already_consumed' then
    raise exception 'single-consumption or replay refusal failed';
  end if;

  uncertain := mark_mobile_action_indeterminate(
    'entity-mobile-continuity', 'mobile-operation-0001', now()
  );
  if uncertain ->> 'state' <> 'indeterminate'
     or uncertain ->> 'retry_safe' <> 'false' then
    raise exception 'indeterminate transition did not burn retry';
  end if;
  provider_evidence := jsonb_build_object(
    '@version', 'EP-MOBILE-PROVIDER-OUTCOME-v1',
    'operation_id', 'mobile-operation-0001',
    'action_caid', caid_one,
    'action_digest', digest_one,
    'consumption_nonce', 'mobile-consumption-nonce-0001',
    'executor_id', executor_id,
    'outcome', 'executed',
    'observed_at', now(),
    'provider_reference', 'provider-effect-0001',
    'proof', jsonb_build_object(
      'algorithm', 'Ed25519',
      'key_id', executor_key_id,
      'public_key', repeat('A', 64),
      'signature_b64u', repeat('B', 86)
    )
  );
  if register_mobile_executor_key(
    'entity-mobile-continuity',
    executor_id,
    'ep:executor-key:sha256:' || repeat('e', 64),
    repeat('C', 64),
    now()
  ) is not true then
    raise exception 'executor key rotation fixture failed';
  end if;
  stale_key_reconciliation := reconcile_mobile_action_operation(
    'entity-mobile-continuity',
    'mobile-operation-0001',
    executor_id,
    executor_key_id,
    'executed',
    'provider-effect-0001',
    'sha256:' || repeat('c', 64),
    provider_evidence,
    now()
  );
  if stale_key_reconciliation ->> 'reason' <> 'executor_key_not_active' then
    raise exception 'reconciliation accepted a rotated executor key';
  end if;
  if register_mobile_executor_key(
    'entity-mobile-continuity',
    executor_id,
    executor_key_id,
    repeat('A', 64),
    now()
  ) is not true then
    raise exception 'executor key restore fixture failed';
  end if;
  reconciled := reconcile_mobile_action_operation(
    'entity-mobile-continuity',
    'mobile-operation-0001',
    executor_id,
    executor_key_id,
    'executed',
    'provider-effect-0001',
    'sha256:' || repeat('c', 64),
    provider_evidence,
    now()
  );
  if reconciled ->> 'state' <> 'executed'
     or (select state from mobile_action_groups
      where entity_ref = 'entity-mobile-continuity'
        and group_id = 'mag_11111111111111111111111111111111') <> 'executed'
     or (select provider_evidence_digest from mobile_action_operations
      where entity_ref = 'entity-mobile-continuity'
        and operation_id = 'mobile-operation-0001') <> 'sha256:' || repeat('c', 64)
     or (select operation.provider_evidence
      from mobile_action_operations operation
      where operation.entity_ref = 'entity-mobile-continuity'
        and operation.operation_id = 'mobile-operation-0001') is distinct from provider_evidence then
    raise exception 'authenticated reconciliation projection failed';
  end if;

  insert into mobile_action_groups(
    group_id, entity_ref, required_approvals, state, current_action_caid
  ) values (
    'mag_99999999999999999999999999999999',
    'entity-mobile-continuity-peer',
    1,
    'consumed',
    caid_one
  );
  insert into mobile_action_revisions(
    entity_ref, group_id, revision, action_caid, action_digest,
    action, presentation, material_fields
  ) values (
    'entity-mobile-continuity-peer',
    'mag_99999999999999999999999999999999',
    1,
    caid_one,
    digest_one,
    '{"action_type":"payment.release.1","amount":"10.00","currency":"USD"}',
    presentation_one,
    presentation_one -> 'material_fields'
  );
  insert into mobile_action_operations(
    operation_id, entity_ref, group_id, revision, action_caid,
    consumption_nonce, executor_id, executor_key_id, status, consumed_at
  ) values (
    'mobile-operation-0001',
    'entity-mobile-continuity-peer',
    'mag_99999999999999999999999999999999',
    1,
    caid_one,
    'mobile-consumption-nonce-peer-0001',
    'legacy:unbound',
    'ep:executor-key:sha256:' || repeat('0', 64),
    'consumed',
    now()
  );
  if (select count(*) from mobile_action_operations
      where operation_id = 'mobile-operation-0001') <> 2 then
    raise exception 'operation identifiers are not tenant scoped';
  end if;

  refused_supersession := supersede_mobile_action(
    'entity-mobile-continuity',
    'mobact_11111111111111111111111111111111',
    '[{"action_reference":"mobact_22222222222222222222222222222222","approver_id":"approver-continuity"}]',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"11.00","currency":"USD"}',
    presentation_two,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_two,
    digest_two,
    '[{"field":"amount","change":"changed","before":"10.00","after":"11.00"}]',
    now() + interval '1 day',
    now()
  );
  if refused_supersession ->> 'reason' <> 'already_consumed' then
    raise exception 'consumed action was superseded';
  end if;

  created := create_mobile_demo_action_v2(
    'mag_22222222222222222222222222222222',
    'mobact_33333333333333333333333333333333',
    'entity-mobile-continuity',
    'approver-continuity',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"11.00","currency":"USD"}',
    presentation_two,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_two,
    digest_two,
    now() + interval '1 day',
    now()
  );
  if created is not true then raise exception 'withdrawal fixture creation failed'; end if;
  insert into mobile_action_challenges(
    challenge_id, session_id, action_reference, entity_ref, approver_id,
    decision, action_hash, expires_at
  ) values (
    'mobile-challenge-continuity-0002',
    '00000000-0000-0000-0000-000000000101',
    'mobact_33333333333333333333333333333333',
    'entity-mobile-continuity',
    'approver-continuity',
    'approved',
    'sha256:' || repeat('2', 64),
    now() + interval '1 hour'
  );
  update mobile_actions
  set status = 'approved',
      decision_challenge_id = 'mobile-challenge-continuity-0002',
      decision_evidence = jsonb_build_object('context', jsonb_build_object(
        'action_reference', 'mobact_33333333333333333333333333333333',
        'action_caid', caid_two,
        'action_digest', digest_two
      )),
      updated_at = now()
  where entity_ref = 'entity-mobile-continuity'
    and action_reference = 'mobact_33333333333333333333333333333333';
  withdrawn := withdraw_mobile_action(
    'entity-mobile-continuity',
    '00000000-0000-0000-0000-000000000101',
    'mobact_33333333333333333333333333333333',
    now()
  );
  consume_withdrawn := consume_mobile_action(
    'entity-mobile-continuity',
    'mobact_33333333333333333333333333333333',
    'mobile-operation-0003',
    'mobile-consumption-nonce-0003',
    executor_id,
    now()
  );
  if withdrawn ->> 'ok' <> 'true'
     or consume_withdrawn ->> 'reason' <> 'not_authorized' then
    raise exception 'withdrawal did not atomically revoke unconsumed authority';
  end if;

  created := create_mobile_demo_action_v2(
    'mag_33333333333333333333333333333333',
    'mobact_44444444444444444444444444444444',
    'entity-mobile-continuity',
    'approver-continuity',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"11.00","currency":"USD"}',
    presentation_two,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_two,
    digest_two,
    now() + interval '1 day',
    now()
  );
  if created is not true then raise exception 'expiry fixture creation failed'; end if;
  insert into mobile_action_challenges(
    challenge_id, session_id, action_reference, entity_ref, approver_id,
    decision, action_hash, expires_at
  ) values (
    'mobile-challenge-continuity-0003',
    '00000000-0000-0000-0000-000000000101',
    'mobact_44444444444444444444444444444444',
    'entity-mobile-continuity',
    'approver-continuity',
    'approved',
    'sha256:' || repeat('3', 64),
    now() + interval '1 hour'
  );
  update mobile_actions
  set status = 'approved',
      decision_challenge_id = 'mobile-challenge-continuity-0003',
      decision_evidence = jsonb_build_object('context', jsonb_build_object(
        'action_reference', 'mobact_44444444444444444444444444444444',
        'action_caid', caid_two,
        'action_digest', digest_two
      )),
      updated_at = now()
  where entity_ref = 'entity-mobile-continuity'
    and action_reference = 'mobact_44444444444444444444444444444444';
  consume_expired := consume_mobile_action(
    'entity-mobile-continuity',
    'mobact_44444444444444444444444444444444',
    'mobile-operation-0004',
    'mobile-consumption-nonce-0004',
    executor_id,
    now() + interval '2 days'
  );
  if consume_expired ->> 'ok' <> 'false'
     or consume_expired ->> 'reason' <> 'expired'
     or (select state from mobile_action_groups
      where entity_ref = 'entity-mobile-continuity'
        and group_id = 'mag_33333333333333333333333333333333') <> 'expired'
     or exists (
       select 1 from mobile_action_operations
       where operation_id = 'mobile-operation-0004'
     ) then
    raise exception 'expired authorization was consumable';
  end if;

  created := create_mobile_demo_action_v2(
    'mag_44444444444444444444444444444444',
    'mobact_55555555555555555555555555555555',
    'entity-mobile-continuity',
    'approver-continuity',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"10.00","currency":"USD"}',
    presentation_one,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_one,
    digest_one,
    now() + interval '1 day',
    now()
  );
  if created is not true then raise exception 'supersession fixture creation failed'; end if;
  insert into mobile_action_challenges(
    challenge_id, session_id, action_reference, entity_ref, approver_id,
    decision, action_hash, expires_at
  ) values (
    'mobile-challenge-continuity-0004',
    '00000000-0000-0000-0000-000000000101',
    'mobact_55555555555555555555555555555555',
    'entity-mobile-continuity',
    'approver-continuity',
    'approved',
    'sha256:' || repeat('4', 64),
    now() + interval '1 hour'
  );
  update mobile_actions
  set status = 'approved',
      decision_challenge_id = 'mobile-challenge-continuity-0004',
      decision_evidence = jsonb_build_object('context', jsonb_build_object(
        'action_reference', 'mobact_55555555555555555555555555555555',
        'action_caid', caid_one,
        'action_digest', digest_one
      )),
      updated_at = now()
  where entity_ref = 'entity-mobile-continuity'
    and action_reference = 'mobact_55555555555555555555555555555555';
  successful_supersession := supersede_mobile_action(
    'entity-mobile-continuity',
    'mobact_55555555555555555555555555555555',
    '[{"action_reference":"mobact_66666666666666666666666666666666","approver_id":"approver-continuity"}]',
    'agent-continuity',
    '{"action_type":"payment.release.1","amount":"11.00","currency":"USD"}',
    presentation_two,
    '{"policy_id":"policy-continuity","required_approvals":1}',
    'policy-continuity',
    caid_two,
    digest_two,
    '[{"field":"amount","change":"changed","before":"10.00","after":"11.00"}]',
    now() + interval '1 day',
    now()
  );
  if successful_supersession ->> 'ok' <> 'true'
     or (select status from mobile_actions
       where entity_ref = 'entity-mobile-continuity'
         and action_reference = 'mobact_55555555555555555555555555555555') <> 'cancelled'
     or (select active_revision from mobile_action_groups
       where entity_ref = 'entity-mobile-continuity'
         and group_id = 'mag_44444444444444444444444444444444') <> 2 then
    raise exception 'supersession preserved stale authorization';
  end if;

  if record_mobile_action_alignment(
    'entity-mobile-continuity',
    'mobact_11111111111111111111111111111111',
    'AgentROA',
    'EQUIVALENT_UNDER_PROFILE',
    'ep:map:agentroa:v1',
    'sha256:' || repeat('e', 64),
    true,
    'sha256:' || repeat('f', 64),
    null,
    now()
  ) is not true then
    raise exception 'evidence-backed alignment recording failed';
  end if;

  insert into mobile_actions(
    action_reference, entity_ref, approver_id, initiator_id, action,
    presentation, policy, policy_id, expires_at, created_at, updated_at
  ) values (
    'mobact_legacy_111111111111111111111111',
    'entity-mobile-continuity',
    'approver-continuity',
    'agent-continuity',
    '{"action_id":"legacy-continuity-1","action_type":"payment.release.1","amount":"9.00","currency":"USD"}',
    presentation_one,
    '{"policy_id":"policy-continuity"}',
    'policy-continuity',
    now() + interval '1 day',
    now() - interval '1 hour',
    now() - interval '1 hour'
  );

  listed := list_mobile_action_continuity(
    'entity-mobile-continuity', 'approver-continuity', false, now()
  );
  if jsonb_array_length(listed) <> 6
     or not exists (
       select 1 from jsonb_array_elements(listed) item
       where item ->> 'action_reference' = 'mobact_11111111111111111111111111111111'
         and item ->> 'group_state' = 'executed'
         and item #>> '{operation,status}' = 'executed'
         and jsonb_array_length(item -> 'events') >= 4
         and jsonb_array_length(item -> 'alignments') = 1
     )
     or not exists (
       select 1 from jsonb_array_elements(listed) item
       where item ->> 'action_reference' = 'mobact_legacy_111111111111111111111111'
         and item -> 'group_id' = 'null'::jsonb
         and item -> 'action_caid' = 'null'::jsonb
     ) then
    raise exception 'consistent continuity snapshot or legacy visibility missing';
  end if;

  if has_table_privilege('anon', 'mobile_action_operations', 'SELECT')
     or has_table_privilege('authenticated', 'mobile_executor_keys', 'UPDATE')
     or has_table_privilege('service_role', 'mobile_action_events', 'INSERT')
     or not has_table_privilege('service_role', 'mobile_action_groups', 'SELECT')
     or has_function_privilege(
       'anon', 'consume_mobile_action(text,text,text,text,text,timestamptz)', 'EXECUTE'
     )
     or has_function_privilege(
       'authenticated',
       'reconcile_mobile_action_operation(text,text,text,text,text,text,text,jsonb,timestamptz)',
       'EXECUTE'
     )
     or not has_function_privilege(
       'service_role', 'list_mobile_action_continuity(text,text,boolean,timestamptz)', 'EXECUTE'
     ) then
    raise exception 'continuity trust boundary privileges are unsafe';
  end if;
end
$$;

select 'MOBILE ACTION CONTINUITY CONTRACT: PASS' as result;
