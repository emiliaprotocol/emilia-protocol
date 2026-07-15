-- SPDX-License-Identifier: Apache-2.0
-- Execute only against a disposable database.

insert into entities(entity_id) values ('entity-mobile-contract');
insert into mobile_sessions(
  session_id, token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
) values (
  '00000000-0000-0000-0000-000000000001', repeat('a', 64), 'entity-mobile-contract',
  'approver-1', 'profile-1', 'android', 'ai.emiliaprotocol.approver', now() + interval '1 day'
);

insert into mobile_actions(
  action_reference, entity_ref, approver_id, initiator_id, action, presentation,
  policy, policy_id, expires_at
) values
  (
    'action-0001', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{}', 'policy-1', now() + interval '1 day'
  ),
  (
    'action-0002', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{}', 'policy-1', now() + interval '1 day'
  ),
  (
    'action-0003', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{}', 'policy-1', now() + interval '1 day'
  );

do $$
declare
  enrolled boolean;
  revoked boolean;
  revoked_again boolean;
  appended boolean;
  evidence_body text;
  evidence_hash text;
  evidence_record jsonb;
  atomic_body text;
  atomic_hash text;
  atomic_record jsonb;
  revoked_body text;
  revoked_hash text;
  revoked_record jsonb;
  committed jsonb;
  state_added boolean;
  state_added_again boolean;
  state_changed boolean;
  state_changed_again boolean;
  pairing_created boolean;
  pairing_created_again boolean;
  session_touched boolean;
  session_touched_wrong_key boolean;
  demo_created boolean;
  demo_created_again boolean;
begin
  select mobile_state_add_if_absent('challenge:contract-0001', 'issued') into state_added;
  select mobile_state_add_if_absent('challenge:contract-0001', 'issued') into state_added_again;
  select mobile_state_compare_and_set('challenge:contract-0001', 'issued', 'consumed') into state_changed;
  select mobile_state_compare_and_set('challenge:contract-0001', 'issued', 'attacker') into state_changed_again;
  if state_added is not true or state_added_again is not false
     or state_changed is not true or state_changed_again is not false then
    raise exception 'mobile state CAS did not fail closed';
  end if;

  select create_mobile_pairing(
    repeat('b', 64), 'entity-mobile-contract', 'approver-1', 'profile-1',
    '{"ios":["ai.emiliaprotocol.approver"],"android":[]}',
    now() + interval '5 minutes', now() + interval '1 day'
  ) into pairing_created;
  select create_mobile_pairing(
    repeat('b', 64), 'entity-mobile-contract', 'approver-1', 'profile-1',
    '{"ios":["ai.emiliaprotocol.approver"],"android":[]}',
    now() + interval '5 minutes', now() + interval '1 day'
  ) into pairing_created_again;
  if pairing_created is not true or pairing_created_again is not false then
    raise exception 'pairing creation did not refuse duplicate state';
  end if;
  if create_mobile_pairing(
    repeat('c', 64), 'entity-mobile-contract', 'approver-1', 'profile-1',
    '{"ios":"attacker.app","android":[]}',
    now() + interval '5 minutes', now() + interval '1 day'
  ) is not false then
    raise exception 'malformed allowed-app set was accepted';
  end if;

  select touch_mobile_session(
    '00000000-0000-0000-0000-000000000001', repeat('a', 64)
  ) into session_touched;
  select touch_mobile_session(
    '00000000-0000-0000-0000-000000000001', repeat('0', 64)
  ) into session_touched_wrong_key;
  if session_touched is not true or session_touched_wrong_key is not false then
    raise exception 'session touch was not bound to its bearer-token digest';
  end if;

  select create_mobile_demo_action(
    'mobact_' || repeat('3', 32), 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{"policy_id":"policy-demo"}',
    'policy-demo', now() + interval '1 day'
  ) into demo_created;
  select create_mobile_demo_action(
    'mobact_' || repeat('3', 32), 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{"policy_id":"policy-demo"}',
    'policy-demo', now() + interval '1 day'
  ) into demo_created_again;
  if demo_created is not true or demo_created_again is not false then
    raise exception 'demo action creation did not refuse duplicate state';
  end if;
  if create_mobile_demo_action(
    'mobact_' || repeat('4', 32), 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"title":"Release"}', '{"policy_id":"weaker-policy"}',
    'policy-demo', now() + interval '1 day'
  ) is not false then
    raise exception 'policy-id substitution was accepted';
  end if;

  select enroll_mobile_device(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000001',
    jsonb_build_object(
      'device_key_id', 'ep:key:device-00000001',
      'credential_id', 'credential-0001',
      'public_key_spki', repeat('p', 64),
      'approver_id', 'approver-1',
      'platform', 'android',
      'app_id', 'ai.emiliaprotocol.approver',
      'attestation_key_id', 'play-integrity:key-1',
      'platform_public_key', '',
      'status', 'active',
      'valid_from', now(),
      'valid_to', now() + interval '30 days',
      'sign_count', 0,
      'attestation_format', 'play-integrity'
    ),
    jsonb_build_object('event_type', 'mobile.enrolled')
  ) into enrolled;
  if enrolled is not true then raise exception 'enrollment failed'; end if;

  evidence_body := '{"event_type":"mobile.ceremony.decision","prev_hash":"genesis","record_id":"mar_00000000000000000000000000000001","seq":0}';
  evidence_hash := encode(digest(convert_to(evidence_body, 'UTF8'), 'sha256'), 'hex');
  evidence_record := evidence_body::jsonb || jsonb_build_object('hash', evidence_hash);
  select append_mobile_evidence_record(
    'entity-mobile-contract', null, evidence_record, evidence_body
  ) into appended;
  if appended is not true then raise exception 'portable evidence append failed'; end if;
  if (select record from mobile_evidence_records where entity_ref = 'entity-mobile-contract')
     is distinct from evidence_record then
    raise exception 'portable evidence readback changed signed record';
  end if;
  if append_mobile_evidence_record(
    'entity-mobile-contract', null, evidence_record, evidence_body
  ) is not false then
    raise exception 'stale evidence head was accepted';
  end if;

  if register_mobile_action_challenge(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'action-0001', 'approver-1', 'challenge-0001',
    'sha256:' || repeat('a', 64), 'approved', now() + interval '5 minutes'
  ) is not true then raise exception 'action challenge registration failed'; end if;

  atomic_body := '{"action_hash":"sha256:' || repeat('a', 64)
    || '","approver_id":"approver-1","challenge_id":"challenge-0001","context_hash":"sha256:'
    || repeat('c', 64)
    || '","decision":"approved","device_key_id":"device-1","event_type":"mobile.ceremony.decision","prev_hash":"'
    || evidence_hash
    || '","profile_hash":"sha256:' || repeat('b', 64)
    || '","record_id":"mar_00000000000000000000000000000002","seq":1,"session_id":"00000000-0000-0000-0000-000000000001","verdict":"verified"}';
  atomic_hash := encode(digest(convert_to(atomic_body, 'UTF8'), 'sha256'), 'hex');
  atomic_record := atomic_body::jsonb || jsonb_build_object('hash', atomic_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0001', 'sha256:' || repeat('a', 64),
    'approved', 'verified', evidence_hash, atomic_record, atomic_body
  ) into committed;
  if committed ->> 'ok' <> 'true' then raise exception 'atomic action/evidence commit failed: %', committed; end if;
  if not exists (
    select 1 from mobile_actions
    where entity_ref = 'entity-mobile-contract' and action_reference = 'action-0001'
      and status = 'approved' and decision_challenge_id = 'challenge-0001'
  ) then raise exception 'terminal action update missing'; end if;
  if not exists (
    select 1 from mobile_evidence_records
    where entity_ref = 'entity-mobile-contract' and record_id = atomic_record ->> 'record_id'
      and record = atomic_record
  ) then raise exception 'atomic evidence update missing'; end if;

  if register_mobile_action_challenge(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'action-0002', 'approver-1', 'challenge-0002',
    'sha256:' || repeat('d', 64), 'approved', now() + interval '5 minutes'
  ) is not true then raise exception 'rollback challenge registration failed'; end if;
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0002', 'sha256:' || repeat('d', 64),
    'approved', 'verified', atomic_hash,
    jsonb_build_object(
      'seq', 2, 'prev_hash', atomic_hash,
      'record_id', 'mar_00000000000000000000000000000003',
      'event_type', 'mobile.ceremony.decision', 'challenge_id', 'challenge-0002',
      'action_hash', 'sha256:' || repeat('d', 64), 'decision', 'approved',
      'verdict', 'verified', 'hash', repeat('0', 64)
    ),
    '{}'
  ) into committed;
  if committed ->> 'reason' <> 'malformed' then raise exception 'malformed atomic record was not refused'; end if;
  if (select status from mobile_actions
      where entity_ref = 'entity-mobile-contract' and action_reference = 'action-0002') <> 'pending' then
    raise exception 'malformed evidence changed the protected action';
  end if;

  if register_mobile_action_challenge(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'action-0003', 'approver-1', 'challenge-0003',
    'sha256:' || repeat('e', 64), 'approved', now() + interval '5 minutes'
  ) is not true then raise exception 'revocation-race challenge registration failed'; end if;

  select revoke_mobile_session(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000001'
  ) into revoked;
  if revoked is not true then raise exception 'revocation failed'; end if;

  select revoke_mobile_session(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000001'
  ) into revoked_again;
  if revoked_again is not false then
    raise exception 'second revocation did not fail closed';
  end if;

  if exists (
    select 1 from mobile_enrollments
    where entity_ref = 'entity-mobile-contract'
      and device_key_id = 'ep:key:device-00000001'
      and status <> 'revoked'
  ) then raise exception 'credential remained active'; end if;

  revoked_body := '{"action_hash":"sha256:' || repeat('e', 64)
    || '","approver_id":"approver-1","challenge_id":"challenge-0003","context_hash":"sha256:'
    || repeat('f', 64)
    || '","decision":"approved","device_key_id":"device-1","event_type":"mobile.ceremony.decision","prev_hash":"'
    || atomic_hash
    || '","profile_hash":"sha256:' || repeat('b', 64)
    || '","record_id":"mar_00000000000000000000000000000004","seq":2,"session_id":"00000000-0000-0000-0000-000000000001","verdict":"verified"}';
  revoked_hash := encode(digest(convert_to(revoked_body, 'UTF8'), 'sha256'), 'hex');
  revoked_record := revoked_body::jsonb || jsonb_build_object('hash', revoked_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0003', 'sha256:' || repeat('e', 64),
    'approved', 'verified', atomic_hash, revoked_record, revoked_body
  ) into committed;
  if committed ->> 'reason' <> 'session_inactive' then
    raise exception 'revoked-session commit did not fail closed: %', committed;
  end if;
  if (select status from mobile_actions
      where entity_ref = 'entity-mobile-contract' and action_reference = 'action-0003') <> 'pending'
     or exists (select 1 from mobile_evidence_records where record_id = revoked_record ->> 'record_id') then
    raise exception 'revoked-session commit changed protected state';
  end if;

  if (select count(*) from mobile_audit_records where entity_ref = 'entity-mobile-contract') <> 2 then
    raise exception 'audit events missing';
  end if;

  if has_table_privilege('anon', 'mobile_sessions', 'SELECT')
     or has_table_privilege('anon', 'mobile_evidence_records', 'SELECT')
     or has_table_privilege('authenticated', 'mobile_enrollments', 'UPDATE')
     or has_function_privilege('anon', 'revoke_mobile_session(text,uuid,timestamptz)', 'EXECUTE')
     or has_function_privilege('authenticated', 'enroll_mobile_device(text,uuid,jsonb,jsonb)', 'EXECUTE')
     or has_function_privilege('anon', 'mobile_state_add_if_absent(text,text)', 'EXECUTE')
     or has_function_privilege('authenticated', 'mobile_state_compare_and_set(text,text,text,timestamptz)', 'EXECUTE')
     or has_function_privilege(
       'anon',
       'create_mobile_pairing(text,text,text,text,jsonb,timestamptz,timestamptz,timestamptz)',
       'EXECUTE'
     )
     or has_function_privilege('authenticated', 'touch_mobile_session(uuid,text,timestamptz)', 'EXECUTE')
     or has_function_privilege(
       'anon',
       'create_mobile_demo_action(text,text,text,text,jsonb,jsonb,jsonb,text,timestamptz,timestamptz)',
       'EXECUTE'
     )
     or has_function_privilege('anon', 'append_mobile_evidence_record(text,text,jsonb,text)', 'EXECUTE')
     or has_function_privilege(
       'authenticated',
       'register_mobile_action_challenge(text,uuid,text,text,text,text,text,timestamptz,timestamptz)',
       'EXECUTE'
     )
     or has_function_privilege(
       'anon',
       'commit_mobile_action_decision(text,uuid,text,text,text,text,text,jsonb,text,timestamptz)',
       'EXECUTE'
     ) then
    raise exception 'public database privilege exposed';
  end if;

  if has_table_privilege('service_role', 'mobile_kv_state', 'INSERT')
     or has_table_privilege('service_role', 'mobile_sessions', 'UPDATE')
     or has_table_privilege('service_role', 'mobile_actions', 'DELETE')
     or not has_table_privilege('service_role', 'mobile_actions', 'SELECT')
     or not has_function_privilege('service_role', 'mobile_state_add_if_absent(text,text)', 'EXECUTE')
     or not has_function_privilege('service_role', 'touch_mobile_session(uuid,text,timestamptz)', 'EXECUTE') then
    raise exception 'service role bypasses the mobile RPC write boundary';
  end if;
end
$$;

select 'MOBILE DATABASE CONTRACT: PASS' as result;
