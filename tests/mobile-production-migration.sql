-- SPDX-License-Identifier: Apache-2.0
-- Execute only against a disposable database.

insert into entities(entity_id) values ('entity-mobile-contract');
insert into mobile_sessions(
  session_id, token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
) values (
  '00000000-0000-0000-0000-000000000001', repeat('a', 64), 'entity-mobile-contract',
  'approver-1', 'profile-1', 'android', 'ai.emiliaprotocol.approver', now() + interval '1 day'
);
insert into mobile_sessions(
  session_id, token_hash, entity_ref, approver_id, profile_id, platform, app_id, expires_at
) values (
  '00000000-0000-0000-0000-000000000002', repeat('d', 64), 'entity-mobile-contract',
  'approver-1', 'profile-1', 'android', 'ai.emiliaprotocol.approver', now() + interval '1 day'
);

insert into mobile_actions(
  action_reference, entity_ref, approver_id, initiator_id, action, presentation,
  policy, policy_id, expires_at
) values
  (
    'action-0001', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the pending item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"action-0001"}}', '{}', 'policy-1', now() + interval '1 day'
  ),
  (
    'action-0002', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the pending item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"action-0002"}}', '{}', 'policy-1', now() + interval '1 day'
  ),
  (
    'action-0003', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the pending item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"action-0003"}}', '{}', 'policy-1', now() + interval '1 day'
  ),
  (
    'action-0004', 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the pending item.","risk":"high","consequence":"The protected release will not execute.","material_fields":{"item":"action-0004"}}', '{}', 'policy-1', now() + interval '1 day'
  );

do $$
declare
  enrolled boolean;
  second_device_enrolled boolean;
  malformed_enrolled boolean;
  revoked boolean;
  revoked_again boolean;
  appended boolean;
  evidence_body text;
  evidence_hash text;
  evidence_record jsonb;
  atomic_body text;
  atomic_hash text;
  atomic_record jsonb;
  approval_evidence jsonb;
  denial_body text;
  denial_hash text;
  denial_record jsonb;
  denial_evidence jsonb;
  approval_guard_body text;
  approval_guard_hash text;
  approval_guard_record jsonb;
  approval_guard_evidence jsonb;
  revoked_body text;
  revoked_hash text;
  revoked_record jsonb;
  revoked_evidence jsonb;
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
  grace_created boolean;
  grace_created_again boolean;
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
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the demo item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"demo"}}', '{"policy_id":"policy-demo"}',
    'policy-demo', now() + interval '1 day'
  ) into demo_created;
  select create_mobile_demo_action(
    'mobact_' || repeat('3', 32), 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the demo item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"demo"}}', '{"policy_id":"policy-demo"}',
    'policy-demo', now() + interval '1 day'
  ) into demo_created_again;
  if demo_created is not true or demo_created_again is not false then
    raise exception 'demo action creation did not refuse duplicate state';
  end if;
  if create_mobile_demo_action(
    'mobact_' || repeat('4', 32), 'entity-mobile-contract', 'approver-1', 'agent-1',
    '{"kind":"release"}', '{"@version":"EP-MOBILE-PRESENTATION-v1","title":"Release","summary":"Release the demo item.","risk":"high","consequence":"The protected release will execute.","material_fields":{"item":"demo"}}', '{"policy_id":"weaker-policy"}',
    'policy-demo', now() + interval '1 day'
  ) is not false then
    raise exception 'policy-id substitution was accepted';
  end if;

  select create_grace_mobile_action_group(
    jsonb_build_array(
      jsonb_build_object('action_reference', 'mobact_' || repeat('5', 32), 'approver_id', 'approver-grace-1'),
      jsonb_build_object('action_reference', 'mobact_' || repeat('6', 32), 'approver_id', 'approver-grace-2')
    ),
    'entity-mobile-contract', 'ep:agent:grid',
    jsonb_build_object(
      '@version', 'EP-GRACE-CURTAILMENT-ACTION-v1',
      'action_id', 'grace:event:contract-1',
      'action_type', 'grid.curtailment',
      'effect_class', 'power_reduction',
      'facility', 'facility:contract-1',
      'target_delta_kw', '30000',
      'window', jsonb_build_object(
        'not_before', '2099-07-15T20:15:00.000Z',
        'not_after', '2099-07-15T21:45:00.000Z'
      ),
      'issued_at', '2099-07-15T20:00:00.000Z',
      'expires_at', '2099-07-15T21:45:00.000Z',
      'baseline_method_hash', 'sha256:' || repeat('b', 64),
      'control_mode', 'human_on_the_loop',
      'envelope_id', 'grace:envelope:contract-1',
      'requested_by', 'ep:agent:grid'
    ),
    jsonb_build_object(
      '@version', 'EP-MOBILE-PRESENTATION-v1',
      'title', 'Reduce load',
      'summary', 'Reduce facility load for the requested grid interval.',
      'risk', 'critical',
      'consequence', 'Facility power use will be curtailed during the interval.',
      'material_fields', jsonb_build_object('reduction', '30 MW')
    ),
    jsonb_build_object(
      'policy_id', 'ep:grace:contract:v1',
      'action_family', 'grid.curtailment',
      'human_approval', 'class_a',
      'required_approvals', 2,
      'approvers', jsonb_build_array('approver-grace-1', 'approver-grace-2'),
      'hard_cut_threshold_kw', '25000'
    ),
    'ep:grace:contract:v1', now() + interval '1 day'
  ) into grace_created;
  select create_grace_mobile_action_group(
    jsonb_build_array(
      jsonb_build_object('action_reference', 'mobact_' || repeat('5', 32), 'approver_id', 'approver-grace-1'),
      jsonb_build_object('action_reference', 'mobact_' || repeat('6', 32), 'approver_id', 'approver-grace-2')
    ),
    'entity-mobile-contract', 'ep:agent:grid',
    jsonb_build_object(
      '@version', 'EP-GRACE-CURTAILMENT-ACTION-v1',
      'action_id', 'grace:event:contract-1',
      'action_type', 'grid.curtailment',
      'effect_class', 'power_reduction',
      'facility', 'facility:contract-1',
      'target_delta_kw', '30000',
      'window', jsonb_build_object(
        'not_before', '2099-07-15T20:15:00.000Z',
        'not_after', '2099-07-15T21:45:00.000Z'
      ),
      'issued_at', '2099-07-15T20:00:00.000Z',
      'expires_at', '2099-07-15T21:45:00.000Z',
      'baseline_method_hash', 'sha256:' || repeat('b', 64),
      'control_mode', 'human_on_the_loop',
      'envelope_id', 'grace:envelope:contract-1',
      'requested_by', 'ep:agent:grid'
    ),
    jsonb_build_object(
      '@version', 'EP-MOBILE-PRESENTATION-v1',
      'title', 'Reduce load',
      'summary', 'Reduce facility load for the requested grid interval.',
      'risk', 'critical',
      'consequence', 'Facility power use will be curtailed during the interval.',
      'material_fields', jsonb_build_object('reduction', '30 MW')
    ),
    jsonb_build_object(
      'policy_id', 'ep:grace:contract:v1',
      'action_family', 'grid.curtailment',
      'human_approval', 'class_a',
      'required_approvals', 2,
      'approvers', jsonb_build_array('approver-grace-1', 'approver-grace-2'),
      'hard_cut_threshold_kw', '25000'
    ),
    'ep:grace:contract:v1', now() + interval '1 day'
  ) into grace_created_again;
  if grace_created is not true or grace_created_again is not false then
    raise exception 'GRACE action group did not commit atomically or refuse duplicate state';
  end if;
  if (select count(*) from mobile_actions where action ->> 'action_id' = 'grace:event:contract-1') <> 2 then
    raise exception 'GRACE action group did not create one ceremony per approver';
  end if;

  select enroll_mobile_device(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000001',
    jsonb_build_object(
      'device_key_id', 'ep:key:mobile-device-0000000000000001',
      'credential_id', 'credential-0001',
      'public_key_spki', repeat('p', 64),
      'approver_id', 'approver-1',
      'platform', 'android',
      'app_id', 'ai.emiliaprotocol.approver',
      'attestation_key_id', 'android-keystore:sha256:' || repeat('A', 43),
      'platform_public_key', repeat('p', 120),
      'status', 'active',
      'valid_from', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'valid_to', to_char((now() + interval '30 days') at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'sign_count', 7,
      'attestation_format', 'play-integrity'
    ),
    jsonb_build_object('event_type', 'mobile.enrolled')
  ) into enrolled;
  if enrolled is not true then raise exception 'enrollment failed'; end if;
  if (select counter_value from mobile_counters
      where counter_key = 'mobile:webauthn:ep:key:mobile-device-0000000000000001') <> 7 then
    raise exception 'registration sign_count baseline was not seeded atomically';
  end if;
  if advance_mobile_counter('mobile:webauthn:ep:key:mobile-device-0000000000000001', 7) is not false
     or advance_mobile_counter('mobile:webauthn:ep:key:mobile-device-0000000000000001', 6) is not false
     or advance_mobile_counter('mobile:webauthn:ep:key:mobile-device-0000000000000001', 8) is not true then
    raise exception 'first assertion did not have to advance the registration baseline';
  end if;
  select enroll_mobile_device(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000002',
    jsonb_build_object(
      'device_key_id', 'ep:key:mobile-device-0000000000000002',
      'credential_id', 'credential-0002',
      'public_key_spki', repeat('q', 64),
      'approver_id', 'approver-1',
      'platform', 'android',
      'app_id', 'ai.emiliaprotocol.approver',
      'attestation_key_id', 'android-keystore:sha256:' || repeat('A', 43),
      'platform_public_key', repeat('q', 120),
      'status', 'active',
      'valid_from', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'valid_to', to_char((now() + interval '30 days') at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'sign_count', 0,
      'attestation_format', 'play-integrity-standard'
    ),
    jsonb_build_object('event_type', 'mobile.enrolled')
  ) into second_device_enrolled;
  if second_device_enrolled is not false then
    raise exception 'a second enrollment reused the active Android device key';
  end if;
  select enroll_mobile_device(
    'entity-mobile-contract',
    '00000000-0000-0000-0000-000000000002',
    jsonb_build_object(
      'device_key_id', 'ep:key:mobile-device-0000000000000003',
      'credential_id', 'credential-0003',
      'public_key_spki', repeat('r', 64),
      'approver_id', 'approver-1',
      'platform', 'android',
      'app_id', 'ai.emiliaprotocol.approver',
      'attestation_key_id', 'android-keystore:sha256:' || repeat('B', 43),
      'platform_public_key', repeat('r', 120),
      'status', 'active',
      'valid_from', 'not-a-date',
      'valid_to', to_char((now() + interval '30 days') at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'sign_count', repeat('9', 100),
      'attestation_format', 'play-integrity-standard'
    ),
    jsonb_build_object('event_type', 'mobile.enrolled')
  ) into malformed_enrolled;
  if malformed_enrolled is not false then
    raise exception 'malformed enrollment was accepted';
  end if;

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

  approval_evidence := jsonb_build_object(
    'context', jsonb_build_object(
      'action_hash', 'sha256:' || repeat('a', 64),
      'decision', 'approved',
      'approver', 'approver-1',
      'issued_at', '2026-07-16T20:00:00.000Z',
      'mobile_binding', jsonb_build_object(
        'profile_hash', 'sha256:' || repeat('b', 64),
        'device_key_id', 'device-1'
      )
    ),
    'signoff', jsonb_build_object(
      'key_class', 'A',
      'approver_key_id', 'device-1',
      'context_hash', 'sha256:' || repeat('c', 64),
      'signed_at', '2026-07-16T20:00:00.000Z',
      'webauthn', jsonb_build_object(
        'authenticator_data', 'YQ', 'client_data_json', 'Yg', 'signature', 'Yw'
      )
    )
  );
  atomic_record := jsonb_build_object(
    'action_hash', 'sha256:' || repeat('a', 64),
    'approver_id', 'approver-1',
    'challenge_id', 'challenge-0001',
    'context_hash', 'sha256:' || repeat('c', 64),
    'decision', 'approved',
    'decision_evidence', approval_evidence,
    'device_key_id', 'device-1',
    'event_type', 'mobile.ceremony.decision',
    'prev_hash', evidence_hash,
    'profile_hash', 'sha256:' || repeat('b', 64),
    'record_id', 'mar_00000000000000000000000000000002',
    'seq', 1,
    'session_id', '00000000-0000-0000-0000-000000000001',
    'verdict', 'verified'
  );
  atomic_body := atomic_record::text;
  atomic_hash := encode(digest(convert_to(atomic_body, 'UTF8'), 'sha256'), 'hex');
  atomic_record := atomic_record || jsonb_build_object('hash', atomic_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0001', 'sha256:' || repeat('a', 64),
    'approved', 'verified',
    approval_evidence,
    evidence_hash, atomic_record, atomic_body
  ) into committed;
  if committed ->> 'ok' <> 'true' then raise exception 'atomic action/evidence commit failed: %', committed; end if;
  if not exists (
    select 1 from mobile_actions
    where entity_ref = 'entity-mobile-contract' and action_reference = 'action-0001'
      and status = 'approved' and decision_challenge_id = 'challenge-0001'
      and decision_evidence -> 'signoff' ->> 'key_class' = 'A'
  ) then raise exception 'terminal action update missing'; end if;
  if not exists (
    select 1 from mobile_evidence_records
    where entity_ref = 'entity-mobile-contract' and record_id = atomic_record ->> 'record_id'
      and record = atomic_record
  ) then raise exception 'atomic evidence update missing'; end if;

  if register_mobile_action_challenge(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'action-0004', 'approver-1', 'challenge-0004',
    'sha256:' || repeat('4', 64), 'denied', now() + interval '5 minutes'
  ) is not true then raise exception 'denial challenge registration failed'; end if;

  denial_evidence := jsonb_build_object(
    'context', jsonb_build_object(
      'action_hash', 'sha256:' || repeat('4', 64),
      'decision', 'denied',
      'approver', 'approver-1',
      'issued_at', '2026-07-16T20:00:00.000Z',
      'mobile_binding', jsonb_build_object(
        'profile_hash', 'sha256:' || repeat('b', 64),
        'device_key_id', 'device-1'
      )
    ),
    'signoff', jsonb_build_object(
      'key_class', 'A',
      'approver_key_id', 'device-1',
      'context_hash', 'sha256:' || repeat('5', 64),
      'signed_at', '2026-07-16T20:00:00.000Z',
      'webauthn', jsonb_build_object(
        'authenticator_data', 'YQ', 'client_data_json', 'Yg', 'signature', 'Yw'
      )
    )
  );
  denial_record := jsonb_build_object(
    'action_hash', 'sha256:' || repeat('4', 64),
    'approver_id', 'approver-1',
    'challenge_id', 'challenge-0004',
    'context_hash', 'sha256:' || repeat('5', 64),
    'decision', 'denied',
    'decision_evidence', denial_evidence,
    'device_key_id', 'device-1',
    'event_type', 'mobile.ceremony.decision',
    'prev_hash', atomic_hash,
    'profile_hash', 'sha256:' || repeat('b', 64),
    'record_id', 'mar_00000000000000000000000000000005',
    'seq', 2,
    'session_id', '00000000-0000-0000-0000-000000000001',
    'verdict', 'verified'
  );
  denial_body := denial_record::text;
  denial_hash := encode(digest(convert_to(denial_body, 'UTF8'), 'sha256'), 'hex');
  denial_record := denial_record || jsonb_build_object('hash', denial_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0004', 'sha256:' || repeat('4', 64),
    'denied', 'verified',
    denial_evidence,
    atomic_hash, denial_record, denial_body
  ) into committed;
  if committed ->> 'ok' <> 'true' then
    raise exception 'atomic denial/evidence commit failed: %', committed;
  end if;
  if not exists (
    select 1
    from mobile_actions action
    join mobile_action_challenges challenge
      on challenge.entity_ref = action.entity_ref
     and challenge.action_reference = action.action_reference
    where action.entity_ref = 'entity-mobile-contract'
      and action.action_reference = 'action-0004'
      and action.status = 'denied'
      and action.decision_evidence -> 'context' ->> 'decision' = 'denied'
      and action.decision_evidence -> 'signoff' ->> 'key_class' = 'A'
      and action.decision_evidence -> 'signoff' -> 'webauthn' ->> 'signature' = 'Yw'
      and not (action.decision_evidence ? 'class_a')
      and challenge.challenge_id = 'challenge-0004'
      and challenge.consumed_at is not null
      and action.decided_at = challenge.consumed_at
  ) then raise exception 'typed denial did not commit with challenge consumption'; end if;

  if register_mobile_action_challenge(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'action-0002', 'approver-1', 'challenge-0002',
    'sha256:' || repeat('d', 64), 'approved', now() + interval '5 minutes'
  ) is not true then raise exception 'rollback challenge registration failed'; end if;
  approval_guard_evidence := jsonb_build_object(
    'context', jsonb_build_object(
      'action_hash', 'sha256:' || repeat('d', 64),
      'decision', 'denied',
      'approver', 'approver-1',
      'issued_at', '2026-07-16T20:00:00.000Z',
      'mobile_binding', jsonb_build_object(
        'profile_hash', 'sha256:' || repeat('b', 64),
        'device_key_id', 'device-1'
      )
    ),
    'signoff', jsonb_build_object(
      'key_class', 'A',
      'approver_key_id', 'device-1',
      'context_hash', 'sha256:' || repeat('0', 64),
      'signed_at', '2026-07-16T20:00:00.000Z',
      'webauthn', jsonb_build_object(
        'authenticator_data', 'YQ', 'client_data_json', 'Yg', 'signature', 'Yw'
      )
    )
  );
  approval_guard_record := jsonb_build_object(
    'action_hash', 'sha256:' || repeat('d', 64),
    'approver_id', 'approver-1',
    'challenge_id', 'challenge-0002',
    'context_hash', 'sha256:' || repeat('0', 64),
    'decision', 'approved',
    'decision_evidence', approval_guard_evidence,
    'device_key_id', 'device-1',
    'event_type', 'mobile.ceremony.decision',
    'prev_hash', denial_hash,
    'profile_hash', 'sha256:' || repeat('b', 64),
    'record_id', 'mar_00000000000000000000000000000003',
    'seq', 3,
    'session_id', '00000000-0000-0000-0000-000000000001',
    'verdict', 'verified'
  );
  approval_guard_body := approval_guard_record::text;
  approval_guard_hash := encode(digest(convert_to(approval_guard_body, 'UTF8'), 'sha256'), 'hex');
  approval_guard_record := approval_guard_record || jsonb_build_object('hash', approval_guard_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0002', 'sha256:' || repeat('d', 64),
    'approved', 'verified',
    approval_guard_evidence,
    denial_hash, approval_guard_record, approval_guard_body
  ) into committed;
  if committed ->> 'reason' <> 'malformed' then
    raise exception 'typed denial evidence was accepted for an approval';
  end if;
  if (select status from mobile_actions
      where entity_ref = 'entity-mobile-contract' and action_reference = 'action-0002') <> 'pending' then
    raise exception 'wrongly typed approval evidence changed the protected action';
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
      and device_key_id = 'ep:key:mobile-device-0000000000000001'
      and status <> 'revoked'
  ) then raise exception 'credential remained active'; end if;

  revoked_evidence := jsonb_build_object(
    'context', jsonb_build_object(
      'action_hash', 'sha256:' || repeat('e', 64),
      'decision', 'approved',
      'approver', 'approver-1',
      'issued_at', '2026-07-16T20:00:00.000Z',
      'mobile_binding', jsonb_build_object(
        'profile_hash', 'sha256:' || repeat('b', 64),
        'device_key_id', 'device-1'
      )
    ),
    'signoff', jsonb_build_object(
      'key_class', 'A',
      'approver_key_id', 'device-1',
      'context_hash', 'sha256:' || repeat('f', 64),
      'signed_at', '2026-07-16T20:00:00.000Z',
      'webauthn', jsonb_build_object(
        'authenticator_data', 'YQ', 'client_data_json', 'Yg', 'signature', 'Yw'
      )
    )
  );
  revoked_record := jsonb_build_object(
    'action_hash', 'sha256:' || repeat('e', 64),
    'approver_id', 'approver-1',
    'challenge_id', 'challenge-0003',
    'context_hash', 'sha256:' || repeat('f', 64),
    'decision', 'approved',
    'decision_evidence', revoked_evidence,
    'device_key_id', 'device-1',
    'event_type', 'mobile.ceremony.decision',
    'prev_hash', atomic_hash,
    'profile_hash', 'sha256:' || repeat('b', 64),
    'record_id', 'mar_00000000000000000000000000000004',
    'seq', 2,
    'session_id', '00000000-0000-0000-0000-000000000001',
    'verdict', 'verified'
  );
  revoked_body := revoked_record::text;
  revoked_hash := encode(digest(convert_to(revoked_body, 'UTF8'), 'sha256'), 'hex');
  revoked_record := revoked_record || jsonb_build_object('hash', revoked_hash);
  select commit_mobile_action_decision(
    'entity-mobile-contract', '00000000-0000-0000-0000-000000000001',
    'challenge-0003', 'sha256:' || repeat('e', 64),
    'approved', 'verified',
    revoked_evidence,
    atomic_hash, revoked_record, revoked_body
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
     or has_function_privilege(
       'anon',
       'create_grace_mobile_action_group(jsonb,text,text,jsonb,jsonb,jsonb,text,timestamptz,timestamptz)',
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
       'commit_mobile_action_decision(text,uuid,text,text,text,text,jsonb,text,jsonb,text,timestamptz)',
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
