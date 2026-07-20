-- SPDX-License-Identifier: Apache-2.0
-- Keep internal trigger functions out of the PostgREST RPC surface and cover
-- the continuity foreign key used by challenge identity lookups.
revoke all on function mobile_action_challenge_identity()
  from public, anon, authenticated;
revoke all on function mobile_action_decision_identity_guard()
  from public, anon, authenticated;
revoke all on function mobile_action_decision_projection()
  from public, anon, authenticated;

create index if not exists mobile_action_challenges_group_revision_idx
  on mobile_action_challenges (entity_ref, group_id, revision)
  where group_id is not null;
