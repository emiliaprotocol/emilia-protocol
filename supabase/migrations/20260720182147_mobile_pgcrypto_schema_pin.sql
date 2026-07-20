-- SPDX-License-Identifier: Apache-2.0
-- Supabase installs pgcrypto in the protected `extensions` schema. The
-- original mobile functions pinned `public, pg_temp`, so unqualified digest()
-- calls compiled locally but failed at runtime in production. Keep table
-- resolution in public while resolving cryptographic primitives from the
-- extension schema first.

alter function append_mobile_audit_event(text, jsonb)
  set search_path = extensions, public, pg_temp;

alter function append_mobile_evidence_record(text, text, jsonb, text)
  set search_path = extensions, public, pg_temp;

alter function commit_mobile_action_decision(
  text, uuid, text, text, text, text, jsonb, text, jsonb, text, timestamptz
)
  set search_path = extensions, public, pg_temp;
