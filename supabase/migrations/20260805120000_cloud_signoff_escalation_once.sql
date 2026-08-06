-- SPDX-License-Identifier: Apache-2.0
-- One durable escalation record per accountable-signoff challenge.

CREATE UNIQUE INDEX IF NOT EXISTS cloud_signoff_escalated_once
  ON public.audit_events (target_id)
  WHERE event_type = 'cloud.signoff.escalated'
    AND target_type = 'signoff_challenge';

COMMENT ON INDEX public.cloud_signoff_escalated_once IS
  'Makes cloud signoff escalation a durable, one-time event instead of an acknowledgement-only response.';
