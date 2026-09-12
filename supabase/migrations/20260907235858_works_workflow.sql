-- SPDX-License-Identifier: Apache-2.0
-- EMILIA Works operating workflow. These tables are additive beside the six
-- public.works_records collections. Selection records a commercial assignment;
-- it never grants Gate, provider-entry, or any other execution permission.

CREATE TABLE public.works_record_workflow (
  collection TEXT COLLATE "C" NOT NULL
    CHECK (collection IN ('listings', 'opportunities', 'submissions')),
  record_id TEXT COLLATE "C" NOT NULL,
  state TEXT COLLATE "C" NOT NULL CHECK (
    (collection = 'listings' AND state IN ('active', 'paused', 'archived'))
    OR (collection = 'opportunities' AND state IN ('open', 'closed', 'assigned'))
    OR (collection = 'submissions' AND state IN ('submitted', 'declined', 'selected'))
  ),
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (collection, record_id),
  FOREIGN KEY (collection, record_id)
    REFERENCES public.works_records(collection, record_id) ON DELETE CASCADE
);

CREATE TABLE public.works_assignments (
  assignment_id TEXT COLLATE "C" PRIMARY KEY
    CHECK (assignment_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
  opportunity_id TEXT COLLATE "C" NOT NULL,
  submission_id TEXT COLLATE "C" NOT NULL UNIQUE,
  buyer_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE RESTRICT,
  builder_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE RESTRICT,
  builder_id TEXT COLLATE "C" NOT NULL,
  listing_id TEXT COLLATE "C",
  state TEXT COLLATE "C" NOT NULL CHECK (state IN (
    'proposed', 'confirmed', 'declined', 'delivery_submitted',
    'changes_requested', 'completed', 'cancelled'
  )),
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 8000),
  acceptance_criteria JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(acceptance_criteria) = 'array'
    AND pg_catalog.jsonb_array_length(acceptance_criteria) BETWEEN 1 AND 32
    AND pg_catalog.pg_column_size(acceptance_criteria) <= 65536
  ),
  terms TEXT NOT NULL CHECK (length(terms) BETWEEN 1 AND 8000),
  frozen_job JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(frozen_job) = 'object'
    AND pg_catalog.pg_column_size(frozen_job) <= 131072
  ),
  frozen_proposal JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(frozen_proposal) = 'object'
    AND pg_catalog.pg_column_size(frozen_proposal) <= 131072
  ),
  delivery JSONB,
  outcome JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  CHECK (buyer_entity_id <> builder_entity_id),
  CHECK (delivery IS NULL OR pg_catalog.jsonb_typeof(delivery) = 'object'),
  CHECK (outcome IS NULL OR pg_catalog.jsonb_typeof(outcome) = 'object'),
  CHECK (state NOT IN ('delivery_submitted', 'changes_requested', 'completed') OR delivery IS NOT NULL),
  CHECK (outcome IS NULL OR state = 'completed'),
  CHECK (state <> 'completed' OR outcome IS NOT NULL)
);

-- The existing table key includes collection. Restrict both references with
-- triggers/functions below instead of adding an ambiguous record_id-only FK.
CREATE UNIQUE INDEX works_assignments_one_active_job_idx
  ON public.works_assignments(opportunity_id)
  WHERE state IN ('proposed', 'confirmed', 'delivery_submitted', 'changes_requested');
CREATE INDEX works_assignments_buyer_idx
  ON public.works_assignments(buyer_entity_id, updated_at DESC, assignment_id);
CREATE INDEX works_assignments_builder_idx
  ON public.works_assignments(builder_entity_id, updated_at DESC, assignment_id);

CREATE TABLE public.works_assignment_events (
  event_id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  assignment_id TEXT COLLATE "C" NOT NULL
    REFERENCES public.works_assignments(assignment_id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  event_type TEXT COLLATE "C" NOT NULL,
  actor_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE RESTRICT,
  evidence JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (
    pg_catalog.jsonb_typeof(evidence) = 'object'
    AND pg_catalog.pg_column_size(evidence) <= 524288
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE (assignment_id, sequence)
);

CREATE TABLE public.works_notifications (
  notification_id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
  owner_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE CASCADE,
  kind TEXT COLLATE "C" NOT NULL CHECK (kind IN (
    'proposal_received', 'proposal_declined', 'proposal_selected',
    'assignment_confirmed', 'assignment_declined', 'delivery_submitted',
    'changes_requested', 'completion_accepted', 'assignment_cancelled'
  )),
  resource_type TEXT COLLATE "C" NOT NULL CHECK (resource_type IN ('proposal', 'assignment')),
  resource_id TEXT COLLATE "C" NOT NULL CHECK (resource_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  read_at TIMESTAMPTZ,
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  email_delivered_at TIMESTAMPTZ,
  email_claimed_until TIMESTAMPTZ,
  email_attempts INTEGER NOT NULL DEFAULT 0 CHECK (email_attempts >= 0)
);
CREATE INDEX works_notifications_owner_idx
  ON public.works_notifications(owner_entity_id, created_at DESC, notification_id);

CREATE TABLE public.works_workflow_commands (
  actor_entity_id UUID NOT NULL REFERENCES public.entities(id) ON DELETE CASCADE,
  idempotency_key TEXT COLLATE "C" NOT NULL
    CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'),
  request_digest TEXT COLLATE "C" NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  response JSONB NOT NULL CHECK (pg_catalog.jsonb_typeof(response) = 'object'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (actor_entity_id, idempotency_key)
);

DO $works_workflow_rls$
DECLARE
  v_table TEXT;
BEGIN
  FOREACH v_table IN ARRAY ARRAY[
    'works_record_workflow', 'works_assignments', 'works_assignment_events',
    'works_notifications', 'works_workflow_commands'
  ] LOOP
    EXECUTE 'ALTER TABLE public.' || pg_catalog.quote_ident(v_table) || ' ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE public.' || pg_catalog.quote_ident(v_table) || ' FORCE ROW LEVEL SECURITY';
    EXECUTE 'REVOKE ALL ON TABLE public.' || pg_catalog.quote_ident(v_table)
      || ' FROM PUBLIC, anon, authenticated, service_role';
  END LOOP;
END
$works_workflow_rls$;

-- Explicit statements retained for schema review and contract checks.
ALTER TABLE public.works_record_workflow ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_record_workflow FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.works_record_workflow FROM PUBLIC, anon, authenticated, service_role;
ALTER TABLE public.works_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_assignments FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.works_assignments FROM PUBLIC, anon, authenticated, service_role;
ALTER TABLE public.works_assignment_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_assignment_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.works_assignment_events FROM PUBLIC, anon, authenticated, service_role;
ALTER TABLE public.works_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_notifications FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.works_notifications FROM PUBLIC, anon, authenticated, service_role;
ALTER TABLE public.works_workflow_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_workflow_commands FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.works_workflow_commands FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.works_workflow_request_digest(p_request JSONB)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = ''
AS $works_workflow_request_digest$
  SELECT 'sha256:' || pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_request::TEXT, 'UTF8'), 'sha256'), 'hex'
  )
$works_workflow_request_digest$;

CREATE FUNCTION public.works_assignment_projection(p_assignment public.works_assignments)
RETURNS JSONB
LANGUAGE SQL
STABLE
STRICT
SECURITY INVOKER
SET search_path = ''
AS $works_assignment_projection$
  SELECT pg_catalog.jsonb_build_object(
    'assignment_id', p_assignment.assignment_id,
    'job_id', p_assignment.opportunity_id,
    'proposal_id', p_assignment.submission_id,
    'builder_id', p_assignment.builder_id,
    'listing_id', p_assignment.listing_id,
    'state', p_assignment.state,
    'revision', p_assignment.revision,
    'scope', p_assignment.scope,
    'acceptance_criteria', p_assignment.acceptance_criteria,
    'terms', p_assignment.terms,
    'frozen', pg_catalog.jsonb_build_object(
      'job', p_assignment.frozen_job, 'proposal', p_assignment.frozen_proposal
    ),
    'delivery', p_assignment.delivery,
    'outcome', p_assignment.outcome,
    'history', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'actor_role', CASE WHEN event.actor_entity_id = p_assignment.buyer_entity_id
          THEN 'buyer' ELSE 'builder' END,
        'command', event.event_type,
        'revision', event.sequence - 1,
        'at', event.created_at,
        'summary', COALESCE(
          event.evidence ->> 'summary', event.evidence #>> '{delivery,summary}',
          event.evidence #>> '{outcome,summary}'
        ),
        'reason', event.evidence ->> 'reason',
        'delivery', event.evidence -> 'delivery'
      ) ORDER BY event.sequence)
      FROM public.works_assignment_events AS event
      WHERE event.assignment_id = p_assignment.assignment_id
    ), '[]'::JSONB),
    'created_at', p_assignment.created_at,
    'updated_at', p_assignment.updated_at
  )
$works_assignment_projection$;

CREATE FUNCTION public.works_workflow_replay(
  p_actor_entity_id UUID,
  p_idempotency_key TEXT,
  p_request_digest TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $works_workflow_replay$
DECLARE
  v_command public.works_workflow_commands%ROWTYPE;
BEGIN
  -- Same actor/key requests serialize before any aggregate is touched.
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(p_actor_entity_id::TEXT || ':' || p_idempotency_key, 0)
  );
  SELECT * INTO v_command
  FROM public.works_workflow_commands
  WHERE actor_entity_id = p_actor_entity_id AND idempotency_key = p_idempotency_key;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF v_command.request_digest IS DISTINCT FROM p_request_digest THEN
    RAISE EXCEPTION 'idempotency_conflict' USING ERRCODE = 'EWIDM';
  END IF;
  RETURN pg_catalog.jsonb_set(v_command.response, '{replayed}', 'true'::JSONB, TRUE);
END
$works_workflow_replay$;

REVOKE ALL ON FUNCTION public.works_workflow_request_digest(JSONB)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_assignment_projection(public.works_assignments)
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_workflow_replay(UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.works_assignment_events_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $works_assignment_events_immutable$
BEGIN
  RAISE EXCEPTION 'works assignment history is immutable' USING ERRCODE = '55000';
END
$works_assignment_events_immutable$;

CREATE TRIGGER works_assignment_events_immutable
  BEFORE UPDATE OR DELETE ON public.works_assignment_events
  FOR EACH ROW EXECUTE FUNCTION public.works_assignment_events_immutable();

CREATE FUNCTION public.works_assignments_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $works_assignments_guard$
DECLARE
  v_job public.works_records%ROWTYPE;
  v_proposal public.works_records%ROWTYPE;
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT * INTO v_job FROM public.works_records
    WHERE collection = 'opportunities' AND record_id = NEW.opportunity_id;
    SELECT * INTO v_proposal FROM public.works_records
    WHERE collection = 'submissions' AND record_id = NEW.submission_id;
    IF v_job.record_id IS NULL OR v_proposal.record_id IS NULL
      OR v_job.owner_entity_id IS DISTINCT FROM NEW.buyer_entity_id
      OR v_proposal.owner_entity_id IS DISTINCT FROM NEW.builder_entity_id
      OR v_proposal.record ->> 'opportunity_id' IS DISTINCT FROM NEW.opportunity_id
      OR v_proposal.record ->> 'builder_id' IS DISTINCT FROM NEW.builder_id
      OR NULLIF(v_proposal.record ->> 'listing_id', '') IS DISTINCT FROM NEW.listing_id
      OR v_job.record IS DISTINCT FROM NEW.frozen_job
      OR v_proposal.record IS DISTINCT FROM NEW.frozen_proposal
    THEN
      RAISE EXCEPTION 'works assignment reference or frozen snapshot mismatch'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
    OR NEW.opportunity_id IS DISTINCT FROM OLD.opportunity_id
    OR NEW.submission_id IS DISTINCT FROM OLD.submission_id
    OR NEW.buyer_entity_id IS DISTINCT FROM OLD.buyer_entity_id
    OR NEW.builder_entity_id IS DISTINCT FROM OLD.builder_entity_id
    OR NEW.builder_id IS DISTINCT FROM OLD.builder_id
    OR NEW.listing_id IS DISTINCT FROM OLD.listing_id
    OR NEW.scope IS DISTINCT FROM OLD.scope
    OR NEW.acceptance_criteria IS DISTINCT FROM OLD.acceptance_criteria
    OR NEW.terms IS DISTINCT FROM OLD.terms
    OR NEW.frozen_job IS DISTINCT FROM OLD.frozen_job
    OR NEW.frozen_proposal IS DISTINCT FROM OLD.frozen_proposal
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  ) THEN
    RAISE EXCEPTION 'works assignment identity and accepted snapshots are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
    RAISE EXCEPTION 'works assignment revision must advance exactly once'
      USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome THEN
    RAISE EXCEPTION 'works buyer acceptance is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$works_assignments_guard$;

CREATE TRIGGER works_assignments_guard_before_write
  BEFORE INSERT OR UPDATE ON public.works_assignments
  FOR EACH ROW EXECUTE FUNCTION public.works_assignments_guard();

CREATE FUNCTION public.works_submission_workflow_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $works_submission_workflow_guard$
DECLARE
  v_job_id TEXT;
  v_job_state TEXT;
BEGIN
  IF NEW.collection <> 'submissions' THEN RETURN NEW; END IF;
  v_job_id := NEW.record ->> 'opportunity_id';
  -- This is the same parent-row lock taken by close and select RPCs. It makes
  -- request acceptance atomic with an open job instead of check-then-insert.
  PERFORM 1 FROM public.works_records
  WHERE collection = 'opportunities' AND record_id = v_job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'job_not_found' USING ERRCODE = 'EW404';
  END IF;
  SELECT state INTO v_job_state FROM public.works_record_workflow
  WHERE collection = 'opportunities' AND record_id = v_job_id;
  v_job_state := COALESCE(v_job_state, 'open');
  IF v_job_state <> 'open' THEN
    RAISE EXCEPTION 'job_not_open' USING ERRCODE = 'EWTRN';
  END IF;
  RETURN NEW;
END
$works_submission_workflow_guard$;

CREATE TRIGGER works_submission_workflow_guard_before_insert
  BEFORE INSERT ON public.works_records
  FOR EACH ROW WHEN (NEW.collection = 'submissions')
  EXECUTE FUNCTION public.works_submission_workflow_guard();

CREATE FUNCTION public.works_submission_notify()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $works_submission_notify$
DECLARE
  v_buyer_entity_id UUID;
BEGIN
  SELECT owner_entity_id INTO v_buyer_entity_id
  FROM public.works_records
  WHERE collection = 'opportunities' AND record_id = NEW.record ->> 'opportunity_id';
  IF v_buyer_entity_id IS NULL THEN
    RAISE EXCEPTION 'job_not_found' USING ERRCODE = 'EW404';
  END IF;
  INSERT INTO public.works_notifications(
    owner_entity_id, kind, resource_type, resource_id
  ) VALUES (
    v_buyer_entity_id, 'proposal_received', 'proposal', NEW.record_id
  );
  RETURN NEW;
END
$works_submission_notify$;

CREATE TRIGGER works_submission_notify_after_insert
  AFTER INSERT ON public.works_records
  FOR EACH ROW WHEN (NEW.collection = 'submissions')
  EXECUTE FUNCTION public.works_submission_notify();

CREATE FUNCTION public.works_listing_status_workflow_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $works_listing_status_workflow_guard$
BEGIN
  IF NEW.collection = 'listings'
    AND NEW.record ->> 'status' IS DISTINCT FROM OLD.record ->> 'status'
    AND COALESCE(pg_catalog.current_setting('emilia.works_workflow_rpc', TRUE), '') <> '1'
  THEN
    RAISE EXCEPTION 'listing_status_requires_workflow_command' USING ERRCODE = 'EWTRN';
  END IF;
  RETURN NEW;
END
$works_listing_status_workflow_guard$;

CREATE TRIGGER works_listing_status_workflow_guard_before_update
  BEFORE UPDATE ON public.works_records
  FOR EACH ROW EXECUTE FUNCTION public.works_listing_status_workflow_guard();

REVOKE ALL ON FUNCTION public.works_assignment_events_immutable()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_assignments_guard()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_submission_workflow_guard()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_submission_notify()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.works_listing_status_workflow_guard()
  FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.command_works_record(
  p_actor_entity_id UUID,
  p_command TEXT,
  p_record_id TEXT,
  p_expected_revision INTEGER,
  p_idempotency_key TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $command_works_record$
DECLARE
  v_request JSONB;
  v_digest TEXT;
  v_replay JSONB;
  v_collection TEXT;
  v_record public.works_records%ROWTYPE;
  v_job public.works_records%ROWTYPE;
  v_state TEXT;
  v_revision INTEGER;
  v_next_state TEXT;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_response JSONB;
BEGIN
  IF p_actor_entity_id IS NULL OR p_command IS NULL OR p_record_id IS NULL
    OR p_record_id !~ '^[a-z0-9][a-z0-9-]{2,63}$'
    OR p_expected_revision IS NULL OR p_expected_revision < 0 OR p_idempotency_key IS NULL
    OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  THEN RAISE EXCEPTION 'invalid_command' USING ERRCODE = '22023'; END IF;
  v_request := pg_catalog.jsonb_build_object(
    'kind', 'record', 'actor', p_actor_entity_id, 'command', p_command,
    'record_id', p_record_id, 'expected_revision', p_expected_revision
  );
  v_digest := public.works_workflow_request_digest(v_request);
  v_replay := public.works_workflow_replay(p_actor_entity_id, p_idempotency_key, v_digest);
  IF v_replay IS NOT NULL THEN RETURN v_replay; END IF;

  v_collection := CASE
    WHEN p_command IN ('pause_listing', 'archive_listing', 'reactivate_listing') THEN 'listings'
    WHEN p_command IN ('close_job', 'reopen_job') THEN 'opportunities'
    WHEN p_command = 'decline_proposal' THEN 'submissions'
    ELSE NULL
  END;
  IF v_collection IS NULL THEN
    RAISE EXCEPTION 'invalid_command' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_record FROM public.works_records
  WHERE collection = v_collection AND record_id = p_record_id
  FOR UPDATE;
  IF NOT FOUND OR v_record.record @> '{"example": true}'::JSONB THEN
    RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
  END IF;

  IF v_collection = 'submissions' THEN
    SELECT * INTO v_job FROM public.works_records
    WHERE collection = 'opportunities'
      AND record_id = v_record.record ->> 'opportunity_id'
    FOR UPDATE;
    IF NOT FOUND OR v_job.owner_entity_id IS DISTINCT FROM p_actor_entity_id THEN
      RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
    END IF;
  ELSIF v_record.owner_entity_id IS DISTINCT FROM p_actor_entity_id THEN
    RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
  END IF;

  SELECT state, revision INTO v_state, v_revision
  FROM public.works_record_workflow
  WHERE collection = v_collection AND record_id = p_record_id;
  IF NOT FOUND THEN
    v_revision := 0;
    v_state := CASE v_collection
      WHEN 'listings' THEN COALESCE(v_record.record ->> 'status', 'active')
      WHEN 'opportunities' THEN 'open'
      ELSE 'submitted'
    END;
  END IF;
  IF v_revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'revision_conflict' USING ERRCODE = 'EWREV';
  END IF;

  v_next_state := CASE
    WHEN p_command = 'pause_listing' AND v_state = 'active' THEN 'paused'
    WHEN p_command = 'archive_listing' AND v_state IN ('active', 'paused') THEN 'archived'
    WHEN p_command = 'reactivate_listing' AND v_state IN ('paused', 'archived') THEN 'active'
    WHEN p_command = 'close_job' AND v_state = 'open' THEN 'closed'
    WHEN p_command = 'reopen_job' AND v_state = 'closed' THEN 'open'
    WHEN p_command = 'decline_proposal' AND v_state = 'submitted' THEN 'declined'
    ELSE NULL
  END;
  IF v_next_state IS NULL THEN
    RAISE EXCEPTION 'invalid_transition' USING ERRCODE = 'EWTRN';
  END IF;

  INSERT INTO public.works_record_workflow(collection, record_id, state, revision, updated_at)
  VALUES (v_collection, p_record_id, v_next_state, v_revision + 1, v_now)
  ON CONFLICT (collection, record_id) DO UPDATE
  SET state = EXCLUDED.state, revision = EXCLUDED.revision, updated_at = EXCLUDED.updated_at;

  IF v_collection = 'listings' THEN
    PERFORM pg_catalog.set_config('emilia.works_workflow_rpc', '1', TRUE);
    UPDATE public.works_records
    SET record = pg_catalog.jsonb_set(record, '{status}', pg_catalog.to_jsonb(v_next_state), TRUE),
        updated_at = v_now
    WHERE collection = 'listings' AND record_id = p_record_id;
  END IF;

  IF p_command = 'decline_proposal' THEN
    INSERT INTO public.works_notifications(owner_entity_id, kind, resource_type, resource_id)
    VALUES (v_record.owner_entity_id, 'proposal_declined', 'proposal', p_record_id);
  END IF;

  v_response := pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'resource', pg_catalog.jsonb_build_object(
      'record_id', p_record_id, 'collection', v_collection,
      'workflow', pg_catalog.jsonb_build_object(
        'state', v_next_state, 'revision', v_revision + 1, 'updated_at', v_now
      )
    )
  );
  INSERT INTO public.works_workflow_commands(
    actor_entity_id, idempotency_key, request_digest, response
  ) VALUES (p_actor_entity_id, p_idempotency_key, v_digest, v_response);
  RETURN v_response;
END
$command_works_record$;

REVOKE ALL ON FUNCTION public.command_works_record(UUID, TEXT, TEXT, INTEGER, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.command_works_record(UUID, TEXT, TEXT, INTEGER, TEXT)
  TO service_role;

CREATE FUNCTION public.select_works_proposal(
  p_actor_entity_id UUID,
  p_proposal_id TEXT,
  p_expected_revision INTEGER,
  p_idempotency_key TEXT,
  p_scope TEXT,
  p_acceptance_criteria JSONB,
  p_terms TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $select_works_proposal$
DECLARE
  v_request JSONB;
  v_digest TEXT;
  v_replay JSONB;
  v_proposal public.works_records%ROWTYPE;
  v_job public.works_records%ROWTYPE;
  v_job_state TEXT;
  v_job_revision INTEGER;
  v_proposal_state TEXT;
  v_proposal_revision INTEGER;
  v_assignment public.works_assignments%ROWTYPE;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_response JSONB;
BEGIN
  IF p_actor_entity_id IS NULL OR p_proposal_id IS NULL
    OR p_proposal_id !~ '^[a-z0-9][a-z0-9-]{2,63}$'
    OR p_expected_revision IS NULL OR p_expected_revision < 0
    OR p_idempotency_key IS NULL
    OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
    OR p_scope IS NULL OR p_terms IS NULL OR p_acceptance_criteria IS NULL
    OR length(pg_catalog.btrim(p_scope)) NOT BETWEEN 1 AND 8000
    OR length(pg_catalog.btrim(p_terms)) NOT BETWEEN 1 AND 8000
    OR pg_catalog.jsonb_typeof(p_acceptance_criteria) <> 'array'
    OR pg_catalog.jsonb_array_length(p_acceptance_criteria) NOT BETWEEN 1 AND 32
    OR EXISTS (
      SELECT 1 FROM pg_catalog.jsonb_array_elements(p_acceptance_criteria) AS criterion(value)
      WHERE pg_catalog.jsonb_typeof(criterion.value) <> 'string'
        OR length(pg_catalog.btrim(criterion.value #>> '{}')) NOT BETWEEN 1 AND 1000
    )
  THEN RAISE EXCEPTION 'invalid_selection' USING ERRCODE = '22023'; END IF;

  v_request := pg_catalog.jsonb_build_object(
    'kind', 'select', 'actor', p_actor_entity_id, 'proposal_id', p_proposal_id,
    'expected_revision', p_expected_revision, 'scope', pg_catalog.btrim(p_scope),
    'acceptance_criteria', p_acceptance_criteria, 'terms', pg_catalog.btrim(p_terms)
  );
  v_digest := public.works_workflow_request_digest(v_request);
  v_replay := public.works_workflow_replay(p_actor_entity_id, p_idempotency_key, v_digest);
  IF v_replay IS NOT NULL THEN RETURN v_replay; END IF;

  SELECT * INTO v_proposal FROM public.works_records
  WHERE collection = 'submissions' AND record_id = p_proposal_id
  FOR UPDATE;
  IF NOT FOUND OR v_proposal.record @> '{"example": true}'::JSONB THEN
    RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
  END IF;
  SELECT * INTO v_job FROM public.works_records
  WHERE collection = 'opportunities'
    AND record_id = v_proposal.record ->> 'opportunity_id'
  FOR UPDATE;
  IF NOT FOUND OR v_job.owner_entity_id IS DISTINCT FROM p_actor_entity_id THEN
    RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
  END IF;
  IF v_proposal.owner_entity_id = p_actor_entity_id THEN
    RAISE EXCEPTION 'self_assignment_forbidden' USING ERRCODE = 'EW403';
  END IF;

  SELECT state, revision INTO v_job_state, v_job_revision
  FROM public.works_record_workflow
  WHERE collection = 'opportunities' AND record_id = v_job.record_id;
  IF NOT FOUND THEN v_job_state := 'open'; v_job_revision := 0; END IF;
  IF v_job_revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'revision_conflict' USING ERRCODE = 'EWREV';
  END IF;
  IF v_job_state <> 'open' THEN
    RAISE EXCEPTION 'invalid_transition' USING ERRCODE = 'EWTRN';
  END IF;

  SELECT state, revision INTO v_proposal_state, v_proposal_revision
  FROM public.works_record_workflow
  WHERE collection = 'submissions' AND record_id = p_proposal_id;
  IF NOT FOUND THEN v_proposal_state := 'submitted'; v_proposal_revision := 0; END IF;
  IF v_proposal_state <> 'submitted' THEN
    RAISE EXCEPTION 'invalid_transition' USING ERRCODE = 'EWTRN';
  END IF;

  INSERT INTO public.works_assignments(
    assignment_id, opportunity_id, submission_id, buyer_entity_id, builder_entity_id,
    builder_id, listing_id, state, revision, scope, acceptance_criteria, terms,
    frozen_job, frozen_proposal, created_at, updated_at
  ) VALUES (
    'assignment-' || pg_catalog.replace(pg_catalog.gen_random_uuid()::TEXT, '-', ''),
    v_job.record_id, v_proposal.record_id, p_actor_entity_id, v_proposal.owner_entity_id,
    v_proposal.record ->> 'builder_id', NULLIF(v_proposal.record ->> 'listing_id', ''),
    'proposed', 0, pg_catalog.btrim(p_scope), p_acceptance_criteria, pg_catalog.btrim(p_terms),
    v_job.record, v_proposal.record, v_now, v_now
  ) RETURNING * INTO v_assignment;

  INSERT INTO public.works_record_workflow(collection, record_id, state, revision, updated_at)
  VALUES ('opportunities', v_job.record_id, 'assigned', v_job_revision + 1, v_now)
  ON CONFLICT (collection, record_id) DO UPDATE
  SET state = EXCLUDED.state, revision = EXCLUDED.revision, updated_at = EXCLUDED.updated_at;
  INSERT INTO public.works_record_workflow(collection, record_id, state, revision, updated_at)
  VALUES ('submissions', v_proposal.record_id, 'selected', v_proposal_revision + 1, v_now)
  ON CONFLICT (collection, record_id) DO UPDATE
  SET state = EXCLUDED.state, revision = EXCLUDED.revision, updated_at = EXCLUDED.updated_at;

  INSERT INTO public.works_assignment_events(
    assignment_id, sequence, event_type, actor_entity_id, evidence, created_at
  ) VALUES (
    v_assignment.assignment_id, 1, 'proposal_selected', p_actor_entity_id,
    pg_catalog.jsonb_build_object(
      'scope', v_assignment.scope, 'acceptance_criteria', v_assignment.acceptance_criteria,
      'terms', v_assignment.terms, 'frozen_job', v_assignment.frozen_job,
      'frozen_proposal', v_assignment.frozen_proposal,
      'execution_authority_granted', FALSE
    ), v_now
  );
  INSERT INTO public.works_notifications(owner_entity_id, kind, resource_type, resource_id)
  VALUES (v_proposal.owner_entity_id, 'proposal_selected', 'assignment', v_assignment.assignment_id);

  v_response := pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE, 'resource', public.works_assignment_projection(v_assignment)
  );
  INSERT INTO public.works_workflow_commands(
    actor_entity_id, idempotency_key, request_digest, response
  ) VALUES (p_actor_entity_id, p_idempotency_key, v_digest, v_response);
  RETURN v_response;
END
$select_works_proposal$;

REVOKE ALL ON FUNCTION public.select_works_proposal(UUID, TEXT, INTEGER, TEXT, TEXT, JSONB, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.select_works_proposal(UUID, TEXT, INTEGER, TEXT, TEXT, JSONB, TEXT)
  TO service_role;

CREATE FUNCTION public.command_works_assignment(
  p_actor_entity_id UUID,
  p_assignment_id TEXT,
  p_command TEXT,
  p_expected_revision INTEGER,
  p_idempotency_key TEXT,
  p_payload JSONB DEFAULT '{}'::JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $command_works_assignment$
DECLARE
  v_request JSONB;
  v_digest TEXT;
  v_replay JSONB;
  v_assignment public.works_assignments%ROWTYPE;
  v_job public.works_records%ROWTYPE;
  v_next_state TEXT;
  v_notify_owner UUID;
  v_notification_kind TEXT;
  v_event_evidence JSONB := '{}'::JSONB;
  v_delivery_url TEXT;
  v_summary TEXT;
  v_reason TEXT;
  v_job_revision INTEGER;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_response JSONB;
BEGIN
  IF p_actor_entity_id IS NULL OR p_assignment_id IS NULL
    OR p_assignment_id !~ '^[a-z0-9][a-z0-9-]{2,63}$'
    OR p_command IS NULL OR p_expected_revision IS NULL OR p_expected_revision < 0
    OR p_idempotency_key IS NULL
    OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
    OR p_payload IS NULL OR pg_catalog.jsonb_typeof(p_payload) <> 'object'
  THEN RAISE EXCEPTION 'invalid_command' USING ERRCODE = '22023'; END IF;

  v_request := pg_catalog.jsonb_build_object(
    'kind', 'assignment', 'actor', p_actor_entity_id, 'assignment_id', p_assignment_id,
    'command', p_command, 'expected_revision', p_expected_revision, 'payload', p_payload
  );
  v_digest := public.works_workflow_request_digest(v_request);
  v_replay := public.works_workflow_replay(p_actor_entity_id, p_idempotency_key, v_digest);
  IF v_replay IS NOT NULL THEN RETURN v_replay; END IF;

  SELECT * INTO v_assignment FROM public.works_assignments
  WHERE assignment_id = p_assignment_id FOR UPDATE;
  IF NOT FOUND OR p_actor_entity_id NOT IN (
    v_assignment.buyer_entity_id, v_assignment.builder_entity_id
  ) THEN RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404'; END IF;
  IF v_assignment.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'revision_conflict' USING ERRCODE = 'EWREV';
  END IF;

  IF p_command IN ('builder_confirm', 'builder_decline', 'submit_delivery')
    AND p_actor_entity_id IS DISTINCT FROM v_assignment.builder_entity_id
  THEN RAISE EXCEPTION 'forbidden' USING ERRCODE = 'EW403'; END IF;
  IF p_command IN ('request_changes', 'accept_completion')
    AND p_actor_entity_id IS DISTINCT FROM v_assignment.buyer_entity_id
  THEN RAISE EXCEPTION 'forbidden' USING ERRCODE = 'EW403'; END IF;

  v_next_state := CASE
    WHEN p_command = 'builder_confirm' AND v_assignment.state = 'proposed' THEN 'confirmed'
    WHEN p_command = 'builder_decline' AND v_assignment.state = 'proposed' THEN 'declined'
    WHEN p_command = 'submit_delivery'
      AND v_assignment.state IN ('confirmed', 'changes_requested') THEN 'delivery_submitted'
    WHEN p_command = 'request_changes' AND v_assignment.state = 'delivery_submitted' THEN 'changes_requested'
    WHEN p_command = 'accept_completion' AND v_assignment.state = 'delivery_submitted' THEN 'completed'
    WHEN p_command = 'cancel'
      AND v_assignment.state IN ('proposed', 'confirmed', 'delivery_submitted', 'changes_requested')
      THEN 'cancelled'
    ELSE NULL
  END;
  IF v_next_state IS NULL THEN
    RAISE EXCEPTION 'invalid_transition' USING ERRCODE = 'EWTRN';
  END IF;

  IF p_command IN ('builder_confirm', 'builder_decline') AND p_payload <> '{}'::JSONB THEN
    RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
  END IF;
  IF p_command = 'submit_delivery' THEN
    IF p_payload - ARRAY['delivery_url', 'summary'] <> '{}'::JSONB
      OR NOT (p_payload ?& ARRAY['delivery_url', 'summary'])
    THEN RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023'; END IF;
    v_delivery_url := pg_catalog.btrim(p_payload ->> 'delivery_url');
    v_summary := pg_catalog.btrim(p_payload ->> 'summary');
    IF v_delivery_url IS NULL OR v_summary IS NULL
      OR length(v_delivery_url) > 600
      OR v_delivery_url !~* '^https://(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:[0-9]+)?([/?#]|$)[^[:space:]\\]*$'
      OR pg_catalog.split_part(
        pg_catalog.split_part(v_delivery_url, '://', 2), '/', 1
      ) LIKE '%@%'
      OR length(v_summary) NOT BETWEEN 1 AND 8000
    THEN RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023'; END IF;
  ELSIF p_command = 'request_changes' THEN
    IF p_payload - 'summary' <> '{}'::JSONB OR NOT p_payload ? 'summary' THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
    v_summary := pg_catalog.btrim(p_payload ->> 'summary');
    IF v_summary IS NULL OR length(v_summary) NOT BETWEEN 1 AND 8000 THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
  ELSIF p_command = 'accept_completion' THEN
    IF p_payload - 'summary' <> '{}'::JSONB THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
    v_summary := NULLIF(pg_catalog.btrim(p_payload ->> 'summary'), '');
    IF v_summary IS NOT NULL AND length(v_summary) > 8000 THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
  ELSIF p_command = 'cancel' THEN
    IF p_payload - 'reason' <> '{}'::JSONB OR NOT p_payload ? 'reason' THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
    v_reason := pg_catalog.btrim(p_payload ->> 'reason');
    IF v_reason IS NULL OR length(v_reason) NOT BETWEEN 1 AND 2000 THEN
      RAISE EXCEPTION 'invalid_command_payload' USING ERRCODE = '22023';
    END IF;
  END IF;

  IF p_command = 'builder_confirm' THEN
    v_notify_owner := v_assignment.buyer_entity_id;
    v_notification_kind := 'assignment_confirmed';
  ELSIF p_command = 'builder_decline' THEN
    v_notify_owner := v_assignment.buyer_entity_id;
    v_notification_kind := 'assignment_declined';
  ELSIF p_command = 'submit_delivery' THEN
    v_notify_owner := v_assignment.buyer_entity_id;
    v_notification_kind := 'delivery_submitted';
  ELSIF p_command = 'request_changes' THEN
    v_notify_owner := v_assignment.builder_entity_id;
    v_notification_kind := 'changes_requested';
  ELSIF p_command = 'accept_completion' THEN
    v_notify_owner := v_assignment.builder_entity_id;
    v_notification_kind := 'completion_accepted';
  ELSE
    v_notify_owner := CASE WHEN p_actor_entity_id = v_assignment.buyer_entity_id
      THEN v_assignment.builder_entity_id ELSE v_assignment.buyer_entity_id END;
    v_notification_kind := 'assignment_cancelled';
  END IF;

  UPDATE public.works_assignments
  SET state = v_next_state,
      revision = revision + 1,
      delivery = CASE WHEN p_command = 'submit_delivery' THEN pg_catalog.jsonb_build_object(
        'url', v_delivery_url, 'summary', v_summary, 'submitted_at', v_now
      ) ELSE delivery END,
      outcome = CASE WHEN p_command = 'accept_completion' THEN pg_catalog.jsonb_build_object(
        'accepted_at', v_now, 'summary', v_summary
      ) ELSE outcome END,
      updated_at = v_now
  WHERE assignment_id = p_assignment_id
  RETURNING * INTO v_assignment;

  IF p_command IN ('builder_decline', 'cancel', 'accept_completion') THEN
    SELECT * INTO v_job FROM public.works_records
    WHERE collection = 'opportunities' AND record_id = v_assignment.opportunity_id
    FOR UPDATE;
    IF NOT FOUND OR v_job.owner_entity_id IS DISTINCT FROM v_assignment.buyer_entity_id THEN
      RAISE EXCEPTION 'workflow_integrity_error' USING ERRCODE = 'EW500';
    END IF;
    SELECT revision INTO v_job_revision FROM public.works_record_workflow
    WHERE collection = 'opportunities' AND record_id = v_assignment.opportunity_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'workflow_integrity_error' USING ERRCODE = 'EW500'; END IF;
    UPDATE public.works_record_workflow
    SET state = CASE WHEN p_command = 'accept_completion' THEN 'closed' ELSE 'open' END,
        revision = v_job_revision + 1, updated_at = v_now
    WHERE collection = 'opportunities' AND record_id = v_assignment.opportunity_id
      AND state = 'assigned' AND revision = v_job_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'workflow_integrity_error' USING ERRCODE = 'EW500'; END IF;
  END IF;

  v_event_evidence := CASE
    WHEN p_command = 'submit_delivery' THEN pg_catalog.jsonb_build_object('delivery', v_assignment.delivery)
    WHEN p_command = 'request_changes' THEN pg_catalog.jsonb_build_object('summary', v_summary)
    WHEN p_command = 'cancel' THEN pg_catalog.jsonb_build_object('reason', v_reason)
    WHEN p_command = 'accept_completion' THEN pg_catalog.jsonb_build_object(
      'outcome', v_assignment.outcome,
      'delivery', v_assignment.delivery,
      'scope', v_assignment.scope,
      'acceptance_criteria', v_assignment.acceptance_criteria,
      'terms', v_assignment.terms,
      'frozen_job', v_assignment.frozen_job,
      'frozen_proposal', v_assignment.frozen_proposal,
      'execution_authority_granted', FALSE
    )
    ELSE '{}'::JSONB
  END;
  INSERT INTO public.works_assignment_events(
    assignment_id, sequence, event_type, actor_entity_id, evidence, created_at
  ) VALUES (
    p_assignment_id, v_assignment.revision + 1, p_command,
    p_actor_entity_id, v_event_evidence, v_now
  );
  INSERT INTO public.works_notifications(owner_entity_id, kind, resource_type, resource_id)
  VALUES (v_notify_owner, v_notification_kind, 'assignment', p_assignment_id);

  v_response := pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE, 'resource', public.works_assignment_projection(v_assignment)
  );
  INSERT INTO public.works_workflow_commands(
    actor_entity_id, idempotency_key, request_digest, response
  ) VALUES (p_actor_entity_id, p_idempotency_key, v_digest, v_response);
  RETURN v_response;
END
$command_works_assignment$;

REVOKE ALL ON FUNCTION public.command_works_assignment(UUID, TEXT, TEXT, INTEGER, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.command_works_assignment(UUID, TEXT, TEXT, INTEGER, TEXT, JSONB)
  TO service_role;

CREATE FUNCTION public.read_works_workspace(p_actor_entity_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $read_works_workspace$
DECLARE
  v_display_name TEXT;
  v_has_buyer BOOLEAN;
  v_has_builder BOOLEAN;
BEGIN
  IF p_actor_entity_id IS NULL THEN
    RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404';
  END IF;
  SELECT display_name INTO v_display_name FROM public.entities WHERE id = p_actor_entity_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404'; END IF;
  SELECT EXISTS (
    SELECT 1 FROM public.works_records
    WHERE owner_entity_id = p_actor_entity_id AND collection = 'opportunities'
  ) OR EXISTS (
    SELECT 1 FROM public.works_assignments WHERE buyer_entity_id = p_actor_entity_id
  ) INTO v_has_buyer;
  SELECT EXISTS (
    SELECT 1 FROM public.works_records
    WHERE owner_entity_id = p_actor_entity_id AND collection IN ('builders', 'submissions')
  ) OR EXISTS (
    SELECT 1 FROM public.works_assignments WHERE builder_entity_id = p_actor_entity_id
  ) INTO v_has_builder;

  RETURN pg_catalog.jsonb_build_object(
    'viewer', pg_catalog.jsonb_build_object(
      'display_name', v_display_name,
      'role', CASE WHEN v_has_buyer AND v_has_builder THEN 'both'
        WHEN v_has_builder THEN 'builder' ELSE 'buyer' END
    ),
    'profiles', COALESCE((
      SELECT pg_catalog.jsonb_agg(record ORDER BY created_at, record_id)
      FROM public.works_records
      WHERE collection = 'builders' AND owner_entity_id = p_actor_entity_id
        AND NOT record @> '{"example": true}'::JSONB
    ), '[]'::JSONB),
    'listings', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'record', base.record,
        'workflow', pg_catalog.jsonb_build_object(
          'state', COALESCE(flow.state, base.record ->> 'status', 'active'),
          'revision', COALESCE(flow.revision, 0),
          'updated_at', flow.updated_at
        )
      ) ORDER BY base.created_at, base.record_id)
      FROM public.works_records AS base
      LEFT JOIN public.works_record_workflow AS flow
        ON flow.collection = base.collection AND flow.record_id = base.record_id
      WHERE base.collection = 'listings' AND base.owner_entity_id = p_actor_entity_id
        AND NOT base.record @> '{"example": true}'::JSONB
    ), '[]'::JSONB),
    'jobs', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'record', base.record,
        'workflow', pg_catalog.jsonb_build_object(
          'state', COALESCE(flow.state, 'open'),
          'revision', COALESCE(flow.revision, 0),
          'updated_at', flow.updated_at
        )
      ) ORDER BY base.created_at, base.record_id)
      FROM public.works_records AS base
      LEFT JOIN public.works_record_workflow AS flow
        ON flow.collection = base.collection AND flow.record_id = base.record_id
      WHERE base.collection = 'opportunities' AND base.owner_entity_id = p_actor_entity_id
        AND NOT base.record @> '{"example": true}'::JSONB
    ), '[]'::JSONB),
    'submitted_proposals', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'record', base.record,
        'workflow', pg_catalog.jsonb_build_object(
          'state', COALESCE(flow.state, 'submitted'),
          'revision', COALESCE(flow.revision, 0),
          'updated_at', flow.updated_at
        )
      ) ORDER BY base.created_at DESC, base.record_id DESC)
      FROM public.works_records AS base
      LEFT JOIN public.works_record_workflow AS flow
        ON flow.collection = base.collection AND flow.record_id = base.record_id
      WHERE base.collection = 'submissions' AND base.owner_entity_id = p_actor_entity_id
        AND NOT base.record @> '{"example": true}'::JSONB
    ), '[]'::JSONB),
    'received_proposals', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'job', job.record,
        'record', proposal.record,
        'workflow', pg_catalog.jsonb_build_object(
          'state', COALESCE(flow.state, 'submitted'),
          'revision', COALESCE(flow.revision, 0),
          'updated_at', flow.updated_at
        )
      ) ORDER BY proposal.created_at DESC, proposal.record_id DESC)
      FROM public.works_records AS proposal
      JOIN public.works_records AS job
        ON job.collection = 'opportunities'
        AND job.record_id = proposal.record ->> 'opportunity_id'
        AND job.owner_entity_id = p_actor_entity_id
      LEFT JOIN public.works_record_workflow AS flow
        ON flow.collection = proposal.collection AND flow.record_id = proposal.record_id
      WHERE proposal.collection = 'submissions'
        AND NOT proposal.record @> '{"example": true}'::JSONB
    ), '[]'::JSONB),
    'assignments', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'viewer_role', CASE WHEN assignment.buyer_entity_id = p_actor_entity_id
          THEN 'buyer' ELSE 'builder' END,
        'assignment', public.works_assignment_projection(assignment)
      ) ORDER BY assignment.updated_at DESC, assignment.assignment_id)
      FROM public.works_assignments AS assignment
      WHERE p_actor_entity_id IN (assignment.buyer_entity_id, assignment.builder_entity_id)
    ), '[]'::JSONB),
    'notifications', COALESCE((
      SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'notification_id', notification_id, 'kind', kind,
        'resource_type', resource_type, 'resource_id', resource_id,
        'created_at', created_at, 'read_at', read_at, 'revision', revision
      ) ORDER BY created_at DESC, notification_id)
      FROM public.works_notifications
      WHERE owner_entity_id = p_actor_entity_id
    ), '[]'::JSONB)
  );
END
$read_works_workspace$;

CREATE FUNCTION public.read_works_assignment(p_actor_entity_id UUID, p_assignment_id TEXT)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $read_works_assignment$
DECLARE
  v_assignment public.works_assignments%ROWTYPE;
BEGIN
  SELECT * INTO v_assignment FROM public.works_assignments
  WHERE assignment_id = p_assignment_id
    AND p_actor_entity_id IN (buyer_entity_id, builder_entity_id);
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN pg_catalog.jsonb_build_object(
    'viewer_role', CASE WHEN v_assignment.buyer_entity_id = p_actor_entity_id
      THEN 'buyer' ELSE 'builder' END,
    'assignment', public.works_assignment_projection(v_assignment)
  );
END
$read_works_assignment$;

CREATE FUNCTION public.read_works_public_workflow_states(
  p_collection TEXT,
  p_record_ids TEXT[]
)
RETURNS JSONB
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $read_works_public_workflow_states$
  SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'record_id', base.record_id,
    'workflow', pg_catalog.jsonb_build_object(
      'state', COALESCE(flow.state, CASE WHEN p_collection = 'listings'
        THEN COALESCE(base.record ->> 'status', 'active') ELSE 'open' END),
      'revision', COALESCE(flow.revision, 0),
      'updated_at', flow.updated_at
    )
  ) ORDER BY base.record_id), '[]'::JSONB)
  FROM public.works_records AS base
  LEFT JOIN public.works_record_workflow AS flow
    ON flow.collection = base.collection AND flow.record_id = base.record_id
  WHERE p_collection IN ('listings', 'opportunities')
    AND base.collection = p_collection AND base.record_id = ANY(p_record_ids)
    AND NOT base.record @> '{"example": true}'::JSONB
$read_works_public_workflow_states$;

REVOKE ALL ON FUNCTION public.read_works_workspace(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.read_works_workspace(UUID) TO service_role;
REVOKE ALL ON FUNCTION public.read_works_assignment(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.read_works_assignment(UUID, TEXT) TO service_role;
REVOKE ALL ON FUNCTION public.read_works_public_workflow_states(TEXT, TEXT[])
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.read_works_public_workflow_states(TEXT, TEXT[])
  TO service_role;

CREATE FUNCTION public.mark_works_notification_read(
  p_actor_entity_id UUID,
  p_notification_id UUID,
  p_expected_revision INTEGER,
  p_idempotency_key TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $mark_works_notification_read$
DECLARE
  v_request JSONB;
  v_digest TEXT;
  v_replay JSONB;
  v_notification public.works_notifications%ROWTYPE;
  v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
  v_response JSONB;
BEGIN
  IF p_actor_entity_id IS NULL OR p_notification_id IS NULL
    OR p_expected_revision IS NULL OR p_expected_revision < 0
    OR p_idempotency_key IS NULL
    OR p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  THEN RAISE EXCEPTION 'invalid_command' USING ERRCODE = '22023'; END IF;
  v_request := pg_catalog.jsonb_build_object(
    'kind', 'notification_read', 'actor', p_actor_entity_id,
    'notification_id', p_notification_id, 'expected_revision', p_expected_revision
  );
  v_digest := public.works_workflow_request_digest(v_request);
  v_replay := public.works_workflow_replay(p_actor_entity_id, p_idempotency_key, v_digest);
  IF v_replay IS NOT NULL THEN RETURN v_replay; END IF;

  SELECT * INTO v_notification FROM public.works_notifications
  WHERE notification_id = p_notification_id AND owner_entity_id = p_actor_entity_id
  FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'not_found' USING ERRCODE = 'EW404'; END IF;
  IF v_notification.revision IS DISTINCT FROM p_expected_revision THEN
    RAISE EXCEPTION 'revision_conflict' USING ERRCODE = 'EWREV';
  END IF;
  IF v_notification.read_at IS NOT NULL THEN
    RAISE EXCEPTION 'invalid_transition' USING ERRCODE = 'EWTRN';
  END IF;
  UPDATE public.works_notifications
  SET read_at = v_now, revision = revision + 1
  WHERE notification_id = p_notification_id
  RETURNING * INTO v_notification;
  v_response := pg_catalog.jsonb_build_object(
    'ok', TRUE, 'replayed', FALSE,
    'resource', pg_catalog.jsonb_build_object(
      'notification_id', v_notification.notification_id,
      'read_at', v_notification.read_at,
      'revision', v_notification.revision
    )
  );
  INSERT INTO public.works_workflow_commands(
    actor_entity_id, idempotency_key, request_digest, response
  ) VALUES (p_actor_entity_id, p_idempotency_key, v_digest, v_response);
  RETURN v_response;
END
$mark_works_notification_read$;

REVOKE ALL ON FUNCTION public.mark_works_notification_read(UUID, UUID, INTEGER, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_works_notification_read(UUID, UUID, INTEGER, TEXT)
  TO service_role;

CREATE FUNCTION public.lease_works_notification_email(
  p_notification_id UUID,
  p_claimed_until TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $lease_works_notification_email$
DECLARE
  v_notification public.works_notifications%ROWTYPE;
BEGIN
  IF p_claimed_until <= pg_catalog.clock_timestamp()
    OR p_claimed_until > pg_catalog.clock_timestamp() + INTERVAL '10 minutes'
  THEN RAISE EXCEPTION 'invalid_lease' USING ERRCODE = '22023'; END IF;
  UPDATE public.works_notifications
  SET email_claimed_until = p_claimed_until, email_attempts = email_attempts + 1
  WHERE notification_id = p_notification_id AND email_delivered_at IS NULL
    AND (email_claimed_until IS NULL OR email_claimed_until < pg_catalog.clock_timestamp())
  RETURNING * INTO v_notification;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN pg_catalog.jsonb_build_object(
    'notification_id', v_notification.notification_id,
    'owner_entity_id', v_notification.owner_entity_id,
    'kind', v_notification.kind,
    'resource_type', v_notification.resource_type,
    'resource_id', v_notification.resource_id,
    'email_attempts', v_notification.email_attempts
  );
END
$lease_works_notification_email$;

CREATE FUNCTION public.mark_works_notification_email_delivered(
  p_notification_id UUID,
  p_delivered_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE SQL
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $mark_works_notification_email_delivered$
  UPDATE public.works_notifications
  SET email_delivered_at = p_delivered_at, email_claimed_until = NULL
  WHERE notification_id = p_notification_id AND email_delivered_at IS NULL
  RETURNING TRUE
$mark_works_notification_email_delivered$;

REVOKE ALL ON FUNCTION public.lease_works_notification_email(UUID, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.lease_works_notification_email(UUID, TIMESTAMPTZ)
  TO service_role;
REVOKE ALL ON FUNCTION public.mark_works_notification_email_delivered(UUID, TIMESTAMPTZ)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_works_notification_email_delivered(UUID, TIMESTAMPTZ)
  TO service_role;

COMMENT ON TABLE public.works_assignments IS
  'Commercial assignment agreement and delivery state; never execution authority.';
COMMENT ON TABLE public.works_assignment_events IS
  'Append-only assignment history, including buyer-sourced acceptance evidence.';
