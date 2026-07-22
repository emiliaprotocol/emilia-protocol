-- Evidence Readiness must never infer ownership from a caller-visible receipt
-- target id. Bind each eligible immutable audit row to one tenant/environment
-- stream, and let unprovable or historically ambiguous rows remain unbound.

CREATE TABLE IF NOT EXISTS public.guard_receipt_streams (
  receipt_id       TEXT PRIMARY KEY,
  tenant_id        UUID NOT NULL,
  environment      TEXT NOT NULL,
  created_event_id UUID NOT NULL UNIQUE
    REFERENCES public.audit_events(id) ON DELETE RESTRICT,
  created_at       TIMESTAMPTZ NOT NULL,
  CONSTRAINT guard_receipt_streams_receipt_id_nonempty
    CHECK (pg_catalog.octet_length(receipt_id) BETWEEN 1 AND 512),
  CONSTRAINT guard_receipt_streams_tenant_environment_fk
    FOREIGN KEY (tenant_id, environment)
    REFERENCES public.tenant_environments(tenant_id, name)
    ON DELETE RESTRICT,
  CONSTRAINT guard_receipt_streams_scope_unique
    UNIQUE (receipt_id, tenant_id, environment)
);

CREATE TABLE IF NOT EXISTS public.guard_receipt_event_bindings (
  event_id         UUID PRIMARY KEY
    REFERENCES public.audit_events(id) ON DELETE RESTRICT,
  receipt_id       TEXT NOT NULL,
  tenant_id        UUID NOT NULL,
  environment      TEXT NOT NULL,
  event_type       TEXT NOT NULL CHECK (event_type IN (
    'guard.trust_receipt.created',
    'guard.signoff.requested',
    'guard.signoff.approved',
    'guard.signoff.rejected',
    'guard.trust_receipt.consumed'
  )),
  event_created_at TIMESTAMPTZ NOT NULL,
  bound_at         TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
  CONSTRAINT guard_receipt_event_bindings_stream_fk
    FOREIGN KEY (receipt_id, tenant_id, environment)
    REFERENCES public.guard_receipt_streams(receipt_id, tenant_id, environment)
    ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS guard_receipt_streams_scope_recent_idx
  ON public.guard_receipt_streams (tenant_id, environment, created_at DESC);

CREATE INDEX IF NOT EXISTS guard_receipt_event_bindings_scope_timeline_idx
  ON public.guard_receipt_event_bindings
  (tenant_id, environment, receipt_id, event_created_at DESC);

-- New rows are bound transactionally. A Cloud-created receipt is scoped only
-- when its immutable actor resolves to the same active tenant key and declared
-- organization. Lifecycle rows inherit that scope only through exact action
-- and signoff bindings. A duplicate creation target aborts instead of merging.
CREATE OR REPLACE FUNCTION public.bind_guard_receipt_event_scope()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_tenant_id UUID;
  v_environment TEXT;
  v_created_actor TEXT;
  v_action_hash TEXT;
BEGIN
  IF NEW.target_type <> 'trust_receipt'
     OR NEW.event_type NOT IN (
       'guard.trust_receipt.created',
       'guard.signoff.requested',
       'guard.signoff.approved',
       'guard.signoff.rejected',
       'guard.trust_receipt.consumed'
     ) THEN
    RETURN NEW;
  END IF;

  IF NEW.event_type = 'guard.trust_receipt.created' THEN
    IF EXISTS (
      SELECT 1
      FROM public.audit_events AS other_created
      WHERE other_created.event_type = 'guard.trust_receipt.created'
        AND other_created.target_type = 'trust_receipt'
        AND other_created.target_id = NEW.target_id
        AND other_created.id <> NEW.id
    ) THEN
      RAISE EXCEPTION 'guard_receipt_target_collision'
        USING ERRCODE = '23505';
    END IF;

    SELECT key_row.tenant_id, key_row.environment
      INTO v_tenant_id, v_environment
    FROM public.tenant_api_keys AS key_row
    JOIN public.tenant_environments AS tenant_environment
      ON tenant_environment.tenant_id = key_row.tenant_id
     AND tenant_environment.name = key_row.environment
    WHERE NEW.actor_id = 'ep:cloud-key:' || key_row.key_id::TEXT
      AND NEW.after_state ->> 'organization_id' = key_row.tenant_id::TEXT
      AND key_row.created_at <= NEW.created_at
      AND (key_row.expires_at IS NULL OR key_row.expires_at > NEW.created_at)
      AND (key_row.revoked_at IS NULL OR key_row.revoked_at > NEW.created_at);

    IF NOT FOUND THEN
      RETURN NEW;
    END IF;

    INSERT INTO public.guard_receipt_streams (
      receipt_id, tenant_id, environment, created_event_id, created_at
    ) VALUES (
      NEW.target_id, v_tenant_id, v_environment, NEW.id, NEW.created_at
    );

    INSERT INTO public.guard_receipt_event_bindings (
      event_id, receipt_id, tenant_id, environment, event_type, event_created_at
    ) VALUES (
      NEW.id, NEW.target_id, v_tenant_id, v_environment,
      NEW.event_type, NEW.created_at
    );
    RETURN NEW;
  END IF;

  SELECT stream.tenant_id,
         stream.environment,
         created.actor_id,
         created.after_state ->> 'action_hash'
    INTO v_tenant_id, v_environment, v_created_actor, v_action_hash
  FROM public.guard_receipt_streams AS stream
  JOIN public.audit_events AS created
    ON created.id = stream.created_event_id
  WHERE stream.receipt_id = NEW.target_id;

  IF NOT FOUND OR v_action_hash IS NULL THEN
    RETURN NEW;
  END IF;

  IF NEW.event_type = 'guard.signoff.requested' THEN
    IF NEW.actor_id IS DISTINCT FROM v_created_actor
       OR NEW.after_state ->> 'action_hash' IS DISTINCT FROM v_action_hash
       OR COALESCE(NEW.after_state ->> 'signoff_id', '') = '' THEN
      RETURN NEW;
    END IF;
  ELSIF NEW.event_type IN ('guard.signoff.approved', 'guard.signoff.rejected') THEN
    IF NEW.after_state ->> 'approved_action_hash' IS DISTINCT FROM v_action_hash
       OR COALESCE(NEW.after_state ->> 'signoff_id', '') = ''
       OR NOT EXISTS (
         SELECT 1
         FROM public.guard_receipt_event_bindings AS request_binding
         JOIN public.audit_events AS request_event
           ON request_event.id = request_binding.event_id
         WHERE request_binding.receipt_id = NEW.target_id
           AND request_binding.tenant_id = v_tenant_id
           AND request_binding.environment = v_environment
           AND request_binding.event_type = 'guard.signoff.requested'
           AND request_event.after_state ->> 'signoff_id'
                 = NEW.after_state ->> 'signoff_id'
           AND request_event.after_state ->> 'action_hash' = v_action_hash
       ) THEN
      RETURN NEW;
    END IF;
  ELSIF NEW.event_type = 'guard.trust_receipt.consumed' THEN
    IF NEW.actor_id IS DISTINCT FROM v_created_actor
       OR NEW.after_state ->> 'action_hash' IS DISTINCT FROM v_action_hash THEN
      RETURN NEW;
    END IF;
  END IF;

  INSERT INTO public.guard_receipt_event_bindings (
    event_id, receipt_id, tenant_id, environment, event_type, event_created_at
  ) VALUES (
    NEW.id, NEW.target_id, v_tenant_id, v_environment,
    NEW.event_type, NEW.created_at
  );
  RETURN NEW;
END;
$$;

-- Supabase applies a migration file as one transaction. Take a lock that
-- conflicts with audit-event inserts before installing the trigger, and keep
-- it through the backfill. A writer already in flight must commit before this
-- lock is granted and is therefore visible to the backfill; later writers wait
-- until commit and then execute the installed trigger. This leaves no
-- snapshot-to-trigger gap in which a committed event can be omitted.
LOCK TABLE public.audit_events IN SHARE ROW EXCLUSIVE MODE;

DROP TRIGGER IF EXISTS bind_guard_receipt_event_scope
  ON public.audit_events;
CREATE TRIGGER bind_guard_receipt_event_scope
  AFTER INSERT ON public.audit_events
  FOR EACH ROW
  EXECUTE FUNCTION public.bind_guard_receipt_event_scope();

-- Backfill only globally unique Cloud-created streams. We intentionally do not
-- guess when a target id has more than one creation row; those histories stay
-- absent from Evidence Readiness until ownership can be established elsewhere.
WITH eligible_created AS (
  SELECT audit.id,
         audit.target_id AS receipt_id,
         key_row.tenant_id,
         key_row.environment,
         audit.created_at
  FROM public.audit_events AS audit
  JOIN public.tenant_api_keys AS key_row
    ON audit.actor_id = 'ep:cloud-key:' || key_row.key_id::TEXT
  JOIN public.tenant_environments AS tenant_environment
    ON tenant_environment.tenant_id = key_row.tenant_id
   AND tenant_environment.name = key_row.environment
  WHERE audit.event_type = 'guard.trust_receipt.created'
    AND audit.target_type = 'trust_receipt'
    AND audit.after_state ->> 'organization_id' = key_row.tenant_id::TEXT
    AND key_row.created_at <= audit.created_at
    AND (key_row.expires_at IS NULL OR key_row.expires_at > audit.created_at)
    AND (key_row.revoked_at IS NULL OR key_row.revoked_at > audit.created_at)
), unique_targets AS (
  SELECT target_id
  FROM public.audit_events
  WHERE event_type = 'guard.trust_receipt.created'
    AND target_type = 'trust_receipt'
  GROUP BY target_id
  HAVING pg_catalog.count(*) = 1
)
INSERT INTO public.guard_receipt_streams (
  receipt_id, tenant_id, environment, created_event_id, created_at
)
SELECT eligible.receipt_id,
       eligible.tenant_id,
       eligible.environment,
       eligible.id,
       eligible.created_at
FROM eligible_created AS eligible
JOIN unique_targets AS unique_target
  ON unique_target.target_id = eligible.receipt_id
ON CONFLICT DO NOTHING;

INSERT INTO public.guard_receipt_event_bindings (
  event_id, receipt_id, tenant_id, environment, event_type, event_created_at
)
SELECT created.id,
       stream.receipt_id,
       stream.tenant_id,
       stream.environment,
       created.event_type,
       created.created_at
FROM public.guard_receipt_streams AS stream
JOIN public.audit_events AS created
  ON created.id = stream.created_event_id
ON CONFLICT DO NOTHING;

INSERT INTO public.guard_receipt_event_bindings (
  event_id, receipt_id, tenant_id, environment, event_type, event_created_at
)
SELECT request.id,
       stream.receipt_id,
       stream.tenant_id,
       stream.environment,
       request.event_type,
       request.created_at
FROM public.guard_receipt_streams AS stream
JOIN public.audit_events AS created
  ON created.id = stream.created_event_id
JOIN public.audit_events AS request
  ON request.target_type = 'trust_receipt'
 AND request.target_id = stream.receipt_id
 AND request.event_type = 'guard.signoff.requested'
WHERE request.actor_id = created.actor_id
  AND request.after_state ->> 'action_hash' = created.after_state ->> 'action_hash'
  AND COALESCE(request.after_state ->> 'signoff_id', '') <> ''
ON CONFLICT DO NOTHING;

INSERT INTO public.guard_receipt_event_bindings (
  event_id, receipt_id, tenant_id, environment, event_type, event_created_at
)
SELECT decision.id,
       stream.receipt_id,
       stream.tenant_id,
       stream.environment,
       decision.event_type,
       decision.created_at
FROM public.guard_receipt_streams AS stream
JOIN public.audit_events AS created
  ON created.id = stream.created_event_id
JOIN public.audit_events AS decision
  ON decision.target_type = 'trust_receipt'
 AND decision.target_id = stream.receipt_id
 AND decision.event_type IN ('guard.signoff.approved', 'guard.signoff.rejected')
WHERE decision.after_state ->> 'approved_action_hash'
        = created.after_state ->> 'action_hash'
  AND COALESCE(decision.after_state ->> 'signoff_id', '') <> ''
  AND EXISTS (
    SELECT 1
    FROM public.guard_receipt_event_bindings AS request_binding
    JOIN public.audit_events AS request
      ON request.id = request_binding.event_id
    WHERE request_binding.receipt_id = stream.receipt_id
      AND request_binding.tenant_id = stream.tenant_id
      AND request_binding.environment = stream.environment
      AND request_binding.event_type = 'guard.signoff.requested'
      AND request.after_state ->> 'signoff_id'
            = decision.after_state ->> 'signoff_id'
      AND request.after_state ->> 'action_hash'
            = created.after_state ->> 'action_hash'
  )
ON CONFLICT DO NOTHING;

INSERT INTO public.guard_receipt_event_bindings (
  event_id, receipt_id, tenant_id, environment, event_type, event_created_at
)
SELECT consumed.id,
       stream.receipt_id,
       stream.tenant_id,
       stream.environment,
       consumed.event_type,
       consumed.created_at
FROM public.guard_receipt_streams AS stream
JOIN public.audit_events AS created
  ON created.id = stream.created_event_id
JOIN public.audit_events AS consumed
  ON consumed.target_type = 'trust_receipt'
 AND consumed.target_id = stream.receipt_id
 AND consumed.event_type = 'guard.trust_receipt.consumed'
WHERE consumed.after_state ->> 'action_hash'
        = created.after_state ->> 'action_hash'
  AND consumed.actor_id = created.actor_id
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION public.reject_guard_receipt_binding_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'GUARD_RECEIPT_BINDING_IMMUTABILITY_VIOLATION: cannot % %.%',
    TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS guard_receipt_streams_append_only
  ON public.guard_receipt_streams;
CREATE TRIGGER guard_receipt_streams_append_only
  BEFORE UPDATE OR DELETE ON public.guard_receipt_streams
  FOR EACH ROW
  EXECUTE FUNCTION public.reject_guard_receipt_binding_mutation();

DROP TRIGGER IF EXISTS guard_receipt_event_bindings_append_only
  ON public.guard_receipt_event_bindings;
CREATE TRIGGER guard_receipt_event_bindings_append_only
  BEFORE UPDATE OR DELETE ON public.guard_receipt_event_bindings
  FOR EACH ROW
  EXECUTE FUNCTION public.reject_guard_receipt_binding_mutation();

ALTER TABLE public.guard_receipt_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_streams FORCE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_event_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guard_receipt_event_bindings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS guard_receipt_streams_service_read
  ON public.guard_receipt_streams;
CREATE POLICY guard_receipt_streams_service_read
  ON public.guard_receipt_streams
  FOR SELECT TO service_role
  USING (true);

DROP POLICY IF EXISTS guard_receipt_event_bindings_service_read
  ON public.guard_receipt_event_bindings;
CREATE POLICY guard_receipt_event_bindings_service_read
  ON public.guard_receipt_event_bindings
  FOR SELECT TO service_role
  USING (true);

REVOKE ALL PRIVILEGES ON TABLE public.guard_receipt_streams
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL PRIVILEGES ON TABLE public.guard_receipt_event_bindings
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.guard_receipt_streams TO service_role;
GRANT SELECT ON TABLE public.guard_receipt_event_bindings TO service_role;

REVOKE ALL ON FUNCTION public.bind_guard_receipt_event_scope()
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.reject_guard_receipt_binding_mutation()
  FROM PUBLIC, anon, authenticated, service_role;

COMMENT ON TABLE public.guard_receipt_streams IS
  'One globally unique Guard receipt id bound to a Cloud tenant and environment.';
COMMENT ON TABLE public.guard_receipt_event_bindings IS
  'Append-only event-id authorization ledger for Evidence Readiness snapshots.';
