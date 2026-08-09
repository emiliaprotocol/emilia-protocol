-- SPDX-License-Identifier: Apache-2.0
-- Durable private-beta store for EMILIA Works records. Public HTTP reads are
-- mediated by the server; database clients receive no direct table access.

CREATE TABLE public.works_records (
  collection TEXT COLLATE "C" NOT NULL
    CHECK (collection IN (
      'builders', 'listings', 'cards', 'activity', 'opportunities', 'submissions'
    )),
  record_id TEXT COLLATE "C" NOT NULL
    CHECK (record_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
  owner_entity_id UUID NOT NULL
    REFERENCES public.entities(id) ON DELETE RESTRICT,
  visibility TEXT NOT NULL DEFAULT 'private'
    CHECK (visibility IN ('private', 'public')),
  record JSONB NOT NULL CHECK (
    pg_catalog.jsonb_typeof(record) = 'object'
    AND pg_catalog.pg_column_size(record) <= 131072
    AND record @> '{"example": false}'::jsonb
    AND NOT record ? 'owner_entity_id'
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (collection, record_id),
  CHECK (updated_at >= created_at),
  CHECK (
    record ->> CASE collection
      WHEN 'builders' THEN 'builder_id'
      WHEN 'listings' THEN 'listing_id'
      WHEN 'cards' THEN 'card_id'
      WHEN 'activity' THEN 'activity_id'
      WHEN 'opportunities' THEN 'opportunity_id'
      WHEN 'submissions' THEN 'submission_id'
    END = record_id
  ),
  CHECK (
    (collection = 'submissions' AND record ->> 'visibility' = visibility)
    OR
    (collection <> 'submissions' AND NOT record ? 'visibility')
  )
);

CREATE INDEX works_records_owner_idx
  ON public.works_records (owner_entity_id, collection, created_at DESC);
CREATE INDEX works_records_collection_created_idx
  ON public.works_records (collection, created_at DESC, record_id);
CREATE INDEX works_records_public_submissions_idx
  ON public.works_records (created_at DESC, record_id)
  WHERE collection = 'submissions' AND visibility = 'public';

ALTER TABLE public.works_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.works_records FORCE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.works_records
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.works_records TO service_role;

CREATE POLICY works_records_service_select
  ON public.works_records FOR SELECT TO service_role USING (TRUE);
CREATE POLICY works_records_service_insert
  ON public.works_records FOR INSERT TO service_role WITH CHECK (TRUE);
CREATE POLICY works_records_service_update
  ON public.works_records FOR UPDATE TO service_role
  USING (TRUE) WITH CHECK (TRUE);

CREATE FUNCTION public.works_records_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $works_records_guard$
DECLARE
  v_builder_id TEXT;
  v_listing_id TEXT;
  v_opportunity_id TEXT;
  v_reference_owner UUID;
  v_reference_record JSONB;
  v_display_name TEXT;
BEGIN
  IF TG_OP = 'UPDATE' AND (
    NEW.collection IS DISTINCT FROM OLD.collection
    OR NEW.record_id IS DISTINCT FROM OLD.record_id
    OR NEW.owner_entity_id IS DISTINCT FROM OLD.owner_entity_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
  ) THEN
    RAISE EXCEPTION 'works identity and ownership are immutable'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.record ? 'owner_entity_id' THEN
    RAISE EXCEPTION 'works owner metadata cannot appear in record payload'
      USING ERRCODE = '23514';
  END IF;
  IF NOT (NEW.record @> '{"example": false}'::jsonb) THEN
    RAISE EXCEPTION 'works example records are server-managed'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.record @? '$ ? (@.status == "VERIFIED")'
    OR NEW.record @? '$.** ? (@.status == "VERIFIED")'
  THEN
    RAISE EXCEPTION 'VERIFIED claims cannot be minted through Works writes'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.collection = 'submissions' THEN
    IF NEW.record ->> 'visibility' IS NOT DISTINCT FROM NEW.visibility THEN
      NULL;
    ELSE
      RAISE EXCEPTION 'submission visibility envelope mismatch'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.record ? 'visibility' THEN
    RAISE EXCEPTION 'visibility is supported only for submissions'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.collection = 'opportunities' THEN
    SELECT entity.display_name
    INTO v_display_name
    FROM public.entities AS entity
    WHERE entity.id = NEW.owner_entity_id;
    IF NOT FOUND OR NEW.record ->> 'posted_by' IS DISTINCT FROM v_display_name THEN
      RAISE EXCEPTION 'opportunity posted_by must match the authenticated entity display_name'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.collection IN ('listings', 'activity', 'cards', 'submissions') THEN
    v_builder_id := NEW.record ->> 'builder_id';
    IF v_builder_id IS NULL
      OR v_builder_id !~ '^[a-z0-9][a-z0-9-]{2,63}$'
    THEN
      RAISE EXCEPTION 'works builder reference is invalid'
        USING ERRCODE = '22023';
    END IF;
    SELECT related.owner_entity_id, related.record
    INTO v_reference_owner, v_reference_record
    FROM public.works_records AS related
    WHERE related.collection = 'builders'
      AND related.record_id = v_builder_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'works reference not found: builder'
        USING ERRCODE = '23503';
    END IF;
    IF v_reference_owner IS DISTINCT FROM NEW.owner_entity_id THEN
      RAISE EXCEPTION 'works reference owner mismatch: builder'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.collection IN ('activity', 'cards', 'submissions') THEN
    v_listing_id := NULLIF(NEW.record ->> 'listing_id', '');
    IF NEW.collection = 'activity' AND v_listing_id IS NULL THEN
      RAISE EXCEPTION 'works reference not found: listing'
        USING ERRCODE = '23503';
    END IF;
    IF v_listing_id IS NOT NULL THEN
      IF v_listing_id !~ '^[a-z0-9][a-z0-9-]{2,63}$' THEN
        RAISE EXCEPTION 'works listing reference is invalid'
          USING ERRCODE = '22023';
      END IF;
      SELECT related.owner_entity_id, related.record
      INTO v_reference_owner, v_reference_record
      FROM public.works_records AS related
      WHERE related.collection = 'listings'
        AND related.record_id = v_listing_id;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'works reference not found: listing'
          USING ERRCODE = '23503';
      END IF;
      IF v_reference_owner IS DISTINCT FROM NEW.owner_entity_id THEN
        RAISE EXCEPTION 'works reference owner mismatch: listing'
          USING ERRCODE = '42501';
      END IF;
      IF v_reference_record ->> 'builder_id' IS DISTINCT FROM v_builder_id THEN
        RAISE EXCEPTION 'works listing and builder references do not match'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  IF NEW.collection = 'submissions' THEN
    v_opportunity_id := NEW.record ->> 'opportunity_id';
    IF v_opportunity_id IS NULL
      OR v_opportunity_id !~ '^[a-z0-9][a-z0-9-]{2,63}$'
    THEN
      RAISE EXCEPTION 'works opportunity reference is invalid'
        USING ERRCODE = '22023';
    END IF;
    PERFORM 1
    FROM public.works_records AS related
    WHERE related.collection = 'opportunities'
      AND related.record_id = v_opportunity_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'works reference not found: opportunity'
        USING ERRCODE = '23503';
    END IF;
  END IF;

  RETURN NEW;
END
$works_records_guard$;

REVOKE ALL ON FUNCTION public.works_records_guard()
  FROM PUBLIC, anon, authenticated, service_role;

CREATE TRIGGER works_records_guard_before_write
  BEFORE INSERT OR UPDATE ON public.works_records
  FOR EACH ROW EXECUTE FUNCTION public.works_records_guard();

COMMENT ON TABLE public.works_records IS
  'Durable server-mediated EMILIA Works records; ownership remains row metadata and submissions default private.';
