-- SPDX-License-Identifier: Apache-2.0
-- Durable EP MCP provenance ledger with atomic head comparison.

BEGIN;

-- One installed schema is one provenance authority domain. This prevents a
-- compromised shared runtime role from selecting another tenant or ledger by
-- calling the SECURITY DEFINER RPC directly instead of through the adapter.
CREATE TABLE IF NOT EXISTS public.ep_mcp_provenance_binding (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  tenant_id text NOT NULL,
  ledger_id text NOT NULL,
  bound_at timestamptz NOT NULL,
  UNIQUE (tenant_id, ledger_id)
);

CREATE TABLE IF NOT EXISTS public.ep_mcp_provenance_heads (
  tenant_id text NOT NULL,
  ledger_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= -1),
  head_hash text CHECK (head_hash IS NULL OR head_hash ~ '^sha256:[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, ledger_id),
  FOREIGN KEY (tenant_id, ledger_id)
    REFERENCES public.ep_mcp_provenance_binding(tenant_id, ledger_id),
  CHECK ((sequence = -1 AND head_hash IS NULL) OR (sequence >= 0 AND head_hash IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS public.ep_mcp_provenance_entries (
  tenant_id text NOT NULL,
  ledger_id text NOT NULL,
  sequence bigint NOT NULL CHECK (sequence >= 0),
  entry_hash text NOT NULL CHECK (entry_hash ~ '^sha256:[0-9a-f]{64}$'),
  previous_hash text CHECK (previous_hash IS NULL OR previous_hash ~ '^sha256:[0-9a-f]{64}$'),
  entry_json jsonb NOT NULL CHECK (jsonb_typeof(entry_json) = 'object'),
  recorded_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, ledger_id, sequence),
  UNIQUE (tenant_id, ledger_id, entry_hash),
  FOREIGN KEY (tenant_id, ledger_id)
    REFERENCES public.ep_mcp_provenance_heads(tenant_id, ledger_id)
);

REVOKE ALL ON TABLE public.ep_mcp_provenance_binding FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_mcp_provenance_heads FROM PUBLIC;
REVOKE ALL ON TABLE public.ep_mcp_provenance_entries FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_refuse_entry_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'MCP provenance history is append-only';
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_refuse_binding_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'MCP provenance binding is permanent';
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ep_mcp_provenance_entries_append_only'
  ) THEN
    CREATE TRIGGER ep_mcp_provenance_entries_append_only
      BEFORE UPDATE OR DELETE ON public.ep_mcp_provenance_entries
      FOR EACH ROW EXECUTE FUNCTION public.ep_mcp_provenance_refuse_entry_mutation();
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'ep_mcp_provenance_binding_permanent'
  ) THEN
    CREATE TRIGGER ep_mcp_provenance_binding_permanent
      BEFORE UPDATE OR DELETE ON public.ep_mcp_provenance_binding
      FOR EACH ROW EXECUTE FUNCTION public.ep_mcp_provenance_refuse_binding_mutation();
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_bind(
  p_tenant_id text,
  p_ledger_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_existing public.ep_mcp_provenance_binding%ROWTYPE;
BEGIN
  IF octet_length(p_tenant_id) > 512
     OR octet_length(p_ledger_id) > 512
     OR p_tenant_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
     OR p_ledger_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$' THEN
    RAISE EXCEPTION 'invalid provenance binding';
  END IF;
  SELECT * INTO v_existing FROM public.ep_mcp_provenance_binding WHERE singleton;
  IF FOUND THEN
    IF v_existing.tenant_id <> p_tenant_id OR v_existing.ledger_id <> p_ledger_id THEN
      RAISE EXCEPTION 'provenance authority domain is already bound';
    END IF;
    RETURN;
  END IF;
  INSERT INTO public.ep_mcp_provenance_binding (
    singleton, tenant_id, ledger_id, bound_at
  ) VALUES (true, p_tenant_id, p_ledger_id, clock_timestamp());
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_assert_binding(
  p_tenant_id text,
  p_ledger_id text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.ep_mcp_provenance_binding
    WHERE singleton AND tenant_id = p_tenant_id AND ledger_id = p_ledger_id
  ) THEN
    RAISE EXCEPTION 'provenance authority domain mismatch';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_append(
  p_tenant_id text,
  p_ledger_id text,
  p_expected_sequence bigint,
  p_expected_previous_hash text,
  p_entry jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_head public.ep_mcp_provenance_heads%ROWTYPE;
  v_entry_hash text;
  v_previous_hash text;
BEGIN
  PERFORM public.ep_mcp_provenance_assert_binding(p_tenant_id, p_ledger_id);
  IF octet_length(p_tenant_id) > 512
     OR octet_length(p_ledger_id) > 512
     OR p_tenant_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
     OR p_ledger_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
     OR p_expected_sequence < 0
     OR jsonb_typeof(p_entry) <> 'object' THEN
    RAISE EXCEPTION 'invalid provenance append input';
  END IF;
  v_entry_hash := p_entry->>'entry_hash';
  v_previous_hash := NULLIF(p_entry->>'prev_entry_hash', '');
  IF v_entry_hash !~ '^sha256:[0-9a-f]{64}$'
     OR (p_entry->>'sequence')::bigint <> p_expected_sequence
     OR COALESCE(v_previous_hash, '') <> p_expected_previous_hash
     OR (p_entry->>'at')::timestamptz IS NULL THEN
    RAISE EXCEPTION 'invalid provenance entry';
  END IF;

  INSERT INTO public.ep_mcp_provenance_heads (
    tenant_id, ledger_id, sequence, head_hash, updated_at
  ) VALUES (p_tenant_id, p_ledger_id, -1, NULL, clock_timestamp())
  ON CONFLICT (tenant_id, ledger_id) DO NOTHING;

  SELECT * INTO STRICT v_head
    FROM public.ep_mcp_provenance_heads
    WHERE tenant_id = p_tenant_id AND ledger_id = p_ledger_id
    FOR UPDATE;
  IF v_head.sequence + 1 <> p_expected_sequence
     OR COALESCE(v_head.head_hash, '') <> p_expected_previous_hash THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'head_conflict');
  END IF;

  INSERT INTO public.ep_mcp_provenance_entries (
    tenant_id, ledger_id, sequence, entry_hash, previous_hash, entry_json, recorded_at
  ) VALUES (
    p_tenant_id,
    p_ledger_id,
    p_expected_sequence,
    v_entry_hash,
    v_previous_hash,
    p_entry,
    (p_entry->>'at')::timestamptz
  );
  UPDATE public.ep_mcp_provenance_heads
    SET sequence = p_expected_sequence,
        head_hash = v_entry_hash,
        updated_at = clock_timestamp()
    WHERE tenant_id = p_tenant_id
      AND ledger_id = p_ledger_id
      AND sequence = v_head.sequence
      AND head_hash IS NOT DISTINCT FROM v_head.head_hash;
  IF NOT FOUND THEN RAISE EXCEPTION 'provenance head CAS changed while locked'; END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;

CREATE OR REPLACE FUNCTION public.ep_mcp_provenance_load(
  p_tenant_id text,
  p_ledger_id text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_head public.ep_mcp_provenance_heads%ROWTYPE;
  v_entries jsonb;
  v_count bigint;
BEGIN
  PERFORM public.ep_mcp_provenance_assert_binding(p_tenant_id, p_ledger_id);
  IF octet_length(p_tenant_id) > 512
     OR octet_length(p_ledger_id) > 512
     OR p_tenant_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$'
     OR p_ledger_id !~ '^[A-Za-z0-9][A-Za-z0-9:_.@/-]*$' THEN
    RAISE EXCEPTION 'invalid provenance ledger reference';
  END IF;
  SELECT * INTO v_head
    FROM public.ep_mcp_provenance_heads
    WHERE tenant_id = p_tenant_id AND ledger_id = p_ledger_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'ok', true,
      'entries', '[]'::jsonb,
      'head_sequence', -1,
      'head_hash', ''
    );
  END IF;
  SELECT count(*), COALESCE(jsonb_agg(entry_json ORDER BY sequence), '[]'::jsonb)
    INTO v_count, v_entries
    FROM public.ep_mcp_provenance_entries
    WHERE tenant_id = p_tenant_id AND ledger_id = p_ledger_id;
  IF v_count <> v_head.sequence + 1
     OR (v_head.sequence >= 0 AND (
       v_entries->(v_head.sequence::integer)->>'entry_hash'
     ) IS DISTINCT FROM v_head.head_hash) THEN
    RAISE EXCEPTION 'durable provenance head does not match entry population';
  END IF;
  RETURN jsonb_build_object(
    'ok', true,
    'entries', v_entries,
    'head_sequence', v_head.sequence,
    'head_hash', COALESCE(v_head.head_hash, '')
  );
END;
$$;

REVOKE ALL ON FUNCTION public.ep_mcp_provenance_refuse_entry_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_mcp_provenance_refuse_binding_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_mcp_provenance_bind(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_mcp_provenance_assert_binding(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_mcp_provenance_append(text, text, bigint, text, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ep_mcp_provenance_load(text, text) FROM PUBLIC;

COMMIT;
