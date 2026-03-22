-- ============================================================================
-- Webhooks — Real-time event notification delivery for tenants
--
-- Tenants register webhook endpoints (URLs) with event type subscriptions.
-- The system delivers signed payloads via HMAC-SHA256, tracks delivery
-- attempts, and auto-disables endpoints after consecutive failures.
-- ============================================================================

-- ============================================================================
-- 1. Webhook Endpoints
-- ============================================================================

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  endpoint_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(tenant_id),
  url             TEXT NOT NULL,
  secret          TEXT NOT NULL,
  events          TEXT[] NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'paused', 'disabled')),
  failure_count   INTEGER NOT NULL DEFAULT 0,
  last_success_at TIMESTAMPTZ,
  last_failure_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE webhook_endpoints IS 'Registered webhook endpoints per tenant. Each endpoint subscribes to specific event types and receives signed payloads.';

-- ============================================================================
-- 2. Webhook Deliveries
-- ============================================================================

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  delivery_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id     UUID NOT NULL REFERENCES webhook_endpoints(endpoint_id),
  event_type      TEXT NOT NULL,
  payload         JSONB NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivered', 'failed', 'retrying')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  response_status INTEGER,
  response_body   TEXT,
  next_retry_at   TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at    TIMESTAMPTZ
);

COMMENT ON TABLE webhook_deliveries IS 'Individual webhook delivery attempts. Tracks status, retry schedule, and response details.';

-- ============================================================================
-- 3. Indexes
-- ============================================================================

-- Look up endpoints by tenant
CREATE INDEX idx_webhook_endpoints_tenant
  ON webhook_endpoints(tenant_id);

-- Filter endpoints by status (e.g. find all active endpoints)
CREATE INDEX idx_webhook_endpoints_status
  ON webhook_endpoints(status);

-- Look up deliveries by endpoint
CREATE INDEX idx_webhook_deliveries_endpoint
  ON webhook_deliveries(endpoint_id);

-- Find deliveries by status (e.g. pending or retrying for the retry worker)
CREATE INDEX idx_webhook_deliveries_status
  ON webhook_deliveries(status, next_retry_at);

-- ============================================================================
-- Summary
-- ============================================================================
-- Tables:
--   webhook_endpoints  — registered webhook URLs per tenant with HMAC secrets
--   webhook_deliveries — individual delivery attempts with retry tracking
--
-- Indexes:
--   idx_webhook_endpoints_tenant      — endpoints by tenant
--   idx_webhook_endpoints_status      — endpoints by status
--   idx_webhook_deliveries_endpoint   — deliveries by endpoint
--   idx_webhook_deliveries_status     — deliveries by status + next_retry_at
