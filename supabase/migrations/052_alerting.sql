-- ============================================================================
-- Alerting — Alert rules and events for the cloud control plane
--
-- Provides configurable alerting: operators define rules (threshold, anomaly,
-- absence, pattern) against system metrics, and the engine fires alert events
-- when conditions are met. Events support acknowledge/resolve lifecycle.
-- ============================================================================

-- ============================================================================
-- 1. Alert Rules
-- ============================================================================

CREATE TABLE IF NOT EXISTS alert_rules (
  rule_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name                  TEXT NOT NULL,
  description           TEXT,
  condition_type        TEXT NOT NULL
                          CHECK (condition_type IN ('threshold', 'anomaly', 'absence', 'pattern')),
  condition_config      JSONB NOT NULL,
  severity              TEXT NOT NULL DEFAULT 'warning'
                          CHECK (severity IN ('info', 'warning', 'critical')),
  notification_channels TEXT[] DEFAULT '{webhook}',
  notification_config   JSONB DEFAULT '{}',
  enabled               BOOLEAN NOT NULL DEFAULT true,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE alert_rules IS 'Configurable alert rules for the cloud control plane. Each rule defines a condition type, configuration, severity, and notification channels.';

-- ============================================================================
-- 2. Alert Events
-- ============================================================================

CREATE TABLE IF NOT EXISTS alert_events (
  alert_event_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id         UUID NOT NULL REFERENCES alert_rules(rule_id),
  severity        TEXT NOT NULL,
  title           TEXT NOT NULL,
  detail          JSONB NOT NULL,
  acknowledged_at TIMESTAMPTZ,
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE alert_events IS 'Alert events fired when rule conditions are met. Supports acknowledge and resolve lifecycle.';

-- ============================================================================
-- 3. Indexes
-- ============================================================================

-- Chronological events per rule
CREATE INDEX idx_alert_events_rule_created
  ON alert_events(rule_id, created_at);

-- Filter by severity and resolution status
CREATE INDEX idx_alert_events_severity_resolved
  ON alert_events(severity, resolved_at);

-- ============================================================================
-- Summary
-- ============================================================================
-- Tables:
--   alert_rules  — configurable alerting rules (threshold/anomaly/absence/pattern)
--   alert_events — fired alert instances with acknowledge/resolve lifecycle
--
-- Indexes:
--   idx_alert_events_rule_created      — chronological per rule
--   idx_alert_events_severity_resolved — filter by severity + resolution
