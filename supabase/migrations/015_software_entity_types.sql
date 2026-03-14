-- ============================================================================
-- EMILIA Protocol — Migration 015: Software Entity Types (EP-SX)
-- ============================================================================
-- Extends entity_type to include software/plugin types.
-- Also adds software-specific metadata fields.
-- ============================================================================

-- Drop existing constraint if it exists, then add expanded one
ALTER TABLE entities DROP CONSTRAINT IF EXISTS entities_entity_type_check;
ALTER TABLE entities ADD CONSTRAINT entities_entity_type_check CHECK (entity_type IN (
  -- Commerce
  'agent', 'merchant', 'service_provider',
  -- Software (EP-SX)
  'github_app', 'github_action', 'mcp_server', 'npm_package',
  'chrome_extension', 'shopify_app', 'marketplace_plugin', 'agent_tool'
));

-- Software-specific metadata
ALTER TABLE entities ADD COLUMN IF NOT EXISTS software_meta JSONB DEFAULT NULL;

COMMENT ON COLUMN entities.software_meta IS
  'EP-SX metadata for software entities. Example: '
  '{ "host": "github", "permissions": ["read:code"], "publisher_verified": true, '
  '  "provenance_verified": true, "registry_url": "https://..." }';

-- Expand receipt transaction_type for software events
ALTER TABLE receipts DROP CONSTRAINT IF EXISTS receipts_transaction_type_check;
ALTER TABLE receipts ADD CONSTRAINT receipts_transaction_type_check CHECK (transaction_type IN (
  -- Commerce
  'purchase', 'service', 'task_completion', 'delivery', 'return',
  -- Software lifecycle (EP-SX)
  'install', 'uninstall', 'permission_grant', 'permission_escalation',
  'execution', 'incident', 'listing_review', 'provenance_check'
));
