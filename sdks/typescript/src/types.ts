// ============================================================================
// EMILIA Protocol — TypeScript Type Definitions
// ============================================================================

// ----------------------------------------------------------------------------
// Core enumerations
// ----------------------------------------------------------------------------

/** Every recognizable entity category in EP. */
export type EntityType =
  | 'agent'
  | 'merchant'
  | 'service_provider'
  | 'github_app'
  | 'github_action'
  | 'mcp_server'
  | 'npm_package'
  | 'chrome_extension'
  | 'shopify_app'
  | 'marketplace_plugin'
  | 'agent_tool';

/** Observable behavioral outcomes — the strongest Phase 1 signal. */
export type AgentBehavior =
  | 'completed'
  | 'retried_same'
  | 'retried_different'
  | 'abandoned'
  | 'disputed';

/** Categories of transactions that can generate receipts. */
export type TransactionType =
  | 'purchase'
  | 'service'
  | 'task_completion'
  | 'delivery'
  | 'return';

/** Named trust policy families. */
export type TrustPolicy =
  | 'strict'
  | 'standard'
  | 'permissive'
  | 'discovery'
  | 'github_private_repo_safe_v1'
  | 'npm_buildtime_safe_v1'
  | 'browser_extension_safe_v1'
  | 'mcp_server_safe_v1';

/** The action output of a trust gate evaluation. */
export type TrustDecision = 'allow' | 'block' | 'review' | 'deny';

/** Recognized grounds for filing a dispute. */
export type DisputeReason =
  | 'fraudulent_receipt'
  | 'inaccurate_signals'
  | 'identity_dispute'
  | 'context_mismatch'
  | 'duplicate_transaction'
  | 'coerced_receipt'
  | 'other';

/** Lifecycle states of a dispute. */
export type DisputeStatus =
  | 'pending'
  | 'responded'
  | 'under_review'
  | 'upheld'
  | 'reversed'
  | 'dismissed';

/** Trust domains for domain-specific scoring (EP domain scores). */
export type TrustDomain =
  | 'financial'
  | 'code_execution'
  | 'communication'
  | 'delegation'
  | 'infrastructure'
  | 'content_creation'
  | 'data_access';

/** Report classification for human trust reports. */
export type ReportType =
  | 'wrongly_downgraded'
  | 'harmed_by_trusted_entity'
  | 'fraudulent_entity'
  | 'inaccurate_profile'
  | 'fake_receipts'
  | 'unsafe_software'
  | 'misleading_identity'
  | 'terms_violation'
  | 'demo_challenge'
  | 'other';

/** Confidence tiers in order of increasing evidence strength. */
export type ConfidenceTier =
  | 'pending'
  | 'insufficient'
  | 'provisional'
  | 'emerging'
  | 'confident';

// ----------------------------------------------------------------------------
// Shared sub-structures
// ----------------------------------------------------------------------------

/**
 * Optional context passed to trust evaluations.
 * All fields are optional — supply only what is relevant to the action.
 */
export interface TrustContext {
  /** Broad task category, e.g. "data_analysis", "payment", "code_review" */
  task_type?: string;
  /** Merchant/product category, e.g. "furniture", "software", "grocery" */
  category?: string;
  /** ISO 3166-1 alpha-2 or sub-region, e.g. "US", "US-CA", "EU" */
  geo?: string;
  /** Interaction channel, e.g. "api", "chat", "browser" */
  modality?: string;
  /** Transaction value bucket, e.g. "low", "medium", "high", "enterprise" */
  value_band?: string;
  /** Risk class label for regulated contexts */
  risk_class?: string;
  /** Install-specific context fields */
  host?: string;
  install_scope?: string;
  permission_class?: string;
  data_sensitivity?: string;
  execution_mode?: string;
  [key: string]: string | undefined;
}

/** Structured boolean claims attached to a receipt. */
export interface ReceiptClaims {
  /** Was the item or result delivered? */
  delivered?: boolean;
  /** Was it delivered on time? */
  on_time?: boolean;
  /** Was the originally stated price honored? */
  price_honored?: boolean;
  /** Did the result match the description? */
  as_described?: boolean;
  [key: string]: boolean | undefined;
}

// ----------------------------------------------------------------------------
// Trust profile sub-components
// ----------------------------------------------------------------------------

/** Aggregate behavioral rates derived from receipt history. */
export interface BehavioralProfile {
  /** Percentage of interactions that completed successfully (0-100) */
  completion_rate?: number;
  /** Percentage that required retry with the same approach (0-100) */
  retry_rate?: number;
  /** Percentage abandoned before completion (0-100) */
  abandon_rate?: number;
  /** Percentage that resulted in a dispute (0-100) */
  dispute_rate?: number;
}

/** Quality-weighted signal averages across receipt dimensions. */
export interface SignalProfile {
  /** Weighted average delivery accuracy score (0-100) */
  delivery_accuracy?: number;
  /** Weighted average product/result accuracy score (0-100) */
  product_accuracy?: number;
  /** Weighted average price integrity score (0-100) */
  price_integrity?: number;
  /** Weighted average return/resolution processing score (0-100) */
  return_processing?: number;
  /** Cross-submitter signal consistency (0-1) */
  consistency?: number;
}

/** Breakdown of receipt provenance by verification tier. */
export interface ProvenanceProfile {
  /** Map of tier name → fractional share (e.g. { bilateral: 0.6, self_attested: 0.4 }) */
  breakdown: Record<string, number>;
  /** Proportion of receipts with bilateral confirmation (0-100) */
  bilateral_rate?: number;
}

/** The nested trust profile returned inside EntityTrustProfile. */
export interface TrustProfile {
  behavioral?: BehavioralProfile;
  signals?: SignalProfile;
  /** Overall cross-submitter consistency score (0-1) */
  consistency?: number;
  provenance?: ProvenanceProfile;
}

/** Summary of dispute activity attached to an entity's profile. */
export interface DisputeSummary {
  /** Total disputes ever filed */
  total: number;
  /** Currently open disputes */
  active: number;
  /** Disputes decided in favor of the disputer */
  reversed: number;
}

/** Anomaly detection result surfaced on a trust profile. */
export interface AnomalyAlert {
  /** Anomaly classification, e.g. "sudden_drop", "burst_receipts" */
  type: string;
  /** Magnitude of the change in score/confidence */
  delta: number;
  /** Human-readable alert message */
  alert: string;
}

// ----------------------------------------------------------------------------
// Primary API response shapes
// ----------------------------------------------------------------------------

/** Full trust profile for an entity — the canonical EP read surface. */
export interface EntityTrustProfile {
  entity_id: string;
  display_name: string;
  entity_type: EntityType;
  /** Current confidence tier based on quality-gated evidence */
  current_confidence: ConfidenceTier;
  /** Whether the entity has established historical evidence */
  historical_establishment: boolean;
  /** Quality-gated effective evidence count for current window */
  effective_evidence_current: number;
  /** Quality-gated effective evidence count for historical window */
  effective_evidence_historical: number;
  /** Raw receipt count (all time) */
  receipt_count?: number;
  /** Number of distinct entities that have submitted receipts */
  unique_submitters?: number;
  /** Nested behavioral, signal, consistency, and provenance data */
  trust_profile?: TrustProfile;
  /** Dispute summary */
  disputes?: DisputeSummary;
  /** Present only when an anomaly is detected */
  anomaly?: AnomalyAlert;
  /** Legacy 0-100 compatibility score — use trust_profile for decisions */
  compat_score: number;
}

/** Result of evaluating an entity against a named trust policy. */
export interface TrustEvaluation {
  entity_id: string;
  display_name: string;
  /** The policy that was applied */
  policy_used: string;
  /** Whether the entity passed the policy */
  pass: boolean;
  confidence: ConfidenceTier;
  /** Context key used for context-aware evaluation */
  context_used?: TrustContext;
  /** Specific failure reasons (non-empty when pass === false) */
  failures?: string[];
  /** Non-blocking warnings */
  warnings?: string[];
}

/** A single receipt record. */
export interface Receipt {
  receipt_id: string;
  entity_id: string;
  /** SHA-256 hash of the canonical receipt payload */
  receipt_hash: string;
  transaction_ref: string;
  transaction_type: TransactionType;
  agent_behavior?: AgentBehavior;
  /** ISO 8601 creation timestamp */
  created_at: string;
  /** Whether this receipt has been anchored to a Merkle root */
  anchored?: boolean;
  /** Whether the Merkle proof verified successfully */
  verified?: boolean;
}

/** Input shape for submitting a single receipt. */
export interface SubmitReceiptInput {
  /** Entity this receipt is about */
  entity_id: string;
  /** External transaction ID — required, must be unique per entity */
  transaction_ref: string;
  transaction_type: TransactionType;
  /** Observable behavioral outcome — the strongest EP signal */
  agent_behavior?: AgentBehavior;
  /** Delivery accuracy score 0-100 */
  delivery_accuracy?: number;
  /** Product/result accuracy score 0-100 */
  product_accuracy?: number;
  /** Price integrity score 0-100 */
  price_integrity?: number;
  /** Return/resolution processing score 0-100 */
  return_processing?: number;
  /** Structured boolean claims */
  claims?: ReceiptClaims;
  /** Freeform supporting evidence references */
  evidence?: Record<string, unknown>;
  /** Context for context-aware trust scoring */
  context?: TrustContext;
}

/** Response from submitting a single receipt. */
export interface SubmitReceiptResult {
  receipt: Receipt;
}

/** Entity summary returned from search results. */
export interface EntitySearchResult {
  entity_id: string;
  display_name: string;
  entity_type: EntityType;
  confidence?: ConfidenceTier;
  effective_evidence?: number;
}

/** A single dispute record. */
export interface Dispute {
  dispute_id: string;
  receipt_id: string;
  status: DisputeStatus;
  reason: DisputeReason;
  description?: string;
  /** Party that filed the dispute */
  filed_by?: { display_name: string };
  filed_by_type?: string;
  /** Entity the dispute is about */
  entity?: { entity_id: string; display_name: string };
  /** Response from the receipt submitter */
  response?: string;
  /** Resolution decision: "upheld" | "reversed" | "dismissed" */
  resolution?: string;
  /** Rationale for the resolution */
  resolution_rationale?: string;
  /** ISO 8601 deadline for the respondent to reply */
  response_deadline?: string;
}

/** A single entry in the entity leaderboard. */
export interface LeaderboardEntry {
  rank: number;
  entity_id: string;
  display_name: string;
  entity_type: EntityType;
  confidence?: ConfidenceTier;
}

/** Result of a pre-action trust gate check. */
export interface TrustGateResult {
  entity_id: string;
  /** The action that was checked */
  action: string;
  /** Gate decision */
  decision: TrustDecision;
  /** Policy applied */
  policy_used: string;
  confidence: ConfidenceTier;
  /** Whether a delegation was verified as part of this check */
  delegation_verified?: boolean;
  /** Reasons for the decision (especially useful for non-allow decisions) */
  reasons?: string[];
  /** Path to appeal a deny/block decision */
  appeal_path?: string;
}

/** A delegation record authorizing an agent to act for a principal. */
export interface DelegationRecord {
  delegation_id: string;
  /** The authorizing principal's ID */
  principal_id: string;
  /** The EP entity ID of the authorized agent */
  agent_entity_id: string;
  /** Action scopes authorized, e.g. ["purchase", "data_access"] */
  scope: string[];
  /** Maximum permitted transaction value in USD */
  max_value_usd?: number;
  /** ISO 8601 expiry timestamp */
  expires_at: string;
  status: 'active' | 'expired' | 'revoked';
  /** Additional structured constraints on the delegation */
  constraints?: Record<string, unknown>;
}

/** Domain-specific trust score for a single domain. */
export interface DomainScore {
  confidence?: ConfidenceTier;
  evidence_count?: number;
  completion_rate?: number;
  dispute_rate?: number;
}

/** Domain-specific trust scores for an entity across multiple domains. */
export interface DomainScoreResult {
  entity_id: string;
  domains: Partial<Record<TrustDomain, DomainScore>>;
}

/** Result of a software install preflight check. */
export interface InstallPreflightResult {
  entity_id: string;
  display_name: string;
  /** Install decision */
  decision: 'allow' | 'review' | 'deny';
  policy_used: string;
  confidence: ConfidenceTier;
  /** Reasons for the decision */
  reasons?: string[];
  /** Publisher and provenance metadata */
  software_meta?: {
    publisher_verified: boolean;
    provenance_verified: boolean;
    permission_class?: string;
  };
  /** Legacy compatibility score — prefer decision field */
  score: number;
}

/** A principal — the enduring actor behind one or more entities. */
export interface Principal {
  principal_id: string;
  display_name: string;
  principal_type: string;
  status: string;
  bootstrap_verified?: boolean;
}

/** Full principal lookup result including controlled entities and bindings. */
export interface PrincipalLookupResult {
  principal: Principal;
  /** EP entities controlled by this principal */
  entities?: Array<{ entity_id: string; display_name: string; entity_type: EntityType }>;
  /** Verified identity bindings (e.g. GitHub org, domain) */
  bindings?: Array<{
    binding_type: string;
    binding_target: string;
    status: string;
    provenance: string;
  }>;
  /** History of identity continuity claims made by or about this principal */
  continuity_claims?: Array<{
    old_entity_id: string;
    new_entity_id: string;
    reason: string;
    status: string;
  }>;
}

/** Entity lineage — predecessor and successor relationships. */
export interface LineageResult {
  entity_id: string;
  predecessors?: Array<{
    from: string;
    reason: string;
    status: string;
    transfer_policy?: string;
  }>;
  successors?: Array<{
    to: string;
    reason: string;
    status: string;
    transfer_policy?: string;
  }>;
}

/** Result of a batch receipt submission. */
export interface BatchReceiptResult {
  results: Array<{
    entity_id: string;
    success: boolean;
    receipt_id?: string;
    error?: string;
  }>;
}

/** Result of a bilateral receipt confirmation. */
export interface ConfirmReceiptResult {
  receipt_id: string;
  confirmed: boolean;
  recorded_at: string;
}

/** A trust policy as returned from the policy registry. */
export interface TrustPolicyDefinition {
  name: string;
  family: string;
  description: string;
  min_confidence?: ConfidenceTier;
}

/** Public proof metrics from /api/stats. */
export interface EPStats {
  total_entities: number;
  trust_surfaces: number;
  automated_checks: number;
  trust_policies: number;
  mcp_tools: number;
}

// ----------------------------------------------------------------------------
// Client configuration
// ----------------------------------------------------------------------------

/** Configuration options for EPClient. */
export interface EPClientOptions {
  /**
   * EP API base URL.
   * Defaults to https://emiliaprotocol.ai.
   * Can also be set via the EP_BASE_URL environment variable.
   */
  baseUrl?: string;
  /**
   * EP API key (ep_live_...).
   * Required for authenticated endpoints (submitReceipt, fileDispute, etc.).
   * Can also be set via the EP_API_KEY environment variable.
   */
  apiKey?: string;
  /**
   * Request timeout in milliseconds.
   * Defaults to 30000 (30 seconds).
   */
  timeout?: number;
  /**
   * Custom fetch implementation.
   * Useful for testing or environments without native fetch.
   */
  fetchImpl?: typeof fetch;
}

// ----------------------------------------------------------------------------
// Error class
// ----------------------------------------------------------------------------

/**
 * Thrown when the EP API returns a non-2xx response or a network error occurs.
 *
 * @example
 * try {
 *   await ep.trustProfile('unknown-entity');
 * } catch (err) {
 *   if (err instanceof EPError && err.status === 404) {
 *     console.log('Entity not found');
 *   }
 * }
 */
export class EPError extends Error {
  constructor(
    message: string,
    /** HTTP status code, if available */
    public readonly status?: number,
    /** API-level error code, if provided */
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'EPError';
    // Maintain proper prototype chain in environments targeting ES5
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
