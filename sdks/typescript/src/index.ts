/** EMILIA Protocol — Full SDK. Zero dependencies, native fetch. @license Apache-2.0 */

// -- Params -----------------------------------------------------------------

export interface EPClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

export interface Party {
  entityRef: string;
  role: 'initiator' | 'responder';
}

export interface InitiateHandshakeParams {
  mode: 'mutual' | 'one-way' | 'delegated';
  policyId: string;
  parties: Party[];
  binding?: Record<string, unknown>;
  interactionId?: string;
}

export interface PresentParams {
  partyRole: string;
  presentationType: 'ep_trust_profile' | 'verifiable_credential' | 'attestation';
  claims: Record<string, unknown>;
  issuerRef?: string;
  disclosureMode?: 'full' | 'selective' | 'zk';
}

export interface GateParams {
  entityId: string;
  action: string;
  policy?: 'strict' | 'standard' | 'permissive' | string;
  handshakeId?: string;
  valueUsd?: number;
  delegationId?: string;
}

export interface ConsumeParams {
  receiptData?: Record<string, unknown>;
}

export interface IssueChallengeParams {
  entityId: string;
  scope: string;
  context?: Record<string, unknown>;
}

export interface AttestParams {
  signature: string;
  payload: Record<string, unknown>;
}

export interface ConsumeSignoffParams {
  action: string;
  context?: Record<string, unknown>;
}

export interface DenyChallengeParams {
  reason?: string;
}

export interface RevokeSignoffOptions {
  reason?: string;
  force?: boolean;
}

export interface CreateDelegationParams {
  delegatorId: string;
  delegateeId: string;
  scope: string;
  policyId: string;
  constraints?: Record<string, unknown>;
  expiresAt?: string;
}

export interface IssueCommitParams {
  handshakeId: string;
  action: string;
  payload: Record<string, unknown>;
  binding?: Record<string, unknown>;
}

// -- Eye Params -------------------------------------------------------------

export interface RecordObservationParams {
  source_type: string;
  source_ref: string;
  subject_ref: string;
  actor_ref: string;
  action_type: string;
  target_ref?: string;
  issuer_ref?: string;
  observation_type: string;
  severity_hint: string;
  evidence_hash?: string;
  expires_at: string;
  metadata?: Record<string, unknown>;
}

export interface CheckActionParams {
  subject_ref: string;
  actor_ref: string;
  action_type: string;
  target_ref?: string;
  issuer_ref?: string;
  context_hash: string;
  payload_hash?: string;
  policy_class?: string;
}

export interface CreateSuppressionParams {
  scope_binding_hash: string;
  reason_code: string;
  justification: string;
  expires_at: string;
}

// -- v1 Guard Params --------------------------------------------------------

export type GuardActionType =
  | 'benefit_bank_account_change'
  | 'benefit_address_change'
  | 'caseworker_override'
  | 'vendor_bank_account_change'
  | 'beneficiary_creation'
  | 'large_payment_release'
  | 'ai_agent_payment_action';

export type GuardDecision = 'allow' | 'observe' | 'allow_with_signoff' | 'deny';
export type GuardEnforcementMode = 'observe' | 'warn' | 'enforce';

export interface GuardQuorumPolicy {
  mode?: 'threshold' | 'all';
  required: number;
  approvers: Array<{ role: string; approver: string }>;
}

export interface CreateTrustReceiptParams {
  organizationId?: string;
  actionType: GuardActionType | string;
  targetResourceId: string;
  policyId?: string;
  enforcementMode?: GuardEnforcementMode;
  beforeState?: Record<string, unknown>;
  afterState?: Record<string, unknown>;
  targetChangedFields?: string[];
  amount?: number;
  currency?: string;
  riskFlags?: string[];
  actorRole?: string;
  actorDepartment?: string;
  businessHours?: boolean;
  velocitySameActor24h?: number;
  priorDenialsActor30d?: number;
  priorChangesTarget30d?: number;
  destinationAgeDays?: number;
  quorumPolicy?: GuardQuorumPolicy;
  metadata?: Record<string, unknown>;
}

export interface TrustReceipt {
  receipt_id: string;
  decision: GuardDecision;
  observed_decision?: GuardDecision | null;
  policy_id: string;
  policy_hash: string;
  action_hash: string;
  before_state_hash?: string | null;
  after_state_hash?: string | null;
  nonce: string;
  expires_at: string;
  signoff_required: boolean;
  signoff_request_id?: string | null;
  risk_flags?: string[];
  receipt_status: string;
  enforcement_mode: string;
  reasons?: string[];
  canonical_action: Record<string, unknown>;
}

export interface TrustReceiptState {
  receipt_id: string;
  organization_id: string;
  action_type: string;
  decision: GuardDecision;
  enforcement_mode: string;
  policy_id: string;
  policy_hash: string;
  action_hash: string;
  expires_at: string;
  signoff_required: boolean;
  receipt_status: string;
  signoff_key_class?: string | null;
  timeline_event_count: number;
}

export interface RequestSignoffParams {
  receiptId: string;
  approverId?: string;
  expiresInMinutes?: number;
  comment?: string;
}

export interface SignoffRequest {
  signoff_id?: string;
  receipt_id: string;
  action_hash: string;
  initiator_id: string;
  approver_id?: string;
  expires_at: string;
  status: string;
  quorum?: { mode: string; required: number; count: number };
  signoffs?: Array<{ signoff_id: string; role?: string; approver_id: string }>;
}

export interface ConsumeTrustReceiptResult {
  receipt_id: string;
  status: string;
  consumed_at: string;
  consumed_by_system: string;
  execution_reference_id?: string | null;
}

export interface ExecutionAttestation {
  receipt_id: string;
  status: string;
  binding_status: string;
  executed_action_hash: string;
  approved_action_hash: string;
  execution_integrity: Record<string, unknown>;
}

export interface TrustReceiptEvidence {
  document: Record<string, unknown> | null;
  public_key: string | null;
  signed: boolean;
  verify_with: string;
  receipt_id: string;
  organization_id: string;
  issued_at: string;
  expires_at: string;
  schema_version: string;
  [key: string]: unknown;
}

export interface RequireReceiptParams extends CreateTrustReceiptParams {
  executingSystem: string;
  executionReferenceId?: string;
  approverId?: string;
  signoffComment?: string;
  signoffExpiresInMinutes?: number;
  onSignoffRequired?: (ctx: { client: EPClient; receipt: TrustReceipt; signoff?: SignoffRequest }) => Promise<void | boolean | { approved?: boolean }>;
  executedAction?: Record<string, unknown> | ((ctx: { receipt: TrustReceipt; result: unknown }) => Record<string, unknown>);
  executionId?: string | ((result: unknown) => string | undefined);
  fetchEvidence?: boolean;
}

export interface RequireReceiptResult<T> {
  result: T;
  receipt: TrustReceipt;
  signoff?: SignoffRequest;
  consume: ConsumeTrustReceiptResult;
  execution: ExecutionAttestation;
  evidence?: TrustReceiptEvidence;
}

// -- Eye Responses ----------------------------------------------------------

export interface ObservationResponse {
  observation_id: string;
  observation_type: string;
  severity_hint: string;
  observed_at: string;
  expires_at: string;
}

export interface AdvisoryResponse {
  advisory_id: string;
  status: string;
  reason_codes: string[];
  recommended_policy_action: string;
  evidence_refs: string[];
  scope_binding_hash: string;
  issued_at: string;
  expires_at: string;
  version: number;
}

export interface SuppressionResponse {
  suppression_id: string;
  status: string;
  created_at: string;
  expires_at: string;
}

// -- Cloud Params -----------------------------------------------------------

export interface SignoffFilters {
  entityId?: string;
  scope?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export interface DateRange {
  from?: string;
  to?: string;
}

export interface EscalateSignoffParams {
  challengeId: string;
  escalateTo: string;
  reason: string;
}

export interface NotifySignoffParams {
  challengeId: string;
  channel: string;
}

export interface SearchEventsParams {
  query: string;
  filters?: Record<string, unknown>;
}

export interface ExportAuditParams {
  format?: 'json' | 'csv' | 'pdf';
  dateRange?: DateRange;
  entityId?: string;
  eventTypes?: string[];
}

export interface GetAuditReportParams {
  reportType: string;
  dateRange: DateRange;
}

export interface SimulatePolicyParams {
  policyId: string;
  context: Record<string, unknown>;
}

export interface RolloutPolicyParams {
  policyId: string;
  /** Policy version number to roll out (resolved against handshake_policies). */
  version: number;
  /** Target environment, e.g. "production" or "staging". */
  environment: string;
  strategy?: 'immediate' | 'canary';
  /** Traffic percentage (1–99) for canary rollouts. */
  canaryPct?: number;
}

export interface DiffPolicyVersionsParams {
  policyId: string;
  /** First version number to compare. */
  v1: number;
  /** Second version number to compare. */
  v2: number;
}

// -- Responses --------------------------------------------------------------

export interface Policy {
  name: string;
  family: string;
  description: string;
  minConfidence?: string;
  minScore?: number;
}

export interface Handshake {
  id: string;
  status: string;
  mode: string;
  policyId: string;
  parties: Party[];
  createdAt: string;
}

export interface Presentation {
  presentationId: string;
  partyRole: string;
  status: string;
  createdAt: string;
}

export interface VerificationResult {
  handshakeId: string;
  result: 'accepted' | 'rejected' | 'partial';
  reasonCodes: string[];
  evaluatedAt: string;
}

export interface GateResult {
  decision: 'allow' | 'deny' | 'review';
  commitRef?: string;
  reasons: string[];
  appealPath?: string;
}

export interface SignoffChallenge {
  challengeId: string;
  entityId: string;
  scope: string;
  nonce: string;
  expiresAt: string;
}

export interface SignoffAttestation {
  attestationId: string;
  challengeId: string;
  status: 'valid' | 'invalid' | 'expired';
  signoffId?: string;
  createdAt: string;
}

export interface SignoffConsumption {
  signoffId: string;
  consumed: boolean;
  action: string;
  consumedAt?: string;
}

export interface Consumption {
  handshakeId: string;
  consumed: boolean;
  receiptId?: string;
  consumedAt?: string;
}

export interface RevokeResult {
  id: string;
  revoked: boolean;
  revokedAt: string;
}

export interface DenyResult {
  challengeId: string;
  denied: boolean;
  reason?: string;
  deniedAt: string;
}

export interface Delegation {
  delegationId: string;
  delegatorId: string;
  delegateeId: string;
  scope: string;
  policyId: string;
  status: string;
  constraints?: Record<string, unknown>;
  createdAt: string;
  expiresAt?: string;
}

export interface DelegationVerification {
  delegationId: string;
  valid: boolean;
  status: string;
  reasonCodes: string[];
  verifiedAt: string;
}

export interface Commit {
  commitId: string;
  handshakeId: string;
  action: string;
  status: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface CommitVerification {
  commitId: string;
  valid: boolean;
  status: string;
  reasonCodes: string[];
  verifiedAt: string;
}

// -- Cloud Responses --------------------------------------------------------

export interface PendingSignoff {
  challengeId: string;
  entityId: string;
  scope: string;
  status: string;
  createdAt: string;
  expiresAt: string;
}

export interface PendingSignoffsResponse {
  items: PendingSignoff[];
  total: number;
  offset: number;
  limit: number;
}

export interface SignoffQueueItem {
  challengeId: string;
  entityId: string;
  scope: string;
  priority: string;
  status: string;
  createdAt: string;
  expiresAt: string;
}

export interface SignoffQueueResponse {
  items: SignoffQueueItem[];
  total: number;
  offset: number;
  limit: number;
}

export interface SignoffDashboard {
  pending: number;
  approved: number;
  denied: number;
  expired: number;
  averageResponseTime: number;
  recentActivity: DashboardActivity[];
}

export interface DashboardActivity {
  challengeId: string;
  action: string;
  entityId: string;
  timestamp: string;
}

export interface SignoffAnalytics {
  totalChallenges: number;
  approvalRate: number;
  averageResponseTime: number;
  byScope: Record<string, number>;
  timeseries: AnalyticsDataPoint[];
}

export interface AnalyticsDataPoint {
  timestamp: string;
  count: number;
  approved: number;
  denied: number;
}

export interface EscalationResult {
  challengeId: string;
  escalatedTo: string;
  escalatedAt: string;
  status: string;
}

export interface NotificationResult {
  challengeId: string;
  channel: string;
  sent: boolean;
  sentAt: string;
}

export interface AuditEvent {
  eventId: string;
  type: string;
  entityId: string;
  action: string;
  metadata: Record<string, unknown>;
  timestamp: string;
}

export interface SearchEventsResponse {
  items: AuditEvent[];
  total: number;
}

export interface EventTimeline {
  handshakeId: string;
  events: AuditEvent[];
}

export interface ExportAuditResult {
  exportId: string;
  format: string;
  status: string;
  downloadUrl?: string;
  createdAt: string;
}

export interface AuditReport {
  reportType: string;
  dateRange: DateRange;
  summary: Record<string, unknown>;
  items: AuditEvent[];
  generatedAt: string;
}

export interface IntegrityCheckResult {
  healthy: boolean;
  checks: IntegrityCheck[];
  checkedAt: string;
}

export interface IntegrityCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  message?: string;
}

export interface PolicySimulationResult {
  policyId: string;
  decision: 'allow' | 'deny' | 'review';
  reasons: string[];
  evaluatedAt: string;
}

export interface PolicyRolloutResult {
  rollout_id: string;
  /** handshake_policies policy_id of the rolled-out version row. */
  policy_id: string;
  policy_key: string;
  version: number;
  environment: string;
  strategy: string;
  status: string;
  canary_pct: number | null;
  initiated_at: string;
  tenant_id: string;
}

/**
 * A policy version is a handshake_policies row. Versions sharing a policy_key
 * form the version history of a single policy.
 */
export interface PolicyVersion {
  policy_id: string;
  policy_key: string;
  version: number;
  name: string;
  mode: string;
  status: string;
  rules: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface PolicyVersionsResult {
  policy_id: string;
  policy_key: string;
  versions: PolicyVersion[];
  count: number;
  tenant_id: string;
}

/** A single classified field change between two policy versions' rules. */
export interface PolicyChange {
  path: string;
  before: unknown;
  after: unknown;
  risk: 'loosening' | 'tightening' | 'neutral';
  rationale: string;
}

/** Semantic diff of v1.rules vs v2.rules. */
export interface PolicyRulesDiff {
  changes: PolicyChange[];
  risk: 'loosening' | 'tightening' | 'neutral';
  summary: {
    loosening: number;
    tightening: number;
    neutral: number;
  };
}

export interface PolicyDiff {
  policy_id: string;
  policy_key: string;
  /** The lower-numbered handshake_policies version row. */
  v1: PolicyVersion;
  /** The higher-numbered handshake_policies version row. */
  v2: PolicyVersion;
  diff: PolicyRulesDiff;
  tenant_id: string;
}

// -- Error ------------------------------------------------------------------

export class EPError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'EPError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// -- Cloud Client -----------------------------------------------------------

export class EPCloudClient {
  /** @internal */
  constructor(private readonly _request: <T>(method: string, path: string, body?: unknown, auth?: boolean) => Promise<T>) {}

  /** Get pending signoffs, optionally filtered by entity, scope, or status. */
  async getPendingSignoffs(filters?: SignoffFilters): Promise<PendingSignoffsResponse> {
    const qs = this._buildQs(filters);
    return this._request<PendingSignoffsResponse>('GET', `/api/cloud/signoffs/pending${qs}`, undefined, true);
  }

  /** Get the signoff queue with optional filtering. */
  async getSignoffQueue(filters?: SignoffFilters): Promise<SignoffQueueResponse> {
    const qs = this._buildQs(filters);
    return this._request<SignoffQueueResponse>('GET', `/api/cloud/signoffs/queue${qs}`, undefined, true);
  }

  /** Get a dashboard summary of signoff activity over a date range. */
  async getSignoffDashboard(dateRange?: DateRange): Promise<SignoffDashboard> {
    const qs = this._buildDateRangeQs(dateRange);
    return this._request<SignoffDashboard>('GET', `/api/cloud/signoffs/dashboard${qs}`, undefined, true);
  }

  /** Get analytics for signoff activity with optional granularity. */
  async getSignoffAnalytics(dateRange?: DateRange, granularity?: 'hour' | 'day' | 'week' | 'month'): Promise<SignoffAnalytics> {
    const params: Record<string, string> = {};
    if (dateRange?.from) params['from'] = dateRange.from;
    if (dateRange?.to) params['to'] = dateRange.to;
    if (granularity) params['granularity'] = granularity;
    const qs = this._toQs(params);
    return this._request<SignoffAnalytics>('GET', `/api/cloud/signoffs/analytics${qs}`, undefined, true);
  }

  /** Escalate a signoff challenge to another entity. */
  async escalateSignoff(challengeId: string, escalateTo: string, reason: string): Promise<EscalationResult> {
    return this._request<EscalationResult>('POST', `/api/cloud/signoffs/${encodeURIComponent(challengeId)}/escalate`, {
      escalateTo,
      reason,
    }, true);
  }

  /** Send a notification about a signoff challenge via the specified channel. */
  async notifySignoff(challengeId: string, channel: string): Promise<NotificationResult> {
    return this._request<NotificationResult>('POST', `/api/cloud/signoffs/${encodeURIComponent(challengeId)}/notify`, {
      channel,
    }, true);
  }

  /** Search audit events by query string and optional filters. */
  async searchEvents(query: string, filters?: Record<string, unknown>): Promise<SearchEventsResponse> {
    return this._request<SearchEventsResponse>('POST', '/api/cloud/events/search', {
      query,
      filters,
    }, true);
  }

  /** Get a chronological timeline of events for a specific handshake. */
  async getEventTimeline(handshakeId: string): Promise<EventTimeline> {
    return this._request<EventTimeline>('GET', `/api/cloud/events/timeline/${encodeURIComponent(handshakeId)}`, undefined, true);
  }

  /** Export audit data in the specified format. */
  async exportAudit(params: ExportAuditParams): Promise<ExportAuditResult> {
    return this._request<ExportAuditResult>('POST', '/api/cloud/audit/export', params, true);
  }

  /** Generate an audit report for the given type and date range. */
  async getAuditReport(reportType: string, dateRange: DateRange): Promise<AuditReport> {
    return this._request<AuditReport>('POST', '/api/cloud/audit/report', {
      reportType,
      dateRange,
    }, true);
  }

  /** Run an integrity check on the protocol data store. */
  async checkIntegrity(): Promise<IntegrityCheckResult> {
    return this._request<IntegrityCheckResult>('POST', '/api/cloud/integrity/check', undefined, true);
  }

  /** Simulate a policy against a hypothetical context without persisting any state. */
  async simulatePolicy(policyId: string, context: Record<string, unknown>): Promise<PolicySimulationResult> {
    return this._request<PolicySimulationResult>('POST', `/api/cloud/policies/${encodeURIComponent(policyId)}/simulate`, {
      context,
    }, true);
  }

  /**
   * Roll out a specific policy version to an environment. The version is
   * resolved against handshake_policies by the policy's policy_key. Immediate
   * rollouts supersede the prior active rollout for that (policy_key,
   * environment); canary rollouts coexist (canaryPct in 1–99).
   */
  async rolloutPolicy(
    policyId: string,
    version: number,
    environment: string,
    strategy: 'immediate' | 'canary' = 'immediate',
    canaryPct?: number,
  ): Promise<PolicyRolloutResult> {
    return this._request<PolicyRolloutResult>('POST', `/api/cloud/policies/${encodeURIComponent(policyId)}/rollout`, {
      version,
      environment,
      strategy,
      ...(strategy === 'canary' && canaryPct !== undefined ? { canary_pct: canaryPct } : {}),
    }, true);
  }

  /**
   * List all versions of a policy. Versions are the handshake_policies rows
   * sharing the policy's policy_key, returned newest-first inside an envelope.
   */
  async getPolicyVersions(policyId: string): Promise<PolicyVersionsResult> {
    return this._request<PolicyVersionsResult>('GET', `/api/cloud/policies/${encodeURIComponent(policyId)}/versions`, undefined, true);
  }

  /**
   * Diff two versions of a policy to see what changed between their rules.
   * v1 and v2 are version numbers; the response includes both version rows and
   * a semantic diff classified as loosening / tightening / neutral.
   */
  async diffPolicyVersions(policyId: string, v1: number, v2: number): Promise<PolicyDiff> {
    const qs = this._toQs({ v1: String(v1), v2: String(v2) });
    return this._request<PolicyDiff>('GET', `/api/cloud/policies/${encodeURIComponent(policyId)}/diff${qs}`, undefined, true);
  }

  /** @internal Build query string from SignoffFilters. */
  private _buildQs(filters?: SignoffFilters): string {
    if (!filters) return '';
    const params: Record<string, string> = {};
    if (filters.entityId) params['entityId'] = filters.entityId;
    if (filters.scope) params['scope'] = filters.scope;
    if (filters.status) params['status'] = filters.status;
    if (filters.limit !== undefined) params['limit'] = String(filters.limit);
    if (filters.offset !== undefined) params['offset'] = String(filters.offset);
    return this._toQs(params);
  }

  /** @internal Build query string from DateRange. */
  private _buildDateRangeQs(dateRange?: DateRange): string {
    if (!dateRange) return '';
    const params: Record<string, string> = {};
    if (dateRange.from) params['from'] = dateRange.from;
    if (dateRange.to) params['to'] = dateRange.to;
    return this._toQs(params);
  }

  /** @internal Convert key-value pairs to a query string. */
  private _toQs(params: Record<string, string>): string {
    const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== '');
    if (entries.length === 0) return '';
    return '?' + entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  }
}

// -- Client -----------------------------------------------------------------

function trustReceiptBody(params: CreateTrustReceiptParams): Record<string, unknown> {
  return {
    organization_id: params.organizationId,
    action_type: params.actionType,
    target_resource_id: params.targetResourceId,
    policy_id: params.policyId,
    enforcement_mode: params.enforcementMode,
    before_state: params.beforeState,
    after_state: params.afterState,
    target_changed_fields: params.targetChangedFields,
    amount: params.amount,
    currency: params.currency,
    risk_flags: params.riskFlags,
    actor_role: params.actorRole,
    actor_department: params.actorDepartment,
    business_hours: params.businessHours,
    velocity_same_actor_24h: params.velocitySameActor24h,
    prior_denials_actor_30d: params.priorDenialsActor30d,
    prior_changes_target_30d: params.priorChangesTarget30d,
    destination_age_days: params.destinationAgeDays,
    quorum_policy: params.quorumPolicy,
    metadata: params.metadata,
  };
}

export class EPClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retries: number;

  /** Cloud-specific endpoints (dashboards, analytics, audit, policy management). */
  public readonly cloud: EPCloudClient;

  constructor(options: EPClientOptions = {}) {
    const env = typeof process !== 'undefined' && process.env ? process.env : {};
    this.baseUrl = (options.baseUrl ?? env.EP_BASE_URL ?? 'https://emiliaprotocol.ai').replace(/\/+$/, '');
    this.apiKey = options.apiKey ?? env.EP_API_KEY ?? '';
    this.timeout = options.timeout ?? 10_000;
    this.retries = options.retries ?? 2;

    // Bind the internal request method for the cloud sub-client
    this.cloud = new EPCloudClient(this.request.bind(this));
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = false,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': '@emilia-protocol/sdk/0.9.0',
    };
    if (auth && this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeout);
      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: ctrl.signal,
        });
        const data: unknown = await res.json().catch(() => undefined);
        if (!res.ok) {
          const p = data as Record<string, unknown> | undefined;
          const msg = typeof p?.['error'] === 'string'
            ? p['error']
            : typeof p?.['detail'] === 'string'
              ? p['detail']
              : typeof p?.['title'] === 'string'
                ? p['title']
                : `EP API error: ${res.status}`;
          const code = typeof p?.['code'] === 'string'
            ? p['code']
            : typeof p?.['type'] === 'string'
              ? p['type'].split('/').pop()
              : undefined;
          throw new EPError(msg, res.status, code);
        }
        return data as T;
      } catch (err) {
        lastErr = err;
        if (err instanceof EPError) {
          // Only retry on 5xx
          if (err.status && err.status < 500) throw err;
        }
        if (err instanceof Error && err.name === 'AbortError') {
          lastErr = new EPError(`Request timed out after ${this.timeout}ms`, undefined, 'timeout');
        }
        if (attempt === this.retries) break;
      } finally {
        clearTimeout(timer);
      }
    }
    if (lastErr instanceof EPError) throw lastErr;
    throw new EPError(
      lastErr instanceof Error ? lastErr.message : 'Unknown network error',
      undefined,
      'network_error',
    );
  }

  // ------------------------------------------------------------------
  // Core protocol endpoints
  // ------------------------------------------------------------------

  /** List available trust policies. */
  async listPolicies(params?: { scope?: string }): Promise<Policy[]> {
    const qs = params?.scope ? `?scope=${encodeURIComponent(params.scope)}` : '';
    return this.request<Policy[]>('GET', `/api/policies${qs}`);
  }

  /** Initiate a trust handshake between parties. */
  async initiateHandshake(params: InitiateHandshakeParams): Promise<Handshake> {
    return this.request<Handshake>('POST', '/api/handshake/initiate', params, true);
  }

  /** Present credentials to a handshake. */
  async present(handshakeId: string, params: PresentParams): Promise<Presentation> {
    return this.request<Presentation>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/present`,
      params,
      true,
    );
  }

  /** Verify a handshake -- evaluate all presentations against policy. */
  async verify(handshakeId: string): Promise<VerificationResult> {
    return this.request<VerificationResult>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/verify`,
      undefined,
      true,
    );
  }

  /** Pre-action trust gate. Returns allow/deny/review with commit ref. */
  async gate(params: GateParams): Promise<GateResult> {
    return this.request<GateResult>('POST', '/api/gate', {
      entity_id: params.entityId,
      action: params.action,
      policy: params.policy ?? 'standard',
      handshake_id: params.handshakeId,
      value_usd: params.valueUsd,
      delegation_id: params.delegationId,
    }, true);
  }

  /** Retrieve details of a specific handshake by ID. */
  async getHandshake(handshakeId: string): Promise<Handshake> {
    return this.request<Handshake>(
      'GET',
      `/api/handshake/${encodeURIComponent(handshakeId)}`,
      undefined,
      true,
    );
  }

  /** Revoke an active handshake, invalidating all associated state. */
  async revokeHandshake(handshakeId: string): Promise<RevokeResult> {
    return this.request<RevokeResult>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/revoke`,
      undefined,
      true,
    );
  }

  /** Consume a handshake -- finalize and optionally bind a receipt. */
  async consume(handshakeId: string, params?: ConsumeParams): Promise<Consumption> {
    return this.request<Consumption>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/consume`,
      params,
      true,
    );
  }

  // ------------------------------------------------------------------
  // v1 Trust Receipt Enforcement
  // ------------------------------------------------------------------

  /** Create a v1 pre-action trust receipt for a high-risk mutation. */
  async createTrustReceipt(params: CreateTrustReceiptParams): Promise<TrustReceipt> {
    return this.request<TrustReceipt>('POST', '/api/v1/trust-receipts', trustReceiptBody(params), true);
  }

  /** Read current receipt state from the append-only v1 audit timeline. */
  async getTrustReceipt(receiptId: string): Promise<TrustReceiptState> {
    return this.request<TrustReceiptState>(
      'GET',
      `/api/v1/trust-receipts/${encodeURIComponent(receiptId)}`,
      undefined,
      true,
    );
  }

  /** Request human signoff for a receipt that requires approval. */
  async requestSignoff(params: RequestSignoffParams): Promise<SignoffRequest> {
    return this.request<SignoffRequest>('POST', '/api/v1/signoffs/request', {
      receipt_id: params.receiptId,
      approver_id: params.approverId,
      expires_in_minutes: params.expiresInMinutes,
      comment: params.comment,
    }, true);
  }

  /** Consume a receipt before mutation. If this fails, do not execute the write. */
  async consumeTrustReceipt(
    receiptId: string,
    params: { actionHash: string; executingSystem: string; executionReferenceId?: string },
  ): Promise<ConsumeTrustReceiptResult> {
    return this.request<ConsumeTrustReceiptResult>(
      'POST',
      `/api/v1/trust-receipts/${encodeURIComponent(receiptId)}/consume`,
      {
        action_hash: params.actionHash,
        executing_system: params.executingSystem,
        execution_reference_id: params.executionReferenceId,
      },
      true,
    );
  }

  /** Emit the post-mutation execution attestation bound to the consumed receipt. */
  async attestExecution(
    receiptId: string,
    params: {
      executedAction: Record<string, unknown>;
      executingSystem: string;
      executionId?: string;
      executedAt?: string;
    },
  ): Promise<ExecutionAttestation> {
    return this.request<ExecutionAttestation>(
      'POST',
      `/api/v1/trust-receipts/${encodeURIComponent(receiptId)}/execution`,
      {
        executed_action: params.executedAction,
        executing_system: params.executingSystem,
        execution_id: params.executionId,
        executed_at: params.executedAt,
      },
      true,
    );
  }

  /** Fetch the signed evidence packet, when the receipt is in a signable state. */
  async getTrustReceiptEvidence(receiptId: string): Promise<TrustReceiptEvidence> {
    return this.request<TrustReceiptEvidence>(
      'GET',
      `/api/v1/trust-receipts/${encodeURIComponent(receiptId)}/evidence`,
      undefined,
      true,
    );
  }

  /**
   * Wrap a dangerous mutation in the v1 receipt lifecycle.
   * The mutation runs only after create + consume succeed.
   */
  async requireReceipt<T>(
    params: RequireReceiptParams,
    mutate: (ctx: { receipt: TrustReceipt; consume: ConsumeTrustReceiptResult }) => Promise<T>,
  ): Promise<RequireReceiptResult<T>> {
    const receipt = await this.createTrustReceipt(params);
    if (receipt.decision === 'deny' || receipt.receipt_status === 'denied') {
      throw new EPError('EMILIA denied the action before execution', 403, 'receipt_denied');
    }

    let signoff: SignoffRequest | undefined;
    if (receipt.signoff_required) {
      if (!params.approverId && !params.quorumPolicy) {
        throw new EPError('Receipt requires signoff; pass approverId or quorumPolicy', 409, 'missing_approver_id');
      }
      signoff = await this.requestSignoff({
        receiptId: receipt.receipt_id,
        approverId: params.approverId,
        expiresInMinutes: params.signoffExpiresInMinutes,
        comment: params.signoffComment,
      });
      if (!params.onSignoffRequired) {
        throw new EPError('Receipt requires human signoff before the mutation can run', 409, 'signoff_required');
      }
      const signoffResult = await params.onSignoffRequired({ client: this, receipt, signoff });
      if (signoffResult === false || (typeof signoffResult === 'object' && signoffResult?.approved === false)) {
        throw new EPError('Human signoff was not approved', 403, 'signoff_rejected');
      }
    }

    const consume = await this.consumeTrustReceipt(receipt.receipt_id, {
      actionHash: receipt.action_hash,
      executingSystem: params.executingSystem,
      executionReferenceId: params.executionReferenceId,
    });
    const result = await mutate({ receipt, consume });
    const executedAction = typeof params.executedAction === 'function'
      ? params.executedAction({ receipt, result })
      : params.executedAction ?? receipt.canonical_action;
    const executionId = typeof params.executionId === 'function'
      ? params.executionId(result)
      : params.executionId;
    const execution = await this.attestExecution(receipt.receipt_id, {
      executedAction,
      executingSystem: params.executingSystem,
      executionId,
    });
    const evidence = params.fetchEvidence
      ? await this.getTrustReceiptEvidence(receipt.receipt_id)
      : undefined;

    return { result, receipt, signoff, consume, execution, evidence };
  }

  /** Wrap an existing async function with requireReceipt(). */
  withReceipt<TArgs extends unknown[], TResult>(
    params: RequireReceiptParams | ((...args: TArgs) => RequireReceiptParams),
    mutate: (...args: TArgs) => Promise<TResult>,
  ): (...args: TArgs) => Promise<RequireReceiptResult<TResult>> {
    return async (...args: TArgs) => {
      const resolved = typeof params === 'function' ? params(...args) : params;
      return this.requireReceipt(resolved, () => mutate(...args));
    };
  }

  // ------------------------------------------------------------------
  // Signoff extension
  // ------------------------------------------------------------------

  /** Issue a signoff challenge for an entity. */
  async issueChallenge(params: IssueChallengeParams): Promise<SignoffChallenge> {
    return this.request<SignoffChallenge>('POST', '/api/signoff/challenge', {
      entity_id: params.entityId,
      scope: params.scope,
      context: params.context,
    }, true);
  }

  /** Attest to a signoff challenge with a cryptographic signature. */
  async attest(challengeId: string, params: AttestParams): Promise<SignoffAttestation> {
    return this.request<SignoffAttestation>(
      'POST',
      `/api/signoff/${encodeURIComponent(challengeId)}/attest`,
      params,
      true,
    );
  }

  /** Deny a signoff challenge with an optional reason. */
  async denyChallenge(challengeId: string, reason?: string): Promise<DenyResult> {
    return this.request<DenyResult>(
      'POST',
      `/api/signoff/${encodeURIComponent(challengeId)}/deny`,
      reason !== undefined ? { reason } : undefined,
      true,
    );
  }

  /** Revoke a previously granted signoff. */
  async revokeSignoff(challengeId: string, options?: RevokeSignoffOptions): Promise<RevokeResult> {
    return this.request<RevokeResult>(
      'POST',
      `/api/signoff/${encodeURIComponent(challengeId)}/revoke`,
      options,
      true,
    );
  }

  /** Consume a signoff -- mark it as used for a specific action. */
  async consumeSignoff(signoffId: string, params: ConsumeSignoffParams): Promise<SignoffConsumption> {
    return this.request<SignoffConsumption>(
      'POST',
      `/api/signoff/${encodeURIComponent(signoffId)}/consume`,
      params,
      true,
    );
  }

  // ------------------------------------------------------------------
  // Delegation
  // ------------------------------------------------------------------

  /** Create a trust delegation from one entity to another. */
  async createDelegation(params: CreateDelegationParams): Promise<Delegation> {
    return this.request<Delegation>('POST', '/api/delegation', {
      delegatorId: params.delegatorId,
      delegateeId: params.delegateeId,
      scope: params.scope,
      policyId: params.policyId,
      constraints: params.constraints,
      expiresAt: params.expiresAt,
    }, true);
  }

  /** Verify the validity of an existing delegation. */
  async verifyDelegation(delegationId: string): Promise<DelegationVerification> {
    return this.request<DelegationVerification>(
      'POST',
      `/api/delegation/${encodeURIComponent(delegationId)}/verify`,
      undefined,
      true,
    );
  }

  // ------------------------------------------------------------------
  // Commit
  // ------------------------------------------------------------------

  /** Issue a trust commit binding a handshake to a specific action. */
  async issueCommit(params: IssueCommitParams): Promise<Commit> {
    return this.request<Commit>('POST', '/api/commit', {
      handshakeId: params.handshakeId,
      action: params.action,
      payload: params.payload,
      binding: params.binding,
    }, true);
  }

  /** Verify a previously issued commit. */
  async verifyCommit(commitId: string): Promise<CommitVerification> {
    return this.request<CommitVerification>(
      'POST',
      `/api/commit/${encodeURIComponent(commitId)}/verify`,
      undefined,
      true,
    );
  }

  // ------------------------------------------------------------------
  // Eye — Observation & Advisory
  // ------------------------------------------------------------------

  /** Record a behavioral or contextual observation for the Eye subsystem. */
  async recordObservation(params: RecordObservationParams): Promise<ObservationResponse> {
    return this.request<ObservationResponse>('POST', '/api/eye/observations', params, true);
  }

  /** Check an action against recorded observations and return an advisory. */
  async checkAction(params: CheckActionParams): Promise<AdvisoryResponse> {
    return this.request<AdvisoryResponse>('POST', '/api/eye/check', params, true);
  }

  /** Retrieve an existing advisory by ID. */
  async getAdvisory(advisoryId: string): Promise<AdvisoryResponse> {
    return this.request<AdvisoryResponse>(
      'GET',
      `/api/eye/advisories/${encodeURIComponent(advisoryId)}`,
      undefined,
      true,
    );
  }

  /** Create a suppression to exclude a reason code from future advisories. */
  async createSuppression(params: CreateSuppressionParams): Promise<SuppressionResponse> {
    return this.request<SuppressionResponse>('POST', '/api/eye/suppressions', params, true);
  }
}
