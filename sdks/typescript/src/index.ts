/** EMILIA Protocol — Full SDK. Zero dependencies, native fetch. @license Apache-2.0 */

// -- Params -----------------------------------------------------------------

export interface EPClientOptions {
  baseUrl: string;
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
  strategy: 'canary' | 'blue-green' | 'linear' | string;
  percentage?: number;
}

export interface DiffPolicyVersionsParams {
  policyId: string;
  versionA: string;
  versionB: string;
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
  policyId: string;
  strategy: string;
  percentage: number;
  status: string;
  startedAt: string;
}

export interface PolicyVersion {
  versionId: string;
  policyId: string;
  version: number;
  createdAt: string;
  createdBy: string;
  changelog?: string;
}

export interface PolicyDiff {
  policyId: string;
  versionA: string;
  versionB: string;
  changes: PolicyChange[];
}

export interface PolicyChange {
  field: string;
  oldValue: unknown;
  newValue: unknown;
  type: 'added' | 'removed' | 'modified';
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

  /** Begin a rollout of a policy using the specified strategy. */
  async rolloutPolicy(policyId: string, strategy: string, percentage?: number): Promise<PolicyRolloutResult> {
    return this._request<PolicyRolloutResult>('POST', `/api/cloud/policies/${encodeURIComponent(policyId)}/rollout`, {
      strategy,
      percentage,
    }, true);
  }

  /** List all versions of a policy. */
  async getPolicyVersions(policyId: string): Promise<PolicyVersion[]> {
    return this._request<PolicyVersion[]>('GET', `/api/cloud/policies/${encodeURIComponent(policyId)}/versions`, undefined, true);
  }

  /** Diff two versions of a policy to see what changed. */
  async diffPolicyVersions(policyId: string, versionA: string, versionB: string): Promise<PolicyDiff> {
    return this._request<PolicyDiff>('POST', `/api/cloud/policies/${encodeURIComponent(policyId)}/diff`, {
      versionA,
      versionB,
    }, true);
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

export class EPClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retries: number;

  /** Cloud-specific endpoints (dashboards, analytics, audit, policy management). */
  public readonly cloud: EPCloudClient;

  constructor(options: EPClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey ?? '';
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
          const msg = typeof p?.['error'] === 'string' ? p['error'] : `EP API error: ${res.status}`;
          const code = typeof p?.['code'] === 'string' ? p['code'] : undefined;
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
}
