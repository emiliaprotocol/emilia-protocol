// ============================================================================
// EMILIA Protocol — TypeScript Client
// ============================================================================

import type {
  EntityType,
  TrustPolicy,
  TrustContext,
  AgentBehavior,
  TransactionType,
  DisputeReason,
  ReportType,
  TrustDomain,
  EntityTrustProfile,
  TrustEvaluation,
  SubmitReceiptInput,
  SubmitReceiptResult,
  EntitySearchResult,
  Dispute,
  LeaderboardEntry,
  TrustGateResult,
  DelegationRecord,
  DomainScoreResult,
  InstallPreflightResult,
  PrincipalLookupResult,
  LineageResult,
  BatchReceiptResult,
  ConfirmReceiptResult,
  TrustPolicyDefinition,
  EPStats,
  EPClientOptions,
  EPCommit,
  EPCommitRequest,
  EPCommitVerification,
  EPCommitIssueResult,
  EPCommitStatusResult,
  EPCommitRevokeResult,
  EPCommitReceiptResult,
} from './types.js';

import { EPError } from './types.js';

const SDK_VERSION = '1.0.0';
const DEFAULT_BASE_URL = 'https://emiliaprotocol.ai';
const DEFAULT_TIMEOUT = 30_000;

// ----------------------------------------------------------------------------
// Internal fetch helper types
// ----------------------------------------------------------------------------

interface FetchOptions {
  method?: string;
  body?: unknown;
  /** If true, include the Bearer token from this.apiKey */
  auth?: boolean;
  /** Query parameters appended to the URL */
  params?: Record<string, string | number | boolean | undefined | null>;
}

// ----------------------------------------------------------------------------
// EPClient
// ----------------------------------------------------------------------------

/**
 * Client for the EMILIA Protocol API.
 *
 * All public methods return typed promises and throw `EPError` on failure.
 *
 * @example
 * ```typescript
 * import { EPClient } from '@emilia-protocol/sdk';
 *
 * const ep = new EPClient({ apiKey: process.env.EP_API_KEY });
 *
 * const profile = await ep.trustProfile('merchant-xyz');
 * console.log(profile.current_confidence); // "confident"
 * ```
 */
export class EPClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: EPClientOptions = {}) {
    this.baseUrl = (
      options.baseUrl ??
      (typeof process !== 'undefined' ? process.env['EP_BASE_URL'] : undefined) ??
      DEFAULT_BASE_URL
    ).replace(/\/+$/, '');

    this.apiKey =
      options.apiKey ??
      (typeof process !== 'undefined' ? process.env['EP_API_KEY'] : undefined) ??
      '';

    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  // --------------------------------------------------------------------------
  // Core fetch implementation
  // --------------------------------------------------------------------------

  private async request<T>(path: string, options: FetchOptions = {}): Promise<T> {
    // Build URL with query params
    let url = `${this.baseUrl}${path}`;
    if (options.params) {
      const entries = Object.entries(options.params).filter(
        ([, v]) => v !== undefined && v !== null,
      ) as [string, string | number | boolean][];
      if (entries.length > 0) {
        url += `?${new URLSearchParams(entries.map(([k, v]) => [k, String(v)]))}`;
      }
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': `@emilia-protocol/sdk/${SDK_VERSION}`,
    };

    if (options.auth && this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await this.fetchImpl(url, {
        method: options.method ?? 'GET',
        headers,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      // Parse JSON regardless of status so we can surface API error messages
      const data: unknown = await res.json().catch(() => undefined);

      if (!res.ok) {
        const payload = data as Record<string, unknown> | undefined;
        const message =
          typeof payload?.['error'] === 'string'
            ? payload['error']
            : `EP API error: ${res.status}`;
        const code =
          typeof payload?.['code'] === 'string' ? payload['code'] : undefined;
        throw new EPError(message, res.status, code);
      }

      return data as T;
    } catch (err) {
      if (err instanceof EPError) throw err;
      // AbortError → timeout
      if (err instanceof Error && err.name === 'AbortError') {
        throw new EPError(`Request timed out after ${this.timeout}ms`, undefined, 'timeout');
      }
      throw new EPError(
        err instanceof Error ? err.message : 'Unknown network error',
        undefined,
        'network_error',
      );
    } finally {
      clearTimeout(timer);
    }
  }

  // --------------------------------------------------------------------------
  // Trust Profile & Evaluation
  // --------------------------------------------------------------------------

  /**
   * Get an entity's full trust profile.
   *
   * This is the CANONICAL read surface for EP trust data. Call this before
   * transacting with any counterparty or installing any software.
   *
   * @example
   * ```typescript
   * const profile = await ep.trustProfile('merchant-xyz');
   * console.log(profile.current_confidence); // "confident"
   * console.log(profile.trust_profile?.behavioral?.completion_rate); // 97.2
   * ```
   */
  async trustProfile(entityId: string): Promise<EntityTrustProfile> {
    return this.request<EntityTrustProfile>(
      `/api/trust/profile/${encodeURIComponent(entityId)}`,
    );
  }

  /**
   * Evaluate an entity against a named trust policy.
   *
   * Returns a canonical TrustDecision with detailed reasoning.
   * Supply `context` for context-aware evaluation (geo, category, value_band, etc.).
   *
   * @example
   * ```typescript
   * const result = await ep.trustEvaluate('merchant-xyz', 'strict', {
   *   category: 'furniture',
   *   geo: 'US-CA',
   *   value_band: 'high',
   * });
   * if (result.decision !== 'allow') console.warn('Reasons:', result.reasons);
   * ```
   */
  async trustEvaluate(
    entityId: string,
    policy: TrustPolicy | string = 'standard',
    context?: TrustContext,
  ): Promise<TrustEvaluation> {
    return this.request<TrustEvaluation>('/api/trust/evaluate', {
      method: 'POST',
      body: {
        entity_id: entityId,
        policy,
        ...(context ? { context } : {}),
      },
    });
  }

  /**
   * Pre-action trust gate — call before any high-stakes autonomous action.
   *
   * Combines trust evaluation with delegation verification in a single call.
   * The gate returns allow/review/deny with appeal paths for non-allow decisions.
   *
   * @example
   * ```typescript
   * const gate = await ep.trustGate({
   *   entityId: 'payment-agent-v2',
   *   action: 'execute_payment',
   *   policy: 'strict',
   *   valueUsd: 500,
   * });
   * if (gate.decision !== 'allow') throw new Error(`Blocked: ${gate.reasons?.join(', ')}`);
   * ```
   */
  async trustGate(options: {
    entityId: string;
    action: string;
    policy?: TrustPolicy | string;
    valueUsd?: number;
    delegationId?: string;
  }): Promise<TrustGateResult> {
    return this.request<TrustGateResult>('/api/trust/gate', {
      method: 'POST',
      body: {
        entity_id: options.entityId,
        action: options.action,
        policy: options.policy ?? 'standard',
        value_usd: options.valueUsd ?? null,
        delegation_id: options.delegationId ?? null,
      },
    });
  }

  /**
   * Get domain-specific trust scores for an entity.
   *
   * Optionally filter to a subset of domains. Useful when you need trust
   * context scoped to a specific action category (e.g. "financial" before
   * authorizing a payment).
   *
   * @example
   * ```typescript
   * const scores = await ep.domainScore('agent-v2', ['financial', 'delegation']);
   * console.log(scores.domains.financial?.confidence); // "confident"
   * ```
   */
  async domainScore(entityId: string, domains?: TrustDomain[]): Promise<DomainScoreResult> {
    return this.request<DomainScoreResult>(
      `/api/trust/domain-score/${encodeURIComponent(entityId)}`,
      { params: domains?.length ? { domains: domains.join(',') } : undefined },
    );
  }

  /**
   * EP-SX: Software install preflight check.
   *
   * Evaluates a software entity (MCP server, npm package, browser extension,
   * GitHub App, Shopify App, etc.) for installation safety. Returns allow/
   * review/deny with publisher verification, permission class, and provenance.
   *
   * @example
   * ```typescript
   * const preflight = await ep.installPreflight(
   *   'mcp-server-acme-v1',
   *   'mcp_server_safe_v1',
   *   { host: 'claude-desktop', permission_class: 'bounded_external_access' },
   * );
   * if (preflight.decision === 'deny') throw new Error('Installation blocked by EP');
   * ```
   */
  async installPreflight(
    entityId: string,
    policy?: TrustPolicy | string,
    context?: Record<string, string>,
  ): Promise<InstallPreflightResult> {
    return this.request<InstallPreflightResult>('/api/trust/install-preflight', {
      method: 'POST',
      body: {
        entity_id: entityId,
        policy: policy ?? 'standard',
        ...(context ? { context } : {}),
      },
    });
  }

  // --------------------------------------------------------------------------
  // Entities
  // --------------------------------------------------------------------------

  /**
   * Register a new entity.
   *
   * Public endpoint — no API key required. Returns the entity record and the
   * first API key. Store the API key securely; it will not be shown again.
   *
   * @example
   * ```typescript
   * const { entity, api_key } = await ep.registerEntity({
   *   entityId: 'acme-payment-agent',
   *   displayName: 'Acme Payment Agent',
   *   entityType: 'agent',
   *   description: 'Handles autonomous payment flows for Acme Corp.',
   *   capabilities: ['payment', 'refund'],
   * });
   * console.log('Save this key:', api_key); // ep_live_...
   * ```
   */
  async registerEntity(options: {
    entityId: string;
    displayName: string;
    entityType: EntityType;
    description: string;
    capabilities?: string[];
  }): Promise<{ entity: { entity_id: string; display_name: string }; api_key: string }> {
    return this.request('/api/entities/register', {
      method: 'POST',
      body: {
        entity_id: options.entityId,
        display_name: options.displayName,
        entity_type: options.entityType,
        description: options.description,
        capabilities: options.capabilities,
      },
    });
  }

  /**
   * Search for entities by name, capability, or category.
   *
   * @example
   * ```typescript
   * const { entities } = await ep.searchEntities('payment', 'agent');
   * for (const e of entities) {
   *   console.log(e.display_name, e.confidence);
   * }
   * ```
   */
  async searchEntities(
    query: string,
    entityType?: EntityType,
    minConfidence?: string,
  ): Promise<{ entities: EntitySearchResult[] }> {
    return this.request('/api/entities/search', {
      params: {
        q: query,
        type: entityType,
        min_confidence: minConfidence,
      },
    });
  }

  /**
   * Get the entity leaderboard ranked by trust confidence.
   *
   * @example
   * ```typescript
   * const { leaderboard } = await ep.leaderboard(5, 'merchant');
   * leaderboard.forEach(e => console.log(`#${e.rank} ${e.display_name}`));
   * ```
   */
  async leaderboard(
    limit = 10,
    entityType?: EntityType,
  ): Promise<{ leaderboard: LeaderboardEntry[] }> {
    return this.request('/api/leaderboard', {
      params: {
        limit: Math.min(limit, 50),
        type: entityType,
      },
    });
  }

  // --------------------------------------------------------------------------
  // Receipts
  // --------------------------------------------------------------------------

  /**
   * Submit a transaction receipt to the EP ledger.
   *
   * Requires an API key. Receipts are append-only, cryptographically hashed,
   * and chain-linked. `transaction_ref` must be unique per entity.
   *
   * The `agent_behavior` field is the strongest Phase 1 signal — always set it.
   *
   * @example
   * ```typescript
   * const { receipt } = await ep.submitReceipt({
   *   entity_id: 'merchant-xyz',
   *   transaction_ref: 'order-8821',
   *   transaction_type: 'purchase',
   *   agent_behavior: 'completed',
   *   delivery_accuracy: 98,
   *   product_accuracy: 95,
   *   price_integrity: 100,
   * });
   * console.log('Receipt ID:', receipt.receipt_id);
   * ```
   */
  async submitReceipt(input: SubmitReceiptInput): Promise<SubmitReceiptResult> {
    return this.request<SubmitReceiptResult>('/api/receipts/submit', {
      method: 'POST',
      auth: true,
      body: input,
    });
  }

  /**
   * Submit multiple receipts atomically. Maximum 50 per call.
   *
   * Each result in the response array indicates success or failure for that
   * receipt independently — partial success is possible.
   *
   * @example
   * ```typescript
   * const result = await ep.batchSubmit([
   *   { entity_id: 'merchant-a', transaction_ref: 'tx-1', transaction_type: 'purchase', agent_behavior: 'completed' },
   *   { entity_id: 'merchant-b', transaction_ref: 'tx-2', transaction_type: 'service', agent_behavior: 'completed' },
   * ]);
   * result.results.forEach(r => console.log(r.entity_id, r.success ? 'ok' : r.error));
   * ```
   */
  async batchSubmit(receipts: SubmitReceiptInput[]): Promise<BatchReceiptResult> {
    return this.request<BatchReceiptResult>('/api/receipts/batch', {
      method: 'POST',
      auth: true,
      body: { receipts: receipts.slice(0, 50) },
    });
  }

  /**
   * Confirm or reject a receipt as the counterparty (bilateral confirmation).
   *
   * The confirmation window is 48 hours from receipt creation. Confirmed
   * receipts receive a higher provenance tier, improving their evidential weight.
   *
   * @example
   * ```typescript
   * await ep.confirmReceipt('ep_rcpt_abc123', true);
   * ```
   */
  async confirmReceipt(receiptId: string, confirm: boolean): Promise<ConfirmReceiptResult> {
    return this.request<ConfirmReceiptResult>('/api/receipts/confirm', {
      method: 'POST',
      auth: true,
      body: { receipt_id: receiptId, confirm },
    });
  }

  /**
   * Verify a receipt against the on-chain Merkle root.
   *
   * @example
   * ```typescript
   * const { verified, anchored } = await ep.verifyReceipt('ep_rcpt_abc123');
   * if (!verified) console.error('Receipt integrity check failed');
   * ```
   */
  async verifyReceipt(receiptId: string): Promise<{
    receipt_id: string;
    receipt_hash: string;
    anchored: boolean;
    verified: boolean;
  }> {
    return this.request(`/api/verify/${encodeURIComponent(receiptId)}`);
  }

  // --------------------------------------------------------------------------
  // Disputes & Due Process
  // --------------------------------------------------------------------------

  /**
   * File a dispute against a receipt.
   *
   * Requires an API key. Any affected party can challenge. The receipt
   * submitter has 7 days to respond before EP escalates.
   *
   * @example
   * ```typescript
   * const dispute = await ep.fileDispute({
   *   receiptId: 'ep_rcpt_abc123',
   *   reason: 'inaccurate_signals',
   *   description: 'Delivery accuracy was reported as 98 but the item arrived damaged.',
   *   evidence: { photo_url: 'https://...' },
   * });
   * console.log('Dispute ID:', dispute.dispute_id);
   * console.log('Respond by:', dispute.response_deadline);
   * ```
   */
  async fileDispute(options: {
    receiptId: string;
    reason: DisputeReason;
    description?: string;
    evidence?: Record<string, unknown>;
  }): Promise<Dispute & { response_deadline: string; _message: string }> {
    return this.request('/api/disputes/file', {
      method: 'POST',
      auth: true,
      body: {
        receipt_id: options.receiptId,
        reason: options.reason,
        description: options.description ?? null,
        evidence: options.evidence ?? null,
      },
    });
  }

  /**
   * Get the current status of a dispute.
   *
   * Dispute status is public — transparency is a protocol value.
   *
   * @example
   * ```typescript
   * const dispute = await ep.disputeStatus('ep_disp_xyz789');
   * console.log(dispute.status, dispute.resolution);
   * ```
   */
  async disputeStatus(disputeId: string): Promise<Dispute> {
    return this.request<Dispute>(`/api/disputes/${encodeURIComponent(disputeId)}`);
  }

  /**
   * Respond to a dispute filed against one of your receipts.
   *
   * Requires an API key. Must be called within the response_deadline window.
   *
   * @example
   * ```typescript
   * await ep.respondToDispute({
   *   disputeId: 'ep_disp_xyz789',
   *   response: 'The delivery accuracy score reflects the state at handoff, confirmed by carrier log.',
   *   evidence: { carrier_log_url: 'https://...' },
   * });
   * ```
   */
  async respondToDispute(options: {
    disputeId: string;
    response: string;
    evidence?: Record<string, unknown>;
  }): Promise<{ dispute_id: string; status: string }> {
    return this.request('/api/disputes/respond', {
      method: 'POST',
      auth: true,
      body: {
        dispute_id: options.disputeId,
        response: options.response,
        evidence: options.evidence ?? null,
      },
    });
  }

  /**
   * Withdraw an open dispute before it reaches resolution.
   *
   * Requires an API key. Only the filer can withdraw.
   *
   * @example
   * ```typescript
   * await ep.withdrawDispute('ep_disp_xyz789');
   * ```
   */
  async withdrawDispute(disputeId: string): Promise<{ dispute_id: string; status: string }> {
    return this.request('/api/disputes/withdraw', {
      method: 'POST',
      auth: true,
      body: { dispute_id: disputeId },
    });
  }

  /**
   * Appeal a dispute resolution.
   *
   * Requires an API key. Only dispute participants may appeal. The dispute must
   * be in upheld, reversed, or dismissed state. The appeal decision is final.
   *
   * "Trust must never be more powerful than appeal." — EP Constitutional Principle
   *
   * @example
   * ```typescript
   * await ep.appealDispute({
   *   disputeId: 'ep_disp_xyz789',
   *   reason: 'New evidence shows the carrier log was misread. Attaching corrected scan.',
   *   evidence: { corrected_scan: 'https://...' },
   * });
   * ```
   */
  async appealDispute(options: {
    disputeId: string;
    reason: string;
    evidence?: Record<string, unknown>;
  }): Promise<{ appeal_id?: string; dispute_id: string; status: string; _message?: string }> {
    return this.request('/api/disputes/appeal', {
      method: 'POST',
      auth: true,
      body: {
        dispute_id: options.disputeId,
        reason: options.reason,
        evidence: options.evidence ?? null,
      },
    });
  }

  /**
   * Report a trust issue as a human.
   *
   * No authentication required. The human appeal channel — use when someone
   * is wrongly downgraded, harmed by a trusted entity, or has observed fraud.
   *
   * @example
   * ```typescript
   * await ep.reportTrustIssue({
   *   entityId: 'merchant-xyz',
   *   reportType: 'harmed_by_trusted_entity',
   *   description: 'I paid for an item marked as delivered but never received it.',
   *   contactEmail: 'jane@example.com',
   * });
   * ```
   */
  async reportTrustIssue(options: {
    entityId: string;
    reportType: ReportType;
    description: string;
    contactEmail?: string;
  }): Promise<{ report_id: string; _message: string; _principle: string }> {
    return this.request('/api/disputes/report', {
      method: 'POST',
      body: {
        entity_id: options.entityId,
        report_type: options.reportType,
        description: options.description,
        contact_email: options.contactEmail ?? null,
      },
    });
  }

  // --------------------------------------------------------------------------
  // Delegation (EP-DX)
  // --------------------------------------------------------------------------

  /**
   * Create a delegation: authorize an agent to act on behalf of a principal.
   *
   * Requires an API key. The delegation record can be verified by any party
   * using `verifyDelegation`.
   *
   * @example
   * ```typescript
   * const delegation = await ep.createDelegation({
   *   principalId: 'ep_principal_acme',
   *   agentEntityId: 'acme-payment-agent',
   *   scope: ['purchase', 'refund'],
   *   maxValueUsd: 1000,
   *   expiresAt: '2026-12-31T23:59:59Z',
   * });
   * console.log('Delegation ID:', delegation.delegation_id);
   * ```
   */
  async createDelegation(options: {
    principalId: string;
    agentEntityId: string;
    scope: string[];
    maxValueUsd?: number;
    expiresAt?: string;
    constraints?: Record<string, unknown>;
  }): Promise<DelegationRecord> {
    return this.request<DelegationRecord>('/api/delegations/create', {
      method: 'POST',
      auth: true,
      body: {
        principal_id: options.principalId,
        agent_entity_id: options.agentEntityId,
        scope: options.scope,
        max_value_usd: options.maxValueUsd ?? null,
        expires_at: options.expiresAt ?? null,
        constraints: options.constraints ?? null,
      },
    });
  }

  /**
   * Verify that a delegation is valid and covers a given action type.
   *
   * @example
   * ```typescript
   * const result = await ep.verifyDelegation('ep_del_abc123', 'purchase');
   * if (!result.valid) throw new Error('Delegation invalid or expired');
   * ```
   */
  async verifyDelegation(
    delegationId: string,
    actionType?: string,
  ): Promise<DelegationRecord & { valid: boolean; action_permitted?: boolean; reason?: string }> {
    return this.request(`/api/delegations/${encodeURIComponent(delegationId)}/verify`, {
      params: { action_type: actionType },
    });
  }

  // --------------------------------------------------------------------------
  // Identity Continuity (EP-IX)
  // --------------------------------------------------------------------------

  /**
   * Look up a principal — the enduring actor behind one or more entities.
   *
   * Returns the principal record, its controlled entities, identity bindings,
   * and continuity claim history.
   *
   * @example
   * ```typescript
   * const result = await ep.principalLookup('ep_principal_acme');
   * console.log('Entities:', result.entities?.map(e => e.entity_id));
   * ```
   */
  async principalLookup(principalId: string): Promise<PrincipalLookupResult> {
    return this.request<PrincipalLookupResult>(
      `/api/identity/principal/${encodeURIComponent(principalId)}`,
    );
  }

  /**
   * View entity lineage — predecessors, successors, and continuity decisions.
   *
   * Use to check whether an entity has suspicious continuity gaps that might
   * indicate reputation laundering (whitewashing).
   *
   * @example
   * ```typescript
   * const lineage = await ep.lineage('merchant-xyz');
   * if (lineage.predecessors?.some(p => p.status === 'disputed')) {
   *   console.warn('Entity has disputed predecessor — review before transacting');
   * }
   * ```
   */
  async lineage(entityId: string): Promise<LineageResult> {
    return this.request<LineageResult>(
      `/api/identity/lineage/${encodeURIComponent(entityId)}`,
    );
  }

  // --------------------------------------------------------------------------
  // Policies
  // --------------------------------------------------------------------------

  /**
   * List all available trust policies with their requirements and families.
   *
   * Returns 8 policies: 4 core (strict, standard, permissive, discovery) and
   * 4 software-specific (github_private_repo_safe_v1, npm_buildtime_safe_v1,
   * browser_extension_safe_v1, mcp_server_safe_v1).
   *
   * @example
   * ```typescript
   * const { policies } = await ep.listPolicies();
   * policies.forEach(p => console.log(p.name, '-', p.description));
   * ```
   */
  async listPolicies(): Promise<{ policies: TrustPolicyDefinition[] }> {
    return this.request('/api/policies');
  }

  // --------------------------------------------------------------------------
  // System
  // --------------------------------------------------------------------------

  /**
   * Public proof metrics — entity count, test count, tool count, policy count.
   *
   * @example
   * ```typescript
   * const stats = await ep.stats();
   * console.log(`${stats.total_entities} entities across ${stats.trust_policies} policies`);
   * ```
   */
  async stats(): Promise<EPStats> {
    return this.request<EPStats>('/api/stats');
  }

  /**
   * Health check. Returns subsystem status.
   *
   * @example
   * ```typescript
   * const health = await ep.health();
   * console.log(health.status); // "ok"
   * ```
   */
  async health(): Promise<{ status: string; [key: string]: unknown }> {
    return this.request('/api/health');
  }

  // --------------------------------------------------------------------------
  // EP Commit
  // --------------------------------------------------------------------------

  /**
   * Issue a signed EP Commit before a high-stakes action.
   *
   * The commit binds the agent to a specific action type, entity, and policy
   * before execution. Returns decision (allow/deny/review), commit_id, expiry,
   * scope, and appeal path.
   *
   * @example
   * ```typescript
   * const { decision, commit } = await ep.issueCommit({
   *   action_type: 'transact',
   *   entity_id: 'payment-agent-v2',
   *   max_value_usd: 500,
   *   policy: 'strict',
   * });
   * if (decision !== 'allow') throw new Error('Commit denied');
   * console.log(commit.commit_id);
   * ```
   */
  async issueCommit(params: EPCommitRequest): Promise<EPCommitIssueResult> {
    return this.request<EPCommitIssueResult>('/api/commit/issue', {
      method: 'POST',
      auth: true,
      body: params,
    });
  }

  /**
   * Verify a commit's signature, status, and validity.
   *
   * @example
   * ```typescript
   * const result = await ep.verifyCommit('epc_abc123');
   * if (!result.valid) console.error('Commit invalid');
   * ```
   */
  async verifyCommit(commitId: string): Promise<EPCommitVerification> {
    return this.request<EPCommitVerification>('/api/commit/verify', {
      method: 'POST',
      body: { commit_id: commitId },
    });
  }

  /**
   * Get the current state of a commit.
   *
   * @example
   * ```typescript
   * const { commit } = await ep.getCommitStatus('epc_abc123');
   * console.log(commit.status); // "active" | "revoked" | "expired" | "fulfilled"
   * ```
   */
  async getCommitStatus(commitId: string): Promise<EPCommitStatusResult> {
    return this.request<EPCommitStatusResult>(`/api/commit/${encodeURIComponent(commitId)}`, {
      auth: true,
    });
  }

  /**
   * Revoke an active commit before it is fulfilled or expires.
   *
   * @example
   * ```typescript
   * await ep.revokeCommit('epc_abc123', 'Action no longer needed');
   * ```
   */
  async revokeCommit(commitId: string, reason: string): Promise<EPCommitRevokeResult> {
    return this.request<EPCommitRevokeResult>(`/api/commit/${encodeURIComponent(commitId)}/revoke`, {
      method: 'POST',
      auth: true,
      body: { reason },
    });
  }

  /**
   * Bind a post-action receipt to a commit, completing the commit-execute-receipt cycle.
   *
   * @example
   * ```typescript
   * await ep.bindReceiptToCommit('epc_abc123', 'ep_rcpt_xyz789');
   * ```
   */
  async bindReceiptToCommit(commitId: string, receiptId: string): Promise<EPCommitReceiptResult> {
    return this.request<EPCommitReceiptResult>(`/api/commit/${encodeURIComponent(commitId)}/receipt`, {
      method: 'POST',
      auth: true,
      body: { receipt_id: receiptId },
    });
  }

  /**
   * Legacy: get the 0-100 compatibility score for an entity.
   *
   * Prefer `trustProfile()` for all new integrations. This endpoint exists
   * for backward compatibility only.
   *
   * @deprecated Use trustProfile() instead.
   */
  async legacyScore(entityId: string): Promise<{ entity_id: string; score: number }> {
    return this.request(`/api/score/${encodeURIComponent(entityId)}`);
  }
}
