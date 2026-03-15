/**
 * EMILIA Protocol TypeScript SDK
 *
 * Reference SDK for portable trust evaluation and appeals across counterparties,
 * software, and machine actors.
 *
 * Source-only until published to npm.
 *
 * @license Apache-2.0
 */

export type JsonObject = Record<string, unknown>;

export interface EmiliaClientConfig {
  baseUrl?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface TrustEvaluateParams {
  entityId: string;
  policy?: string | JsonObject;
  context?: JsonObject | null;
}

export interface SubmitReceiptParams {
  entityId: string;
  transactionRef: string;
  transactionType: string;
  agentBehavior?: string | null;
  signals?: Record<string, number | null>;
  context?: JsonObject | null;
  provenanceTier?: string;
  requestBilateral?: boolean;
}

export interface FileDisputeParams {
  receiptId: string;
  reason: string;
  description: string;
  evidence?: JsonObject | null;
}

export interface ReportTrustIssueParams {
  entityId: string;
  reportType: string;
  description: string;
  contactEmail?: string | null;
  evidence?: JsonObject | null;
}

export class EmiliaApiError extends Error {
  readonly status: number;
  readonly payload?: unknown;

  constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'EmiliaApiError';
    this.status = status;
    this.payload = payload;
  }
}

export class EmiliaClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | null;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(config: EmiliaClientConfig = {}) {
    this.baseUrl = (config.baseUrl || 'https://emiliaprotocol.ai').replace(/\/+$/, '');
    this.apiKey = config.apiKey || null;
    this.fetchImpl = config.fetchImpl || fetch;
    this.timeoutMs = config.timeoutMs ?? 15000;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...((options.headers as Record<string, string>) || {})
      };

      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...options,
        headers,
        signal: controller.signal
      });

      const payload = await res.json().catch(() => undefined);
      if (!res.ok) {
        const message = typeof payload === 'object' && payload && 'error' in payload
          ? String((payload as { error?: unknown }).error)
          : `EP API error: ${res.status}`;
        throw new EmiliaApiError(message, res.status, payload);
      }

      return payload as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Full trust profile — the canonical read surface. */
  async getTrustProfile<T = JsonObject>(entityId: string): Promise<T> {
    return this.request<T>(`/api/trust/profile/${encodeURIComponent(entityId)}`);
  }

  /** Evaluate against a trust policy with optional context. */
  async evaluateTrust<T = JsonObject>(params: TrustEvaluateParams): Promise<T> {
    return this.request<T>('/api/trust/evaluate', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        policy: params.policy ?? 'standard',
        context: params.context ?? null
      })
    });
  }

  /** EP-SX: Should I install this plugin/app/package? */
  async installPreflight<T = JsonObject>(params: TrustEvaluateParams): Promise<T> {
    return this.request<T>('/api/trust/install-preflight', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        policy: params.policy ?? 'standard',
        context: params.context ?? null
      })
    });
  }

  /** Submit a transaction receipt. */
  async submitReceipt<T = JsonObject>(params: SubmitReceiptParams): Promise<T> {
    return this.request<T>('/api/receipts/submit', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        transaction_ref: params.transactionRef,
        transaction_type: params.transactionType,
        agent_behavior: params.agentBehavior ?? null,
        ...(params.signals || {}),
        context: params.context ?? null,
        provenance_tier: params.provenanceTier ?? 'self_attested',
        request_bilateral: params.requestBilateral ?? false
      })
    });
  }

  /** File a formal dispute against a receipt. */
  async fileDispute<T = JsonObject>(params: FileDisputeParams): Promise<T> {
    return this.request<T>('/api/disputes/file', {
      method: 'POST',
      body: JSON.stringify({
        receipt_id: params.receiptId,
        reason: params.reason,
        description: params.description,
        evidence: params.evidence ?? null
      })
    });
  }

  /** Report a trust issue — no auth required (human appeal channel). */
  async reportTrustIssue<T = JsonObject>(params: ReportTrustIssueParams): Promise<T> {
    return this.request<T>('/api/disputes/report', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        report_type: params.reportType,
        description: params.description,
        contact_email: params.contactEmail ?? null,
        evidence: params.evidence ?? null
      })
    });
  }

  /** Legacy: compatibility score only. Prefer getTrustProfile(). */
  async getScore<T = JsonObject>(entityId: string): Promise<T> {
    return this.request<T>(`/api/score/${encodeURIComponent(entityId)}`);
  }
}

export default EmiliaClient;
