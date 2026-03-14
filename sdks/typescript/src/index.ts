/**
 * EMILIA Protocol TypeScript SDK
 * 
 * Portable trust evaluation and appeals for counterparties, software, and machine actors.
 * 
 * @license Apache-2.0
 */

export interface EmiliaClientConfig {
  baseUrl?: string;
  apiKey?: string;
}

export class EmiliaClient {
  private baseUrl: string;
  private apiKey: string | null;

  constructor(config: EmiliaClientConfig = {}) {
    this.baseUrl = (config.baseUrl || 'https://emiliaprotocol.ai').replace(/\/+$/, '');
    this.apiKey = config.apiKey || null;
  }

  private async request(path: string, options: RequestInit = {}): Promise<any> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    const res = await fetch(`${this.baseUrl}${path}`, { ...options, headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `EP API error: ${res.status}`);
    }
    return res.json();
  }

  /** Full trust profile — the canonical read surface */
  async getTrustProfile(entityId: string) {
    return this.request(`/api/trust/profile/${encodeURIComponent(entityId)}`);
  }

  /** Evaluate against a trust policy with optional context */
  async evaluateTrust(params: { entityId: string; policy?: string; context?: Record<string, any> }) {
    return this.request('/api/trust/evaluate', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        policy: params.policy || 'standard',
        context: params.context || null,
      }),
    });
  }

  /** EP-SX: Should I install this plugin/app/package? */
  async installPreflight(params: { entityId: string; policy?: string; context?: Record<string, any> }) {
    return this.request('/api/trust/install-preflight', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        policy: params.policy || 'standard',
        context: params.context || null,
      }),
    });
  }

  /** Submit a transaction receipt */
  async submitReceipt(params: {
    entityId: string;
    transactionRef: string;
    transactionType: string;
    agentBehavior?: string;
    signals?: Record<string, number>;
    context?: Record<string, any>;
    provenanceTier?: string;
    requestBilateral?: boolean;
  }) {
    return this.request('/api/receipts/submit', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        transaction_ref: params.transactionRef,
        transaction_type: params.transactionType,
        agent_behavior: params.agentBehavior || null,
        ...(params.signals || {}),
        context: params.context || null,
        provenance_tier: params.provenanceTier || 'self_attested',
        request_bilateral: params.requestBilateral || false,
      }),
    });
  }

  /** File a formal dispute against a receipt */
  async fileDispute(params: { receiptId: string; reason: string; description: string; evidence?: Record<string, any> }) {
    return this.request('/api/disputes/file', {
      method: 'POST',
      body: JSON.stringify({
        receipt_id: params.receiptId,
        reason: params.reason,
        description: params.description,
        evidence: params.evidence || null,
      }),
    });
  }

  /** Report a trust issue — no auth required (human appeal) */
  async reportTrustIssue(params: { entityId: string; reportType: string; description: string; contactEmail?: string }) {
    return this.request('/api/disputes/report', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: params.entityId,
        report_type: params.reportType,
        description: params.description,
        contact_email: params.contactEmail || null,
      }),
    });
  }

  /** Legacy: compatibility score only. Use getTrustProfile() instead. */
  async getScore(entityId: string) {
    return this.request(`/api/score/${encodeURIComponent(entityId)}`);
  }
}

export default EmiliaClient;
