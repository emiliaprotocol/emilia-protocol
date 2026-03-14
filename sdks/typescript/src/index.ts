/**
 * @emilia-protocol/sdk
 *
 * TypeScript SDK for EMILIA Protocol (EP).
 * The trust layer for agentic commerce.
 *
 * Usage:
 *   import { EmiliaClient } from '@emilia-protocol/sdk';
 *   const ep = new EmiliaClient({ apiKey: 'ep_live_...' });
 *   const score = await ep.getScore('rex-booking-v1');
 *
 * @license Apache-2.0
 */

// =============================================================================
// Types
// =============================================================================

export interface EmiliaConfig {
  /** Base URL of the EP implementation. Default: https://emiliaprotocol.ai */
  baseUrl?: string;
  /** API key for write operations (ep_live_...) */
  apiKey?: string;
  /** Request timeout in ms. Default: 10000 */
  timeout?: number;
}

export interface ScoreBreakdown {
  delivery_accuracy: number | null;
  product_accuracy: number | null;
  price_integrity: number | null;
  return_processing: number | null;
  agent_satisfaction: number | null;
  consistency: number | null;
}

export interface ScoreResult {
  entity_id: string;
  display_name: string;
  entity_type: 'agent' | 'merchant' | 'service_provider';
  description?: string;
  category?: string;
  capabilities?: string[];
  emilia_score: number;
  established: boolean;
  total_receipts: number;
  successful_receipts: number;
  success_rate: number | null;
  breakdown: ScoreBreakdown | null;
  verified: boolean;
  a2a_endpoint?: string;
  ucp_profile_url?: string;
  member_since: string;
}

export type TransactionType = 'purchase' | 'service' | 'task_completion' | 'delivery' | 'return';

export interface SubmitReceiptInput {
  entity_id: string;
  transaction_type: TransactionType;
  transaction_ref?: string;
  delivery_accuracy?: number;
  product_accuracy?: number;
  price_integrity?: number;
  return_processing?: number;
  agent_satisfaction?: number;
  evidence?: Record<string, unknown>;
}

export interface ReceiptResult {
  receipt: {
    receipt_id: string;
    entity_id: string;
    composite_score: number;
    receipt_hash: string;
    created_at: string;
  };
  entity_score: {
    emilia_score: number;
    total_receipts: number;
  };
}

export interface RegisterEntityInput {
  entity_id: string;
  display_name: string;
  entity_type: 'agent' | 'merchant' | 'service_provider';
  description: string;
  capabilities?: string[];
  website_url?: string;
  category?: string;
  service_area?: string;
  a2a_endpoint?: string;
  ucp_profile_url?: string;
}

export interface RegisterResult {
  entity: {
    id: string;
    entity_id: string;
    display_name: string;
    entity_number?: number;
    emilia_score: number;
  };
  api_key: string;
}

export interface VerifyResult {
  receipt_id: string;
  receipt_hash: string;
  anchored: boolean;
  batch?: {
    id: string;
    merkle_root: string;
    leaf_count: number;
    tx_hash: string | null;
    block_number: number | null;
    status: string;
    created_at: string;
  };
  proof?: Array<{ hash: string; position: 'left' | 'right' }>;
  verified: boolean;
  how_to_verify?: Record<string, string | null>;
}

export interface SearchResult {
  entities: Array<{
    entity_id: string;
    display_name: string;
    entity_type: string;
    description: string;
    emilia_score: number;
    total_receipts: number;
    verified: boolean;
  }>;
}

export interface LeaderboardResult {
  entities: Array<{
    entity_id: string;
    display_name: string;
    entity_type: string;
    emilia_score: number;
    total_receipts: number;
  }>;
}

export class EmiliaError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'EmiliaError';
    this.status = status;
  }
}

// =============================================================================
// Client
// =============================================================================

export class EmiliaClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;

  constructor(config: EmiliaConfig = {}) {
    this.baseUrl = (config.baseUrl || 'https://emiliaprotocol.ai').replace(/\/$/, '');
    this.apiKey = config.apiKey || '';
    this.timeout = config.timeout || 10000;
  }

  // ---------------------------------------------------------------------------
  // Internal fetch
  // ---------------------------------------------------------------------------

  private async request<T>(path: string, options: {
    method?: string;
    body?: unknown;
    auth?: boolean;
  } = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (options.auth) {
      if (!this.apiKey) {
        throw new EmiliaError('API key required for this operation. Pass apiKey in EmiliaClient config.', 401);
      }
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(url, {
        method: options.method || 'GET',
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      const data = await res.json();

      if (!res.ok) {
        throw new EmiliaError(data.error || `EP API error: ${res.status}`, res.status);
      }

      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Look up an entity's EMILIA Score.
   * No authentication required — scores are public by design.
   */
  async getScore(entityId: string): Promise<ScoreResult> {
    return this.request<ScoreResult>(`/api/score/${encodeURIComponent(entityId)}`);
  }

  /**
   * Submit a transaction receipt.
   * Requires API key.
   */
  async submitReceipt(input: SubmitReceiptInput): Promise<ReceiptResult> {
    return this.request<ReceiptResult>('/api/receipts/submit', {
      method: 'POST',
      auth: true,
      body: input,
    });
  }

  /**
   * Register a new entity.
   * Requires API key.
   */
  async registerEntity(input: RegisterEntityInput): Promise<RegisterResult> {
    return this.request<RegisterResult>('/api/entities/register', {
      method: 'POST',
      auth: true,
      body: input,
    });
  }

  /**
   * Verify a receipt against the on-chain Merkle root.
   * No authentication required.
   */
  async verifyReceipt(receiptId: string): Promise<VerifyResult> {
    return this.request<VerifyResult>(`/api/verify/${encodeURIComponent(receiptId)}`);
  }

  /**
   * Search for entities.
   * No authentication required.
   */
  async searchEntities(query: string, options?: {
    entityType?: 'agent' | 'merchant' | 'service_provider';
    minScore?: number;
  }): Promise<SearchResult> {
    const params = new URLSearchParams({ q: query });
    if (options?.entityType) params.set('type', options.entityType);
    if (options?.minScore) params.set('min_score', options.minScore.toString());
    return this.request<SearchResult>(`/api/entities/search?${params}`);
  }

  /**
   * Get the leaderboard.
   * No authentication required.
   */
  async getLeaderboard(options?: {
    limit?: number;
    entityType?: 'agent' | 'merchant' | 'service_provider';
  }): Promise<LeaderboardResult> {
    const params = new URLSearchParams();
    if (options?.limit) params.set('limit', Math.min(options.limit, 50).toString());
    if (options?.entityType) params.set('type', options.entityType);
    return this.request<LeaderboardResult>(`/api/leaderboard?${params}`);
  }

  // ---------------------------------------------------------------------------
  // Convenience methods
  // ---------------------------------------------------------------------------

  /**
   * Check if an entity meets a minimum trust threshold.
   * Returns true if the entity's score >= minScore.
   */
  async isTrusted(entityId: string, minScore: number = 70): Promise<boolean> {
    try {
      const result = await this.getScore(entityId);
      return result.emilia_score >= minScore && result.established;
    } catch {
      return false;
    }
  }

  /**
   * Submit a receipt and verify the entity meets a threshold in one call.
   * Returns the receipt result and whether the entity is still trusted.
   */
  async submitAndCheck(
    input: SubmitReceiptInput,
    minScore: number = 70
  ): Promise<ReceiptResult & { still_trusted: boolean }> {
    const result = await this.submitReceipt(input);
    return {
      ...result,
      still_trusted: result.entity_score.emilia_score >= minScore,
    };
  }
}

// Default export
export default EmiliaClient;
