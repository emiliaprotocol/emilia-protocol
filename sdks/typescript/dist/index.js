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
export class EmiliaError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.name = 'EmiliaError';
        this.status = status;
    }
}
// =============================================================================
// Client
// =============================================================================
export class EmiliaClient {
    baseUrl;
    apiKey;
    timeout;
    constructor(config = {}) {
        this.baseUrl = (config.baseUrl || 'https://emiliaprotocol.ai').replace(/\/$/, '');
        this.apiKey = config.apiKey || '';
        this.timeout = config.timeout || 10000;
    }
    // ---------------------------------------------------------------------------
    // Internal fetch
    // ---------------------------------------------------------------------------
    async request(path, options = {}) {
        const url = `${this.baseUrl}${path}`;
        const headers = {
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
            return data;
        }
        finally {
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
    async getScore(entityId) {
        return this.request(`/api/score/${encodeURIComponent(entityId)}`);
    }
    /**
     * Submit a transaction receipt.
     * Requires API key.
     */
    async submitReceipt(input) {
        return this.request('/api/receipts/submit', {
            method: 'POST',
            auth: true,
            body: input,
        });
    }
    /**
     * Register a new entity.
     * Requires API key.
     */
    async registerEntity(input) {
        return this.request('/api/entities/register', {
            method: 'POST',
            auth: true,
            body: input,
        });
    }
    /**
     * Verify a receipt against the on-chain Merkle root.
     * No authentication required.
     */
    async verifyReceipt(receiptId) {
        return this.request(`/api/verify/${encodeURIComponent(receiptId)}`);
    }
    /**
     * Search for entities.
     * No authentication required.
     */
    async searchEntities(query, options) {
        const params = new URLSearchParams({ q: query });
        if (options?.entityType)
            params.set('type', options.entityType);
        if (options?.minScore)
            params.set('min_score', options.minScore.toString());
        return this.request(`/api/entities/search?${params}`);
    }
    /**
     * Get the leaderboard.
     * No authentication required.
     */
    async getLeaderboard(options) {
        const params = new URLSearchParams();
        if (options?.limit)
            params.set('limit', Math.min(options.limit, 50).toString());
        if (options?.entityType)
            params.set('type', options.entityType);
        return this.request(`/api/leaderboard?${params}`);
    }
    // ---------------------------------------------------------------------------
    // Convenience methods
    // ---------------------------------------------------------------------------
    /**
     * Check if an entity meets a minimum trust threshold.
     * Returns true if the entity's score >= minScore.
     */
    async isTrusted(entityId, minScore = 70) {
        try {
            const result = await this.getScore(entityId);
            return result.emilia_score >= minScore && result.established;
        }
        catch {
            return false;
        }
    }
    /**
     * Submit a receipt and verify the entity meets a threshold in one call.
     * Returns the receipt result and whether the entity is still trusted.
     */
    async submitAndCheck(input, minScore = 70) {
        const result = await this.submitReceipt(input);
        return {
            ...result,
            still_trusted: result.entity_score.emilia_score >= minScore,
        };
    }
}
// Default export
export default EmiliaClient;
