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
    proof?: Array<{
        hash: string;
        position: 'left' | 'right';
    }>;
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
export declare class EmiliaError extends Error {
    status: number;
    constructor(message: string, status: number);
}
export declare class EmiliaClient {
    private baseUrl;
    private apiKey;
    private timeout;
    constructor(config?: EmiliaConfig);
    private request;
    /**
     * Look up an entity's EMILIA Score.
     * No authentication required — scores are public by design.
     */
    getScore(entityId: string): Promise<ScoreResult>;
    /**
     * Submit a transaction receipt.
     * Requires API key.
     */
    submitReceipt(input: SubmitReceiptInput): Promise<ReceiptResult>;
    /**
     * Register a new entity.
     * Requires API key.
     */
    registerEntity(input: RegisterEntityInput): Promise<RegisterResult>;
    /**
     * Verify a receipt against the on-chain Merkle root.
     * No authentication required.
     */
    verifyReceipt(receiptId: string): Promise<VerifyResult>;
    /**
     * Search for entities.
     * No authentication required.
     */
    searchEntities(query: string, options?: {
        entityType?: 'agent' | 'merchant' | 'service_provider';
        minScore?: number;
    }): Promise<SearchResult>;
    /**
     * Get the leaderboard.
     * No authentication required.
     */
    getLeaderboard(options?: {
        limit?: number;
        entityType?: 'agent' | 'merchant' | 'service_provider';
    }): Promise<LeaderboardResult>;
    /**
     * Check if an entity meets a minimum trust threshold.
     * Returns true if the entity's score >= minScore.
     */
    isTrusted(entityId: string, minScore?: number): Promise<boolean>;
    /**
     * Submit a receipt and verify the entity meets a threshold in one call.
     * Returns the receipt result and whether the entity is still trusted.
     */
    submitAndCheck(input: SubmitReceiptInput, minScore?: number): Promise<ReceiptResult & {
        still_trusted: boolean;
    }>;
}
export default EmiliaClient;
