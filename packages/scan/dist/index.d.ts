import { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS } from '../risk-packs.js';
export interface ActionInput {
    name: string;
    description?: string;
    annotations?: Record<string, unknown>;
    http_method?: string;
    [key: string]: unknown;
}
export interface Classification {
    decision: 'gate' | 'review_fail_closed' | 'pass_through' | 'review';
    receipt_required: boolean;
    assurance_class?: string;
    category?: string;
    label?: string;
    required_fields?: string[];
    why?: string;
    reason: string;
    confidence: 'low' | 'medium' | 'high';
}
export declare function classifyAction(action: unknown): Classification;
export declare function scanActions(actions: ActionInput[], { source, blindSpots }?: {
    source?: string;
    blindSpots?: string[];
}): {
    source: string;
    counts: {
        total: number;
        gate: number;
        review_fail_closed: number;
        pass_through: number;
        review: number;
    };
    results: {
        action: ActionInput;
        classification: Classification;
    }[];
    manifest: {
        '@version': string;
        actions: Record<string, unknown>[];
    };
    blindSpots: string[];
};
export declare const KNOWN_CATEGORIES: string[];
export { HIGH_RISK_ACTION_PACKS, DEFAULT_PASS_THROUGH_ACTIONS };
//# sourceMappingURL=index.d.ts.map