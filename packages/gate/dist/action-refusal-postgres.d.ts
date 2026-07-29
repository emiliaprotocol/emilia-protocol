/** Durable, tenant-scoped replay protection for action-refusal acceptance. */
import type { ActionRefusalReplayStore } from './action-refusal-statement.js';
export declare const ACTION_REFUSAL_REPLAY_FUNCTION = "emilia_gate_evidence.consume_action_refusal";
export declare const ACTION_REFUSAL_POSTGRES_SQL: Readonly<{
    consume: "SELECT accepted, reason\nFROM emilia_gate_evidence.consume_action_refusal($1, $2, $3, $4, $5)";
}>;
/**
 * The query credential is the authorization boundary. The migration grants it
 * EXECUTE on one SECURITY DEFINER function and no direct table writes.
 */
export declare function createPostgresActionRefusalReplayStore({ query, tenantId, gateId, }?: {
    query?: (sql: string, params?: any[]) => Promise<any>;
    tenantId?: string;
    gateId?: string;
}): ActionRefusalReplayStore & {
    scope: Readonly<{
        tenantId: string;
        gateId: string;
    }>;
};
declare const _default: {
    ACTION_REFUSAL_REPLAY_FUNCTION: string;
    ACTION_REFUSAL_POSTGRES_SQL: Readonly<{
        consume: "SELECT accepted, reason\nFROM emilia_gate_evidence.consume_action_refusal($1, $2, $3, $4, $5)";
    }>;
    createPostgresActionRefusalReplayStore: typeof createPostgresActionRefusalReplayStore;
};
export default _default;
//# sourceMappingURL=action-refusal-postgres.d.ts.map