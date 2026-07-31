export declare const RLS_DEFINITION_BINDING_VERSION = "EP-SUPABASE-RLS-DEFINITION-v1";
/** Heuristic: is this SQL destructive (DELETE/DROP/TRUNCATE/ALTER, or UPDATE without WHERE)? */
export declare function isDestructiveSql(sql: any): boolean;
/** Canonical hash of a SQL statement, whitespace-collapsed and lowercased. */
export declare function statementHash(sql: any): string;
/** Digest the exact canonical RLS definition without placing it in evidence. */
export declare function rlsDefinitionDigest(definition: any): string;
export declare const SUPABASE_ACTION_PACK: readonly (Readonly<{
    id: "supabase.sql.destructive";
    label: "Destructive SQL";
    action_type: "supabase.sql.destructive";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "DELETE/DROP/TRUNCATE/ALTER destroys or rewrites system-of-record state. Bind the exact statement.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "supabase.data.export";
    label: "Bulk data export";
    action_type: "supabase.data.export";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves data out of its system of record. Bind table + recipient to the approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "supabase.rls.change";
    label: "RLS policy change";
    action_type: "supabase.rls.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes who can read/write rows. Row-Level-Security changes deserve the two-person rule.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const SUPABASE_OPS: readonly string[];
export declare function createSupabaseManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/**
 * Guard a destructive Supabase/Postgres mutation behind the gate.
 * @param {object} gate    a gate built with createSupabaseManifest()
 * @param {object} client  a client exposing { query(sql), export(table,recipient), alterPolicy(table,policy,def) }
 * @param {object} args    { op:'sql.destructive'|'data.export'|'rls.change', params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the statement never executes
 */
export declare function guardSupabaseMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
/** Bind a typed RLS client to the project identity returned by a trusted provider probe. */
export declare function createSupabaseAllowanceConnector({ client, }?: {
    client?: any;
}): Promise<Readonly<{}>>;
/**
 * Replace one specifically bound RLS policy under a signed Gate allowance.
 *
 * Arbitrary SQL is intentionally excluded: the wrapper binds table, policy,
 * canonical definition digest, definition version, and operation identifier,
 * then invokes only the typed alterPolicy actuator.
 */
export declare function guardSupabaseAllowanceMutation({ connector, params, operationId, ...allowanceOptions }: {
    [x: string]: any;
    connector: any;
    params: any;
    operationId: any;
}): Promise<import("../reliance-risk-crypto.js").RiskRecord>;
declare const _default: {
    SUPABASE_ACTION_PACK: readonly (Readonly<{
        id: "supabase.sql.destructive";
        label: "Destructive SQL";
        action_type: "supabase.sql.destructive";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "DELETE/DROP/TRUNCATE/ALTER destroys or rewrites system-of-record state. Bind the exact statement.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "supabase.data.export";
        label: "Bulk data export";
        action_type: "supabase.data.export";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Moves data out of its system of record. Bind table + recipient to the approval.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "supabase.rls.change";
        label: "RLS policy change";
        action_type: "supabase.rls.change";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes who can read/write rows. Row-Level-Security changes deserve the two-person rule.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    SUPABASE_OPS: readonly string[];
    createSupabaseManifest: typeof createSupabaseManifest;
    guardSupabaseMutation: typeof guardSupabaseMutation;
    guardSupabaseAllowanceMutation: typeof guardSupabaseAllowanceMutation;
    createSupabaseAllowanceConnector: typeof createSupabaseAllowanceConnector;
    isDestructiveSql: typeof isDestructiveSql;
    statementHash: typeof statementHash;
    rlsDefinitionDigest: typeof rlsDefinitionDigest;
    RLS_DEFINITION_BINDING_VERSION: string;
};
export default _default;
//# sourceMappingURL=supabase.d.ts.map