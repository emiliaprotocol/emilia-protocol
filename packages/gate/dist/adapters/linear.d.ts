export declare const LINEAR_ACTION_PACK: readonly (Readonly<{
    id: "linear.issue.delete";
    label: "Delete issue";
    action_type: "linear.issue.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys an issue. Bind the issue id.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "linear.issue.bulk_delete";
    label: "Bulk delete issues";
    action_type: "linear.issue.bulk_delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Mass-destroys issues. Bind the exact query.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "linear.team.delete";
    label: "Delete team";
    action_type: "linear.team.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes a team and its issues. Quorum.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const LINEAR_OPS: readonly string[];
export declare function createLinearManifest(extra?: never[]): {
    '@version': string;
    actions: any[];
};
export declare function guardLinearMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    LINEAR_ACTION_PACK: readonly (Readonly<{
        id: "linear.issue.delete";
        label: "Delete issue";
        action_type: "linear.issue.delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys an issue. Bind the issue id.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "linear.issue.bulk_delete";
        label: "Bulk delete issues";
        action_type: "linear.issue.bulk_delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Mass-destroys issues. Bind the exact query.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "linear.team.delete";
        label: "Delete team";
        action_type: "linear.team.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes a team and its issues. Quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    LINEAR_OPS: readonly string[];
    createLinearManifest: typeof createLinearManifest;
    guardLinearMutation: typeof guardLinearMutation;
};
export default _default;
//# sourceMappingURL=linear.d.ts.map