export declare const JIRA_ACTION_PACK: readonly (Readonly<{
    id: "jira.issue.bulk_delete";
    label: "Bulk delete issues";
    action_type: "jira.issue.bulk_delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Mass-destroys issues. Bind the exact JQL.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "jira.project.delete";
    label: "Delete project";
    action_type: "jira.project.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes a project and its issues. Quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "jira.permission.grant";
    label: "Grant permission";
    action_type: "jira.permission.grant";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes who can act. Quorum + bind project/principal/role.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const JIRA_OPS: any;
export declare function createJiraManifest(extra?: never[]): any;
export declare function guardJiraMutation(gate: any, client: any, args: any): any;
declare const _default: {
    JIRA_ACTION_PACK: readonly (Readonly<{
        id: "jira.issue.bulk_delete";
        label: "Bulk delete issues";
        action_type: "jira.issue.bulk_delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Mass-destroys issues. Bind the exact JQL.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "jira.project.delete";
        label: "Delete project";
        action_type: "jira.project.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes a project and its issues. Quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "jira.permission.grant";
        label: "Grant permission";
        action_type: "jira.permission.grant";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes who can act. Quorum + bind project/principal/role.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    JIRA_OPS: any;
    createJiraManifest: typeof createJiraManifest;
    guardJiraMutation: typeof guardJiraMutation;
};
export default _default;
//# sourceMappingURL=jira.d.ts.map