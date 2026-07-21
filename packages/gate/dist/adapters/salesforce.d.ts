export declare const SALESFORCE_ACTION_PACK: readonly (Readonly<{
    id: "salesforce.records.bulk_delete";
    label: "Bulk delete records";
    action_type: "salesforce.records.bulk_delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Mass-destroys CRM records. Bind object + the exact SOQL.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "salesforce.data.export";
    label: "Bulk data export";
    action_type: "salesforce.data.export";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Exfiltrates CRM data. Bind object + recipient.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "salesforce.permission_set.assign";
    label: "Assign permission set";
    action_type: "salesforce.permission_set.assign";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Grants privileges. Quorum + bind user + permission set.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const SALESFORCE_OPS: readonly string[];
export declare function createSalesforceManifest(extra?: never[]): {
    '@version': string;
    actions: any[];
};
export declare function guardSalesforceMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    SALESFORCE_ACTION_PACK: readonly (Readonly<{
        id: "salesforce.records.bulk_delete";
        label: "Bulk delete records";
        action_type: "salesforce.records.bulk_delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Mass-destroys CRM records. Bind object + the exact SOQL.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "salesforce.data.export";
        label: "Bulk data export";
        action_type: "salesforce.data.export";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Exfiltrates CRM data. Bind object + recipient.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "salesforce.permission_set.assign";
        label: "Assign permission set";
        action_type: "salesforce.permission_set.assign";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Grants privileges. Quorum + bind user + permission set.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    SALESFORCE_OPS: readonly string[];
    createSalesforceManifest: typeof createSalesforceManifest;
    guardSalesforceMutation: typeof guardSalesforceMutation;
};
export default _default;
//# sourceMappingURL=salesforce.d.ts.map