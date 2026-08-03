export declare function mongoFilterDigest(filter: unknown): string;
export declare function mongoUpdateDigest(update: unknown): string;
export declare const MONGODB_ACTION_PACK: readonly (Readonly<{
    id: "mongodb.document.delete_many";
    label: "MongoDB bulk document deletion";
    action_type: "mongodb.document.delete_many";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes a selected population from the system of record. Bind the pinned cluster, namespace, filter, and operation id.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "mongodb.document.update_many";
    label: "MongoDB bulk document update";
    action_type: "mongodb.document.update_many";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Rewrites a selected population. Bind both the selection and update documents.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "mongodb.collection.drop";
    label: "MongoDB collection drop";
    action_type: "mongodb.collection.drop";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys an entire collection. Require a distinct-person quorum bound to the exact namespace.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const MONGODB_OPS: readonly string[];
export declare function createMongoManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/** Bind the held client to a cluster identity configured outside agent input. */
export declare function createMongoConnector({ client, cluster }?: {
    client?: any;
    cluster?: string;
}): Readonly<{}>;
export declare function guardMongoMutation(gate: any, connector: any, { op, params, receipt }?: {
    op?: string;
    params?: object;
    receipt?: any;
}): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    MONGODB_ACTION_PACK: readonly (Readonly<{
        id: "mongodb.document.delete_many";
        label: "MongoDB bulk document deletion";
        action_type: "mongodb.document.delete_many";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes a selected population from the system of record. Bind the pinned cluster, namespace, filter, and operation id.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "mongodb.document.update_many";
        label: "MongoDB bulk document update";
        action_type: "mongodb.document.update_many";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Rewrites a selected population. Bind both the selection and update documents.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "mongodb.collection.drop";
        label: "MongoDB collection drop";
        action_type: "mongodb.collection.drop";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys an entire collection. Require a distinct-person quorum bound to the exact namespace.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    MONGODB_OPS: readonly string[];
    createMongoManifest: typeof createMongoManifest;
    createMongoConnector: typeof createMongoConnector;
    guardMongoMutation: typeof guardMongoMutation;
    mongoFilterDigest: typeof mongoFilterDigest;
    mongoUpdateDigest: typeof mongoUpdateDigest;
};
export default _default;
//# sourceMappingURL=mongodb.d.ts.map