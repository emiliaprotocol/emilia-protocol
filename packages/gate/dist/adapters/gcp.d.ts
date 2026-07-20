export declare const GCP_ACTION_PACK: readonly (Readonly<{
    id: "gcp.iam.set_policy";
    label: "GCP IAM set policy";
    action_type: "gcp.iam.set_policy";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Grants cloud permissions. Bind resource+member+role; quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "gcp.sa_key.create";
    label: "GCP service-account key create";
    action_type: "gcp.sa_key.create";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Mints long-lived cloud credentials. Bind the service account.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "gcp.project.delete";
    label: "GCP project delete";
    action_type: "gcp.project.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes an entire project. Quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "gcp.storage.bucket_delete";
    label: "GCP bucket delete";
    action_type: "gcp.storage.bucket_delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys a storage bucket and its objects. Bind the bucket.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const GCP_OPS: any;
export declare function createGcpManifest(extraActions?: never[]): any;
export declare function guardGcpMutation(gate: any, client: any, args: any): any;
declare const _default: {
    GCP_ACTION_PACK: readonly (Readonly<{
        id: "gcp.iam.set_policy";
        label: "GCP IAM set policy";
        action_type: "gcp.iam.set_policy";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Grants cloud permissions. Bind resource+member+role; quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "gcp.sa_key.create";
        label: "GCP service-account key create";
        action_type: "gcp.sa_key.create";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Mints long-lived cloud credentials. Bind the service account.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "gcp.project.delete";
        label: "GCP project delete";
        action_type: "gcp.project.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes an entire project. Quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "gcp.storage.bucket_delete";
        label: "GCP bucket delete";
        action_type: "gcp.storage.bucket_delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys a storage bucket and its objects. Bind the bucket.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    GCP_OPS: any;
    createGcpManifest: typeof createGcpManifest;
    guardGcpMutation: typeof guardGcpMutation;
};
export default _default;
//# sourceMappingURL=gcp.d.ts.map