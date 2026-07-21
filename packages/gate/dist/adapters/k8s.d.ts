export declare const K8S_ACTION_PACK: readonly (Readonly<{
    id: "k8s.namespace.delete";
    label: "Delete namespace";
    action_type: "k8s.namespace.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes an entire namespace and everything in it. Quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "k8s.workload.delete";
    label: "Delete workload";
    action_type: "k8s.workload.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes a deployment/statefulset/job. Bind namespace+kind+name.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "k8s.rbac.bind";
    label: "RBAC binding";
    action_type: "k8s.rbac.bind";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Grants cluster permissions. Privilege change → two-person rule.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "k8s.secret.delete";
    label: "Delete secret";
    action_type: "k8s.secret.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys a secret. Bind namespace+name.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const K8S_OPS: readonly string[];
export declare function createK8sManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
export declare function guardK8sMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    K8S_ACTION_PACK: readonly (Readonly<{
        id: "k8s.namespace.delete";
        label: "Delete namespace";
        action_type: "k8s.namespace.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes an entire namespace and everything in it. Quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "k8s.workload.delete";
        label: "Delete workload";
        action_type: "k8s.workload.delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes a deployment/statefulset/job. Bind namespace+kind+name.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "k8s.rbac.bind";
        label: "RBAC binding";
        action_type: "k8s.rbac.bind";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Grants cluster permissions. Privilege change → two-person rule.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "k8s.secret.delete";
        label: "Delete secret";
        action_type: "k8s.secret.delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys a secret. Bind namespace+name.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    K8S_OPS: readonly string[];
    createK8sManifest: typeof createK8sManifest;
    guardK8sMutation: typeof guardK8sMutation;
};
export default _default;
//# sourceMappingURL=k8s.d.ts.map