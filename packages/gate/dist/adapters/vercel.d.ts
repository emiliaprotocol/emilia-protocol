export declare const SECRET_VALUE_BINDING_VERSION = "EP-VERCEL-SECRET-VALUE-v1";
/** Digest an exact secret value for receipt binding; callers must never log it. */
export declare function secretValueDigest(value: any): any;
export declare const VERCEL_ACTION_PACK: readonly (Readonly<{
    id: "vercel.deploy.promote";
    label: "Promote to production";
    action_type: "vercel.deploy.promote";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes live production. Quorum for the prod cutover.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "vercel.project.delete";
    label: "Delete project";
    action_type: "vercel.project.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys a project and its deployments. Bind the project.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "vercel.env.set";
    label: "Set env / secret";
    action_type: "vercel.env.set";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes production secrets/config. Bind project+key+target.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const VERCEL_OPS: any;
export declare function createVercelManifest(extra?: never[]): any;
export declare function guardVercelMutation(gate: any, client: any, args: any): any;
declare const _default: {
    VERCEL_ACTION_PACK: readonly (Readonly<{
        id: "vercel.deploy.promote";
        label: "Promote to production";
        action_type: "vercel.deploy.promote";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes live production. Quorum for the prod cutover.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "vercel.project.delete";
        label: "Delete project";
        action_type: "vercel.project.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys a project and its deployments. Bind the project.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "vercel.env.set";
        label: "Set env / secret";
        action_type: "vercel.env.set";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes production secrets/config. Bind project+key+target.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    VERCEL_OPS: any;
    SECRET_VALUE_BINDING_VERSION: string;
    secretValueDigest: typeof secretValueDigest;
    createVercelManifest: typeof createVercelManifest;
    guardVercelMutation: typeof guardVercelMutation;
};
export default _default;
//# sourceMappingURL=vercel.d.ts.map