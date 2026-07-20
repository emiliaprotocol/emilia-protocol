export declare const TERRAFORM_ACTION_PACK: readonly (Readonly<{
    id: "terraform.apply.destroy";
    label: "Terraform destroy";
    action_type: "terraform.apply.destroy";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Tears down real infrastructure. Bind the workspace + plan hash; quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "terraform.state.rm";
    label: "Terraform state rm";
    action_type: "terraform.state.rm";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Detaches a resource from state (orphans real infra). Bind workspace+address.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "terraform.workspace.delete";
    label: "Terraform workspace delete";
    action_type: "terraform.workspace.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes a workspace and its state. Bind the workspace.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const TERRAFORM_OPS: any;
export declare function createTerraformManifest(extraActions?: never[]): any;
export declare function guardTerraformMutation(gate: any, runner: any, args: any): any;
declare const _default: {
    TERRAFORM_ACTION_PACK: readonly (Readonly<{
        id: "terraform.apply.destroy";
        label: "Terraform destroy";
        action_type: "terraform.apply.destroy";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Tears down real infrastructure. Bind the workspace + plan hash; quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "terraform.state.rm";
        label: "Terraform state rm";
        action_type: "terraform.state.rm";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Detaches a resource from state (orphans real infra). Bind workspace+address.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "terraform.workspace.delete";
        label: "Terraform workspace delete";
        action_type: "terraform.workspace.delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes a workspace and its state. Bind the workspace.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    TERRAFORM_OPS: any;
    createTerraformManifest: typeof createTerraformManifest;
    guardTerraformMutation: typeof guardTerraformMutation;
};
export default _default;
//# sourceMappingURL=terraform.d.ts.map