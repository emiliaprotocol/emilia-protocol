/**
 * @typedef {object} AwsIamClient
 * @property {(input: {UserName: string, PolicyArn: string}) => any} attachUserPolicy
 * @property {(input: {UserName: string}) => any} createAccessKey
 * @property {(input: {UserName: string}) => any} deleteUser
 */
/**
 * @typedef {object} AwsEc2Client
 * @property {(input: {GroupId: string, CidrIp: string, FromPort: number, ToPort: number, IpProtocol: string}) => any} authorizeSecurityGroupIngress
 */
/** @typedef {{ iam: AwsIamClient, ec2: AwsEc2Client }} AwsClient */
export declare const AWS_ACTION_PACK: readonly (Readonly<{
    id: "aws.iam.attach_policy";
    label: "IAM attach policy";
    action_type: "aws.iam.attach_policy";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Grants permissions. Privilege escalation deserves the two-person rule.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "aws.iam.create_access_key";
    label: "IAM create access key";
    action_type: "aws.iam.create_access_key";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Mints long-lived credentials. Bind the user to a named approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "aws.iam.delete_user";
    label: "IAM delete user";
    action_type: "aws.iam.delete_user";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Destroys an identity. Bind the target user.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "aws.ec2.authorize_ingress";
    label: "Open security-group ingress";
    action_type: "aws.ec2.authorize_ingress";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Opens the network. Bind group/CIDR/port so 0.0.0.0/0:22 cannot slip through.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const AWS_OPS: readonly string[];
/** @param {object[]} extraActions */
export declare function createAwsManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/**
 * Guard a high-blast-radius AWS mutation behind the gate.
 * @param {object} gate    a gate built with createAwsManifest()
 * @param {AwsClient} client  { iam: {attachUserPolicy, createAccessKey, deleteUser}, ec2: {authorizeSecurityGroupIngress} }
 * @param {{ op: string, params?: object, receipt?: any }} args    { op, params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches AWS
 */
export declare function guardAwsMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    AWS_ACTION_PACK: readonly (Readonly<{
        id: "aws.iam.attach_policy";
        label: "IAM attach policy";
        action_type: "aws.iam.attach_policy";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Grants permissions. Privilege escalation deserves the two-person rule.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "aws.iam.create_access_key";
        label: "IAM create access key";
        action_type: "aws.iam.create_access_key";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Mints long-lived credentials. Bind the user to a named approval.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "aws.iam.delete_user";
        label: "IAM delete user";
        action_type: "aws.iam.delete_user";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Destroys an identity. Bind the target user.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "aws.ec2.authorize_ingress";
        label: "Open security-group ingress";
        action_type: "aws.ec2.authorize_ingress";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Opens the network. Bind group/CIDR/port so 0.0.0.0/0:22 cannot slip through.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    AWS_OPS: readonly string[];
    createAwsManifest: typeof createAwsManifest;
    guardAwsMutation: typeof guardAwsMutation;
};
export default _default;
//# sourceMappingURL=aws.d.ts.map