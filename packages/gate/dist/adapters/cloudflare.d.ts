/**
 * @typedef {object} CloudflareClient
 * @property {(input: {zone: string, recordId: string}) => any} deleteDnsRecord
 * @property {(input: {zone: string}) => any} deleteZone
 * @property {(input: {zone: string, ruleId: string, enabled: boolean}) => any} setFirewallRule
 */
export declare const CLOUDFLARE_ACTION_PACK: readonly (Readonly<{
    id: "cloudflare.dns.delete";
    label: "Delete DNS record";
    action_type: "cloudflare.dns.delete";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Removing DNS can take a service offline or enable takeover. Bind zone+record.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "cloudflare.zone.delete";
    label: "Delete zone";
    action_type: "cloudflare.zone.delete";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Deletes an entire zone. Quorum.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "cloudflare.firewall.disable";
    label: "Disable firewall rule";
    action_type: "cloudflare.firewall.disable";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Disabling WAF/firewall opens the perimeter. Quorum + bind zone+rule.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const CLOUDFLARE_OPS: readonly string[];
/** @param {object[]} extra */
export declare function createCloudflareManifest(extra?: never[]): {
    '@version': string;
    actions: any[];
};
export declare function guardCloudflareMutation(gate: any, client: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
declare const _default: {
    CLOUDFLARE_ACTION_PACK: readonly (Readonly<{
        id: "cloudflare.dns.delete";
        label: "Delete DNS record";
        action_type: "cloudflare.dns.delete";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Removing DNS can take a service offline or enable takeover. Bind zone+record.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "cloudflare.zone.delete";
        label: "Delete zone";
        action_type: "cloudflare.zone.delete";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Deletes an entire zone. Quorum.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "cloudflare.firewall.disable";
        label: "Disable firewall rule";
        action_type: "cloudflare.firewall.disable";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Disabling WAF/firewall opens the perimeter. Quorum + bind zone+rule.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    CLOUDFLARE_OPS: readonly string[];
    createCloudflareManifest: typeof createCloudflareManifest;
    guardCloudflareMutation: typeof guardCloudflareMutation;
};
export default _default;
//# sourceMappingURL=cloudflare.d.ts.map