export declare const STRIPE_ACTION_PACK: readonly (Readonly<{
    id: "stripe.payout.create";
    label: "Stripe payout";
    action_type: "stripe.payout.create";
    risk: "critical";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Moves money out. Bind amount/currency/destination to a named human approval.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "stripe.refund.create";
    label: "Stripe refund";
    action_type: "stripe.refund.create";
    risk: "high";
    receipt_required: true;
    assurance_class: "class_a";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Returns funds. Bind the payment and amount so a refund cannot be silently inflated.";
    execution_binding: {
        required_fields: string[];
    };
}> | Readonly<{
    id: "stripe.bank_account.change";
    label: "Stripe payout-destination change";
    action_type: "stripe.bank_account.change";
    risk: "critical";
    receipt_required: true;
    assurance_class: "quorum";
    match: {
        protocol: string;
        tool: string;
    };
    why: "Changes WHERE future money flows. Quorum: the classic redirect-the-payouts attack.";
    execution_binding: {
        required_fields: string[];
    };
}>)[];
export declare const STRIPE_OPS: readonly string[];
export declare function createStripeManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/**
 * Guard a destructive Stripe mutation behind the gate.
 * @param {object} gate    a gate built with createStripeManifest()
 * @param {object} stripe  a Stripe-like client (the official `stripe` SDK or compatible)
 * @param {object} args    { op:'payout.create'|'refund.create'|'bank_account.change', params, receipt }
 * @throws Error{code:'EMILIA_RECEIPT_REQUIRED'} if refused — the call never reaches Stripe
 */
export declare function guardStripeMutation(gate: any, stripe: any, args: any): Promise<{
    result: any;
    reliance: any;
    execution: any;
}>;
/**
 * Bind a Stripe client to the account identity returned by a trusted provider
 * identity probe. The returned opaque connector is created during trusted
 * deployment setup; action callers cannot pair an arbitrary client with a
 * caller-asserted account string.
 */
export declare function createStripeAllowanceConnector({ stripe, }?: {
    stripe?: any;
}): Promise<Readonly<{}>>;
/**
 * Execute a typed Stripe payout under a signed Gate allowance.
 *
 * The Stripe client and credentials remain in the caller's process. This
 * adapter constructs the exact closed action that the signed allowance names;
 * generic Stripe methods are deliberately not exposed through this path.
 */
export declare function guardStripeAllowanceMutation({ connector, params, operationId, attemptGroup, ...allowanceOptions }: {
    [x: string]: any;
    connector: any;
    params: any;
    operationId: any;
    attemptGroup?: string | undefined;
}): Promise<import("../reliance-risk-crypto.js").RiskRecord> | Promise<{
    ok: boolean;
    reason: string;
}>;
declare const _default: {
    STRIPE_ACTION_PACK: readonly (Readonly<{
        id: "stripe.payout.create";
        label: "Stripe payout";
        action_type: "stripe.payout.create";
        risk: "critical";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Moves money out. Bind amount/currency/destination to a named human approval.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "stripe.refund.create";
        label: "Stripe refund";
        action_type: "stripe.refund.create";
        risk: "high";
        receipt_required: true;
        assurance_class: "class_a";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Returns funds. Bind the payment and amount so a refund cannot be silently inflated.";
        execution_binding: {
            required_fields: string[];
        };
    }> | Readonly<{
        id: "stripe.bank_account.change";
        label: "Stripe payout-destination change";
        action_type: "stripe.bank_account.change";
        risk: "critical";
        receipt_required: true;
        assurance_class: "quorum";
        match: {
            protocol: string;
            tool: string;
        };
        why: "Changes WHERE future money flows. Quorum: the classic redirect-the-payouts attack.";
        execution_binding: {
            required_fields: string[];
        };
    }>)[];
    STRIPE_OPS: readonly string[];
    createStripeManifest: typeof createStripeManifest;
    guardStripeMutation: typeof guardStripeMutation;
    createStripeAllowanceConnector: typeof createStripeAllowanceConnector;
    guardStripeAllowanceMutation: typeof guardStripeAllowanceMutation;
};
export default _default;
//# sourceMappingURL=stripe.d.ts.map