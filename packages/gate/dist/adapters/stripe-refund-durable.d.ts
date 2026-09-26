import { type CreateProposalToEffectPostgresStoreOptions, type ProposalToEffectPostgresAttemptSnapshot, type ProposalToEffectPostgresStore } from '../proposal-to-effect-postgres.js';
import type { ConsequenceAttemptBinding } from '../proposal-to-effect.js';
declare const PROFILE = "EMILIA-STRIPE-REFUND-DURABLE-v1";
/**
 * The durable profile's own action type. Gate refuses a receipt whose signed
 * action_type differs from the resolved manifest entry, and both Stripe refund
 * paths bind action_type as a material execution field. A receipt minted for
 * this profile therefore cannot execute on the legacy guardStripeMutation()
 * refund path ('stripe.refund.create'), and a legacy refund receipt cannot
 * execute here.
 */
export declare const STRIPE_REFUND_DURABLE_ACTION_TYPE = "stripe.refund.durable.create";
type RefundParameters = {
    payment_intent: string;
    amount: number;
    operation_id: string;
};
type StripeRefundRecord = {
    id?: unknown;
    payment_intent?: unknown;
    amount?: unknown;
    created?: unknown;
    status?: unknown;
    metadata?: unknown;
};
type StripeClient = {
    accounts: {
        retrieve(): Promise<{
            id?: unknown;
        }>;
    };
    refunds: {
        create(input: Record<string, unknown>, options: {
            idempotencyKey: string;
        }): Promise<StripeRefundRecord>;
        list(input: {
            payment_intent: string;
            limit: number;
        }): Promise<{
            data?: unknown;
            has_more?: unknown;
        }>;
    };
};
type GateRequirement = {
    receipt_required?: boolean;
    action_type?: string;
    execution_binding?: {
        required_fields?: string[];
    };
};
type Gate = {
    check(input: Record<string, unknown>): Promise<{
        allow?: boolean;
        reason?: string;
        requirement?: GateRequirement;
    }>;
    run(input: Record<string, unknown>, effect: (authorization: {
        allow?: boolean;
        requirement?: GateRequirement;
    }) => Promise<unknown>): Promise<{
        ok?: boolean;
        result?: unknown;
        authorization?: {
            reason?: string;
        };
        packet?: unknown;
        execution?: unknown;
    }>;
};
export type StripeRefundDurableStore = Pick<ProposalToEffectPostgresStore, 'reserve' | 'transition' | 'reconcile' | 'read' | 'recover' | 'durable' | 'ownershipFenced' | 'compareAndSwap' | 'atomicEvidenceBinding'>;
export interface StripeRefundDurableConnector {
    readonly profile: typeof PROFILE;
    readonly account_id: string;
    readonly tenant_id: string;
    readonly environment: string;
}
/**
 * Build a manifest whose refund receipt uses this profile's own action type
 * and binds the connector tenant and environment and the provider account as
 * well as the payment, amount, and operation. The direct adapter's older
 * manifest is intentionally not changed and is refused by this connector.
 */
export declare function createStripeDurableRefundManifest(extraActions?: never[]): {
    '@version': string;
    actions: any[];
};
/** Deterministic PTE digests: no parallel journal or process-local binding map. */
export declare function stripeRefundAttemptDigests(binding: ConsequenceAttemptBinding): {
    operation_digest: `sha256:${string}`;
    action_digest: `sha256:${string}`;
    config_digest: `sha256:${string}`;
};
/** Configure the existing PTE PostgreSQL machinery for this Stripe profile. */
export declare function createStripeRefundDurableStore(options: Omit<CreateProposalToEffectPostgresStoreOptions, 'resolve_binding_digests' | 'authorize_recovery'> & {
    tenant_id: string;
    provider_account_id: string;
    environment: string;
    authorize_recovery(snapshot: ProposalToEffectPostgresAttemptSnapshot): Promise<boolean> | boolean;
}): ProposalToEffectPostgresStore;
/**
 * The operation resolver must read the business system's immutable refund job,
 * not echo agent-supplied payment fields or mint an ID for each retry.
 */
export declare function createStripeRefundDurableConnector(input: {
    stripe: StripeClient;
    gate: Gate;
    store: StripeRefundDurableStore;
    tenant_id: string;
    environment: string;
    /** Stable, server-only key; retain it for the full recovery window. */
    metadata_hmac_sha256_key: Uint8Array;
    resolve_operation(reference: string): Promise<RefundParameters> | RefundParameters;
}): Promise<StripeRefundDurableConnector>;
/**
 * At most one provider-entry attempt for a stable business operation on this
 * covered connector, assuming every mutation uses it, each Stripe account has
 * one owning tenant for this profile, and the durable PTE store is configured
 * correctly. An existing, uncertain or terminal attempt
 * never calls Stripe again, even with fresh receipts or after Stripe's
 * idempotency-key retention window.
 *
 * Before the first refunds.create for an operation, the connector lists the
 * payment intent's refunds under the recovery rules. A matching refund (for
 * example after the attempt row was lost to a restore) commits from that
 * refund without creating; a conflicting, ambiguous, incomplete or unavailable
 * view leaves the attempt INDETERMINATE without creating. The lookup is not
 * atomic with the create: two setups that lack each other's attempt row and
 * create at the same instant can both see no refund.
 */
export declare function guardStripeRefundDurable(connector: StripeRefundDurableConnector, input: {
    operation_reference: string;
    receipt: unknown;
}): Promise<{
    ok: boolean;
    state: string;
    reason: string | undefined;
} | {
    refund: {} | null;
    reliance: {} | null;
    execution: {} | null;
    reason?: string | undefined;
    ok: boolean;
    state: string;
}>;
/**
 * Recovery never calls refunds.create. A bounded list query supplies positive
 * evidence only if exactly one matching refund is found, no other listed refund
 * carries this operation's metadata, and the page is complete. Empty,
 * incomplete, unavailable, or conflicting results stay INDETERMINATE; none
 * proves NOT_COMMITTED.
 * The server-secret tag narrows accidental/external collision, but it can be
 * copied by an actor with access to both the Stripe metadata and refund-write
 * credentials. A matching object proves existence, not exclusive authorship.
 */
export declare function reconcileStripeRefundDurable(connector: StripeRefundDurableConnector, operation_reference: string): Promise<{
    ok: boolean;
    state: string;
    reason: string | undefined;
    refund_id?: undefined;
} | {
    ok: boolean;
    state: string;
    refund_id: string;
    reason?: undefined;
}>;
declare const _default: {
    STRIPE_REFUND_DURABLE_ACTION_TYPE: string;
    createStripeDurableRefundManifest: typeof createStripeDurableRefundManifest;
    stripeRefundAttemptDigests: typeof stripeRefundAttemptDigests;
    createStripeRefundDurableStore: typeof createStripeRefundDurableStore;
    createStripeRefundDurableConnector: typeof createStripeRefundDurableConnector;
    guardStripeRefundDurable: typeof guardStripeRefundDurable;
    reconcileStripeRefundDurable: typeof reconcileStripeRefundDurable;
};
export default _default;
//# sourceMappingURL=stripe-refund-durable.d.ts.map