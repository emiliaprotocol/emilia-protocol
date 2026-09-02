/** Versioned derivation string. Changing any input rule changes this label. */
export declare const PROVIDER_REPLAY_KEY_VERSION = "EP-PROVIDER-REPLAY-KEY-v1";
/** Versioned carriage table. Rows are added under a new label, never mutated. */
export declare const PROVIDER_CARRIAGE_TABLE_VERSION = "EP-PROVIDER-REPLAY-CARRIAGE-v1";
/**
 * Version label for the derivation of an authorization INSTANCE digest from an
 * authorization artifact plus the one material action it authorizes.
 */
export declare const AUTHORIZATION_INSTANCE_VERSION = "EP-AUTHORIZATION-INSTANCE-v1";
export type ProviderReplayKeyRefusal = 'authorization_digest_invalid' | 'caid_invalid' | 'provider_env_invalid' | 'attempt_group_invalid' | 'slot_spec_invalid' | 'slot_id_invalid' | 'slot_charset_invalid' | 'slot_encoded_length_invalid' | 'slot_prefix_invalid' | 'slot_prefix_charset_violation' | 'slot_max_length_invalid' | 'slot_length_exceeds_max' | 'slot_capacity_insufficient' | 'slot_content_rule_violation' | 'derivation_input_uncanonicalizable';
export interface ProviderSlotSpec {
    /** Stable identifier of the carrier slot; enters the derivation preimage. */
    readonly slot_id: string;
    /** Characters the provider accepts in this slot. Order is significant. */
    readonly charset: string;
    /** Number of derived characters to emit (excludes any literal prefix). */
    readonly encoded_length: number;
    /** Total field length the provider accepts, prefix included. */
    readonly max_length: number;
    /** Literal prefix the provider or our own record format requires. */
    readonly prefix?: string;
    /** Whether the slot's charset also constrains the prefix. */
    readonly charset_applies_to_prefix?: boolean;
    /** Refuse below this many bits carried by the encoded portion. */
    readonly min_entropy_bits?: number;
    /** The final value must not start with any of these. */
    readonly forbid_leading?: readonly string[];
    /** The final value must not end with any of these. */
    readonly forbid_trailing?: readonly string[];
    /** The final value must not contain any of these. */
    readonly forbid_substrings?: readonly string[];
}
export interface ProviderReplayKeyInput {
    /** sha256:<hex> over the exact authorization instance. See authorizationInstanceDigest. */
    readonly authorization_digest: string;
    /** A full CAID string, or the registered action-type identifier of the action. */
    readonly caid: string;
    /** Provider environment: which account, network, region and mode this key lands in. */
    readonly provider_env: string;
    /**
     * Attempt group. The SAME group under the SAME authorization always yields the
     * SAME key, which is what makes a legitimate retry return the provider's stored
     * result. A different authorization always yields a different key regardless of
     * group. Changing the group under one authorization deliberately releases the
     * provider-side fence for that authorization and must be an explicit, recorded
     * operator act, never a default retry behaviour.
     */
    readonly attempt_group: string;
    readonly slot_spec: ProviderSlotSpec;
}
export interface ProviderReplayKeyResult {
    readonly ok: true;
    /** The value to place in the provider's slot, prefix included. */
    readonly key: string;
    readonly slot_id: string;
    /** Bits of the 256-bit MAC actually carried by the encoded portion. */
    readonly entropy_bits: number;
    readonly derivation: {
        readonly version: string;
        readonly authorization_digest: string;
        readonly caid: string;
        readonly provider_env: string;
        readonly attempt_group: string;
        readonly slot_id: string;
    };
}
export interface ProviderReplayKeyRefusalResult {
    readonly ok: false;
    readonly reason: ProviderReplayKeyRefusal;
    /** Human-readable detail. Safe to log; carries no secret material. */
    readonly detail: string;
}
export type ProviderReplayKeyOutcome = ProviderReplayKeyResult | ProviderReplayKeyRefusalResult;
/**
 * Derive the value to place in a provider's caller-chosen replay slot.
 *
 * Same authorization instance + same attempt group + same slot => same key, on
 * any machine, offline, forever. Different authorization instance => different
 * key. Different slot => different key, so a value observed in one carrier can
 * never be replayed into another.
 */
export declare function deriveProviderReplayKey(input: ProviderReplayKeyInput): ProviderReplayKeyOutcome;
export declare function deriveProviderReplayKey(authorizationDigest: string, caid: string, providerEnv: string, attemptGroup: string, slotSpec: ProviderSlotSpec): ProviderReplayKeyOutcome;
/**
 * Recompute and compare. This is what a reconciler runs against a value it read
 * out of a provider's own authenticated record: it establishes only that the
 * value recomputes from the authorization the reconciler holds. It establishes
 * nothing about whether the provider executed, accepted, or attested anything.
 */
export declare function matchesProviderReplayKey(candidate: unknown, input: ProviderReplayKeyInput): {
    ok: true;
} | {
    ok: false;
    reason: ProviderReplayKeyRefusal | 'replay_key_mismatch';
    detail: string;
};
/**
 * Bind an authorization artifact to the ONE material action it authorizes and
 * return the instance digest the derivation consumes.
 *
 * `material_action` must exclude any request-wrapper field (an operation id, a
 * request id, a timestamp). Excluding the wrapper is what makes a retry of one
 * action produce the same provider key; including it would mint a new provider
 * key per attempt and defeat the whole mechanism.
 */
export declare function authorizationInstanceDigest({ authorization_digest: authorizationDigest, material_action: materialAction, profile, }: {
    authorization_digest: string;
    material_action: unknown;
    profile: string;
}): {
    ok: true;
    digest: string;
} | {
    ok: false;
    reason: string;
    detail: string;
};
export declare const MCP_META_REPLAY_KEY = "ai.emiliaprotocol/authorization-replay-key";
export declare const PROVIDER_SLOT_SPECS: Readonly<{
    /** MCP tools/call params._meta member. */
    'mcp.tools-call.meta': ProviderSlotSpec;
    /** Stripe Idempotency-Key request header. */
    'stripe.idempotency-key': ProviderSlotSpec;
    /** ERC-3009 bytes32 nonce, hex encoded with the 0x prefix. */
    'eip3009.nonce': ProviderSlotSpec;
    /** ISO 20022 EndToEndIdentification, Max35Text under the SEPA Latin set. */
    'iso20022.end-to-end-id': ProviderSlotSpec;
    /** AWS EC2 RunInstances ClientToken: up to 64 ASCII characters. */
    'aws.ec2.run-instances.client-token': ProviderSlotSpec;
    /**
     * EMILIA action-escrow provider release key. Not a third-party carrier: this
     * is our own record format, kept in the same derivation so the escrow key and
     * a carrier key are produced by one rule.
     */
    'ep.action-escrow.release': ProviderSlotSpec;
}>;
/**
 * Per-carrier facts an adapter needs before it puts a derived value in a slot.
 *
 * VERIFICATION RULE. Every field whose value is the literal string 'unverified'
 * was NOT confirmed from the provider's own documentation during the run that
 * wrote this table. Do not guess and do not fill one in from recollection.
 * Replace it only with text traced to a provider document you opened, and add
 * the locator to `sources`.
 */
export interface CarriageRow {
    readonly id: string;
    readonly carrier: string;
    readonly slot: string;
    readonly slot_spec: ProviderSlotSpec;
    /** Field length and charset as the provider states them. */
    readonly slot_length: string;
    readonly slot_charset: string;
    /** How long the provider keeps the key for duplicate detection. */
    readonly retention: string;
    /** What the key is unique within. */
    readonly scope: string;
    /** Whether a party on the dispatch path can rewrite the field. */
    readonly intermediary_rewrite: string;
    /** Where the value comes back in the provider's own authenticated record. */
    readonly echo: string;
    /** What the provider does on same key, different parameters. */
    readonly mismatch_behaviour: string;
    /** Documents opened while writing this row. */
    readonly sources: readonly string[];
    /** Anything an adapter author would otherwise get wrong. */
    readonly notes: string;
}
export declare const PROVIDER_CARRIAGE_TABLE: readonly CarriageRow[];
export declare function getCarriageRow(id: string): CarriageRow | null;
/**
 * Derive the value for the MCP tools/call `_meta` member.
 *
 * The CAID covers the content of the call under CAID type tool.call.1: target,
 * tool and the complete argument object, with NO occurrence. The model-issued
 * call id is the attempt group instead. That split is what produces the three
 * server outcomes the thesis needs:
 *
 *   same call id retried              -> same key            -> stored result
 *   different call id, same content   -> different key,
 *                                        same content digest -> probable duplicate
 *   different content                 -> different key,
 *                                        different digest    -> fresh call
 *
 * `target` is the stable identity of the service that will execute the call.
 * Changing it changes the content digest and the key, which is the point: a
 * key minted for one target cannot be presented at another.
 */
export declare function deriveMcpToolCallReplayKey({ authorization_digest: authorizationDigest, target, tool, args, call_id: callId, server_env: serverEnv, }: {
    authorization_digest: string;
    target: string;
    tool: string;
    args: unknown;
    call_id: string;
    server_env: string;
}): (ProviderReplayKeyResult & {
    content_digest: string;
}) | ProviderReplayKeyRefusalResult;
export type McpReplayOutcome = 'fresh' | 'stored_result' | 'in_flight_refused' | 'probable_duplicate_flagged' | 'key_content_mismatch_refused';
/**
 * The server half of the MCP row, as an in-memory ledger.
 *
 * This is what an MCP server that adopts the key would do before dispatch. It
 * is deliberately small and deliberately NOT a claim that any MCP server does
 * this today: the base protocol defines no duplicate detection at all, so this
 * ledger is a proposal in runnable form.
 *
 * `probable_duplicate_flagged` never silently dedupes. It reports; the caller
 * decides. Silently collapsing two distinct model calls with identical content
 * would drop a legitimate second effect.
 */
export declare function createMcpReplayLedger({ windowMs }?: {
    windowMs?: number | undefined;
}): {
    windowMs: number;
    /** Decide what to do with an inbound call. Never throws. */
    evaluate({ key, contentDigest, now }: {
        key: string;
        contentDigest: string;
        now?: number;
    }): {
        outcome: McpReplayOutcome;
        reason: string;
        result?: unknown;
        priorKeys?: string[];
    };
    begin({ key, contentDigest, now }: {
        key: string;
        contentDigest: string;
        now?: number;
    }): void;
    complete({ key, result, now }: {
        key: string;
        result: unknown;
        now?: number;
    }): boolean;
};
/**
 * THE MEASUREMENT THAT DECIDES THE THESIS.
 *
 * The mechanism has two halves. The JOIN half (a party holding the
 * authorization recomputes the provider's reference and joins the provider's
 * own record to it with no lookup table) holds for as long as the provider
 * keeps that record, which is normally forever. The CONSUMPTION half (the
 * provider's own duplicate-detection engine refuses a second effect under one
 * authorization) holds only while the provider still remembers the key.
 *
 * So the consumption half is true exactly when the authorization's usable
 * lifetime is shorter than the provider's key retention. Where it is not, the
 * mechanism is an adapter feature, not a fence.
 */
export declare const PROVIDER_KEY_RETENTION_MEASUREMENT: Readonly<{
    '@version': "EP-PROVIDER-REPLAY-RETENTION-MEASUREMENT-v1";
    measured_on: "2026-09-02";
    rows: readonly (Readonly<{
        id: "stripe.idempotency-key";
        provider_retention_hours: 24;
        provider_retention_verified: true;
        provider_retention_quote: "keys expire out of the system after 24 hours";
        verdict: "join_only_beyond_24h";
        finding: "A Gate allowance is issued with an expiry and is usually valid for days or weeks, and an action escrow release can sit reserved across a milestone. Any authorization whose usable life exceeds 24 hours outlives the Stripe fence. On this rail the provider consumes the authorization only inside a 24 hour window from the first request; after that a second dispatch under the same authorization reaches Stripe as a fresh request and only the EMILIA action fence stops it.";
    }> | Readonly<{
        id: "eip3009.nonce";
        provider_retention_hours: null;
        provider_retention_verified: true;
        provider_retention_quote: "_authorizationStates[from][nonce] = true, with no pruning defined in the ERC";
        verdict: "consumption_and_join";
        finding: "Permanent on-chain state. The consumption half holds for any authorization lifetime.";
    }> | Readonly<{
        id: "aws.ec2.run-instances.client-token";
        provider_retention_hours: "unverified";
        provider_retention_verified: false;
        provider_retention_quote: "unverified";
        verdict: "unknown";
        finding: "The AWS idempotency page states no expiry. Unknown is not the same as unbounded; do not assume either.";
    }> | Readonly<{
        id: "iso20022.end-to-end-id";
        provider_retention_hours: "unverified";
        provider_retention_verified: false;
        provider_retention_quote: "unverified";
        verdict: "join_only";
        finding: "No duplicate check keyed on EndToEndId is documented in the guidelines opened this run, so there is no consumption half to measure. The echo in pain.002 OrgnlEndToEndId makes the join half real.";
    }> | Readonly<{
        id: "mcp.tools-call.meta";
        provider_retention_hours: "not applicable";
        provider_retention_verified: false;
        provider_retention_quote: "not applicable";
        verdict: "join_only";
        finding: "The base protocol has no duplicate-detection engine to borrow. This row is a proposal to server authors, not a fence.";
    }>)[];
    verdict: "MIXED, and adapter-feature on the money rail that matters most. One of five rows (ERC-3009) supports the consumption half for any authorization lifetime, because its state is permanent. Stripe supports it only inside 24 hours, which is shorter than a normal Gate allowance lifetime, so on Stripe the honest claim is: a second dispatch within 24 hours is refused by Stripe itself, and beyond 24 hours only the join half survives and the fence is ours alone. Two rows have no documented consumption engine at all. This satisfies kill condition (1) of the thesis for the Stripe rail as written: most authorizations outlive the provider retention, so on that rail this is an adapter feature and not a plate.";
}>;
declare const _default: {
    PROVIDER_REPLAY_KEY_VERSION: string;
    PROVIDER_CARRIAGE_TABLE_VERSION: string;
    AUTHORIZATION_INSTANCE_VERSION: string;
    MCP_META_REPLAY_KEY: string;
    PROVIDER_SLOT_SPECS: Readonly<{
        /** MCP tools/call params._meta member. */
        'mcp.tools-call.meta': ProviderSlotSpec;
        /** Stripe Idempotency-Key request header. */
        'stripe.idempotency-key': ProviderSlotSpec;
        /** ERC-3009 bytes32 nonce, hex encoded with the 0x prefix. */
        'eip3009.nonce': ProviderSlotSpec;
        /** ISO 20022 EndToEndIdentification, Max35Text under the SEPA Latin set. */
        'iso20022.end-to-end-id': ProviderSlotSpec;
        /** AWS EC2 RunInstances ClientToken: up to 64 ASCII characters. */
        'aws.ec2.run-instances.client-token': ProviderSlotSpec;
        /**
         * EMILIA action-escrow provider release key. Not a third-party carrier: this
         * is our own record format, kept in the same derivation so the escrow key and
         * a carrier key are produced by one rule.
         */
        'ep.action-escrow.release': ProviderSlotSpec;
    }>;
    PROVIDER_CARRIAGE_TABLE: readonly CarriageRow[];
    PROVIDER_KEY_RETENTION_MEASUREMENT: Readonly<{
        '@version': "EP-PROVIDER-REPLAY-RETENTION-MEASUREMENT-v1";
        measured_on: "2026-09-02";
        rows: readonly (Readonly<{
            id: "stripe.idempotency-key";
            provider_retention_hours: 24;
            provider_retention_verified: true;
            provider_retention_quote: "keys expire out of the system after 24 hours";
            verdict: "join_only_beyond_24h";
            finding: "A Gate allowance is issued with an expiry and is usually valid for days or weeks, and an action escrow release can sit reserved across a milestone. Any authorization whose usable life exceeds 24 hours outlives the Stripe fence. On this rail the provider consumes the authorization only inside a 24 hour window from the first request; after that a second dispatch under the same authorization reaches Stripe as a fresh request and only the EMILIA action fence stops it.";
        }> | Readonly<{
            id: "eip3009.nonce";
            provider_retention_hours: null;
            provider_retention_verified: true;
            provider_retention_quote: "_authorizationStates[from][nonce] = true, with no pruning defined in the ERC";
            verdict: "consumption_and_join";
            finding: "Permanent on-chain state. The consumption half holds for any authorization lifetime.";
        }> | Readonly<{
            id: "aws.ec2.run-instances.client-token";
            provider_retention_hours: "unverified";
            provider_retention_verified: false;
            provider_retention_quote: "unverified";
            verdict: "unknown";
            finding: "The AWS idempotency page states no expiry. Unknown is not the same as unbounded; do not assume either.";
        }> | Readonly<{
            id: "iso20022.end-to-end-id";
            provider_retention_hours: "unverified";
            provider_retention_verified: false;
            provider_retention_quote: "unverified";
            verdict: "join_only";
            finding: "No duplicate check keyed on EndToEndId is documented in the guidelines opened this run, so there is no consumption half to measure. The echo in pain.002 OrgnlEndToEndId makes the join half real.";
        }> | Readonly<{
            id: "mcp.tools-call.meta";
            provider_retention_hours: "not applicable";
            provider_retention_verified: false;
            provider_retention_quote: "not applicable";
            verdict: "join_only";
            finding: "The base protocol has no duplicate-detection engine to borrow. This row is a proposal to server authors, not a fence.";
        }>)[];
        verdict: "MIXED, and adapter-feature on the money rail that matters most. One of five rows (ERC-3009) supports the consumption half for any authorization lifetime, because its state is permanent. Stripe supports it only inside 24 hours, which is shorter than a normal Gate allowance lifetime, so on Stripe the honest claim is: a second dispatch within 24 hours is refused by Stripe itself, and beyond 24 hours only the join half survives and the fence is ours alone. Two rows have no documented consumption engine at all. This satisfies kill condition (1) of the thesis for the Stripe rail as written: most authorizations outlive the provider retention, so on that rail this is an adapter feature and not a plate.";
    }>;
    deriveProviderReplayKey: typeof deriveProviderReplayKey;
    deriveMcpToolCallReplayKey: typeof deriveMcpToolCallReplayKey;
    createMcpReplayLedger: typeof createMcpReplayLedger;
    matchesProviderReplayKey: typeof matchesProviderReplayKey;
    authorizationInstanceDigest: typeof authorizationInstanceDigest;
    getCarriageRow: typeof getCarriageRow;
};
export default _default;
//# sourceMappingURL=provider-replay-key.d.ts.map