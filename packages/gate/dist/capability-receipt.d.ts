/**
 * EP Capability Receipt v1.
 *
 * A capability receipt is an issuer-signed envelope around an ordinary EP
 * receipt.  The ordinary receipt remains the policy/assurance proof; the
 * capability envelope adds a secret preimage, an immutable budget, an expiry,
 * and (optionally) Shamir shares.  Spend state is never trusted from the
 * envelope.  Every spend must pass through an atomic capability store.
 *
 * The executor deliberately follows the same indeterminate-outcome rule as
 * Gate: once the external effect is entered, a storage failure cannot reopen
 * the budget.  The reservation remains blocked until reconciliation.
 */
import { randomBytes, type KeyObject } from 'node:crypto';
export declare const CAPABILITY_RECEIPT_VERSION = "EP-CAPABILITY-RECEIPT-v1";
export declare const CAPABILITY_STATE_VERSION = "EP-CAPABILITY-STATE-v1";
export declare const CAPABILITY_SHARE_VERSION = "EP-CAPABILITY-SHARE-v1";
export declare const CAPABILITY_HASH_ALGORITHM = "sha256";
export declare const CAPABILITY_SCOPE_PROFILE = "urn:emilia:scope:action-digest-set-v1";
export declare const CAPABILITY_CAID_SCOPE_PROFILE = "urn:emilia:scope:caid-set-v1";
type KeyMaterial = KeyObject | string | Buffer;
type CapabilityBudget = {
    amount: number;
    currency: string;
};
type ReserveSpendOptions = {
    capabilityId: string;
    capabilityFingerprint: string;
    operationId: string;
    actionDigest: string;
    amount: number;
    currency: string;
    now?: number | (() => number);
};
type CommitSpendOptions = {
    capabilityId?: string;
    operationId?: string;
    reservationToken?: string;
    outcome?: string;
    now?: number | (() => number);
};
type ReconcileSpendOptions = {
    capabilityId?: string;
    operationId?: string;
    actionDigest?: string;
    evidenceDigest?: string;
    outcome?: string;
    now?: number | (() => number);
};
type ExecuteWithCapabilityOptions = {
    capabilityReceipt?: Record<string, any>;
    secret?: Buffer | string;
    action?: Record<string, any>;
    store?: Record<string, any>;
    executeAction?: (...args: any[]) => any;
    gate?: Record<string, any> | null;
    selector?: Record<string, any>;
    observedAction?: Record<string, any> | null;
    trustedIssuerKeys?: string[];
    verifyBaseReceipt?: ((...args: any[]) => any) | null;
    resolveCaid?: ((action: any) => any) | null;
    operationId?: string | null;
    now?: number | (() => number);
    thresholdSecretVerified?: boolean;
};
/** Digest the exact immutable action snapshot exercised under a capability. */
export declare function capabilityActionDigest(action: any): string;
/**
 * @param {object} capability
 * @param {object} action
 * @param {string} operationId
 * @param {object} [options]
 * @param {Function|null} [options.resolveCaid]
 */
export declare function verifyCapabilityScope(capability: any, action: any, operationId: any, { resolveCaid }?: {
    resolveCaid?: ((action: any) => any) | null;
}): {
    ok: boolean;
    reason: string;
    action_digest: string;
    caid?: undefined;
    operation_id_field?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    action_digest: string;
    caid: never;
    operation_id_field?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    action_digest: string;
    operation_id_field: string;
    caid?: undefined;
    detail?: undefined;
} | {
    operation_id_field: string;
    caid?: undefined;
    ok: boolean;
    action_digest: string;
    reason?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    detail: string;
    action_digest?: undefined;
    caid?: undefined;
    operation_id_field?: undefined;
};
export declare function capabilityBaseReceiptDigest(receipt: any): string;
/**
 * Mint a signed capability envelope. The issuer must sign the capability
 * metadata; a holder cannot enlarge the budget by editing a bearer object.
 * For m-of-n > 1, the raw secret is not returned; distribute the returned
 * shares instead.
 *
 * @param {object} baseReceipt EP-RECEIPT-v1 document
 * @param {object} [options]
 * @param {KeyMaterial} [options.issuerPrivateKey]
 * @param {CapabilityBudget} [options.budget]
 * @param {string|number} [options.expiry]
 * @param {{m:number,n:number}} [options.threshold]
 * @param {object} [options.scope]
 * @param {any[]} [options.delegationChain]
 * @param {string} [options.capabilityId]
 * @param {Buffer|string} [options.secret]
 */
export declare function mintCapabilityReceipt(baseReceipt: any, { issuerPrivateKey, budget, expiry, threshold, scope, delegationChain, capabilityId, secret, }?: {
    issuerPrivateKey?: KeyMaterial;
    budget?: CapabilityBudget;
    expiry?: string | number;
    threshold?: {
        m: number;
        n: number;
    };
    scope?: Record<string, any>;
    delegationChain?: any[];
    capabilityId?: string;
    secret?: Buffer | string;
}): Readonly<{
    capabilityReceipt: Readonly<{
        '@version': string;
        receipt: Record<string, any>;
        capability: {
            version: string;
            id: string;
            secret_hash: string;
            budget: {
                amount: any;
                currency: string;
            };
            consumed: number;
            threshold: {
                m: number;
                n: number;
            };
            scope: {
                [x: string]: any;
                profile: any;
                operation_id_field: string;
            };
            delegation_chain: Record<string, any>[];
            expiry: string;
        };
        capability_signature: {
            algorithm: string;
            public_key: string;
            value: string;
        };
    }>;
    secret: Buffer<ArrayBuffer> | null;
    shares: string[] | null;
}>;
/**
 * Verify the issuer signature and immutable capability metadata.
 * @param {object} capabilityReceipt
 * @param {object} [options]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {boolean} [options.allowUntrustedIssuer]
 */
export declare function verifyCapabilityReceipt(capabilityReceipt: any, { trustedIssuerKeys, allowUntrustedIssuer, }?: {
    trustedIssuerKeys?: string[];
    allowUntrustedIssuer?: boolean;
}): {
    ok: boolean;
    reason: string;
    receipt?: undefined;
    capability?: undefined;
    issuer_public_key?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    receipt: Record<string, any>;
    capability: any;
    issuer_public_key: any;
    reason?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    detail: string;
    receipt?: undefined;
    capability?: undefined;
    issuer_public_key?: undefined;
};
/** Split the 32-byte capability secret using Shamir's polynomial scheme. */
export declare function splitCapabilitySecret(secret: any, threshold: any, { randomBytesFn }?: {
    randomBytesFn?: typeof randomBytes | undefined;
}): string[];
/** Reconstruct a capability secret from at least m unique shares. */
export declare function reconstructCapabilitySecret(shares: any, threshold: any): Buffer<ArrayBuffer>;
/**
 * Production capability-store contract. Methods alone are insufficient: an
 * adapter must explicitly assert durable custody and reconciliation support.
 */
export declare function isSecureCapabilityStore(store: any): boolean;
/**
 * An in-memory atomic reference store. It is intentionally marked non-durable
 * and is suitable only for tests; production callers must use an implementation
 * backed by a transactional database or equivalent linearizable store.
 */
export declare function createMemoryCapabilityStore(): {
    durable: boolean;
    reconciliationCapable: boolean;
    registerCapability(capabilityReceipt: any): boolean;
    reserveSpend({ capabilityId, capabilityFingerprint, operationId, actionDigest, amount, currency, now }: ReserveSpendOptions): Promise<{
        ok: boolean;
        reason: string;
        operation_id?: undefined;
        reservation_token?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        operation_id: string;
        reservation_token: `${string}-${string}-${string}-${string}-${string}`;
        remaining: number;
        reason?: undefined;
    }>;
    commitSpend({ capabilityId, operationId, reservationToken, outcome, now }?: CommitSpendOptions): Promise<{
        ok: boolean;
        reason: string;
        outcome?: undefined;
        consumed?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        outcome: string;
        consumed: any;
        remaining: number;
        reason?: undefined;
    }>;
    reconcileSpend({ capabilityId, operationId, actionDigest, evidenceDigest, outcome, now }?: ReconcileSpendOptions): Promise<{
        ok: boolean;
        reason: string;
        idempotent?: undefined;
        outcome?: undefined;
    } | {
        ok: boolean;
        idempotent: boolean;
        outcome: string;
        reason?: undefined;
    }>;
    getState(capabilityId: any): any;
    getOperation(operationId: any): any;
};
export declare const CAPABILITY_STATE_TABLE = "ep_capability_state";
export declare const CAPABILITY_OPERATION_TABLE = "ep_capability_operations";
export declare const CAPABILITY_STATE_DDL = "CREATE TABLE IF NOT EXISTS ep_capability_state (\n  capability_id TEXT PRIMARY KEY,\n  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),\n  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),\n  currency TEXT NOT NULL,\n  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),\n  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),\n  expires_at TIMESTAMPTZ NOT NULL,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT now()\n);\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;\nCREATE TABLE IF NOT EXISTS ep_capability_operations (\n  operation_id TEXT PRIMARY KEY,\n  capability_id TEXT NOT NULL REFERENCES ep_capability_state(capability_id),\n  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),\n  amount BIGINT NOT NULL CHECK (amount > 0),\n  currency TEXT NOT NULL,\n  status TEXT NOT NULL CHECK (status IN ('reserved', 'committed')),\n  reservation_token TEXT NOT NULL,\n  outcome TEXT,\n  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed')),\n  reconciliation_evidence_digest TEXT CHECK (reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  reserved_at TIMESTAMPTZ NOT NULL,\n  committed_at TIMESTAMPTZ,\n  reconciled_at TIMESTAMPTZ,\n  CHECK (\n    (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)\n    OR\n    (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)\n  )\n);\nCREATE INDEX IF NOT EXISTS ep_capability_operations_capability_idx ON ep_capability_operations(capability_id);";
export declare const CAPABILITY_SQL: Readonly<{
    register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(ep_capability_state.capability_fingerprint, EXCLUDED.capability_fingerprint) WHERE ep_capability_state.budget_amount = EXCLUDED.budget_amount AND ep_capability_state.currency = EXCLUDED.currency AND ep_capability_state.expires_at = EXCLUDED.expires_at";
    readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
    readOperation: "SELECT operation_id, capability_id, action_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, reconciled_at FROM ep_capability_operations WHERE operation_id = $1 FOR UPDATE";
    insertOperation: "INSERT INTO ep_capability_operations (operation_id, capability_id, action_digest, amount, currency, status, reservation_token, reserved_at) VALUES ($1, $2, $3, $4, $5, 'reserved', $6, $7)";
    reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2";
    commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $3, committed_at = $4 WHERE operation_id = $1 AND capability_id = $2 AND status = 'reserved' AND reservation_token = $5";
    reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $3, reconciliation_evidence_digest = $4, reconciled_at = $5 WHERE operation_id = $1 AND capability_id = $2 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
    commitState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2";
}>;
/**
 * Production adapter. `transaction` MUST run the callback on one database
 * connection with BEGIN/COMMIT/ROLLBACK. The state row is locked before the
 * operation row is inserted, making budget reservation linearizable per
 * capability and refusing all ambiguous database outcomes.
 *
 * @param {object} [options]
 * @param {(callback: (query: Function) => any) => any} [options.transaction]
 */
export declare function createPostgresCapabilityStore({ transaction }?: {
    transaction?: (callback: (query: Function) => any) => any;
}): {
    durable: boolean;
    reconciliationCapable: boolean;
    registerCapability(capabilityReceipt: any): Promise<any>;
    reserveSpend({ capabilityId, capabilityFingerprint, operationId, actionDigest, amount, currency, now }: ReserveSpendOptions): Promise<any>;
    commitSpend({ capabilityId, operationId, reservationToken, outcome, now }?: CommitSpendOptions): Promise<any>;
    reconcileSpend({ capabilityId, operationId, actionDigest, evidenceDigest, outcome, now }?: ReconcileSpendOptions): Promise<any>;
};
/**
 * Execute one spend under a capability. The base EP receipt is checked on
 * every spend with consumptionMode=none; the capability store is the replay
 * and budget authority. The external function is entered only after the
 * atomic reservation succeeds. `action` is the budget projection; the
 * external function receives only a clone of the exact verified
 * `observedAction ?? action`. Any exception after entry permanently commits
 * the reserved amount as indeterminate.
 *
 * @param {object} [options]
 * @param {object} [options.capabilityReceipt]
 * @param {Buffer|string} [options.secret]
 * @param {{amount:number,currency:string}} [options.action]
 * @param {any} [options.store]
 * @param {Function} [options.executeAction]
 * @param {any} [options.gate]
 * @param {object} [options.selector]
 * @param {object|null} [options.observedAction]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {Function|null} [options.verifyBaseReceipt]
 * @param {Function|null} [options.resolveCaid]
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 * @param {boolean} [options.thresholdSecretVerified]
 */
export declare function executeWithCapability({ capabilityReceipt, secret, action, store, executeAction, gate, selector, observedAction, trustedIssuerKeys, verifyBaseReceipt, resolveCaid, operationId, now, thresholdSecretVerified, }?: ExecuteWithCapabilityOptions): Promise<{
    ok: boolean;
    reason: string | undefined;
    scope?: undefined;
    authorization?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: any;
    scope: any;
    authorization?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: string;
    authorization: any;
    scope?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: any;
    authorization: Record<string, any> | null;
    scope?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: string;
    authorization: Record<string, any> | null;
    result: any;
    operation_id: string | null;
    scope?: undefined;
} | {
    remaining: any;
    caid?: any;
    ok: boolean;
    result: any;
    authorization: Record<string, any> | null;
    operation_id: string | null;
    action_digest: any;
    reason?: undefined;
    scope?: undefined;
} | {
    caid?: any;
    ok: boolean;
    reason: string;
    authorization: Record<string, any> | null;
    operation_id: string | null;
    action_digest: any;
    scope?: undefined;
    result?: undefined;
}>;
/**
 * Execute a capability requiring m-of-n Shamir shares.
 * @param {Record<string, any>} [args] capabilityReceipt, shares, and executeWithCapability passthrough options
 */
export declare function executeWithThreshold({ capabilityReceipt, shares, ...options }?: ExecuteWithCapabilityOptions & {
    shares?: string[];
}): Promise<{
    ok: boolean;
    reason: string | undefined;
    scope?: undefined;
    authorization?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: any;
    scope: any;
    authorization?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: string;
    authorization: any;
    scope?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: any;
    authorization: Record<string, any> | null;
    scope?: undefined;
    result?: undefined;
    operation_id?: undefined;
} | {
    ok: boolean;
    reason: string;
    authorization: Record<string, any> | null;
    result: any;
    operation_id: string | null;
    scope?: undefined;
} | {
    remaining: any;
    caid?: any;
    ok: boolean;
    result: any;
    authorization: Record<string, any> | null;
    operation_id: string | null;
    action_digest: any;
    reason?: undefined;
    scope?: undefined;
} | {
    caid?: any;
    ok: boolean;
    reason: string;
    authorization: Record<string, any> | null;
    operation_id: string | null;
    action_digest: any;
    scope?: undefined;
    result?: undefined;
}>;
/**
 * Authentically reconcile a committed indeterminate capability operation.
 * The generic path records only a proven `executed` outcome and never restores
 * budget. A deployment that wants to prove the effect boundary was not crossed
 * needs a separate, action-specific negative-evidence profile.
 *
 * @param {object} [options]
 * @param {any} [options.store]
 * @param {string} [options.capabilityId]
 * @param {string} [options.operationId]
 * @param {object} [options.action]
 * @param {object} [options.evidence]
 * @param {Function} [options.verifyEvidence]
 * @param {number|(() => number)} [options.now]
 */
export declare function reconcileCapabilityOperation({ store, capabilityId, operationId, action, evidence, verifyEvidence, now, }?: {
    store?: Record<string, any>;
    capabilityId?: string;
    operationId?: string;
    action?: Record<string, any>;
    evidence?: Record<string, any>;
    verifyEvidence?: (...args: any[]) => any;
    now?: number | (() => number);
}): Promise<{
    ok: boolean;
    outcome: string;
    action_digest: any;
    evidence_digest: string;
    idempotent: boolean;
    reason?: undefined;
} | {
    ok: boolean;
    reason: any;
    outcome?: undefined;
    action_digest?: undefined;
    evidence_digest?: undefined;
    idempotent?: undefined;
}>;
/**
 * Issue a bounded child capability from a parent capability.
 *
 * Delegation is issuer-authorized metadata plus an atomic parent spend. The
 * parent budget is committed as `delegated` before the child is registered;
 * if child registration fails, the safe result is an orphaned child issuance
 * that must be reconciled, never a child with unbacked budget.
 *
 * @param {object} [options]
 * @param {object} [options.parentCapabilityReceipt]
 * @param {Buffer|string} [options.parentSecret]
 * @param {KeyMaterial} [options.issuerPrivateKey]
 * @param {CapabilityBudget} [options.budget]
 * @param {string|number} [options.expiry]
 * @param {{m:number,n:number}} [options.threshold]
 * @param {object|null} [options.scope]
 * @param {string} [options.delegateId]
 * @param {string} [options.capabilityId]
 * @param {Buffer|string} [options.secret]
 * @param {any} [options.store]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 */
export declare function delegateCapabilityReceipt({ parentCapabilityReceipt, parentSecret, issuerPrivateKey, budget, expiry, threshold, scope, delegateId, capabilityId, secret, store, trustedIssuerKeys, operationId, now, }?: {
    parentCapabilityReceipt?: Record<string, any>;
    parentSecret?: Buffer | string;
    issuerPrivateKey?: KeyMaterial;
    budget?: CapabilityBudget;
    expiry?: string | number;
    threshold?: {
        m: number;
        n: number;
    };
    scope?: Record<string, any> | null;
    delegateId?: string;
    capabilityId?: string;
    secret?: Buffer | string;
    store?: Record<string, any>;
    trustedIssuerKeys?: string[];
    operationId?: string | null;
    now?: number | (() => number);
}): Promise<{
    ok: boolean;
    reason: any;
    operation_id?: undefined;
    capabilityReceipt?: undefined;
    secret?: undefined;
    shares?: undefined;
    remaining?: undefined;
} | {
    ok: boolean;
    reason: string;
    operation_id: string;
    capabilityReceipt?: undefined;
    secret?: undefined;
    shares?: undefined;
    remaining?: undefined;
} | {
    ok: boolean;
    capabilityReceipt: Readonly<{
        '@version': string;
        receipt: Record<string, any>;
        capability: {
            version: string;
            id: string;
            secret_hash: string;
            budget: {
                amount: any;
                currency: string;
            };
            consumed: number;
            threshold: {
                m: number;
                n: number;
            };
            scope: {
                [x: string]: any;
                profile: any;
                operation_id_field: string;
            };
            delegation_chain: Record<string, any>[];
            expiry: string;
        };
        capability_signature: {
            algorithm: string;
            public_key: string;
            value: string;
        };
    }>;
    secret: Buffer<ArrayBuffer> | null;
    shares: string[] | null;
    operation_id: string;
    remaining: any;
    reason?: undefined;
}>;
declare const _default: {
    CAPABILITY_RECEIPT_VERSION: string;
    CAPABILITY_STATE_VERSION: string;
    CAPABILITY_SHARE_VERSION: string;
    CAPABILITY_SCOPE_PROFILE: string;
    CAPABILITY_CAID_SCOPE_PROFILE: string;
    CAPABILITY_STATE_DDL: string;
    CAPABILITY_SQL: Readonly<{
        register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(ep_capability_state.capability_fingerprint, EXCLUDED.capability_fingerprint) WHERE ep_capability_state.budget_amount = EXCLUDED.budget_amount AND ep_capability_state.currency = EXCLUDED.currency AND ep_capability_state.expires_at = EXCLUDED.expires_at";
        readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
        readOperation: "SELECT operation_id, capability_id, action_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, reconciled_at FROM ep_capability_operations WHERE operation_id = $1 FOR UPDATE";
        insertOperation: "INSERT INTO ep_capability_operations (operation_id, capability_id, action_digest, amount, currency, status, reservation_token, reserved_at) VALUES ($1, $2, $3, $4, $5, 'reserved', $6, $7)";
        reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND budget_amount - consumed_amount - reserved_amount >= $2";
        commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $3, committed_at = $4 WHERE operation_id = $1 AND capability_id = $2 AND status = 'reserved' AND reservation_token = $5";
        reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $3, reconciliation_evidence_digest = $4, reconciled_at = $5 WHERE operation_id = $1 AND capability_id = $2 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
        commitState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2";
    }>;
    capabilityBaseReceiptDigest: typeof capabilityBaseReceiptDigest;
    capabilityActionDigest: typeof capabilityActionDigest;
    verifyCapabilityScope: typeof verifyCapabilityScope;
    mintCapabilityReceipt: typeof mintCapabilityReceipt;
    verifyCapabilityReceipt: typeof verifyCapabilityReceipt;
    splitCapabilitySecret: typeof splitCapabilitySecret;
    reconstructCapabilitySecret: typeof reconstructCapabilitySecret;
    createMemoryCapabilityStore: typeof createMemoryCapabilityStore;
    createPostgresCapabilityStore: typeof createPostgresCapabilityStore;
    isSecureCapabilityStore: typeof isSecureCapabilityStore;
    executeWithCapability: typeof executeWithCapability;
    executeWithThreshold: typeof executeWithThreshold;
    reconcileCapabilityOperation: typeof reconcileCapabilityOperation;
    delegateCapabilityReceipt: typeof delegateCapabilityReceipt;
};
export default _default;
//# sourceMappingURL=capability-receipt.d.ts.map