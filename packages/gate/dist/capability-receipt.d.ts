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
import { type ProviderEntryGuard } from './provider-entry.js';
import { type AgilityOptions } from '@emilia-protocol/verify/pq-signature-agility';
export declare const CAPABILITY_RECEIPT_VERSION = "EP-CAPABILITY-RECEIPT-v1";
export declare const CAPABILITY_STATE_VERSION = "EP-CAPABILITY-STATE-v1";
export declare const CAPABILITY_SHARE_VERSION = "EP-CAPABILITY-SHARE-v1";
export declare const CAPABILITY_HASH_ALGORITHM = "sha256";
export declare const CAPABILITY_SCOPE_PROFILE = "urn:emilia:scope:action-digest-set-v1";
export declare const CAPABILITY_CAID_SCOPE_PROFILE = "urn:emilia:scope:caid-set-v1";
export declare const CAPABILITY_ALLOWANCE_SCOPE_PROFILE = "EP-CAPABILITY-ALLOWANCE-SCOPE-v1";
export declare const CAPABILITY_ACTION_FENCE_PROFILE = "EP-CAPABILITY-ACTION-FENCE-v1";
export declare const CAPABILITY_REVOCATION_MODES: readonly ["direct", "cascade"];
type KeyMaterial = KeyObject | string | Buffer;
type CapabilityBudget = {
    amount: number;
    currency: string;
};
type CapabilityRevocationMode = typeof CAPABILITY_REVOCATION_MODES[number];
type AllowanceStatusAssertion = {
    allowance_profile_id: string;
    allowance_digest: string;
    revision: number;
    status_epoch: number;
    status_head_digest: string;
};
type AdvanceAllowanceStatusOptions = AllowanceStatusAssertion & {
    expected_status_epoch: number | null;
    expected_status_head_digest: string | null;
    status: 'active' | 'suspended' | 'revoked';
};
type ReserveSpendOptions = {
    capabilityId: string;
    capabilityFingerprint: string;
    operationNamespace?: string;
    operationId: string;
    actionDigest: string;
    actionFenceDigest?: string;
    amount: number;
    currency: string;
    controlDomainId?: string;
    allowanceStatus?: AllowanceStatusAssertion;
    now?: number | (() => number);
};
type CommitSpendOptions = {
    capabilityId?: string;
    operationNamespace?: string;
    operationId?: string;
    reservationToken?: string;
    outcome?: string;
    now?: number | (() => number);
};
type BeginProviderEntryOptions = {
    capabilityId?: string;
    operationNamespace?: string;
    operationId?: string;
    reservationToken?: string;
    controlDomainId?: string;
    now?: number | (() => number);
};
type ControlTransitionVerification = {
    authenticated: boolean;
    authorized: boolean;
    authority_instance_digest?: string;
    action_digest?: string;
};
type ControlTransitionOptions = {
    controlDomainId?: string;
    operationId?: string;
    actionDigest?: string;
    authorization?: unknown;
    now?: number | (() => number);
};
type VerifyControlTransition = (input: Readonly<{
    event_type: 'freeze' | 'restore';
    control_domain_id: string;
    operation_id: string;
    action_digest: string;
    authorization: unknown;
}>) => ControlTransitionVerification | Promise<ControlTransitionVerification>;
type RecoverPreEntrySpendOptions = {
    capabilityId?: string;
    operationNamespace?: string;
    operationId?: string;
    actionDigest?: string;
    reservationToken?: string;
    disposition?: 'release' | 'burn';
    now?: number | (() => number);
};
type ReconcileSpendOptions = {
    capabilityId?: string;
    operationNamespace?: string;
    operationId?: string;
    actionDigest?: string;
    evidenceDigest?: string;
    evidenceProfile?: string;
    evidenceFinal?: boolean;
    evidenceObservedAt?: string;
    outcome?: string;
    now?: number | (() => number);
};
type RevokeCapabilityOptions = {
    capabilityId?: string;
    capabilityFingerprint?: string;
    now?: number | (() => number);
};
type CapabilityExecutionDomain = {
    executor_id: string;
    expected_state_domain_digest?: string | null;
    single_executor_id?: string | null;
    require_aggregate?: boolean;
};
type HumanAuthorizationVerificationContext = {
    action: Readonly<Record<string, any>>;
    action_digest: string;
    pins: Readonly<Record<string, any>>;
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
    verifyActionProfile?: ((action: any, profile: {
        profile_id: string;
        profile_digest: string;
    }) => any) | null;
    executionDomain?: CapabilityExecutionDomain | null;
    requireHumanAuthorization?: boolean;
    humanAuthorization?: unknown;
    humanAuthorizationPins?: Record<string, any> | null;
    verifyHumanAuthorization?: ((artifact: unknown, context: HumanAuthorizationVerificationContext) => any) | null;
    allowanceStatus?: AllowanceStatusAssertion;
    controlDomainId?: string;
    operationId?: string | null;
    now?: number | (() => number);
    thresholdSecretVerified?: boolean;
    providerEntryGuard?: ProviderEntryGuard | null;
};
type ExecuteWithCapabilityResult = {
    ok: boolean;
    reason?: string;
    result?: any;
    scope?: any;
    authorization?: any;
    human_authorization?: any;
    budget_guarantee?: any;
    operation_id?: string | null;
    action_digest?: string;
    action_fence_digest?: string;
    holding_operation_id?: string | null;
    caid?: string;
    remaining?: any;
};
/** Digest the exact immutable action snapshot exercised under a capability. */
export declare function capabilityActionDigest(action: any): string;
/**
 * @param {object} capability
 * @param {object} action
 * @param {string} operationId
 * @param {object} [options]
 * @param {Function|null} [options.resolveCaid]
 * @param {Function|null} [options.verifyActionProfile]
 */
export declare function verifyCapabilityScope(capability: any, action: any, operationId: any, { resolveCaid, verifyActionProfile, }?: {
    resolveCaid?: ((action: any) => any) | null;
    verifyActionProfile?: ((action: any, profile: {
        profile_id: string;
        profile_digest: string;
    }) => any) | null;
}): {
    ok: boolean;
    reason: any;
    action_digest: string;
    caid?: undefined;
    operation_id_field?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    action_digest: string;
    caid: string;
    operation_id_field?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    action_digest: string;
    operation_id_field: any;
    caid?: undefined;
    detail?: undefined;
} | {
    operation_id_field: any;
    operation_namespace?: any;
    caid?: string | undefined;
    ok: boolean;
    action_digest: string;
    action_fence_digest: string;
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
 * @param {'direct'|'cascade'} [options.revocationMode]
 * @param {object} [options.scope]
 * @param {any[]} [options.delegationChain]
 * @param {string} [options.capabilityId]
 * @param {string} [options.operationNamespace]
 * @param {Buffer|string} [options.secret]
 */
export declare function mintCapabilityReceipt(baseReceipt: any, { issuerPrivateKey, budget, expiry, threshold, revocationMode, scope, delegationChain, capabilityId, secret, }?: {
    issuerPrivateKey?: KeyMaterial;
    budget?: CapabilityBudget;
    expiry?: string | number;
    threshold?: {
        m: number;
        n: number;
    };
    revocationMode?: CapabilityRevocationMode;
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
            revocation_mode: "direct" | "cascade";
            scope: any;
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
export declare function createMemoryCapabilityStore({ providerEntryTimeoutMs, verifyControlTransition, }?: {
    providerEntryTimeoutMs?: number;
    verifyControlTransition?: VerifyControlTransition;
}): {
    durable: boolean;
    atomicStateDomainCapable: boolean;
    stateDomainDigest: string;
    reconciliationCapable: boolean;
    revocationInheritanceCapable: boolean;
    allowanceCurrentnessCapable: boolean;
    providerEntryDispositionCapable: boolean;
    controlDomainCapable: boolean;
    registerControlDomain({ controlDomainId, now, }?: {
        controlDomainId?: string;
        now?: number | (() => number);
    }): Promise<{
        ok: boolean;
        idempotent: boolean;
        control_domain_id: string;
        status: any;
        epoch: any;
    }>;
    freezeControlDomain(options?: ControlTransitionOptions): Promise<any>;
    restoreControlDomain(options?: ControlTransitionOptions): Promise<any>;
    registerCapability(capabilityReceipt: any): boolean;
    revokeCapability({ capabilityId, capabilityFingerprint, now }?: RevokeCapabilityOptions): Promise<{
        ok: boolean;
        reason: string;
        idempotent?: undefined;
        capability_id?: undefined;
        revocation_mode?: undefined;
        revoked_at?: undefined;
    } | {
        ok: boolean;
        idempotent: boolean;
        capability_id: string | undefined;
        revocation_mode: any;
        revoked_at: any;
        reason?: undefined;
    }>;
    advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions): {
        ok: boolean;
        idempotent: boolean;
        reason?: undefined;
    } | {
        ok: boolean;
        reason: string;
        idempotent?: undefined;
    };
    reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace, operationId, actionDigest, actionFenceDigest, amount, currency, controlDomainId, allowanceStatus, now }: ReserveSpendOptions): Promise<{
        ok: boolean;
        reason: string;
        action_digest?: undefined;
        action_fence_digest?: undefined;
        holding_operation_id?: undefined;
        operation_id?: undefined;
        reservation_token?: undefined;
        entry_deadline_at?: undefined;
        control_domain_id?: undefined;
        reserved_control_epoch?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        reason: string;
        action_digest: string;
        action_fence_digest: string;
        holding_operation_id: any;
        operation_id?: undefined;
        reservation_token?: undefined;
        entry_deadline_at?: undefined;
        control_domain_id?: undefined;
        reserved_control_epoch?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        operation_id: string;
        action_digest: string;
        action_fence_digest: string;
        reservation_token: `${string}-${string}-${string}-${string}-${string}`;
        entry_deadline_at: number;
        control_domain_id: any;
        reserved_control_epoch: any;
        remaining: number;
        reason?: undefined;
        holding_operation_id?: undefined;
    }>;
    beginProviderEntry({ capabilityId, operationNamespace, operationId, reservationToken, controlDomainId, now }?: BeginProviderEntryOptions): Promise<{
        ok: boolean;
        reason: string;
        outcome?: undefined;
        reservation?: undefined;
        operation_id?: undefined;
        provider_entry_at?: undefined;
        consumed?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        reason: string;
        outcome: string;
        reservation: string;
        operation_id?: undefined;
        provider_entry_at?: undefined;
        consumed?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        operation_id: string | undefined;
        provider_entry_at: any;
        consumed: any;
        remaining: number;
        reason?: undefined;
        outcome?: undefined;
        reservation?: undefined;
    }>;
    recoverPreEntrySpend({ capabilityId, operationNamespace, operationId, actionDigest, reservationToken, disposition, now }?: RecoverPreEntrySpendOptions): Promise<{
        ok: boolean;
        reason: string;
        idempotent?: undefined;
        outcome?: undefined;
        released?: undefined;
        consumed?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        idempotent: boolean;
        outcome: string;
        released: any;
        reason?: undefined;
        consumed?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        idempotent: boolean;
        outcome: string;
        consumed: any;
        reason?: undefined;
        released?: undefined;
        remaining?: undefined;
    } | {
        ok: boolean;
        outcome: string;
        consumed: any;
        remaining: number;
        reason?: undefined;
        idempotent?: undefined;
        released?: undefined;
    } | {
        ok: boolean;
        outcome: string;
        released: any;
        remaining: number;
        reason?: undefined;
        idempotent?: undefined;
        consumed?: undefined;
    } | {
        ok: boolean;
        idempotent: boolean;
        outcome: string;
        released: any;
        remaining: number;
        reason?: undefined;
        consumed?: undefined;
    }>;
    commitSpend({ capabilityId, operationNamespace, operationId, reservationToken, outcome, now }?: CommitSpendOptions): Promise<{
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
    reconcileSpend({ capabilityId, operationNamespace, operationId, actionDigest, evidenceDigest, evidenceProfile, evidenceFinal, evidenceObservedAt, outcome, now }?: ReconcileSpendOptions): Promise<{
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
    getAllowanceStatus(allowanceProfileId: any): any;
    getControlDomain(controlDomainId: any): Readonly<{
        [x: string]: any;
    }> | null;
    getControlDomainEvent(operationId: any): Readonly<{
        result: any;
    }> | null;
    getOperation(operationId: any, capabilityId?: null, operationNamespace?: null): any;
};
export declare const CAPABILITY_STATE_TABLE = "ep_capability_state";
export declare const CAPABILITY_OPERATION_TABLE = "ep_capability_operations";
export declare const CAPABILITY_ALLOWANCE_STATUS_TABLE = "ep_gate_allowance_status";
export declare const CAPABILITY_CONTROL_DOMAIN_TABLE = "ep_gate_control_domains";
export declare const CAPABILITY_CONTROL_DOMAIN_EVENT_TABLE = "ep_gate_control_domain_events";
export declare const CAPABILITY_STATE_DDL = "CREATE TABLE IF NOT EXISTS ep_capability_state (\n  capability_id TEXT PRIMARY KEY,\n  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),\n  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),\n  currency TEXT NOT NULL,\n  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),\n  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),\n  expires_at TIMESTAMPTZ NOT NULL,\n  revocation_mode TEXT NOT NULL CHECK (revocation_mode IN ('direct', 'cascade')),\n  parent_capability_id TEXT REFERENCES ep_capability_state(capability_id),\n  revoked_at TIMESTAMPTZ,\n  revocation_state_ready BOOLEAN NOT NULL DEFAULT TRUE,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),\n  allowance_profile_id TEXT,\n  allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),\n  semantic_fence_ready BOOLEAN NOT NULL DEFAULT TRUE,\n  CHECK ((allowance_profile_id IS NULL) = (allowance_digest IS NULL))\n);\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS allowance_profile_id TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS semantic_fence_ready BOOLEAN;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS revocation_mode TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS parent_capability_id TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS revocation_state_ready BOOLEAN;\nALTER TABLE ep_capability_state DROP CONSTRAINT IF EXISTS ep_capability_state_revocation_mode_check;\nALTER TABLE ep_capability_state\n  ADD CONSTRAINT ep_capability_state_revocation_mode_check\n  CHECK (revocation_mode IS NULL OR revocation_mode IN ('direct', 'cascade'));\nALTER TABLE ep_capability_state DROP CONSTRAINT IF EXISTS ep_capability_state_parent_capability_id_fkey;\nALTER TABLE ep_capability_state\n  ADD CONSTRAINT ep_capability_state_parent_capability_id_fkey\n  FOREIGN KEY (parent_capability_id) REFERENCES ep_capability_state(capability_id);\nUPDATE ep_capability_state\n  SET revocation_state_ready = (revocation_mode IN ('direct', 'cascade'))\n  WHERE revocation_state_ready IS NULL\n     OR (revocation_state_ready IS TRUE AND revocation_mode NOT IN ('direct', 'cascade'));\nALTER TABLE ep_capability_state\n  ALTER COLUMN revocation_state_ready SET DEFAULT TRUE,\n  ALTER COLUMN revocation_state_ready SET NOT NULL;\nCREATE OR REPLACE FUNCTION ep_require_capability_revocation_metadata()\nRETURNS TRIGGER\nLANGUAGE plpgsql\nSET search_path FROM CURRENT\nAS $capability_revocation_metadata_function$\nBEGIN\n  IF NEW.revocation_state_ready IS TRUE\n     AND (\n       NEW.revocation_mode IS NULL\n       OR NEW.revocation_mode NOT IN ('direct', 'cascade')\n     ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'capability revocation metadata is not ready',\n      DETAIL = format('capability_id=%s', NEW.capability_id),\n      HINT = 'Reissue the capability with an explicitly signed direct or cascade revocation mode.';\n  END IF;\n  RETURN NEW;\nEND\n$capability_revocation_metadata_function$;\nDROP TRIGGER IF EXISTS ep_capability_state_revocation_metadata_guard\n  ON ep_capability_state;\nCREATE TRIGGER ep_capability_state_revocation_metadata_guard\n  BEFORE INSERT OR UPDATE OF revocation_mode, revocation_state_ready\n  ON ep_capability_state\n  FOR EACH ROW\n  EXECUTE FUNCTION ep_require_capability_revocation_metadata();\nCREATE TABLE IF NOT EXISTS ep_gate_allowance_status (\n  allowance_profile_id TEXT PRIMARY KEY,\n  allowance_digest TEXT NOT NULL CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),\n  revision BIGINT NOT NULL CHECK (revision > 0),\n  status_epoch BIGINT NOT NULL CHECK (status_epoch > 0),\n  status_head_digest TEXT NOT NULL CHECK (status_head_digest ~ '^sha256:[0-9a-f]{64}$'),\n  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),\n  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()\n);\nCREATE TABLE IF NOT EXISTS ep_gate_control_domains (\n  control_domain_id TEXT PRIMARY KEY,\n  status TEXT NOT NULL CHECK (status IN ('active', 'frozen')),\n  epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch > 0),\n  frozen_at TIMESTAMPTZ,\n  frozen_by_digest TEXT CHECK (frozen_by_digest ~ '^sha256:[0-9a-f]{64}$'),\n  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),\n  CHECK (\n    (status = 'active' AND frozen_at IS NULL AND frozen_by_digest IS NULL)\n    OR\n    (status = 'frozen' AND frozen_at IS NOT NULL AND frozen_by_digest IS NOT NULL)\n  )\n);\nCREATE TABLE IF NOT EXISTS ep_gate_control_domain_events (\n  operation_id TEXT NOT NULL,\n  control_domain_id TEXT NOT NULL REFERENCES ep_gate_control_domains(control_domain_id),\n  event_type TEXT NOT NULL CHECK (event_type IN ('freeze', 'restore')),\n  epoch_at_event BIGINT NOT NULL CHECK (epoch_at_event > 0),\n  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),\n  authority_instance_digest TEXT NOT NULL CHECK (authority_instance_digest ~ '^sha256:[0-9a-f]{64}$'),\n  result JSONB NOT NULL,\n  committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),\n  PRIMARY KEY (operation_id)\n);\nCREATE TABLE IF NOT EXISTS ep_capability_operations (\n  operation_namespace TEXT NOT NULL,\n  operation_id TEXT NOT NULL,\n  capability_id TEXT NOT NULL REFERENCES ep_capability_state(capability_id),\n  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),\n  action_fence_digest TEXT NOT NULL CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  amount BIGINT NOT NULL CHECK (amount > 0),\n  currency TEXT NOT NULL,\n  status TEXT NOT NULL CONSTRAINT ep_capability_operations_status_check CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released')),\n  reservation_token TEXT NOT NULL,\n  outcome TEXT,\n  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed', 'not_entered')),\n  reconciliation_evidence_digest TEXT CHECK (reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  allowance_revision BIGINT CHECK (allowance_revision > 0),\n  allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0),\n  allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$'),\n  reserved_at TIMESTAMPTZ NOT NULL,\n  entry_deadline_at TIMESTAMPTZ,\n  provider_entry_at TIMESTAMPTZ,\n  committed_at TIMESTAMPTZ,\n  reconciled_at TIMESTAMPTZ,\n  released_at TIMESTAMPTZ,\n  release_reason TEXT,\n  release_evidence_profile TEXT,\n  release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  control_domain_id TEXT REFERENCES ep_gate_control_domains(control_domain_id),\n  reserved_control_epoch BIGINT CHECK (reserved_control_epoch > 0),\n  CHECK (\n    (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)\n    OR\n    (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)\n  ),\n  CHECK (\n    (allowance_revision IS NULL AND allowance_status_epoch IS NULL AND allowance_status_head_digest IS NULL)\n    OR\n    (allowance_revision IS NOT NULL AND allowance_status_epoch IS NOT NULL AND allowance_status_head_digest IS NOT NULL)\n  ),\n  CHECK ((control_domain_id IS NULL) = (reserved_control_epoch IS NULL)),\n  PRIMARY KEY (operation_namespace, operation_id)\n);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS operation_namespace TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS entry_deadline_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS provider_entry_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_reason TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_evidence_profile TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS control_domain_id TEXT REFERENCES ep_gate_control_domains(control_domain_id);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS reserved_control_epoch BIGINT CHECK (reserved_control_epoch > 0);\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_control_domain_binding_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_control_domain_binding_check\n  CHECK ((control_domain_id IS NULL) = (reserved_control_epoch IS NULL));\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_action_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_action_digest_check\n  CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_release_evidence_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_release_evidence_digest_check\n  CHECK (release_evidence_digest IS NULL OR release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_status_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_status_check\n  CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released'));\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_reconciliation_outcome_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_reconciliation_outcome_check\n  CHECK (reconciliation_outcome IS NULL OR reconciliation_outcome IN ('executed', 'not_entered'));\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_revision BIGINT CHECK (allowance_revision > 0);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS action_fence_digest TEXT CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_action_fence_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_action_fence_digest_check\n  CHECK (action_fence_digest IS NULL OR action_fence_digest ~ '^sha256:[0-9a-f]{64}$');\n-- Capture legacy capability ids before compatibility backfills erase the only\n-- reliable signal that their historical rows never carried a semantic fence.\n-- This also closes an incomplete-bootstrap case where the state flag was\n-- already added with its TRUE default but operation bindings remain legacy.\nDROP TABLE IF EXISTS pg_temp.ep_capability_action_fence_legacy_ids;\nCREATE TEMP TABLE ep_capability_action_fence_legacy_ids\nON COMMIT DROP\nAS\nSELECT DISTINCT capability_id\nFROM ep_capability_operations\nWHERE operation_namespace IS NULL\n   OR action_fence_digest IS NULL;\nUPDATE ep_capability_operations\n  SET operation_namespace = capability_id\n  WHERE operation_namespace IS NULL;\nUPDATE ep_capability_operations\n  SET action_fence_digest = action_digest\n  WHERE action_fence_digest IS NULL;\nDO $capability_legacy_reservation_preflight$\nBEGIN\n  IF EXISTS (\n    SELECT 1 FROM ep_capability_operations\n      WHERE status = 'reserved' AND entry_deadline_at IS NULL\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'legacy reserved capability operations require operator reconciliation before action-fence migration';\n  END IF;\nEND\n$capability_legacy_reservation_preflight$;\nUPDATE ep_capability_state AS capability_state\n  SET semantic_fence_ready = FALSE\n  FROM pg_temp.ep_capability_action_fence_legacy_ids AS legacy_capability\n  WHERE legacy_capability.capability_id = capability_state.capability_id;\nUPDATE ep_capability_state AS capability_state\n  SET semantic_fence_ready = NOT EXISTS (\n    SELECT 1 FROM ep_capability_operations AS operation\n      WHERE operation.capability_id = capability_state.capability_id\n  )\n  WHERE capability_state.semantic_fence_ready IS NULL;\nALTER TABLE ep_capability_state\n  ALTER COLUMN semantic_fence_ready SET DEFAULT TRUE,\n  ALTER COLUMN semantic_fence_ready SET NOT NULL;\nCREATE OR REPLACE FUNCTION ep_require_semantic_capability_fence()\nRETURNS TRIGGER\nLANGUAGE plpgsql\nSET search_path FROM CURRENT\nAS $semantic_capability_fence_function$\nBEGIN\n  IF NOT EXISTS (\n    SELECT 1\n      FROM ep_capability_state AS capability_state\n      WHERE capability_state.capability_id = NEW.capability_id\n        AND capability_state.semantic_fence_ready IS TRUE\n        AND capability_state.revocation_state_ready IS TRUE\n        AND capability_state.revocation_mode IN ('direct', 'cascade')\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'capability semantic action fence is not ready',\n      DETAIL = format('capability_id=%s', NEW.capability_id),\n      HINT = 'Reissue a fresh capability with a new capability ID; do not infer semantic equivalence from historical exact digests.';\n  END IF;\n  RETURN NEW;\nEND\n$semantic_capability_fence_function$;\nDROP TRIGGER IF EXISTS ep_capability_operations_semantic_fence_guard\n  ON ep_capability_operations;\nCREATE TRIGGER ep_capability_operations_semantic_fence_guard\n  BEFORE INSERT ON ep_capability_operations\n  FOR EACH ROW\n  EXECUTE FUNCTION ep_require_semantic_capability_fence();\nALTER TABLE ep_capability_operations\n  ALTER COLUMN operation_namespace SET NOT NULL;\nALTER TABLE ep_capability_operations\n  ALTER COLUMN action_fence_digest SET NOT NULL;\nDO $capability_operation_primary_key$\nDECLARE\n  current_primary_key_name TEXT;\n  current_primary_key_definition TEXT;\nBEGIN\n  SELECT conname, pg_get_constraintdef(oid)\n    INTO current_primary_key_name, current_primary_key_definition\n    FROM pg_constraint\n    WHERE conrelid = 'ep_capability_operations'::regclass\n      AND contype = 'p';\n  IF current_primary_key_definition IS DISTINCT FROM 'PRIMARY KEY (operation_namespace, operation_id)' THEN\n    IF current_primary_key_name IS NOT NULL THEN\n      EXECUTE format(\n        'ALTER TABLE %I DROP CONSTRAINT %I',\n        'ep_capability_operations',\n        current_primary_key_name\n      );\n    END IF;\n    ALTER TABLE ep_capability_operations\n      ADD CONSTRAINT ep_capability_operations_pkey\n      PRIMARY KEY (operation_namespace, operation_id);\n  END IF;\nEND\n$capability_operation_primary_key$;\nCREATE INDEX IF NOT EXISTS ep_capability_operations_capability_idx ON ep_capability_operations(capability_id);\nCREATE INDEX IF NOT EXISTS ep_capability_operations_recovery_idx ON ep_capability_operations(status, entry_deadline_at);\nDO $capability_live_action_preflight$\nBEGIN\n  IF EXISTS (\n    SELECT 1\n      FROM ep_capability_operations\n      WHERE status IN ('reserved', 'provider_entered', 'committed')\n      GROUP BY operation_namespace, action_fence_digest\n      HAVING count(*) > 1\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '23505',\n      MESSAGE = 'duplicate live capability actions require operator reconciliation before installing the action fence';\n  END IF;\nEND\n$capability_live_action_preflight$;\nCREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq\n  ON ep_capability_operations(operation_namespace, action_fence_digest)\n  WHERE status IN ('reserved', 'provider_entered', 'committed');\nDO $capability_action_fence_index_contract$\nDECLARE\n  index_is_unique BOOLEAN;\n  index_is_valid BOOLEAN;\n  index_is_ready BOOLEAN;\n  index_is_immediate BOOLEAN;\n  index_is_exclusion BOOLEAN;\n  index_nulls_not_distinct BOOLEAN;\n  index_access_method TEXT;\n  index_table OID;\n  index_key_count INTEGER;\n  index_attribute_count INTEGER;\n  index_key_columns TEXT[];\n  index_key_collations OID[];\n  expected_key_collations OID[];\n  index_key_opclasses OID[];\n  expected_key_opclasses OID[];\n  index_key_options SMALLINT[];\n  index_predicate TEXT;\n  normalized_predicate TEXT;\nBEGIN\n  SELECT\n      i.indisunique,\n      i.indisvalid,\n      i.indisready,\n      i.indimmediate,\n      i.indisexclusion,\n      i.indnullsnotdistinct,\n      access_method.amname,\n      i.indrelid,\n      i.indnkeyatts,\n      i.indnatts,\n      ARRAY(\n        SELECT a.attname\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS a\n            ON a.attrelid = i.indrelid\n           AND a.attnum = key.attnum\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.collation_oid\n          FROM unnest(i.indcollation::OID[]) WITH ORDINALITY AS key(collation_oid, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT attribute.attcollation\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS attribute\n            ON attribute.attrelid = i.indrelid\n           AND attribute.attnum = key.attnum\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.opclass_oid\n          FROM unnest(i.indclass::OID[]) WITH ORDINALITY AS key(opclass_oid, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT default_opclass.oid\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS attribute\n            ON attribute.attrelid = i.indrelid\n           AND attribute.attnum = key.attnum\n          JOIN LATERAL (\n            SELECT opclass.oid\n              FROM pg_opclass AS opclass\n              WHERE opclass.opcmethod = index_relation.relam\n                AND opclass.opcdefault\n                AND opclass.opcintype = attribute.atttypid\n              ORDER BY opclass.oid\n              LIMIT 1\n          ) AS default_opclass ON TRUE\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.option_bits\n          FROM unnest(i.indoption::SMALLINT[]) WITH ORDINALITY AS key(option_bits, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      pg_get_expr(i.indpred, i.indrelid)\n    INTO\n      index_is_unique,\n      index_is_valid,\n      index_is_ready,\n      index_is_immediate,\n      index_is_exclusion,\n      index_nulls_not_distinct,\n      index_access_method,\n      index_table,\n      index_key_count,\n      index_attribute_count,\n      index_key_columns,\n      index_key_collations,\n      expected_key_collations,\n      index_key_opclasses,\n      expected_key_opclasses,\n      index_key_options,\n      index_predicate\n    FROM pg_index AS i\n    JOIN pg_class AS index_relation\n      ON index_relation.oid = i.indexrelid\n    JOIN pg_am AS access_method\n      ON access_method.oid = index_relation.relam\n    WHERE i.indexrelid = to_regclass('ep_capability_operations_live_action_uniq')\n      AND i.indrelid = 'ep_capability_operations'::regclass;\n\n  normalized_predicate := replace(\n    regexp_replace(coalesce(index_predicate, ''), '\\s+', '', 'g'),\n    '::text',\n    ''\n  );\n\n  IF index_is_unique IS DISTINCT FROM TRUE\n     OR index_is_valid IS DISTINCT FROM TRUE\n     OR index_is_ready IS DISTINCT FROM TRUE\n     OR index_is_immediate IS DISTINCT FROM TRUE\n     OR index_is_exclusion IS DISTINCT FROM FALSE\n     OR index_nulls_not_distinct IS DISTINCT FROM FALSE\n     OR index_access_method IS DISTINCT FROM 'btree'\n     OR index_table IS DISTINCT FROM 'ep_capability_operations'::regclass::OID\n     OR index_key_count IS DISTINCT FROM 2\n     OR index_attribute_count IS DISTINCT FROM 2\n     OR index_key_columns IS DISTINCT FROM ARRAY['operation_namespace', 'action_fence_digest']::TEXT[]\n     OR index_key_collations IS DISTINCT FROM expected_key_collations\n     OR index_key_opclasses IS DISTINCT FROM expected_key_opclasses\n     OR index_key_options IS DISTINCT FROM ARRAY[0, 0]::SMALLINT[]\n     OR normalized_predicate IS DISTINCT FROM\n       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'EMILIA capability action-fence index does not match its required contract',\n      DETAIL = format(\n        'unique=%s valid=%s ready=%s immediate=%s exclusion=%s nulls_not_distinct=%s method=%s table_oid=%s key_count=%s attribute_count=%s columns=%s collations=%s expected_collations=%s opclasses=%s expected_opclasses=%s options=%s predicate=%s',\n        coalesce(index_is_unique::TEXT, '<missing>'),\n        coalesce(index_is_valid::TEXT, '<missing>'),\n        coalesce(index_is_ready::TEXT, '<missing>'),\n        coalesce(index_is_immediate::TEXT, '<missing>'),\n        coalesce(index_is_exclusion::TEXT, '<missing>'),\n        coalesce(index_nulls_not_distinct::TEXT, '<missing>'),\n        coalesce(index_access_method, '<missing>'),\n        coalesce(index_table::TEXT, '<missing>'),\n        coalesce(index_key_count::TEXT, '<missing>'),\n        coalesce(index_attribute_count::TEXT, '<missing>'),\n        coalesce(array_to_string(index_key_columns, ','), '<missing>'),\n        coalesce(array_to_string(index_key_collations, ','), '<missing>'),\n        coalesce(array_to_string(expected_key_collations, ','), '<missing>'),\n        coalesce(array_to_string(index_key_opclasses, ','), '<missing>'),\n        coalesce(array_to_string(expected_key_opclasses, ','), '<missing>'),\n        coalesce(array_to_string(index_key_options, ','), '<missing>'),\n        coalesce(index_predicate, '<missing>')\n      ),\n      HINT = 'Do not continue. Remove or repair the conflicting index only through a reviewed migration after preserving all operation history.';\n  END IF;\nEND\n$capability_action_fence_index_contract$;";
export declare const CAPABILITY_SQL: Readonly<{
    register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest, revocation_mode, parent_capability_id, revocation_state_ready) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE) ON CONFLICT (capability_id) DO NOTHING";
    readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest, semantic_fence_ready, revocation_mode, parent_capability_id, revoked_at, revocation_state_ready FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
    revokeState: "UPDATE ep_capability_state SET revoked_at = $3 WHERE capability_id = $1 AND capability_fingerprint = $2 AND revoked_at IS NULL AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade')";
    readAllowanceStatus: "SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ep_gate_allowance_status WHERE allowance_profile_id = $1 FOR UPDATE";
    insertAllowanceStatus: "INSERT INTO ep_gate_allowance_status (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING";
    updateAllowanceStatus: "UPDATE ep_gate_allowance_status SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3";
    insertControlDomain: "INSERT INTO ep_gate_control_domains (control_domain_id, status, epoch, updated_at) VALUES ($1, 'active', 1, $2) ON CONFLICT (control_domain_id) DO NOTHING RETURNING control_domain_id, status, epoch";
    readControlDomain: "SELECT control_domain_id, status, epoch, frozen_at, frozen_by_digest, updated_at FROM ep_gate_control_domains WHERE control_domain_id = $1 FOR UPDATE";
    readControlDomainEvent: "SELECT operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at FROM ep_gate_control_domain_events WHERE operation_id = $1";
    freezeControlDomain: "UPDATE ep_gate_control_domains SET status = 'frozen', epoch = epoch + 1, frozen_at = $2, frozen_by_digest = $3, updated_at = $2 WHERE control_domain_id = $1 AND status = 'active' RETURNING control_domain_id, status, epoch";
    restoreControlDomain: "UPDATE ep_gate_control_domains SET status = 'active', epoch = epoch + 1, frozen_at = NULL, frozen_by_digest = NULL, updated_at = $2 WHERE control_domain_id = $1 AND status = 'frozen' RETURNING control_domain_id, status, epoch";
    insertControlDomainEvent: "INSERT INTO ep_gate_control_domain_events (operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)";
    readOperation: "SELECT operation_namespace, operation_id, capability_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest, control_domain_id, reserved_control_epoch FROM ep_capability_operations WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE";
    readActionHolder: "SELECT operation_id, status, action_digest, action_fence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND action_fence_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE";
    insertOperation: "INSERT INTO ep_capability_operations (operation_namespace, capability_id, operation_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest, control_domain_id, reserved_control_epoch) VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved', $8, $9, $10, $11, $12, $13, $14, $15)";
    reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND semantic_fence_ready IS TRUE AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade') AND revoked_at IS NULL AND budget_amount - consumed_amount - reserved_amount >= $2";
    beginProviderEntry: "UPDATE ep_capability_operations SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5";
    commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6";
    reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
    recoverPreEntryOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5";
    releaseGuardRefusedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'provider_entry_guard_release', released_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND reservation_token = $5 AND status = 'reserved'";
    releaseControlBlockedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = $6, released_at = $7 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND reservation_token = $4 AND status = 'reserved' AND control_domain_id = $5";
    releaseReservedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'authenticated_final_provider_non_entry', release_evidence_profile = $5, release_evidence_digest = $6, released_at = $8 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $7 AND $7 <= $8 AND status = 'reserved'";
    commitState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2";
    releaseReservedState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2 WHERE capability_id = $1 AND reserved_amount >= $2";
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
export declare function createPostgresCapabilityStore({ transaction, providerEntryTimeoutMs, stateDomainDigest, verifyControlTransition, }?: {
    transaction?: (callback: (query: Function) => any) => any;
    providerEntryTimeoutMs?: number;
    stateDomainDigest?: string | null;
    verifyControlTransition?: VerifyControlTransition;
}): {
    durable: boolean;
    atomicStateDomainCapable: boolean;
    stateDomainDigest: string | null;
    reconciliationCapable: boolean;
    revocationInheritanceCapable: boolean;
    allowanceCurrentnessCapable: boolean;
    providerEntryDispositionCapable: boolean;
    controlDomainCapable: boolean;
    registerControlDomain({ controlDomainId, now, }?: {
        controlDomainId?: string;
        now?: number | (() => number);
    }): Promise<any>;
    freezeControlDomain(options?: ControlTransitionOptions): Promise<any>;
    restoreControlDomain(options?: ControlTransitionOptions): Promise<any>;
    registerCapability(capabilityReceipt: any): Promise<any>;
    revokeCapability({ capabilityId, capabilityFingerprint, now }?: RevokeCapabilityOptions): Promise<any>;
    advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions): Promise<any>;
    reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace, operationId, actionDigest, actionFenceDigest, amount, currency, controlDomainId, allowanceStatus, now }: ReserveSpendOptions): Promise<any>;
    beginProviderEntry({ capabilityId, operationNamespace, operationId, reservationToken, controlDomainId, now }?: BeginProviderEntryOptions): Promise<any>;
    recoverPreEntrySpend({ capabilityId, operationNamespace, operationId, actionDigest, reservationToken, disposition, now }?: RecoverPreEntrySpendOptions): Promise<any>;
    commitSpend({ capabilityId, operationNamespace, operationId, reservationToken, outcome, now }?: CommitSpendOptions): Promise<any>;
    reconcileSpend({ capabilityId, operationNamespace, operationId, actionDigest, evidenceDigest, evidenceProfile, evidenceFinal, evidenceObservedAt, outcome, now }?: ReconcileSpendOptions): Promise<any>;
    getControlDomain(controlDomainId: any): Promise<any>;
    getControlDomainEvent(operationId: any): Promise<any>;
};
/**
 * Execute one spend under a capability. The base EP receipt is checked on
 * every spend with consumptionMode=none; the capability store is the replay
 * and budget authority. The external function is entered only after the
 * atomic reservation and durable provider-entry transition succeed. `action` is the budget projection; the
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
 * @param {Function|null} [options.verifyActionProfile]
 * @param {object|null} [options.executionDomain] relying-party executor and
 *   atomic state-domain binding. Aggregate accounting is claimed only when
 *   the pinned digest matches an atomic-capable store; otherwise an explicit
 *   single-executor binding is required for fallback.
 * @param {boolean} [options.requireHumanAuthorization]
 * @param {unknown} [options.humanAuthorization] native per-action artifact
 * @param {object|null} [options.humanAuthorizationPins] relying-party trust inputs
 * @param {Function|null} [options.verifyHumanAuthorization] native verifier
 * @param {Function|null} [options.providerEntryGuard] final relying-party check
 *   after the atomic budget reservation and immediately before provider entry.
 *   A refusal atomically releases, burns, or holds the pre-entry reservation
 *   according to the guard's closed disposition; it never invokes the provider.
 * @param {string} [options.controlDomainId] optional Gate execution-control
 *   domain. A guard-owned requirement is derived automatically; an explicit
 *   different domain is refused.
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 * @param {boolean} [options.thresholdSecretVerified]
 */
export declare function executeWithCapability({ capabilityReceipt, secret, action, store, executeAction, gate, selector, observedAction, trustedIssuerKeys, verifyBaseReceipt, resolveCaid, verifyActionProfile, executionDomain, requireHumanAuthorization, humanAuthorization, humanAuthorizationPins, verifyHumanAuthorization, providerEntryGuard, allowanceStatus, controlDomainId, operationId, now, thresholdSecretVerified, }?: ExecuteWithCapabilityOptions): Promise<ExecuteWithCapabilityResult>;
/**
 * Execute a capability requiring m-of-n Shamir shares.
 * @param {Record<string, any>} [args] capabilityReceipt, shares, and executeWithCapability passthrough options
 */
export declare function executeWithThreshold({ capabilityReceipt, shares, ...options }?: ExecuteWithCapabilityOptions & {
    shares?: string[];
}): Promise<ExecuteWithCapabilityResult>;
/**
 * Authentically reconcile a capability operation. Positive evidence records an
 * executed outcome without restoring budget. Final authenticated negative
 * evidence may release only a still-reserved operation after its durable
 * provider-entry deadline. Once provider entry consumes authority, negative
 * evidence records the reconciled outcome but never restores authority.
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
export declare function reconcileCapabilityOperation({ store, capabilityId, operationNamespace, operationId, action, evidence, verifyEvidence, now, }?: {
    store?: Record<string, any>;
    capabilityId?: string;
    operationNamespace?: string;
    operationId?: string;
    action?: Record<string, any>;
    evidence?: Record<string, any>;
    verifyEvidence?: (...args: any[]) => any;
    now?: number | (() => number);
}): Promise<{
    idempotent: boolean;
    evidence_profile?: any;
    ok: boolean;
    outcome: any;
    action_digest: any;
    evidence_digest: string;
    reason?: undefined;
} | {
    ok: boolean;
    reason: any;
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
 * @param {'direct'|'cascade'} [options.revocationMode]
 * @param {object|null} [options.scope]
 * @param {string} [options.delegateId]
 * @param {string} [options.capabilityId]
 * @param {Buffer|string} [options.secret]
 * @param {any} [options.store]
 * @param {string[]} [options.trustedIssuerKeys]
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 */
export declare function delegateCapabilityReceipt({ parentCapabilityReceipt, parentSecret, issuerPrivateKey, budget, expiry, threshold, revocationMode, scope, delegateId, capabilityId, secret, store, trustedIssuerKeys, operationId, now, }?: {
    parentCapabilityReceipt?: Record<string, any>;
    parentSecret?: Buffer | string;
    issuerPrivateKey?: KeyMaterial;
    budget?: CapabilityBudget;
    expiry?: string | number;
    threshold?: {
        m: number;
        n: number;
    };
    revocationMode?: CapabilityRevocationMode;
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
            revocation_mode: "direct" | "cascade";
            scope: any;
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference hybrid
 * migration in docs/protocol/pq-hybrid-program.md, section "PATTERN: the
 * reference hybrid migration" (EP-REVOCATION-v2, packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `capability_signature`, a wire-format change, so the artifact takes a new
 *    `@version` (EP-CAPABILITY-RECEIPT-v2). verifyCapabilityReceipt (v1) is
 *    untouched and refuses a v2 envelope on the version marker
 *    ('malformed_capability_receipt') before inspecting any signature; it never
 *    throws on caller input.
 * 2. SET SHAPE. `capability_signature` carries `required_algorithms` plus a
 *    `signatures` array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one per algorithm in the registered order. Ed25519
 *    keeps its base64url SPKI DER public key; ML-DSA-65 carries raw base64url
 *    public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (capabilityV2SignedPayload below), over the SAME canonical
 *    unsigned body v1 signs plus `required_algorithms`. Drop the ML-DSA leg and
 *    narrow `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies. The verifier rebuilds the bytes from the REGISTERED set.
 * 4. V1 COMPATIBILITY. v1 envelopes keep verifying through the unchanged
 *    synchronous verifyCapabilityReceipt; v2 verification is ASYNC (ML-DSA is
 *    async), so it is a SEPARATE entry point, with verifyCapabilityReceiptAny()
 *    routing on @version. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure returns a named reason; nothing throws on
 *    caller input. An absent ML-DSA backend is 'capability_pq_backend_unavailable'
 *    surfaced through the agility result, never a skipped check and never a pass on
 *    the classical leg.
 *
 * HONEST BOUNDARIES carry over from v1: the envelope authenticates issuer-signed
 * capability metadata; spend state is never trusted from the envelope, and every
 * spend must still pass through the atomic capability store. The ML-DSA backend is
 * @noble/post-quantum's pure-JS FIPS 204 implementation, not independently audited
 * and not a FIPS validated module. v2 does NOT retroactively protect v1 envelopes.
 */
export declare const CAPABILITY_RECEIPT_V2_VERSION = "EP-CAPABILITY-RECEIPT-v2";
/** The registered required algorithm set, in canonical order. */
export declare const CAPABILITY_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface CapabilityV2IssuerPin {
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key: string;
}
/**
 * The bytes BOTH legs sign: the SAME canonical unsigned body v1 signs, under the
 * v2 marker, plus the committed `required_algorithms` set. Recomputed
 * independently by the verifier from the PRESENTED receipt/capability and the
 * REGISTERED set. See PATTERN move 3.
 */
export declare function capabilityV2SignedPayload(receipt: any, capability: any, requiredAlgorithms?: readonly string[]): Buffer;
/**
 * Mint a signed HYBRID capability envelope. Reuses mintCapabilityReceipt for the
 * entire receipt/capability construction and validation, then re-signs the same
 * canonical body under both algorithms. For m-of-n > 1 the raw secret is not
 * returned; distribute the returned shares instead. Issuance throws on invalid
 * local input; verification below never throws.
 */
export declare function mintCapabilityReceiptV2(baseReceipt: any, options?: {
    issuerPrivateKey?: KeyMaterial;
    pqPublicKey?: string;
    pqPrivateKey?: string | Uint8Array;
    budget?: CapabilityBudget;
    expiry?: string | number;
    threshold?: {
        m: number;
        n: number;
    };
    revocationMode?: CapabilityRevocationMode;
    scope?: Record<string, any>;
    delegationChain?: any[];
    capabilityId?: string;
    secret?: Buffer | string;
}): Promise<Readonly<{
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
            revocation_mode: "direct" | "cascade";
            scope: any;
            delegation_chain: Record<string, any>[];
            expiry: string;
        };
        capability_signature: {
            profile: string;
            required_algorithms: ("Ed25519" | "ML-DSA-65")[];
            public_key: string;
            key_id: string;
            pq_public_key: string;
            pq_key_id: string;
            signatures: import("@emilia-protocol/verify/pq-signature-agility").AgileSignature[];
        };
    }>;
    secret: Buffer<ArrayBuffer> | null;
    shares: string[] | null;
}>>;
/**
 * FAIL-CLOSED hybrid verifier for one EP-CAPABILITY-RECEIPT-v2 envelope. Never
 * throws on caller input; a v2 envelope NEVER verifies on one leg alone. Trust
 * follows the same model as v1: a pinned issuer PAIR is required unless
 * allowUntrustedIssuer is set, in which case the presented (self-asserted) pair is
 * used and is explicitly untrusted.
 */
export declare function verifyCapabilityReceiptV2(capabilityReceipt: any, { trustedIssuerKeys, allowUntrustedIssuer, mldsaBackend, mldsaBackendLoader, }?: {
    trustedIssuerKeys?: CapabilityV2IssuerPin[];
    allowUntrustedIssuer?: boolean;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}): Promise<{
    ok: boolean;
    reason: string;
    receipt?: undefined;
    capability?: undefined;
    issuer_public_key?: undefined;
    issuer_pq_public_key?: undefined;
    issuer_trusted?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    receipt: Record<string, any>;
    capability: any;
    issuer_public_key: any;
    issuer_pq_public_key: any;
    issuer_trusted: boolean;
    reason?: undefined;
    detail?: undefined;
} | {
    ok: boolean;
    reason: string;
    detail: string;
    receipt?: undefined;
    capability?: undefined;
    issuer_public_key?: undefined;
    issuer_pq_public_key?: undefined;
    issuer_trusted?: undefined;
}>;
/**
 * Route an envelope of EITHER version to its verifier. v1 envelopes keep the exact
 * v1 verdict; v2 envelopes get the hybrid check. An envelope whose @version is
 * neither refuses through the v1 verifier, which is fail-closed.
 */
export declare function verifyCapabilityReceiptAny(capabilityReceipt: any, options?: any): Promise<{
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
}>;
declare const _default: {
    CAPABILITY_RECEIPT_VERSION: string;
    CAPABILITY_RECEIPT_V2_VERSION: string;
    CAPABILITY_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
    CAPABILITY_STATE_VERSION: string;
    CAPABILITY_SHARE_VERSION: string;
    CAPABILITY_SCOPE_PROFILE: string;
    CAPABILITY_CAID_SCOPE_PROFILE: string;
    CAPABILITY_ALLOWANCE_SCOPE_PROFILE: string;
    CAPABILITY_ACTION_FENCE_PROFILE: string;
    CAPABILITY_REVOCATION_MODES: readonly ["direct", "cascade"];
    CAPABILITY_ALLOWANCE_STATUS_TABLE: string;
    CAPABILITY_STATE_DDL: string;
    CAPABILITY_SQL: Readonly<{
        register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest, revocation_mode, parent_capability_id, revocation_state_ready) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE) ON CONFLICT (capability_id) DO NOTHING";
        readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest, semantic_fence_ready, revocation_mode, parent_capability_id, revoked_at, revocation_state_ready FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
        revokeState: "UPDATE ep_capability_state SET revoked_at = $3 WHERE capability_id = $1 AND capability_fingerprint = $2 AND revoked_at IS NULL AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade')";
        readAllowanceStatus: "SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ep_gate_allowance_status WHERE allowance_profile_id = $1 FOR UPDATE";
        insertAllowanceStatus: "INSERT INTO ep_gate_allowance_status (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING";
        updateAllowanceStatus: "UPDATE ep_gate_allowance_status SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3";
        insertControlDomain: "INSERT INTO ep_gate_control_domains (control_domain_id, status, epoch, updated_at) VALUES ($1, 'active', 1, $2) ON CONFLICT (control_domain_id) DO NOTHING RETURNING control_domain_id, status, epoch";
        readControlDomain: "SELECT control_domain_id, status, epoch, frozen_at, frozen_by_digest, updated_at FROM ep_gate_control_domains WHERE control_domain_id = $1 FOR UPDATE";
        readControlDomainEvent: "SELECT operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at FROM ep_gate_control_domain_events WHERE operation_id = $1";
        freezeControlDomain: "UPDATE ep_gate_control_domains SET status = 'frozen', epoch = epoch + 1, frozen_at = $2, frozen_by_digest = $3, updated_at = $2 WHERE control_domain_id = $1 AND status = 'active' RETURNING control_domain_id, status, epoch";
        restoreControlDomain: "UPDATE ep_gate_control_domains SET status = 'active', epoch = epoch + 1, frozen_at = NULL, frozen_by_digest = NULL, updated_at = $2 WHERE control_domain_id = $1 AND status = 'frozen' RETURNING control_domain_id, status, epoch";
        insertControlDomainEvent: "INSERT INTO ep_gate_control_domain_events (operation_id, control_domain_id, event_type, epoch_at_event, action_digest, authority_instance_digest, result, committed_at) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)";
        readOperation: "SELECT operation_namespace, operation_id, capability_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest, control_domain_id, reserved_control_epoch FROM ep_capability_operations WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE";
        readActionHolder: "SELECT operation_id, status, action_digest, action_fence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND action_fence_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE";
        insertOperation: "INSERT INTO ep_capability_operations (operation_namespace, capability_id, operation_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest, control_domain_id, reserved_control_epoch) VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved', $8, $9, $10, $11, $12, $13, $14, $15)";
        reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND semantic_fence_ready IS TRUE AND revocation_state_ready IS TRUE AND revocation_mode IN ('direct', 'cascade') AND revoked_at IS NULL AND budget_amount - consumed_amount - reserved_amount >= $2";
        beginProviderEntry: "UPDATE ep_capability_operations SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5";
        commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6";
        reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
        recoverPreEntryOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5";
        releaseGuardRefusedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'provider_entry_guard_release', released_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND reservation_token = $5 AND status = 'reserved'";
        releaseControlBlockedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = $6, released_at = $7 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND reservation_token = $4 AND status = 'reserved' AND control_domain_id = $5";
        releaseReservedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'authenticated_final_provider_non_entry', release_evidence_profile = $5, release_evidence_digest = $6, released_at = $8 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $7 AND $7 <= $8 AND status = 'reserved'";
        commitState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2, consumed_amount = consumed_amount + $2 WHERE capability_id = $1 AND reserved_amount >= $2";
        releaseReservedState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount - $2 WHERE capability_id = $1 AND reserved_amount >= $2";
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