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
export declare const CAPABILITY_ALLOWANCE_SCOPE_PROFILE = "EP-CAPABILITY-ALLOWANCE-SCOPE-v1";
export declare const CAPABILITY_ACTION_FENCE_PROFILE = "EP-CAPABILITY-ACTION-FENCE-v1";
type KeyMaterial = KeyObject | string | Buffer;
type CapabilityBudget = {
    amount: number;
    currency: string;
};
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
    now?: number | (() => number);
};
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
    operationId?: string | null;
    now?: number | (() => number);
    thresholdSecretVerified?: boolean;
    providerEntryGuard?: ((context: Record<string, any>) => any) | null;
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
 * @param {object} [options.scope]
 * @param {any[]} [options.delegationChain]
 * @param {string} [options.capabilityId]
 * @param {string} [options.operationNamespace]
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
export declare function createMemoryCapabilityStore({ providerEntryTimeoutMs, }?: {
    providerEntryTimeoutMs?: number;
}): {
    durable: boolean;
    atomicStateDomainCapable: boolean;
    stateDomainDigest: string;
    reconciliationCapable: boolean;
    allowanceCurrentnessCapable: boolean;
    providerEntryDispositionCapable: boolean;
    registerCapability(capabilityReceipt: any): boolean;
    advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions): {
        ok: boolean;
        idempotent: boolean;
        reason?: undefined;
    } | {
        ok: boolean;
        reason: string;
        idempotent?: undefined;
    };
    reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace, operationId, actionDigest, actionFenceDigest, amount, currency, allowanceStatus, now }: ReserveSpendOptions): Promise<{
        ok: boolean;
        reason: string;
        action_digest?: undefined;
        action_fence_digest?: undefined;
        holding_operation_id?: undefined;
        operation_id?: undefined;
        reservation_token?: undefined;
        entry_deadline_at?: undefined;
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
        remaining?: undefined;
    } | {
        ok: boolean;
        operation_id: string;
        action_digest: string;
        action_fence_digest: string;
        reservation_token: `${string}-${string}-${string}-${string}-${string}`;
        entry_deadline_at: number;
        remaining: number;
        reason?: undefined;
        holding_operation_id?: undefined;
    }>;
    beginProviderEntry({ capabilityId, operationNamespace, operationId, reservationToken, now }?: BeginProviderEntryOptions): Promise<{
        ok: boolean;
        reason: string;
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
    getOperation(operationId: any, capabilityId?: null, operationNamespace?: null): any;
};
export declare const CAPABILITY_STATE_TABLE = "ep_capability_state";
export declare const CAPABILITY_OPERATION_TABLE = "ep_capability_operations";
export declare const CAPABILITY_ALLOWANCE_STATUS_TABLE = "ep_gate_allowance_status";
export declare const CAPABILITY_STATE_DDL = "CREATE TABLE IF NOT EXISTS ep_capability_state (\n  capability_id TEXT PRIMARY KEY,\n  capability_fingerprint TEXT NOT NULL CHECK (capability_fingerprint ~ '^sha256:[0-9a-f]{64}$'),\n  budget_amount BIGINT NOT NULL CHECK (budget_amount >= 0),\n  currency TEXT NOT NULL,\n  consumed_amount BIGINT NOT NULL DEFAULT 0 CHECK (consumed_amount >= 0),\n  reserved_amount BIGINT NOT NULL DEFAULT 0 CHECK (reserved_amount >= 0),\n  expires_at TIMESTAMPTZ NOT NULL,\n  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),\n  allowance_profile_id TEXT,\n  allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),\n  semantic_fence_ready BOOLEAN NOT NULL DEFAULT TRUE,\n  CHECK ((allowance_profile_id IS NULL) = (allowance_digest IS NULL))\n);\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS capability_fingerprint TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS allowance_profile_id TEXT;\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS allowance_digest TEXT CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_state ADD COLUMN IF NOT EXISTS semantic_fence_ready BOOLEAN;\nCREATE TABLE IF NOT EXISTS ep_gate_allowance_status (\n  allowance_profile_id TEXT PRIMARY KEY,\n  allowance_digest TEXT NOT NULL CHECK (allowance_digest ~ '^sha256:[0-9a-f]{64}$'),\n  revision BIGINT NOT NULL CHECK (revision > 0),\n  status_epoch BIGINT NOT NULL CHECK (status_epoch > 0),\n  status_head_digest TEXT NOT NULL CHECK (status_head_digest ~ '^sha256:[0-9a-f]{64}$'),\n  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),\n  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()\n);\nCREATE TABLE IF NOT EXISTS ep_capability_operations (\n  operation_namespace TEXT NOT NULL,\n  operation_id TEXT NOT NULL,\n  capability_id TEXT NOT NULL REFERENCES ep_capability_state(capability_id),\n  action_digest TEXT NOT NULL CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$'),\n  action_fence_digest TEXT NOT NULL CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  amount BIGINT NOT NULL CHECK (amount > 0),\n  currency TEXT NOT NULL,\n  status TEXT NOT NULL CONSTRAINT ep_capability_operations_status_check CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released')),\n  reservation_token TEXT NOT NULL,\n  outcome TEXT,\n  reconciliation_outcome TEXT CHECK (reconciliation_outcome IN ('executed')),\n  reconciliation_evidence_digest TEXT CHECK (reconciliation_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  allowance_revision BIGINT CHECK (allowance_revision > 0),\n  allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0),\n  allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$'),\n  reserved_at TIMESTAMPTZ NOT NULL,\n  entry_deadline_at TIMESTAMPTZ,\n  provider_entry_at TIMESTAMPTZ,\n  committed_at TIMESTAMPTZ,\n  reconciled_at TIMESTAMPTZ,\n  released_at TIMESTAMPTZ,\n  release_reason TEXT,\n  release_evidence_profile TEXT,\n  release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$'),\n  CHECK (\n    (reconciliation_outcome IS NULL AND reconciliation_evidence_digest IS NULL AND reconciled_at IS NULL)\n    OR\n    (reconciliation_outcome IS NOT NULL AND reconciliation_evidence_digest IS NOT NULL AND reconciled_at IS NOT NULL)\n  ),\n  CHECK (\n    (allowance_revision IS NULL AND allowance_status_epoch IS NULL AND allowance_status_head_digest IS NULL)\n    OR\n    (allowance_revision IS NOT NULL AND allowance_status_epoch IS NOT NULL AND allowance_status_head_digest IS NOT NULL)\n  ),\n  PRIMARY KEY (operation_namespace, operation_id)\n);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS operation_namespace TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS entry_deadline_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS provider_entry_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS released_at TIMESTAMPTZ;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_reason TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_evidence_profile TEXT;\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS release_evidence_digest TEXT CHECK (release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_action_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_action_digest_check\n  CHECK (action_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_release_evidence_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_release_evidence_digest_check\n  CHECK (release_evidence_digest IS NULL OR release_evidence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_status_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_status_check\n  CHECK (status IN ('reserved', 'provider_entered', 'committed', 'released'));\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_revision BIGINT CHECK (allowance_revision > 0);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_status_epoch BIGINT CHECK (allowance_status_epoch > 0);\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS allowance_status_head_digest TEXT CHECK (allowance_status_head_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations ADD COLUMN IF NOT EXISTS action_fence_digest TEXT CHECK (action_fence_digest ~ '^sha256:[0-9a-f]{64}$');\nALTER TABLE ep_capability_operations DROP CONSTRAINT IF EXISTS ep_capability_operations_action_fence_digest_check;\nALTER TABLE ep_capability_operations\n  ADD CONSTRAINT ep_capability_operations_action_fence_digest_check\n  CHECK (action_fence_digest IS NULL OR action_fence_digest ~ '^sha256:[0-9a-f]{64}$');\n-- Capture legacy capability ids before compatibility backfills erase the only\n-- reliable signal that their historical rows never carried a semantic fence.\n-- This also closes an incomplete-bootstrap case where the state flag was\n-- already added with its TRUE default but operation bindings remain legacy.\nDROP TABLE IF EXISTS pg_temp.ep_capability_action_fence_legacy_ids;\nCREATE TEMP TABLE ep_capability_action_fence_legacy_ids\nON COMMIT DROP\nAS\nSELECT DISTINCT capability_id\nFROM ep_capability_operations\nWHERE operation_namespace IS NULL\n   OR action_fence_digest IS NULL;\nUPDATE ep_capability_operations\n  SET operation_namespace = capability_id\n  WHERE operation_namespace IS NULL;\nUPDATE ep_capability_operations\n  SET action_fence_digest = action_digest\n  WHERE action_fence_digest IS NULL;\nDO $capability_legacy_reservation_preflight$\nBEGIN\n  IF EXISTS (\n    SELECT 1 FROM ep_capability_operations\n      WHERE status = 'reserved' AND entry_deadline_at IS NULL\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'legacy reserved capability operations require operator reconciliation before action-fence migration';\n  END IF;\nEND\n$capability_legacy_reservation_preflight$;\nUPDATE ep_capability_state AS capability_state\n  SET semantic_fence_ready = FALSE\n  FROM pg_temp.ep_capability_action_fence_legacy_ids AS legacy_capability\n  WHERE legacy_capability.capability_id = capability_state.capability_id;\nUPDATE ep_capability_state AS capability_state\n  SET semantic_fence_ready = NOT EXISTS (\n    SELECT 1 FROM ep_capability_operations AS operation\n      WHERE operation.capability_id = capability_state.capability_id\n  )\n  WHERE capability_state.semantic_fence_ready IS NULL;\nALTER TABLE ep_capability_state\n  ALTER COLUMN semantic_fence_ready SET DEFAULT TRUE,\n  ALTER COLUMN semantic_fence_ready SET NOT NULL;\nCREATE OR REPLACE FUNCTION ep_require_semantic_capability_fence()\nRETURNS TRIGGER\nLANGUAGE plpgsql\nSET search_path FROM CURRENT\nAS $semantic_capability_fence_function$\nBEGIN\n  IF NOT EXISTS (\n    SELECT 1\n      FROM ep_capability_state AS capability_state\n      WHERE capability_state.capability_id = NEW.capability_id\n        AND capability_state.semantic_fence_ready IS TRUE\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'capability semantic action fence is not ready',\n      DETAIL = format('capability_id=%s', NEW.capability_id),\n      HINT = 'Reissue a fresh capability with a new capability ID; do not infer semantic equivalence from historical exact digests.';\n  END IF;\n  RETURN NEW;\nEND\n$semantic_capability_fence_function$;\nDROP TRIGGER IF EXISTS ep_capability_operations_semantic_fence_guard\n  ON ep_capability_operations;\nCREATE TRIGGER ep_capability_operations_semantic_fence_guard\n  BEFORE INSERT ON ep_capability_operations\n  FOR EACH ROW\n  EXECUTE FUNCTION ep_require_semantic_capability_fence();\nALTER TABLE ep_capability_operations\n  ALTER COLUMN operation_namespace SET NOT NULL;\nALTER TABLE ep_capability_operations\n  ALTER COLUMN action_fence_digest SET NOT NULL;\nDO $capability_operation_primary_key$\nDECLARE\n  current_primary_key_name TEXT;\n  current_primary_key_definition TEXT;\nBEGIN\n  SELECT conname, pg_get_constraintdef(oid)\n    INTO current_primary_key_name, current_primary_key_definition\n    FROM pg_constraint\n    WHERE conrelid = 'ep_capability_operations'::regclass\n      AND contype = 'p';\n  IF current_primary_key_definition IS DISTINCT FROM 'PRIMARY KEY (operation_namespace, operation_id)' THEN\n    IF current_primary_key_name IS NOT NULL THEN\n      EXECUTE format(\n        'ALTER TABLE %I DROP CONSTRAINT %I',\n        'ep_capability_operations',\n        current_primary_key_name\n      );\n    END IF;\n    ALTER TABLE ep_capability_operations\n      ADD CONSTRAINT ep_capability_operations_pkey\n      PRIMARY KEY (operation_namespace, operation_id);\n  END IF;\nEND\n$capability_operation_primary_key$;\nCREATE INDEX IF NOT EXISTS ep_capability_operations_capability_idx ON ep_capability_operations(capability_id);\nCREATE INDEX IF NOT EXISTS ep_capability_operations_recovery_idx ON ep_capability_operations(status, entry_deadline_at);\nDO $capability_live_action_preflight$\nBEGIN\n  IF EXISTS (\n    SELECT 1\n      FROM ep_capability_operations\n      WHERE status IN ('reserved', 'provider_entered', 'committed')\n      GROUP BY operation_namespace, action_fence_digest\n      HAVING count(*) > 1\n  ) THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '23505',\n      MESSAGE = 'duplicate live capability actions require operator reconciliation before installing the action fence';\n  END IF;\nEND\n$capability_live_action_preflight$;\nCREATE UNIQUE INDEX IF NOT EXISTS ep_capability_operations_live_action_uniq\n  ON ep_capability_operations(operation_namespace, action_fence_digest)\n  WHERE status IN ('reserved', 'provider_entered', 'committed');\nDO $capability_action_fence_index_contract$\nDECLARE\n  index_is_unique BOOLEAN;\n  index_is_valid BOOLEAN;\n  index_is_ready BOOLEAN;\n  index_is_immediate BOOLEAN;\n  index_is_exclusion BOOLEAN;\n  index_nulls_not_distinct BOOLEAN;\n  index_access_method TEXT;\n  index_table OID;\n  index_key_count INTEGER;\n  index_attribute_count INTEGER;\n  index_key_columns TEXT[];\n  index_key_collations OID[];\n  expected_key_collations OID[];\n  index_key_opclasses OID[];\n  expected_key_opclasses OID[];\n  index_key_options SMALLINT[];\n  index_predicate TEXT;\n  normalized_predicate TEXT;\nBEGIN\n  SELECT\n      i.indisunique,\n      i.indisvalid,\n      i.indisready,\n      i.indimmediate,\n      i.indisexclusion,\n      i.indnullsnotdistinct,\n      access_method.amname,\n      i.indrelid,\n      i.indnkeyatts,\n      i.indnatts,\n      ARRAY(\n        SELECT a.attname\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS a\n            ON a.attrelid = i.indrelid\n           AND a.attnum = key.attnum\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.collation_oid\n          FROM unnest(i.indcollation::OID[]) WITH ORDINALITY AS key(collation_oid, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT attribute.attcollation\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS attribute\n            ON attribute.attrelid = i.indrelid\n           AND attribute.attnum = key.attnum\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.opclass_oid\n          FROM unnest(i.indclass::OID[]) WITH ORDINALITY AS key(opclass_oid, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT default_opclass.oid\n          FROM unnest(i.indkey::SMALLINT[]) WITH ORDINALITY AS key(attnum, ordinal)\n          JOIN pg_attribute AS attribute\n            ON attribute.attrelid = i.indrelid\n           AND attribute.attnum = key.attnum\n          JOIN LATERAL (\n            SELECT opclass.oid\n              FROM pg_opclass AS opclass\n              WHERE opclass.opcmethod = index_relation.relam\n                AND opclass.opcdefault\n                AND opclass.opcintype = attribute.atttypid\n              ORDER BY opclass.oid\n              LIMIT 1\n          ) AS default_opclass ON TRUE\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      ARRAY(\n        SELECT key.option_bits\n          FROM unnest(i.indoption::SMALLINT[]) WITH ORDINALITY AS key(option_bits, ordinal)\n          WHERE key.ordinal <= i.indnkeyatts\n          ORDER BY key.ordinal\n      ),\n      pg_get_expr(i.indpred, i.indrelid)\n    INTO\n      index_is_unique,\n      index_is_valid,\n      index_is_ready,\n      index_is_immediate,\n      index_is_exclusion,\n      index_nulls_not_distinct,\n      index_access_method,\n      index_table,\n      index_key_count,\n      index_attribute_count,\n      index_key_columns,\n      index_key_collations,\n      expected_key_collations,\n      index_key_opclasses,\n      expected_key_opclasses,\n      index_key_options,\n      index_predicate\n    FROM pg_index AS i\n    JOIN pg_class AS index_relation\n      ON index_relation.oid = i.indexrelid\n    JOIN pg_am AS access_method\n      ON access_method.oid = index_relation.relam\n    WHERE i.indexrelid = to_regclass('ep_capability_operations_live_action_uniq')\n      AND i.indrelid = 'ep_capability_operations'::regclass;\n\n  normalized_predicate := replace(\n    regexp_replace(coalesce(index_predicate, ''), '\\s+', '', 'g'),\n    '::text',\n    ''\n  );\n\n  IF index_is_unique IS DISTINCT FROM TRUE\n     OR index_is_valid IS DISTINCT FROM TRUE\n     OR index_is_ready IS DISTINCT FROM TRUE\n     OR index_is_immediate IS DISTINCT FROM TRUE\n     OR index_is_exclusion IS DISTINCT FROM FALSE\n     OR index_nulls_not_distinct IS DISTINCT FROM FALSE\n     OR index_access_method IS DISTINCT FROM 'btree'\n     OR index_table IS DISTINCT FROM 'ep_capability_operations'::regclass::OID\n     OR index_key_count IS DISTINCT FROM 2\n     OR index_attribute_count IS DISTINCT FROM 2\n     OR index_key_columns IS DISTINCT FROM ARRAY['operation_namespace', 'action_fence_digest']::TEXT[]\n     OR index_key_collations IS DISTINCT FROM expected_key_collations\n     OR index_key_opclasses IS DISTINCT FROM expected_key_opclasses\n     OR index_key_options IS DISTINCT FROM ARRAY[0, 0]::SMALLINT[]\n     OR normalized_predicate IS DISTINCT FROM\n       '(status=ANY(ARRAY[''reserved'',''provider_entered'',''committed'']))' THEN\n    RAISE EXCEPTION USING\n      ERRCODE = '55000',\n      MESSAGE = 'EMILIA capability action-fence index does not match its required contract',\n      DETAIL = format(\n        'unique=%s valid=%s ready=%s immediate=%s exclusion=%s nulls_not_distinct=%s method=%s table_oid=%s key_count=%s attribute_count=%s columns=%s collations=%s expected_collations=%s opclasses=%s expected_opclasses=%s options=%s predicate=%s',\n        coalesce(index_is_unique::TEXT, '<missing>'),\n        coalesce(index_is_valid::TEXT, '<missing>'),\n        coalesce(index_is_ready::TEXT, '<missing>'),\n        coalesce(index_is_immediate::TEXT, '<missing>'),\n        coalesce(index_is_exclusion::TEXT, '<missing>'),\n        coalesce(index_nulls_not_distinct::TEXT, '<missing>'),\n        coalesce(index_access_method, '<missing>'),\n        coalesce(index_table::TEXT, '<missing>'),\n        coalesce(index_key_count::TEXT, '<missing>'),\n        coalesce(index_attribute_count::TEXT, '<missing>'),\n        coalesce(array_to_string(index_key_columns, ','), '<missing>'),\n        coalesce(array_to_string(index_key_collations, ','), '<missing>'),\n        coalesce(array_to_string(expected_key_collations, ','), '<missing>'),\n        coalesce(array_to_string(index_key_opclasses, ','), '<missing>'),\n        coalesce(array_to_string(expected_key_opclasses, ','), '<missing>'),\n        coalesce(array_to_string(index_key_options, ','), '<missing>'),\n        coalesce(index_predicate, '<missing>')\n      ),\n      HINT = 'Do not continue. Remove or repair the conflicting index only through a reviewed migration after preserving all operation history.';\n  END IF;\nEND\n$capability_action_fence_index_contract$;";
export declare const CAPABILITY_SQL: Readonly<{
    register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(ep_capability_state.capability_fingerprint, EXCLUDED.capability_fingerprint), allowance_profile_id = COALESCE(ep_capability_state.allowance_profile_id, EXCLUDED.allowance_profile_id), allowance_digest = COALESCE(ep_capability_state.allowance_digest, EXCLUDED.allowance_digest) WHERE ep_capability_state.budget_amount = EXCLUDED.budget_amount AND ep_capability_state.currency = EXCLUDED.currency AND ep_capability_state.expires_at = EXCLUDED.expires_at AND (ep_capability_state.allowance_profile_id IS NULL OR ep_capability_state.allowance_profile_id IS NOT DISTINCT FROM EXCLUDED.allowance_profile_id) AND (ep_capability_state.allowance_digest IS NULL OR ep_capability_state.allowance_digest IS NOT DISTINCT FROM EXCLUDED.allowance_digest)";
    readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest, semantic_fence_ready FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
    readAllowanceStatus: "SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ep_gate_allowance_status WHERE allowance_profile_id = $1 FOR UPDATE";
    insertAllowanceStatus: "INSERT INTO ep_gate_allowance_status (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING";
    updateAllowanceStatus: "UPDATE ep_gate_allowance_status SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3";
    readOperation: "SELECT operation_namespace, operation_id, capability_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE";
    readActionHolder: "SELECT operation_id, status, action_digest, action_fence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND action_fence_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE";
    insertOperation: "INSERT INTO ep_capability_operations (operation_namespace, capability_id, operation_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest) VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved', $8, $9, $10, $11, $12, $13)";
    reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND semantic_fence_ready IS TRUE AND budget_amount - consumed_amount - reserved_amount >= $2";
    beginProviderEntry: "UPDATE ep_capability_operations SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5";
    commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6";
    reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
    recoverPreEntryOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5";
    releaseGuardRefusedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'provider_entry_guard_release', released_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND reservation_token = $5 AND status = 'reserved'";
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
export declare function createPostgresCapabilityStore({ transaction, providerEntryTimeoutMs, stateDomainDigest, }?: {
    transaction?: (callback: (query: Function) => any) => any;
    providerEntryTimeoutMs?: number;
    stateDomainDigest?: string | null;
}): {
    durable: boolean;
    atomicStateDomainCapable: boolean;
    stateDomainDigest: string | null;
    reconciliationCapable: boolean;
    allowanceCurrentnessCapable: boolean;
    providerEntryDispositionCapable: boolean;
    registerCapability(capabilityReceipt: any): Promise<any>;
    advanceAllowanceStatus(options: AdvanceAllowanceStatusOptions): Promise<any>;
    reserveSpend({ capabilityId, capabilityFingerprint, operationNamespace, operationId, actionDigest, actionFenceDigest, amount, currency, allowanceStatus, now }: ReserveSpendOptions): Promise<any>;
    beginProviderEntry({ capabilityId, operationNamespace, operationId, reservationToken, now }?: BeginProviderEntryOptions): Promise<any>;
    recoverPreEntrySpend({ capabilityId, operationNamespace, operationId, actionDigest, reservationToken, disposition, now }?: RecoverPreEntrySpendOptions): Promise<any>;
    commitSpend({ capabilityId, operationNamespace, operationId, reservationToken, outcome, now }?: CommitSpendOptions): Promise<any>;
    reconcileSpend({ capabilityId, operationNamespace, operationId, actionDigest, evidenceDigest, evidenceProfile, evidenceFinal, evidenceObservedAt, outcome, now }?: ReconcileSpendOptions): Promise<any>;
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
 * @param {string|null} [options.operationId]
 * @param {number|(() => number)} [options.now]
 * @param {boolean} [options.thresholdSecretVerified]
 */
export declare function executeWithCapability({ capabilityReceipt, secret, action, store, executeAction, gate, selector, observedAction, trustedIssuerKeys, verifyBaseReceipt, resolveCaid, verifyActionProfile, executionDomain, requireHumanAuthorization, humanAuthorization, humanAuthorizationPins, verifyHumanAuthorization, providerEntryGuard, allowanceStatus, operationId, now, thresholdSecretVerified, }?: ExecuteWithCapabilityOptions): Promise<ExecuteWithCapabilityResult>;
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
declare const _default: {
    CAPABILITY_RECEIPT_VERSION: string;
    CAPABILITY_STATE_VERSION: string;
    CAPABILITY_SHARE_VERSION: string;
    CAPABILITY_SCOPE_PROFILE: string;
    CAPABILITY_CAID_SCOPE_PROFILE: string;
    CAPABILITY_ALLOWANCE_SCOPE_PROFILE: string;
    CAPABILITY_ACTION_FENCE_PROFILE: string;
    CAPABILITY_ALLOWANCE_STATUS_TABLE: string;
    CAPABILITY_STATE_DDL: string;
    CAPABILITY_SQL: Readonly<{
        register: "INSERT INTO ep_capability_state (capability_id, budget_amount, currency, expires_at, capability_fingerprint, allowance_profile_id, allowance_digest) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (capability_id) DO UPDATE SET capability_fingerprint = COALESCE(ep_capability_state.capability_fingerprint, EXCLUDED.capability_fingerprint), allowance_profile_id = COALESCE(ep_capability_state.allowance_profile_id, EXCLUDED.allowance_profile_id), allowance_digest = COALESCE(ep_capability_state.allowance_digest, EXCLUDED.allowance_digest) WHERE ep_capability_state.budget_amount = EXCLUDED.budget_amount AND ep_capability_state.currency = EXCLUDED.currency AND ep_capability_state.expires_at = EXCLUDED.expires_at AND (ep_capability_state.allowance_profile_id IS NULL OR ep_capability_state.allowance_profile_id IS NOT DISTINCT FROM EXCLUDED.allowance_profile_id) AND (ep_capability_state.allowance_digest IS NULL OR ep_capability_state.allowance_digest IS NOT DISTINCT FROM EXCLUDED.allowance_digest)";
        readState: "SELECT capability_id, capability_fingerprint, budget_amount, currency, consumed_amount, reserved_amount, expires_at, allowance_profile_id, allowance_digest, semantic_fence_ready FROM ep_capability_state WHERE capability_id = $1 FOR UPDATE";
        readAllowanceStatus: "SELECT allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status FROM ep_gate_allowance_status WHERE allowance_profile_id = $1 FOR UPDATE";
        insertAllowanceStatus: "INSERT INTO ep_gate_allowance_status (allowance_profile_id, allowance_digest, revision, status_epoch, status_head_digest, status, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (allowance_profile_id) DO NOTHING";
        updateAllowanceStatus: "UPDATE ep_gate_allowance_status SET allowance_digest = $4, revision = $5, status_epoch = $6, status_head_digest = $7, status = $8, updated_at = $9 WHERE allowance_profile_id = $1 AND status_epoch = $2 AND status_head_digest = $3";
        readOperation: "SELECT operation_namespace, operation_id, capability_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, outcome, reconciliation_outcome, reconciliation_evidence_digest, allowance_revision, allowance_status_epoch, allowance_status_head_digest, reconciled_at, reserved_at, entry_deadline_at, provider_entry_at, released_at, release_reason, release_evidence_profile, release_evidence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND operation_id = $2 FOR UPDATE";
        readActionHolder: "SELECT operation_id, status, action_digest, action_fence_digest FROM ep_capability_operations WHERE operation_namespace = $1 AND action_fence_digest = $2 AND status IN ('reserved', 'provider_entered', 'committed') LIMIT 1 FOR UPDATE";
        insertOperation: "INSERT INTO ep_capability_operations (operation_namespace, capability_id, operation_id, action_digest, action_fence_digest, amount, currency, status, reservation_token, reserved_at, entry_deadline_at, allowance_revision, allowance_status_epoch, allowance_status_head_digest) VALUES ($1, $2, $3, $4, $5, $6, $7, 'reserved', $8, $9, $10, $11, $12, $13)";
        reserveState: "UPDATE ep_capability_state SET reserved_amount = reserved_amount + $2 WHERE capability_id = $1 AND semantic_fence_ready IS TRUE AND budget_amount - consumed_amount - reserved_amount >= $2";
        beginProviderEntry: "UPDATE ep_capability_operations SET status = 'provider_entered', provider_entry_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'reserved' AND reservation_token = $4 AND entry_deadline_at IS NOT NULL AND entry_deadline_at > $5";
        commitOperation: "UPDATE ep_capability_operations SET status = 'committed', outcome = $4, committed_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = $7 AND reservation_token = $6";
        reconcileOperation: "UPDATE ep_capability_operations SET reconciliation_outcome = $4, reconciliation_evidence_digest = $5, reconciled_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND status = 'committed' AND outcome = 'indeterminate' AND reconciliation_outcome IS NULL";
        recoverPreEntryOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'pre_entry_deadline_elapsed', released_at = $5 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND status = 'reserved' AND entry_deadline_at IS NOT NULL AND entry_deadline_at <= $5";
        releaseGuardRefusedOperation: "UPDATE ep_capability_operations SET status = 'released', outcome = 'not_entered', release_reason = 'provider_entry_guard_release', released_at = $6 WHERE operation_namespace = $1 AND operation_id = $2 AND capability_id = $3 AND action_digest = $4 AND reservation_token = $5 AND status = 'reserved'";
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