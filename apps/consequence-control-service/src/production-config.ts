// SPDX-License-Identifier: Apache-2.0
import { AsyncLocalStorage } from 'node:async_hooks';
import crypto from 'node:crypto';

import { computeCaid } from '../../../caid/impl/js/caid.mjs';
import {
  createDefaultActionControlManifest,
  createTrustedActionFirewall,
  createProposalToEffectPostgresStore,
  createPostgresAebDurableConsumptionStore,
} from '@emilia-protocol/gate';
import { createProposalToEffect } from '@emilia-protocol/gate/proposal-to-effect';
import {
  createPostgresProposalToEffectStatusHeadStore,
  createProposalToEffectStatusVerifier,
} from '@emilia-protocol/gate/proposal-to-effect-status';
import {
  createAebNativeVerificationAttestationAdapter,
  digestAeb,
} from '@emilia-protocol/verify/aeb-adapter-contract';
import { strictJsonGate } from '@emilia-protocol/require-receipt/strict-json';
import { createStaticBearerAuthenticator } from '../../gate-service/src/auth.js';
import {
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
} from './github-app.js';

const BRIDGE_ADAPTER_ID = 'bridge:native';
const BRIDGE_ADAPTER_VERSION = '1';
const NORMAL_PROFILE = 'github.issue.update.v1';
const INDETERMINATE_PROFILE = 'github.issue.update.indeterminate-smoke.v1';
const ACTION_TYPE = 'github.issue.update.1';
const ACTION_FIELDS = Object.freeze([
  'action_type', 'owner', 'repo', 'issue_number', 'title', 'body',
]);
const ACTION_DEFINITION = Object.freeze({
  action_type: ACTION_TYPE,
  required_fields: [
    { name: 'owner', type: 'string' },
    { name: 'repo', type: 'string' },
    { name: 'issue_number', type: 'integer' },
    { name: 'title', type: 'string' },
    { name: 'body', type: 'string' },
  ],
  optional_fields: [],
});
const RECOVERY_TOKEN_MIN = 32;
const AEB_DATABASE_READINESS_CONTRACT = '20260723143500';
const PTE_DATABASE_READINESS_CONTRACT = '20260723150000';
const AEB_PRINCIPAL_READINESS_SQL = `
  SELECT
    principal_name,
    expected_recovery,
    tenant_binding_ok,
    role_membership_ok,
    opposite_role_absent,
    rpc_grants_ok,
    schema_objects_ok,
    schema_contract,
    TRUE AS recovery_precision_ok
  FROM ep_aeb_private.principal_readiness($1, $2)
`;
const PTE_PRINCIPAL_READINESS_SQL = `
  SELECT
    principal_name,
    expected_recovery,
    tenant_binding_ok,
    role_membership_ok,
    opposite_role_absent,
    rpc_grants_ok,
    schema_objects_ok,
    schema_contract,
    COALESCE(
      POSITION(
        'HH24:MI:SS.US' IN pg_catalog.pg_get_functiondef(
          pg_catalog.to_regprocedure(
            'proposal_to_effect_private.read_attempt(text,text,text,text,text,text)'
          )
        )
      ) > 0,
      FALSE
    ) AS recovery_precision_ok
  FROM proposal_to_effect_private.principal_readiness($1, $2)
`;

type JsonObject = Record<string, any>;

interface EvidenceContext {
  principal: { id: string };
  proposal: JsonObject;
  evidence: {
    artifacts: JsonObject;
    statuses: JsonObject;
  };
}

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function parseStrictEnvironmentJson(source: unknown, name: string): JsonObject {
  if (typeof source !== 'string' || source.length === 0 || source.length > 1024 * 1024
      || !strictJsonGate(source).ok) {
    throw new Error(`${name}_invalid`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(source); } catch { throw new Error(`${name}_invalid`); }
  if (!plainObject(parsed)) throw new Error(`${name}_invalid`);
  return parsed;
}

function required(environment: JsonObject, name: string, max = 1024 * 1024): string {
  const value = environment[name];
  if (typeof value !== 'string' || value.length === 0 || value.length > max || value.includes('\0')) {
    throw new Error(`${name}_required`);
  }
  return value;
}

function positiveInteger(environment: JsonObject, name: string, maximum = Number.MAX_SAFE_INTEGER): number {
  const value = required(environment, name, 32);
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${name}_invalid`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number > maximum) throw new Error(`${name}_invalid`);
  return number;
}

function githubSlug(value: unknown, name: string): string {
  if (typeof value !== 'string'
      || value.length < 1
      || value.length > 100
      || !/^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$/.test(value)) {
    throw new Error(`${name}_invalid`);
  }
  return value;
}

export function createGitHubIssueSelector({
  owner,
  repo,
  issueNumber,
}: {
  owner: string;
  repo: string;
  issueNumber: number;
}) {
  const safeOwner = githubSlug(owner, 'github_owner');
  const safeRepo = githubSlug(repo, 'github_repo');
  if (!Number.isSafeInteger(issueNumber) || issueNumber < 1) {
    throw new Error('github_issue_number_invalid');
  }
  return Object.freeze({
    action_type: ACTION_TYPE,
    protocol: 'http',
    method: 'PATCH',
    path: `/repos/${safeOwner}/${safeRepo}/issues/${issueNumber}`,
  });
}

export function createGitHubIssueControlManifest({
  owner,
  repo,
  issueNumber,
}: {
  owner: string;
  repo: string;
  issueNumber: number;
}) {
  const selector = createGitHubIssueSelector({ owner, repo, issueNumber });
  return createDefaultActionControlManifest({
    service: {
      name: 'EMILIA managed consequence-control canary',
      issuer: 'https://www.emiliaprotocol.ai',
      manifest_url: 'https://www.emiliaprotocol.ai/.well-known/agent-action-control.json',
    },
    includePassThrough: false,
    extraActions: [{
      id: 'github.issue.update.canary',
      label: 'Configured GitHub issue mutation',
      action_type: ACTION_TYPE,
      risk: 'high',
      receipt_required: true,
      assurance_class: 'class_a',
      max_age_sec: 900,
      match: {
        protocol: selector.protocol,
        method: selector.method,
        path: selector.path,
      },
      execution_binding: {
        required_fields: [...ACTION_FIELDS],
      },
    }],
  });
}

function secretBytes(environment: JsonObject, name: string): Uint8Array {
  const value = required(environment, name, 4096);
  let bytes: Buffer;
  try { bytes = Buffer.from(value, 'base64url'); } catch { throw new Error(`${name}_invalid`); }
  if (bytes.byteLength < 32) throw new Error(`${name}_invalid`);
  return bytes;
}

function constantTimeSecret(expected: string, candidate: unknown): boolean {
  if (typeof candidate !== 'string') return false;
  const left = crypto.createHash('sha256').update(expected).digest();
  const right = crypto.createHash('sha256').update(candidate).digest();
  return crypto.timingSafeEqual(left, right);
}

export function createAebGateConsumptionAdapter(store: any) {
  if (!store || store.durable !== true || store.ownershipFenced !== true
      || store.permanentConsumption !== true
      || typeof store.reserve !== 'function' || typeof store.commit !== 'function'
      || typeof store.release !== 'function') {
    throw new TypeError('aeb_gate_consumption_store_invalid');
  }
  const key = (receiptKey: string) => `gate-receipt:${receiptKey}`;
  return Object.freeze({
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
    async reserve(receiptKey: string) {
      return await store.reserve(key(receiptKey), [`gate-native:${receiptKey}`]) === 'RESERVED';
    },
    async commit(receiptKey: string) {
      return store.commit(key(receiptKey));
    },
    async release(receiptKey: string) {
      return store.release(key(receiptKey));
    },
    async consume(receiptKey: string) {
      const operationKey = key(receiptKey);
      if (await store.reserve(operationKey, [`gate-native:${receiptKey}`]) !== 'RESERVED') return false;
      return store.commit(operationKey);
    },
  });
}

function canonicalizeAction(input: unknown): { action: JsonObject; caid: string } {
  if (!plainObject(input) || Object.keys(input).sort().join(',')
      !== [...ACTION_FIELDS].sort().join(',')) {
    throw new Error('github_issue_action_invalid');
  }
  const result = computeCaid(input, {
    suite: 'jcs-sha256',
    definitions: [ACTION_DEFINITION],
  });
  if (!result.caid) throw new Error(`github_issue_action_invalid:${result.refusals?.join(',')}`);
  return { action: structuredClone(input), caid: result.caid };
}

function contextValue(storage: AsyncLocalStorage<EvidenceContext>): EvidenceContext {
  const value = storage.getStore();
  if (!value) throw new Error('consequence_evidence_context_missing');
  return value;
}

function readinessPrincipal(
  result: any,
  expectedRecovery: boolean,
  expectedContract: string,
): string | null {
  if (result?.rowCount !== 1 || result?.rows?.length !== 1) return null;
  const row = result.rows[0];
  if (!plainObject(row)
      || typeof row.principal_name !== 'string'
      || row.principal_name.length === 0
      || row.expected_recovery !== expectedRecovery
      || row.tenant_binding_ok !== true
      || row.role_membership_ok !== true
      || row.opposite_role_absent !== true
      || row.rpc_grants_ok !== true
      || row.schema_objects_ok !== true
      || row.recovery_precision_ok !== true
      || row.schema_contract !== expectedContract) {
    return null;
  }
  return row.principal_name;
}

async function verifyPoolPrincipal(
  pool: any,
  tenantId: string,
  expectedRecovery: boolean,
): Promise<string | null> {
  const parameters = [tenantId, expectedRecovery];
  const [aeb, pte] = await Promise.all([
    pool.query(AEB_PRINCIPAL_READINESS_SQL, parameters),
    pool.query(PTE_PRINCIPAL_READINESS_SQL, parameters),
  ]);
  const aebPrincipal = readinessPrincipal(
    aeb,
    expectedRecovery,
    AEB_DATABASE_READINESS_CONTRACT,
  );
  const ptePrincipal = readinessPrincipal(
    pte,
    expectedRecovery,
    PTE_DATABASE_READINESS_CONTRACT,
  );
  return aebPrincipal && aebPrincipal === ptePrincipal ? aebPrincipal : null;
}

export async function verifyDatabasePrincipalSeparation({
  executorPool,
  recoveryPool,
  tenantId,
}: {
  executorPool: any;
  recoveryPool: any;
  tenantId: string;
}): Promise<boolean> {
  if (!executorPool || !recoveryPool
      || typeof tenantId !== 'string' || tenantId.length === 0) return false;
  try {
    const [executorPrincipal, recoveryPrincipal] = await Promise.all([
      verifyPoolPrincipal(executorPool, tenantId, false),
      verifyPoolPrincipal(recoveryPool, tenantId, true),
    ]);
    return executorPrincipal !== null
      && recoveryPrincipal !== null
      && executorPrincipal !== recoveryPrincipal;
  } catch {
    return false;
  }
}

export async function createProductionConsequenceControlConfig({
  environment = process.env,
  PoolClass = null,
  fetchImpl = globalThis.fetch,
}: any = {}) {
  const executorDatabaseUrl = required(environment, 'EMILIA_CONSEQUENCE_EXECUTOR_DATABASE_URL');
  const recoveryDatabaseUrl = required(environment, 'EMILIA_CONSEQUENCE_RECOVERY_DATABASE_URL');
  if (executorDatabaseUrl === recoveryDatabaseUrl) {
    throw new Error('consequence_database_identities_must_differ');
  }
  const tenantId = required(environment, 'EMILIA_CONSEQUENCE_TENANT_ID', 256);
  const relyingPartyId = required(environment, 'EMILIA_CONSEQUENCE_RELYING_PARTY_ID', 256);
  const executorId = required(environment, 'EMILIA_CONSEQUENCE_EXECUTOR_ID', 256);
  const principalId = required(environment, 'EMILIA_CONSEQUENCE_PRINCIPAL_ID', 256);
  const apiToken = required(environment, 'EMILIA_CONSEQUENCE_API_TOKEN', 1024);
  const recoveryToken = required(environment, 'EMILIA_CONSEQUENCE_RECOVERY_TOKEN', 1024);
  if (recoveryToken.length < RECOVERY_TOKEN_MIN) throw new Error('EMILIA_CONSEQUENCE_RECOVERY_TOKEN_invalid');
  const proposalKey = secretBytes(environment, 'EMILIA_CONSEQUENCE_PROPOSAL_HMAC_KEY');
  const ownerKey = secretBytes(environment, 'EMILIA_CONSEQUENCE_OWNER_HMAC_KEY');
  const trust = parseStrictEnvironmentJson(
    required(environment, 'EMILIA_CONSEQUENCE_GATE_TRUST_JSON'),
    'EMILIA_CONSEQUENCE_GATE_TRUST_JSON',
  );
  const aebConfig = parseStrictEnvironmentJson(
    required(environment, 'EMILIA_CONSEQUENCE_AEB_CONFIG_JSON'),
    'EMILIA_CONSEQUENCE_AEB_CONFIG_JSON',
  );
  const statusConfig = parseStrictEnvironmentJson(
    required(environment, 'EMILIA_CONSEQUENCE_STATUS_CONFIG_JSON'),
    'EMILIA_CONSEQUENCE_STATUS_CONFIG_JSON',
  );
  const approvalEndpoint = required(environment, 'EMILIA_CONSEQUENCE_APPROVAL_ENDPOINT', 2048);
  const approvalToken = required(environment, 'EMILIA_CONSEQUENCE_APPROVAL_TOKEN', 4096);
  const githubOwner = githubSlug(
    required(environment, 'EMILIA_CONSEQUENCE_GITHUB_OWNER', 100),
    'EMILIA_CONSEQUENCE_GITHUB_OWNER',
  );
  const githubRepo = githubSlug(
    required(environment, 'EMILIA_CONSEQUENCE_GITHUB_REPO', 100),
    'EMILIA_CONSEQUENCE_GITHUB_REPO',
  );
  const githubIssueNumber = positiveInteger(environment, 'EMILIA_CONSEQUENCE_GITHUB_ISSUE_NUMBER');
  const ttlSeconds = positiveInteger(environment, 'EMILIA_CONSEQUENCE_PROPOSAL_TTL_SEC', 3600);

  const ResolvedPool = PoolClass ?? (await import('pg')).default.Pool;
  const executorPool = new ResolvedPool({
    connectionString: executorDatabaseUrl,
    max: 4,
    application_name: 'emilia-consequence-executor',
  });
  const recoveryPool = new ResolvedPool({
    connectionString: recoveryDatabaseUrl,
    max: 2,
    application_name: 'emilia-consequence-recovery',
  });
  const storage = new AsyncLocalStorage<EvidenceContext>();

  const aebStore = createPostgresAebDurableConsumptionStore({
    pool: executorPool,
    recoveryPool,
    tenantId,
    relyingPartyId,
    authorizeRecoveryClaim: async (claim: any) => (
      constantTimeSecret(recoveryToken, claim?.authorization)
      && contextValue(storage).proposal.operation_id.length > 0
    ),
  });
  const receiptStore = createPostgresAebDurableConsumptionStore({
    pool: executorPool,
    recoveryPool,
    tenantId,
    relyingPartyId: `${relyingPartyId}:receipt-gate`,
    authorizeRecoveryClaim: async () => false,
  });
  const statusHeadStore = createPostgresProposalToEffectStatusHeadStore({
    pool: executorPool,
    tenantId,
    relyingPartyId,
  });

  const consequenceStore = createProposalToEffectPostgresStore({
    pool: executorPool,
    recovery_pool: recoveryPool,
    owner_hmac_sha256_key: ownerKey,
    lease_seconds: 5,
    resolve_binding_digests: () => {
      const { proposal } = contextValue(storage);
      return {
        operation_digest: digestAeb({ operation_id: proposal.operation_id }),
        action_digest: proposal.aeb_action_digest,
        config_digest: proposal.aeb.pinned_config_digest,
      };
    },
    authorize_recovery: async (snapshot: any) => {
      const { principal, proposal } = contextValue(storage);
      return principal.id === principalId
        && snapshot.tenant_id === tenantId
        && snapshot.request_digest === proposal.consequence.request_digest;
    },
  });

  const tokenProvider = createGitHubAppInstallationTokenProvider({
    appId: required(environment, 'EMILIA_CONSEQUENCE_GITHUB_APP_ID', 32),
    installationId: required(environment, 'EMILIA_CONSEQUENCE_GITHUB_INSTALLATION_ID', 32),
    privateKeyPem: required(environment, 'EMILIA_CONSEQUENCE_GITHUB_PRIVATE_KEY', 32 * 1024),
    fetchImpl,
  });
  const normalProvider = createGitHubIssueEffectProvider({
    owner: githubOwner,
    repo: githubRepo,
    issueNumber: githubIssueNumber,
    tokenProvider,
    fetchImpl,
  });
  const indeterminateProvider = createGitHubIssueEffectProvider({
    owner: githubOwner,
    repo: githubRepo,
    issueNumber: githubIssueNumber,
    tokenProvider,
    forceIndeterminateAfterCommit: true,
    fetchImpl,
  });

  const adapter = createAebNativeVerificationAttestationAdapter({
    id: BRIDGE_ADAPTER_ID,
    version: BRIDGE_ADAPTER_VERSION,
  });
  const adapters = Object.freeze({ [BRIDGE_ADAPTER_ID]: adapter });

  const statusVerifier = createProposalToEffectStatusVerifier({
    authorityPin: statusConfig.authority_pin,
    targetMapper: ({ expected }) => ({
      type: 'receipt',
      id: expected.artifact_ref,
      digest: expected.evidence_digest,
      usage: 'authorization',
    }),
    certificateResolver: () => statusConfig.certificate,
    statusHeadStore,
    // This is an authenticated, tenant-bound lookup for the exact native
    // replay unit. Atomic reserve immediately afterwards still closes races.
    consumptionStateResolver: async ({ expected }) => ({
      authenticated: true,
      consumed: await aebStore.hasReplayFence(expected.replay_unit),
    }),
  });

  const gate = createTrustedActionFirewall({
    manifest: createGitHubIssueControlManifest({
      owner: githubOwner,
      repo: githubRepo,
      issueNumber: githubIssueNumber,
    }),
    store: createAebGateConsumptionAdapter(receiptStore),
    trustedKeys: trust.trustedKeys,
    keyRegistry: trust.keyRegistry,
    approverKeys: trust.approverKeys,
    rpId: trust.rpId,
    allowedOrigins: trust.allowedOrigins,
    maxAgeSec: trust.maxAgeSec ?? 900,
  });

  const profile = (id: string) => ({
    id,
    action_type: ACTION_TYPE,
    selector: createGitHubIssueSelector({
      owner: githubOwner,
      repo: githubRepo,
      issueNumber: githubIssueNumber,
    }),
    required_fields: [...ACTION_FIELDS],
    authorization: {
      authorization_endpoint: approvalEndpoint,
      flow: 'EP-APPROVAL-v1' as const,
    },
    aeb_requirement_ref: required(environment, 'EMILIA_CONSEQUENCE_AEB_REQUIREMENT_REF', 256),
    ttl_sec: ttlSeconds,
    canonicalize_action: canonicalizeAction,
  });

  const controller = createProposalToEffect({
    gate,
    proposal_integrity: { hmac_sha256_key: proposalKey },
    consequence: {
      tenant_id: tenantId,
      provider_id: 'github',
      provider_account_id: githubOwner,
      environment: 'production-smoke',
      executor_id: executorId,
      store: consequenceStore,
    },
    profiles: {
      [NORMAL_PROFILE]: profile(NORMAL_PROFILE),
      [INDETERMINATE_PROFILE]: profile(INDETERMINATE_PROFILE),
    },
    aeb: {
      config: aebConfig as any,
      adapters,
      store: aebStore,
      resolve_artifacts: () => structuredClone(contextValue(storage).evidence.artifacts),
      currentStatusResolver: ({ leg }: any) => {
        const entry = contextValue(storage).evidence.statuses[leg.artifact_ref];
        if (!plainObject(entry) || !Object.hasOwn(entry, 'artifact')) {
          throw new Error('status_artifact_missing');
        }
        return structuredClone(entry.artifact);
      },
      statusVerifier,
      verify_provider_evidence: ({ evidence, expected }: any) => {
        const { proposal } = contextValue(storage);
        const provider = proposal.profile_id === INDETERMINATE_PROFILE
          ? indeterminateProvider : normalProvider;
        return provider.verifyProviderEvidence({
          evidence,
          expected,
          action: proposal.action,
        }) as any;
      },
    },
  });

  const principal = Object.freeze({ id: principalId });
  const authenticateRequest = createStaticBearerAuthenticator(apiToken, principal);
  return {
    controller,
    authenticateRequest,
    authorizeProfile: async (candidate: any, profileId: string, action: unknown) => {
      if (candidate?.id !== principalId
          || ![NORMAL_PROFILE, INDETERMINATE_PROFILE].includes(profileId)) return false;
      try {
        const normalized = canonicalizeAction(action);
        return normalized.action.owner === githubOwner
          && normalized.action.repo === githubRepo
          && normalized.action.issue_number === githubIssueNumber;
      } catch {
        return false;
      }
    },
    effectForProfile: async ({ profile_id: profileId }: any) => (
      profileId === INDETERMINATE_PROFILE
        ? indeterminateProvider.effect
        : normalProvider.effect
    ),
    requesterAuthorization: async () => `Bearer ${approvalToken}`,
    lookupAttempt: async ({ lookup }: any) => {
      const reference = await consequenceStore.lookup(lookup);
      return reference ? consequenceStore.read(reference) : null;
    },
    recoverAttempt: async ({ attempt }: any) => {
      const recovered = await consequenceStore.recover(attempt);
      if (!recovered.recovered) throw new Error(recovered.reason);
      return {
        tenant_id: attempt.tenant_id,
        attempt_id: attempt.attempt_id,
        owner: recovered.owner,
      };
    },
    aebRecoveryAuthorization: async () => recoveryToken,
    withEvidenceContext: async <T>(input: EvidenceContext, work: () => Promise<T>) => (
      storage.run(structuredClone(input), work)
    ),
    readiness: async () => {
      const databaseReady = await verifyDatabasePrincipalSeparation({
        executorPool,
        recoveryPool,
        tenantId,
      });
      if (!databaseReady) return { ok: false };
      try {
        return { ok: typeof await tokenProvider.getToken() === 'string' };
      } catch {
        return { ok: false };
      }
    },
    close: async () => {
      await Promise.allSettled([executorPool.end(), recoveryPool.end()]);
    },
  };
}

export default createProductionConsequenceControlConfig;
