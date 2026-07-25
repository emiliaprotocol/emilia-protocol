// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

import { computeCaid } from '../../../caid/impl/js/caid.mjs';
import {
  createMemoryConsequenceActuatorStore,
  createPostgresConsequenceActuatorStore,
} from '@emilia-protocol/gate/consequence-actuator';
import { digestAeb } from '@emilia-protocol/verify/aeb-adapter-contract';

import {
  createGitHubAppInstallationTokenProvider,
  createGitHubIssueEffectProvider,
} from './github-app.js';
import { createConsequenceActuatorObservationSigner } from './observation.js';

const NORMAL_OPERATION = 'github.issue.update.1';
const INDETERMINATE_OPERATION =
  'github.issue.update.indeterminate-smoke.1';
const ACTION_FIELDS = Object.freeze([
  'action_type', 'owner', 'repo', 'issue_number', 'title', 'body',
]);
const ACTION_DEFINITION = Object.freeze({
  action_type: 'github.issue.update.1',
  required_fields: [
    { name: 'owner', type: 'string' },
    { name: 'repo', type: 'string' },
    { name: 'issue_number', type: 'integer' },
    { name: 'title', type: 'string' },
    { name: 'body', type: 'string' },
  ],
  optional_fields: [],
});

type JsonObject = Record<string, any>;

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function required(
  environment: JsonObject,
  name: string,
  maximum = 1024 * 1024,
): string {
  const value = environment[name];
  if (typeof value !== 'string' || value.length < 1
      || value.length > maximum || value.includes('\0')) {
    throw new Error(`${name}_required`);
  }
  return value;
}

function identifier(value: unknown, name: string): string {
  if (typeof value !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(value)) {
    throw new Error(`${name}_invalid`);
  }
  return value;
}

function positiveInteger(
  environment: JsonObject,
  name: string,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const value = required(environment, name, 32);
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`${name}_invalid`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result > maximum) {
    throw new Error(`${name}_invalid`);
  }
  return result;
}

function constantTimeBearer(expected: string, authorization: unknown): boolean {
  if (typeof authorization !== 'string'
      || !authorization.startsWith('Bearer ')) return false;
  const candidate = authorization.slice('Bearer '.length);
  const left = crypto.createHash('sha256').update(expected).digest();
  const right = crypto.createHash('sha256').update(candidate).digest();
  return crypto.timingSafeEqual(left, right);
}

function targetDigest({
  providerAccountId,
  owner,
  repo,
  issueNumber,
}: {
  providerAccountId: string;
  owner: string;
  repo: string;
  issueNumber: number;
}) {
  return digestAeb({
    domain: 'EP-CONSEQUENCE-ACTUATOR-TARGET-v1',
    provider_id: 'github',
    provider_account_id: providerAccountId,
    target: {
      kind: 'github.issue',
      owner,
      repo,
      issue_number: issueNumber,
    },
  });
}

function createActionNormalizer({
  owner,
  repo,
  issueNumber,
  configuredTargetDigest,
}: {
  owner: string;
  repo: string;
  issueNumber: number;
  configuredTargetDigest: string;
}) {
  return (input: unknown) => {
    if (!plainObject(input)
        || Object.keys(input).sort().join(',')
          !== [...ACTION_FIELDS].sort().join(',')
        || input.action_type !== 'github.issue.update.1'
        || input.owner !== owner
        || input.repo !== repo
        || input.issue_number !== issueNumber
        || typeof input.title !== 'string'
        || input.title.length < 1
        || input.title.length > 256
        || typeof input.body !== 'string'
        || input.body.length > 65_536
        || input.title.includes('\0')
        || input.body.includes('\0')) {
      throw new Error('github_issue_action_refused');
    }
    const action = structuredClone(input);
    const computed = computeCaid(action, {
      suite: 'jcs-sha256',
      definitions: [ACTION_DEFINITION],
    });
    if (!computed.caid) throw new Error('github_issue_caid_refused');
    return {
      action,
      actionDigest: digestAeb(action),
      caid: computed.caid,
      targetDigest: configuredTargetDigest,
    };
  };
}

export async function createProductionConsequenceActuatorConfig({
  environment = process.env,
  PoolClass = null,
  fetchImpl = globalThis.fetch,
}: any = {}) {
  const memoryFlag = environment.EMILIA_ACTUATOR_ALLOW_MEMORY_STORE_FOR_TESTS;
  if (memoryFlag !== undefined
      && memoryFlag !== 'true'
      && memoryFlag !== 'false') {
    throw new Error('EMILIA_ACTUATOR_ALLOW_MEMORY_STORE_FOR_TESTS_invalid');
  }
  if (memoryFlag === 'true' && environment.NODE_ENV !== 'test') {
    throw new Error('consequence_actuator_memory_store_test_only');
  }
  const useMemoryStore = memoryFlag === 'true';
  const databaseUrl = useMemoryStore
    ? null
    : environment.EMILIA_ACTUATOR_DATABASE_URL;
  if (!useMemoryStore
      && (typeof databaseUrl !== 'string'
        || databaseUrl.length === 0
        || databaseUrl.includes('\0'))) {
    throw new Error('consequence_actuator_durable_store_required');
  }
  const databasePrincipal = useMemoryStore
    ? null
    : identifier(
      required(environment, 'EMILIA_ACTUATOR_DATABASE_PRINCIPAL', 256),
      'EMILIA_ACTUATOR_DATABASE_PRINCIPAL',
    );
  const tenantId = identifier(
    required(environment, 'EMILIA_ACTUATOR_TENANT_ID', 256),
    'EMILIA_ACTUATOR_TENANT_ID',
  );
  const apiToken = required(environment, 'EMILIA_ACTUATOR_API_TOKEN', 4096);
  if (apiToken.length < 32) throw new Error('EMILIA_ACTUATOR_API_TOKEN_invalid');
  const providerAccountId = identifier(
    required(environment, 'EMILIA_ACTUATOR_GITHUB_OWNER', 100),
    'EMILIA_ACTUATOR_GITHUB_OWNER',
  );
  const repo = identifier(
    required(environment, 'EMILIA_ACTUATOR_GITHUB_REPO', 100),
    'EMILIA_ACTUATOR_GITHUB_REPO',
  );
  const issueNumber = positiveInteger(
    environment,
    'EMILIA_ACTUATOR_GITHUB_ISSUE_NUMBER',
  );
  const configuredTargetDigest = targetDigest({
    providerAccountId,
    owner: providerAccountId,
    repo,
    issueNumber,
  });
  const envelopeIssuerId = identifier(
    required(environment, 'EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID', 256),
    'EMILIA_ACTUATOR_ENVELOPE_ISSUER_ID',
  );
  const envelopeKeyId = identifier(
    required(environment, 'EMILIA_ACTUATOR_ENVELOPE_KEY_ID', 256),
    'EMILIA_ACTUATOR_ENVELOPE_KEY_ID',
  );
  const envelopePublicKey = required(
    environment,
    'EMILIA_ACTUATOR_ENVELOPE_PUBLIC_KEY',
    32 * 1024,
  );
  const observationIssuerId = identifier(
      required(environment, 'EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID', 256),
      'EMILIA_ACTUATOR_OBSERVATION_ISSUER_ID',
  );
  const observationKeyId = identifier(
      required(environment, 'EMILIA_ACTUATOR_OBSERVATION_KEY_ID', 256),
      'EMILIA_ACTUATOR_OBSERVATION_KEY_ID',
  );
  const observationPrivateKey = required(
    environment,
    'EMILIA_ACTUATOR_OBSERVATION_PRIVATE_KEY',
    32 * 1024,
  );
  const observationSigner = createConsequenceActuatorObservationSigner({
    issuerId: observationIssuerId,
    keyId: observationKeyId,
    privateKey: observationPrivateKey,
  });

  let pool: any = null;
  let store: any;
  if (useMemoryStore) {
    store = createMemoryConsequenceActuatorStore();
  } else {
    const ResolvedPool = PoolClass ?? (await import('pg')).default.Pool;
    pool = new ResolvedPool({
      connectionString: databaseUrl,
      max: 4,
      application_name: 'emilia-consequence-actuator',
    });
    const executorPool = Object.freeze({
      principal: databasePrincipal!,
      query: pool.query.bind(pool),
    });
    store = createPostgresConsequenceActuatorStore({
      tenantId,
      executorPrincipal: databasePrincipal!,
      executorPool,
    });
  }
  const tokenProvider = createGitHubAppInstallationTokenProvider({
    appId: required(environment, 'EMILIA_ACTUATOR_GITHUB_APP_ID', 32),
    installationId: required(
      environment,
      'EMILIA_ACTUATOR_GITHUB_INSTALLATION_ID',
      32,
    ),
    privateKeyPem: required(
      environment,
      'EMILIA_ACTUATOR_GITHUB_PRIVATE_KEY',
      32 * 1024,
    ),
    fetchImpl,
  });
  const normalProvider = createGitHubIssueEffectProvider({
    owner: providerAccountId,
    repo,
    issueNumber,
    tokenProvider,
    fetchImpl,
  });
  const indeterminateProvider = createGitHubIssueEffectProvider({
    owner: providerAccountId,
    repo,
    issueNumber,
    tokenProvider,
    forceIndeterminateAfterCommit: true,
    fetchImpl,
  });
  const perform = (provider: any) => async ({
    action,
    binding,
  }: any) => provider.effect({
    action,
    attempt: {
      tenant_id: binding.tenant_id,
      provider_id: 'github',
      provider_account_id: binding.provider_account_id,
      environment: 'production-smoke',
      attempt_id: binding.attempt_id,
      request_digest: binding.action_digest,
    },
  });

  return {
    tenantId,
    providerId: 'github',
    providerAccountId,
    targetDigest: configuredTargetDigest,
    envelopeIssuerId,
    envelopeKeyId,
    envelopePublicKey,
    maxEnvelopeTtlMs: 60_000,
    clockSkewMs: 5_000,
    store,
    normalizeAction: createActionNormalizer({
      owner: providerAccountId,
      repo,
      issueNumber,
      configuredTargetDigest,
    }),
    operations: Object.freeze({
      [NORMAL_OPERATION]: perform(normalProvider),
      [INDETERMINATE_OPERATION]: perform(indeterminateProvider),
    }),
    observationSigner,
    reconciliationEvidence: {
      privateKey: observationPrivateKey,
      keyId: observationKeyId,
    },
    observeProvider: async ({ action, expected }: any) => {
      const observation = await normalProvider.verifyProviderEvidence({
        evidence: { kind: 'github-issue-observation-v1' },
        expected,
        action,
      });
      if (observation?.valid !== true
          || observation.outcome !== 'ESCALATED'
          || typeof observation.reason !== 'string'
          || typeof observation.observed_at !== 'string'
          || typeof observation.evidence_digest !== 'string') {
        throw new Error('github_provider_observation_refused');
      }
      return {
        outcome: 'ESCALATED',
        reason: observation.reason,
        observed_at: observation.observed_at,
        provider_observation_digest: observation.evidence_digest,
      };
    },
    authenticateRequest: (authorization: unknown) => (
      constantTimeBearer(apiToken, authorization)
    ),
    readiness: async () => {
      try {
        const [principal, token] = await Promise.all([
          useMemoryStore ? Promise.resolve({
            rowCount: 1,
            rows: [{
              principal_name: 'test-memory',
              role_membership_ok: true,
            }],
          }) : pool.query(`
            SELECT
              SESSION_USER::TEXT AS principal_name,
              pg_catalog.pg_has_role(
                SESSION_USER,
                'consequence_actuator_executor',
                'MEMBER'
              ) AS role_membership_ok
          `),
          tokenProvider.getToken(),
        ]);
        return {
          ok: principal?.rowCount === 1
            && (useMemoryStore
              || principal.rows?.[0]?.principal_name === databasePrincipal)
            && principal.rows?.[0]?.role_membership_ok === true
            && typeof token === 'string'
            && token.length > 0,
        };
      } catch {
        return { ok: false };
      }
    },
    close: async () => {
      if (pool) await pool.end();
    },
  };
}

export default createProductionConsequenceActuatorConfig;
