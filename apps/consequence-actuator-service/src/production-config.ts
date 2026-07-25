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
const PROVIDER_RESPONSE_LOSS_OPERATION =
  'github.issue.update.indeterminate-smoke.1';
const ACTUATOR_RESPONSE_LOSS_OPERATION =
  'github.issue.update.actuator-response-loss-smoke.1';
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

const WRITE_PROVIDER_RECORD_SQL = `
  SELECT provider_record_digest
  FROM consequence_actuator_private.record_provider_record(
    $1::jsonb,
    $2::text
  )
`;
const READ_PROVIDER_RECORD_SQL = `
  SELECT provider_record, provider_record_digest
  FROM consequence_actuator_private.read_provider_record(
    $1::text, $2::text, $3::text, $4::text, $5::text,
    $6::text, $7::text, $8::text, $9::text
  )
`;

function plainObject(value: unknown): value is JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function providerRecordKey(value: JsonObject): string {
  return JSON.stringify([
    value.tenant_id,
    value.provider_id,
    value.provider_account_id,
    value.environment,
    value.attempt_id,
    value.request_digest,
  ]);
}

function createMemoryProviderRecordStore() {
  const records = new Map<string, JsonObject>();
  return Object.freeze({
    async write(value: JsonObject) {
      const binding = value?.record?.payload?.provider_attribution?.payload;
      if (!plainObject(binding)) throw new Error('provider_record_invalid');
      const key = providerRecordKey(binding);
      const current = records.get(key);
      if (current && JSON.stringify(current) !== JSON.stringify(value)) {
        throw new Error('provider_record_conflict');
      }
      records.set(key, structuredClone(value));
      return structuredClone(value);
    },
    async read(expected: JsonObject) {
      const value = records.get(providerRecordKey(expected));
      return value ? structuredClone(value) : null;
    },
  });
}

function createPostgresProviderRecordStore(query: (
  text: string,
  values: readonly unknown[],
) => Promise<any>) {
  return Object.freeze({
    async write(value: JsonObject) {
      const result = await query(WRITE_PROVIDER_RECORD_SQL, [
        JSON.stringify(value.record),
        value.record_digest,
      ]);
      if (result?.rowCount !== 1
          || !Array.isArray(result.rows)
          || result.rows.length !== 1
          || result.rows[0]?.provider_record_digest !== value.record_digest) {
        throw new Error('provider_record_acknowledgement_ambiguous');
      }
      return structuredClone(value);
    },
    async read(expected: JsonObject) {
      const result = await query(READ_PROVIDER_RECORD_SQL, [
        expected.tenant_id,
        expected.provider_id,
        expected.provider_account_id,
        expected.environment,
        expected.request_digest,
        expected.attempt_id,
        expected.operation_id,
        expected.caid,
        expected.action_digest,
      ]);
      if (result?.rowCount === 0
          && Array.isArray(result.rows)
          && result.rows.length === 0) {
        return null;
      }
      if (result?.rowCount !== 1
          || !Array.isArray(result.rows)
          || result.rows.length !== 1
          || !plainObject(result.rows[0]?.provider_record)
          || typeof result.rows[0]?.provider_record_digest !== 'string') {
        throw new Error('provider_record_read_ambiguous');
      }
      return {
        record: structuredClone(result.rows[0].provider_record),
        record_digest: result.rows[0].provider_record_digest,
      };
    },
  });
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
  const left = Buffer.from(expected, 'utf8');
  const right = Buffer.from(candidate, 'utf8');
  if (left.length !== right.length) return false;
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
  let providerRecordStore: any;
  if (useMemoryStore) {
    store = createMemoryConsequenceActuatorStore();
    providerRecordStore = createMemoryProviderRecordStore();
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
    providerRecordStore = createPostgresProviderRecordStore(
      executorPool.query,
    );
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
    attributionIssuerId: envelopeIssuerId,
    attributionKeyId: observationKeyId,
    attributionPrivateKey: observationPrivateKey,
    providerAttributionKeyId: envelopeKeyId,
    providerAttributionPublicKey: envelopePublicKey,
    targetDigest: configuredTargetDigest,
    providerRecordStore,
    fetchImpl,
  });
  const providerResponseLossProvider = createGitHubIssueEffectProvider({
    owner: providerAccountId,
    repo,
    issueNumber,
    tokenProvider,
    attributionIssuerId: envelopeIssuerId,
    attributionKeyId: observationKeyId,
    attributionPrivateKey: observationPrivateKey,
    providerAttributionKeyId: envelopeKeyId,
    providerAttributionPublicKey: envelopePublicKey,
    targetDigest: configuredTargetDigest,
    providerRecordStore,
    forceProviderResponseLossBeforeTerminalRecord: true,
    fetchImpl,
  });
  const actuatorResponseLossProvider = createGitHubIssueEffectProvider({
    owner: providerAccountId,
    repo,
    issueNumber,
    tokenProvider,
    attributionIssuerId: envelopeIssuerId,
    attributionKeyId: observationKeyId,
    attributionPrivateKey: observationPrivateKey,
    providerAttributionKeyId: envelopeKeyId,
    providerAttributionPublicKey: envelopePublicKey,
    targetDigest: configuredTargetDigest,
    providerRecordStore,
    forceIndeterminateAfterCommit: true,
    fetchImpl,
  });
  const perform = (provider: any) => async ({
    action,
    signedAttribution,
  }: any) => provider.effect({
    action,
    attempt: signedAttribution,
  });

  return {
    ...(useMemoryStore ? { testOnly: true as const } : {}),
    tenantId,
    providerId: 'github',
    providerAccountId,
    environment: 'production-smoke',
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
      [PROVIDER_RESPONSE_LOSS_OPERATION]:
        perform(providerResponseLossProvider),
      [ACTUATOR_RESPONSE_LOSS_OPERATION]:
        perform(actuatorResponseLossProvider),
    }),
    observationSigner,
    reconciliationEvidence: {
      privateKey: observationPrivateKey,
      keyId: observationKeyId,
    },
    observeProvider: async ({ action, expected, operation }: any) => {
      const observation = await normalProvider.verifyProviderEvidence({
        evidence: { kind: 'github-issue-observation-v1' },
        expected,
        action,
        operation,
      });
      if (observation?.valid !== true
          || typeof observation.outcome !== 'string'
          || !['COMMITTED', 'NOT_COMMITTED']
            .includes(observation.outcome)
          || typeof observation.reason !== 'string'
          || typeof observation.observed_at !== 'string'
          || typeof observation.evidence_digest !== 'string') {
        throw new Error('github_provider_observation_refused');
      }
      return {
        outcome: observation.outcome,
        reason: observation.reason,
        observed_at: observation.observed_at,
        tenant_id: observation.tenant_id,
        request_digest: observation.request_digest,
        provider_id: observation.provider_id,
        provider_account_id: observation.provider_account_id,
        environment: observation.environment,
        attempt_id: observation.attempt_id,
        operation_id: observation.operation_id,
        caid: observation.caid,
        action_digest: observation.action_digest,
        target_digest: observation.target_digest,
        operation: observation.operation,
        nonce: observation.nonce,
        envelope_digest: observation.envelope_digest,
        provider_attribution_digest:
          observation.provider_attribution_digest,
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
