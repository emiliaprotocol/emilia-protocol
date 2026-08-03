// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const docs = readFileSync(resolve(ROOT, 'docs/AGENT-RECORD.md'), 'utf8');
const deploymentDocs = readFileSync(resolve(ROOT, 'docs/operations/DEPLOYMENT.md'), 'utf8');
const capabilityDocs = readFileSync(
  resolve(ROOT, 'docs/AGENT-RECORD-CREATION-CAPABILITY.md'),
  'utf8',
);
const schemaWorkflow = readFileSync(resolve(ROOT, '.github/workflows/schema-security.yml'), 'utf8');
const openApiSource = readFileSync(resolve(ROOT, 'openapi.yaml'), 'utf8');
const openApiDocument = YAML.parseDocument(openApiSource, { uniqueKeys: true });
const openApi = openApiDocument.toJS();

function markdownSection(heading: string, nextHeading: string): string {
  const start = docs.indexOf(`## ${heading}`);
  const end = docs.indexOf(`## ${nextHeading}`, start + 1);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return docs.slice(start, end);
}

function resolveRef(ref: string): any {
  expect(ref).toMatch(/^#\//);
  return ref
    .slice(2)
    .split('/')
    .reduce((value, key) => value?.[key], openApi);
}

describe('Agent Record documentation and OpenAPI lifecycle contract', () => {
  it('keeps the canonical OpenAPI document parseable with unique keys', () => {
    expect(openApiDocument.errors.map((error) => error.message)).toEqual([]);
    expect(openApiDocument.warnings.map((warning) => warning.message)).toEqual([]);
  });

  it('documents read and sign before the atomic record transaction', () => {
    const creationDocs = markdownSection('Creation boundary', 'Public projection');
    const operation = openApi.paths['/api/adopt/sessions/{sessionId}/records'].post;

    for (const lifecycle of [creationDocs, operation.description]) {
      const normalized = lifecycle.replaceAll('`', '').replace(/\s+/g, ' ').toLowerCase();
      const readIndex = normalized.indexOf('read');
      const signIndex = normalized.indexOf('signs');
      const insertIndex = normalized.indexOf('inserts the immutable agent record');

      expect(readIndex).toBeGreaterThanOrEqual(0);
      expect(signIndex).toBeGreaterThan(readIndex);
      expect(insertIndex).toBeGreaterThan(signIndex);
      expect(normalized).toMatch(
        /signs (?:the )?ep-agent-record-observation-v1 (?:projection )?before any database mutation/,
      );
      expect(normalized).toContain('creation capability');
      expect(normalized).toMatch(/one (?:base )?(?:create_agent_record )?database transaction|authorizes one database transaction/);
      expect(lifecycle).not.toContain('publishBoundAgentTrialRefusal');
      expect(normalized).not.toContain('publishes the exact arena share');
    }
  });

  it('pins exact replay to the original record and rejects conflicting reuse', () => {
    const creationDocs = markdownSection('Creation boundary', 'Public projection');
    const operation = openApi.paths['/api/adopt/sessions/{sessionId}/records'].post;
    const requestSchema = operation.requestBody.content['application/json'].schema;
    const operationDescription = operation.description.replace(/\s+/g, ' ');

    expect(creationDocs).toContain('fresh observation and retention');
    expect(creationDocs).toContain('original committed record');
    expect(creationDocs).toContain('fails as a conflict');
    expect(operationDescription).toContain('fresh observation and retention timestamps');
    expect(operationDescription).toContain('original committed record');
    expect(operation.responses['409'].description).toContain('Conflicting reuse');
    expect(requestSchema.properties).not.toHaveProperty('observed_at');
    expect(requestSchema.properties).not.toHaveProperty('retention_expires_at');
  });

  it('keeps the public envelope closed and excludes private source identifiers', () => {
    const publicDocs = markdownSection('Public projection', 'Operator signing-key rotation');
    const observation = openApi.components.schemas.AgentRecordObservation;
    const publicResponseRef = openApi.paths['/api/agent-records/{recordId}']
      .get.responses['200'].content['application/json'].schema.$ref;
    const publicResponse = resolveRef(publicResponseRef);

    expect(publicDocs).toContain('private source commitment');
    expect(publicDocs).toContain('not a field in the signed Agent Record envelope');
    expect(observation.additionalProperties).toBe(false);
    expect(observation.properties.record.additionalProperties).toBe(false);
    expect(Object.keys(observation.properties.record.properties.source.properties).sort())
      .toEqual(['artifact_digest', 'profile']);
    expect(JSON.stringify(observation)).not.toMatch(/arena_share_id|arena_share_/i);
    expect(JSON.stringify(publicResponse)).not.toMatch(/arena_share_id|arena_share_/i);
    expect(observation.properties.record.properties.claim_boundary.enum).toEqual([
      'one_operator_observation_of_one_verified_signed_refusal_artifact_only',
    ]);
    expect(openApi.components.schemas.AgentRecordPublicVerification.properties.claim_boundary.enum)
      .toEqual(['one_operator_observation_of_one_verified_signed_refusal_artifact_only']);
    expect(openApi.paths['/api/agent-records/{recordId}/revoke'].post.description)
      .not.toMatch(/marks?.*Arena share.*revoked/is);
  });

  it('documents the non-disclosing fail-closed production readiness boundary', () => {
    const runtimeDocs = markdownSection('Runtime readiness', 'Access model');
    const create = openApi.paths['/api/adopt/sessions/{sessionId}/records'].post;
    const read = openApi.paths['/api/agent-records/{recordId}'].get;
    const revoke = openApi.paths['/api/agent-records/{recordId}/revoke'].post;

    for (const dependency of [
      'EP_COMMIT_SIGNING_KEY',
      'UPSTASH_REDIS_REST_URL',
      'SUPABASE_SERVICE_ROLE_KEY',
      'EP_AGENT_RECORD_CREATION_CAPABILITY',
      'check_agent_record_creation_capability',
      'create_agent_record_with_capability',
      'read_agent_adoption_session',
      'read_agent_record_public',
      'read_agent_record_refusal_source',
      'revoke_agent_record',
    ]) expect(runtimeDocs).toContain(dependency);
    expect(runtimeDocs.replace(/\s+/g, ' ')).toContain(
      'generic `503 agent_record_unavailable`',
    );
    for (const operation of [create, read, revoke]) {
      expect(operation.description.replace(/\s+/g, ' ')).toContain('runtime readiness gate');
      expect(operation.responses['503'].description).toContain('no dependency detail is disclosed');
    }
  });

  it('deploys the forward-compatible database contract before the Vercel application', () => {
    const normalizedDeploymentDocs = deploymentDocs.replace(/\s+/g, ' ');
    const migrationIndex = normalizedDeploymentDocs.indexOf(
      'Apply the forward-compatible Supabase migration first.',
    );
    const verificationIndex = normalizedDeploymentDocs.indexOf(
      'Verify the live database contract before application promotion',
    );
    const applicationIndex = normalizedDeploymentDocs.indexOf(
      'promote or merge the Vercel application',
    );

    expect(migrationIndex).toBeGreaterThanOrEqual(0);
    expect(verificationIndex).toBeGreaterThan(migrationIndex);
    expect(applicationIndex).toBeGreaterThan(verificationIndex);
    expect(deploymentDocs).toContain(
      'Application rollback does not roll back the Supabase schema.',
    );
    expect(deploymentDocs).toContain('Do not invent or apply an Agent Record rollback migration.');
    expect(deploymentDocs).not.toContain('apply the corresponding rollback migration');
  });

  it('provisions through the post-migration non-superuser operator RPC', () => {
    expect(capabilityDocs).toContain(
      'SELECT public.configure_agent_record_creation_capability(',
    );
    expect(capabilityDocs).not.toMatch(/SET (?:LOCAL )?ROLE agent_record_store_owner/);
    expect(capabilityDocs).toMatch(/migration[^.]*receives\s+direct `EXECUTE`/s);
    expect(capabilityDocs).toContain(
      'retains no `ADMIN`, `SET`, or `INHERIT` membership',
    );
    expect(capabilityDocs).toContain('cannot execute the base creator');
  });

  it('pins one unique GitHub check name and exact external Vercel alias gate', () => {
    expect(schemaWorkflow).toContain('name: emilia-production-schema-contract');
    expect(schemaWorkflow.match(/name: emilia-production-schema-contract/g)).toHaveLength(1);
    expect(deploymentDocs).toContain('--check-name "emilia-production-schema-contract"');
    expect(deploymentDocs).toContain('--requires build-ready');
    expect(deploymentDocs).toContain('--blocks deployment-alias');
    expect(deploymentDocs).toContain('--targets production');
    expect(deploymentDocs).toContain(
      '"externalCheckName":"emilia-production-schema-contract"',
    );
    expect(deploymentDocs).toContain(
      'POST /v2/projects/{projectIdOrName}/checks',
    );
    expect(deploymentDocs.replace(/\s+/g, ' ')).toContain(
      'Production aliasing remains unsafe until this external check exists',
    );
  });
});
