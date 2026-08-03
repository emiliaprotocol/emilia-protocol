// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const docs = readFileSync(resolve(ROOT, 'docs/AGENT-RECORD.md'), 'utf8');
const deploymentDocs = readFileSync(resolve(ROOT, 'docs/operations/DEPLOYMENT.md'), 'utf8');
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

  it('documents read and sign before the atomic publication transaction', () => {
    const creationDocs = markdownSection('Creation boundary', 'Public projection');
    const operation = openApi.paths['/api/adopt/sessions/{sessionId}/records'].post;

    for (const lifecycle of [creationDocs, operation.description]) {
      const normalized = lifecycle.replaceAll('`', '').replace(/\s+/g, ' ').toLowerCase();
      const readIndex = normalized.indexOf('read');
      const signIndex = normalized.indexOf('signs');
      const publishIndex = normalized.indexOf('publishes the exact arena share');
      const insertIndex = normalized.indexOf('inserts the immutable agent record');

      expect(readIndex).toBeGreaterThanOrEqual(0);
      expect(signIndex).toBeGreaterThan(readIndex);
      expect(publishIndex).toBeGreaterThan(signIndex);
      expect(insertIndex).toBeGreaterThan(publishIndex);
      expect(normalized).toMatch(
        /signs (?:the )?ep-agent-record-observation-v1 (?:projection )?before any database mutation/,
      );
      expect(normalized).toMatch(/one (?:create_agent_record )?database transaction/);
      expect(lifecycle).not.toContain('publishBoundAgentTrialRefusal');
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

  it('keeps the public envelope closed and excludes the Arena share identifier', () => {
    const publicDocs = markdownSection('Public projection', 'Operator signing-key rotation');
    const observation = openApi.components.schemas.AgentRecordObservation;
    const publicResponseRef = openApi.paths['/api/agent-records/{recordId}']
      .get.responses['200'].content['application/json'].schema.$ref;
    const publicResponse = resolveRef(publicResponseRef);

    expect(publicDocs).toContain('not a field in the signed Agent Record envelope');
    expect(observation.additionalProperties).toBe(false);
    expect(observation.properties.record.additionalProperties).toBe(false);
    expect(Object.keys(observation.properties.record.properties.source.properties).sort())
      .toEqual(['artifact_digest', 'profile']);
    expect(JSON.stringify(observation)).not.toMatch(/arena_share_id|arena_share_/i);
    expect(JSON.stringify(publicResponse)).not.toMatch(/arena_share_id|arena_share_/i);
  });

  it('documents the secret-free fail-closed production readiness boundary', () => {
    const runtimeDocs = markdownSection('Runtime readiness', 'Access model');
    const create = openApi.paths['/api/adopt/sessions/{sessionId}/records'].post;
    const read = openApi.paths['/api/agent-records/{recordId}'].get;
    const revoke = openApi.paths['/api/agent-records/{recordId}/revoke'].post;

    for (const dependency of [
      'EP_COMMIT_SIGNING_KEY',
      'UPSTASH_REDIS_REST_URL',
      'SUPABASE_SERVICE_ROLE_KEY',
      'create_agent_record',
      'read_agent_record_public',
      'revoke_agent_record',
    ]) expect(runtimeDocs).toContain(dependency);
    expect(runtimeDocs).toContain('generic `503 agent_record_unavailable`');
    for (const operation of [create, read, revoke]) {
      expect(operation.description.replace(/\s+/g, ' ')).toContain('runtime readiness gate');
      expect(operation.responses['503'].description).toContain('no dependency detail is disclosed');
    }
  });

  it('deploys the forward-compatible database contract before the Vercel application', () => {
    const migrationIndex = deploymentDocs.indexOf(
      'Apply the forward-compatible Supabase migration first.',
    );
    const verificationIndex = deploymentDocs.indexOf(
      'Verify the live database contract before application promotion',
    );
    const applicationIndex = deploymentDocs.indexOf(
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
});
