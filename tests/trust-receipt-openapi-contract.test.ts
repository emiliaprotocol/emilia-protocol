// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = resolve(import.meta.dirname, '..');
const SPEC_PATHS = ['openapi.yaml', 'docs/api/govguard-v1.yaml'];
const LIFECYCLE = [
  ['/api/v1/trust-receipts', 'post'],
  ['/api/v1/trust-receipts/{receiptId}', 'get'],
  ['/api/v1/trust-receipts/{receiptId}/consume', 'post'],
  ['/api/v1/trust-receipts/{receiptId}/evidence', 'get'],
  ['/api/v1/trust-receipts/{receiptId}/execution', 'post'],
  ['/api/v1/signoffs/request', 'post'],
] as const;

function loadSpec(relativePath: string) {
  const document = YAML.parseDocument(
    readFileSync(resolve(ROOT, relativePath), 'utf8'),
    { uniqueKeys: true },
  );
  return { relativePath, document, spec: document.toJS() };
}

function resolveRef(spec: any, value: any) {
  if (!value?.$ref) return value;
  expect(value.$ref).toMatch(/^#\//);
  return value.$ref.slice(2).split('/').reduce((node: any, key: string) => node?.[key], spec);
}

function requestSchema(spec: any, path: string) {
  return resolveRef(spec, spec.paths[path].post.requestBody.content['application/json'].schema);
}

const SPECS = SPEC_PATHS.map(loadSpec);

describe('Trust Receipt lifecycle OpenAPI contract', () => {
  it('keeps both specifications parseable without duplicate keys', () => {
    for (const { relativePath, document } of SPECS) {
      expect(document.errors.map((error) => error.message), relativePath).toEqual([]);
      expect(document.warnings.map((warning) => warning.message), relativePath).toEqual([]);
    }
  });

  it('documents the complete authenticated lifecycle in both specifications', () => {
    for (const { spec } of SPECS) {
      for (const [path, method] of LIFECYCLE) {
        expect(spec.paths[path]?.[method], `${method.toUpperCase()} ${path}`).toBeDefined();
        expect(spec.paths[path][method].security).toEqual([{ BearerAuth: [] }]);
      }
    }
  });

  it('derives organization identity, includes policy rollout, and binds canonical quorum semantics', () => {
    for (const { spec } of SPECS) {
      const create = requestSchema(spec, '/api/v1/trust-receipts');
      expect(create.required).toEqual(['action_type', 'target_resource_id']);
      expect(create.required).not.toContain('organization_id');
      expect(create.properties.organization_id.description).toContain('authenticated');
      expect(create.properties.action_type.enum).toContain('policy_rollout');
      expect(resolveRef(spec, create.properties.quorum_policy)).toBe(spec.components.schemas.GuardQuorumPolicy);

      const quorum = spec.components.schemas.GuardQuorumPolicy;
      expect(quorum.required).toEqual(['mode', 'required', 'approvers']);
      expect(quorum.properties.mode.enum).toEqual(['threshold', 'ordered']);
      expect(resolveRef(spec, quorum.properties.approvers.items))
        .toBe(spec.components.schemas.GuardQuorumApprover);
    }
  });

  it('documents independently observed execution when the stored binding requires it', () => {
    for (const { spec } of SPECS) {
      const execution = requestSchema(spec, '/api/v1/trust-receipts/{receiptId}/execution');
      expect(execution.required).toEqual(['executed_action', 'executing_system']);
      expect(execution.properties.observed_action).toBeDefined();
      expect(execution.properties.observed_action.description).toContain('Required when');
      expect(execution.properties.observed_action['x-emilia-conditionally-required'])
        .toBe('execution_binding.required=true');
    }
  });

  it('distinguishes create and replayed state projections and supports server-bound quorum signoff fan-out', () => {
    for (const { spec } of SPECS) {
      const getResponse = resolveRef(
        spec,
        spec.paths['/api/v1/trust-receipts/{receiptId}'].get.responses['200']
          .content['application/json'].schema,
      );
      expect(getResponse).toBe(spec.components.schemas.TrustReceiptState);
      expect(getResponse.required).toContain('timeline_event_count');

      const signoff = requestSchema(spec, '/api/v1/signoffs/request');
      expect(signoff.required).toEqual(['receipt_id']);
      expect(signoff.properties.approver_id.description)
        .toContain('stored receipt has no quorum policy');
    }
  });
});

describe('protected surface authentication descriptions', () => {
  const root = SPECS.find(({ relativePath }) => relativePath === 'openapi.yaml')!.spec;

  it('does not publish tenant entity and identity records as anonymous APIs', () => {
    for (const path of [
      '/api/entities/search',
      '/api/identity/principal/{principalId}',
      '/api/identity/principal/{principalId}/delegation-judgment',
      '/api/identity/principal/{principalId}/agents',
      '/api/identity/lineage/{entityId}',
      '/api/identity/continuity/challenge',
    ]) {
      expect(root.paths[path].get?.security ?? root.paths[path].post?.security)
        .toEqual([{ BearerAuth: [] }]);
    }
    expect(root.paths['/api/identity/continuity/challenge'].post.requestBody
      .content['application/json'].schema.required).toEqual(['continuity_id', 'reason']);
  });

  it('requires a named operator for binding verification', () => {
    expect(root.paths['/api/identity/verify'].post.security).toEqual([{ OperatorAuth: [] }]);
    expect(root.paths['/api/identity/verify'].post.description).toContain('binding.verify');
  });

  it('separates the anonymous bucketed statistics projection from exact authenticated metrics', () => {
    const stats = root.paths['/api/stats'].get;
    expect(stats.security).toEqual([{ BearerAuth: [] }, {}]);
    expect(stats.parameters[0].schema.enum).toEqual(['public']);
    expect(stats.description).toContain('bucketed');
  });
});
