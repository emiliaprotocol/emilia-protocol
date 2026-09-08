import fs from 'node:fs';
import path from 'node:path';

import yaml from 'js-yaml';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const document = yaml.load(fs.readFileSync(path.join(ROOT, 'openapi.yaml'), 'utf8')) as any;

const accountPaths = [
  '/api/works/account/start',
  '/api/works/account/verify',
  '/api/works/account/session',
  '/api/works/account/logout',
] as const;

const workflowPaths = [
  '/api/works/workspace',
  '/api/works/workspace/commands',
  '/api/works/workspace/notifications/{id}/read',
  '/api/works/assignments',
  '/api/works/assignments/{id}',
  '/api/works/assignments/{id}/commands',
] as const;

function authNames(operation: any): string[] {
  return (operation.security || []).flatMap((entry: Record<string, unknown>) => Object.keys(entry));
}

function parameter(operation: any, ref: string): any {
  return (operation.parameters || []).find((entry: any) => entry.$ref === ref);
}

describe('Works OpenAPI contract', () => {
  it('documents every account and operating-workflow route', () => {
    for (const route of [...accountPaths, ...workflowPaths]) {
      expect(document.paths[route], route).toBeDefined();
    }
  });

  it('keeps account email and session routes off legacy bearer authentication', () => {
    expect(document.paths[accountPaths[0]].post.security).toEqual([]);
    expect(document.paths[accountPaths[1]].post.security).toEqual([]);

    for (const operation of [
      document.paths[accountPaths[2]].get,
      document.paths[accountPaths[3]].post,
    ]) {
      expect(authNames(operation)).toEqual(['WorksSessionAuth']);
      expect(operation.security).toContainEqual({});
    }

    expect(document.components.securitySchemes.WorksSessionAuth).toMatchObject({
      type: 'apiKey',
      in: 'cookie',
      name: '__Host-emilia_works_session',
    });
  });

  it('documents session-or-bearer workflow authentication as alternatives', () => {
    const operations = [
      document.paths[workflowPaths[0]].get,
      document.paths[workflowPaths[1]].post,
      document.paths[workflowPaths[2]].post,
      document.paths[workflowPaths[3]].post,
      document.paths[workflowPaths[4]].get,
      document.paths[workflowPaths[5]].post,
    ];

    for (const operation of operations) {
      expect(operation.security).toEqual([
        { WorksSessionAuth: [] },
        { BearerAuth: [] },
      ]);
    }
  });

  it('requires the pinned Origin for account mutations and conditionally for cookie workflow writes', () => {
    for (const operation of [
      document.paths[accountPaths[0]].post,
      document.paths[accountPaths[1]].post,
      document.paths[accountPaths[3]].post,
    ]) {
      expect(parameter(operation, '#/components/parameters/WorksOriginRequired')).toBeDefined();
    }

    for (const operation of [
      document.paths[workflowPaths[1]].post,
      document.paths[workflowPaths[2]].post,
      document.paths[workflowPaths[3]].post,
      document.paths[workflowPaths[5]].post,
    ]) {
      expect(parameter(operation, '#/components/parameters/WorksOriginWhenCookie')).toBeDefined();
    }

    expect(document.components.parameters.WorksOriginRequired).toMatchObject({
      name: 'Origin',
      in: 'header',
      required: true,
    });
    expect(document.components.parameters.WorksOriginWhenCookie.description).toMatch(/legacy bearer/i);
  });

  it('publishes closed request shapes and a least-disclosure account projection', () => {
    const schemas = document.components.schemas;
    expect(schemas.WorksAccountStartRequest.oneOf.every((shape: any) => shape.additionalProperties === false)).toBe(true);
    expect(schemas.WorksAccountVerifyRequest).toMatchObject({ additionalProperties: false });
    expect(schemas.WorksAccountVerifyRequest.properties.code.pattern).toBe('^\\d{6}$');
    expect(Object.keys(schemas.WorksAccountPublic.properties).sort()).toEqual([
      'claimsVerified',
      'displayName',
      'emailNotifications',
    ]);

    for (const name of ['WorksWorkspaceCommandRequest', 'WorksSelectProposalRequest', 'WorksCommandBase']) {
      expect(schemas[name].additionalProperties, name).toBe(false);
    }
    expect(schemas.WorksAssignmentCommandRequest.oneOf).toHaveLength(6);
    expect(schemas.WorksAssignmentCommandRequest.oneOf.every((shape: any) => shape.additionalProperties === false)).toBe(true);
  });

  it('states that marketplace coordination grants no consequential authority', () => {
    const text = [
      document.components.securitySchemes.WorksSessionAuth.description,
      document.paths[workflowPaths[1]].post.description,
      document.paths[workflowPaths[3]].post.description,
      document.paths[workflowPaths[5]].post.description,
    ].join('\n');

    expect(text).toMatch(/no execution authority/i);
    expect(text).toMatch(/payment authority/i);
    expect(text).toMatch(/Gate authority/i);
    expect(text).toMatch(/provider-entry/i);
  });
});
