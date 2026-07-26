// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const decisionPlaneRoot = path.join(ROOT, 'apps/consequence-control-service/src');
const actuatorRoot = path.join(ROOT, 'apps/consequence-actuator-service/src');

function source(relative: string): string {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

describe('complete-mediation deployment boundary', () => {
  it('keeps raw provider credential material out of the decision plane', () => {
    const decisionSources = fs.readdirSync(decisionPlaneRoot)
      .filter((name) => name.endsWith('.ts'))
      .map((name) => fs.readFileSync(path.join(decisionPlaneRoot, name), 'utf8'))
      .join('\n');

    for (const forbidden of [
      'GITHUB_APP_PRIVATE_KEY',
      'GITHUB_APP_ID',
      'GITHUB_INSTALLATION_ID',
      'createGitHubAppInstallationTokenProvider',
      'createGitHubIssueEffectProvider',
    ]) {
      expect(decisionSources, `${forbidden} belongs only in the actuator`).not.toContain(forbidden);
    }
    expect(decisionSources).toContain('createConsequenceActuatorClient');
  });

  it('ships the credential-owning actuator as a separately startable service', () => {
    for (const relative of [
      'apps/consequence-actuator-service/package.json',
      'apps/consequence-actuator-service/src/server.ts',
      'apps/consequence-actuator-service/src/routes.ts',
      'apps/consequence-actuator-service/src/runtime.ts',
      'apps/consequence-actuator-service/src/production-config.ts',
    ]) {
      expect(fs.existsSync(path.join(ROOT, relative)), relative).toBe(true);
    }

    const packageJson = JSON.parse(
      source('apps/consequence-actuator-service/package.json'),
    );
    expect(packageJson.private).toBe(true);
    expect(packageJson.scripts?.start).toBeTruthy();
    expect(packageJson.scripts?.test).toBeTruthy();

    const actuatorSources = fs.readdirSync(actuatorRoot)
      .filter((name) => name.endsWith('.ts'))
      .map((name) => fs.readFileSync(path.join(actuatorRoot, name), 'utf8'))
      .join('\n');
    expect(actuatorSources).toContain('ConsequenceActuator');
    expect(actuatorSources).toContain('createGitHubAppInstallationTokenProvider');
  });

  it('binds the remote request to an execution envelope, not ambient caller data', () => {
    const client = source('apps/consequence-control-service/src/actuator-client.ts');
    const routes = source('apps/consequence-actuator-service/src/routes.ts');

    for (const required of [
      'action_digest',
      'attempt_id',
      'caid',
      'expires_at',
      'idempotency_key',
      'nonce',
      'operation',
      'provider_account_id',
      'target_digest',
      'tenant_id',
    ]) {
      expect(`${client}\n${routes}`, required).toContain(required);
    }
  });
});
