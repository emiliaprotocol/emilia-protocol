// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs/promises';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GATE_ROUTE_PATHS } from '../src/routes.js';

test('OpenAPI contract covers every service route and critical fail-closed semantics', async () => {
  const document = JSON.parse(await fs.readFile(
    new URL('../openapi.json', import.meta.url),
    'utf8',
  ));
  assert.match(document.openapi, /^3\./);
  assert.deepEqual(
    Object.keys(document.paths).sort(),
    Object.values(GATE_ROUTE_PATHS).sort(),
  );
  assert.ok(document.components.securitySchemes.bearerAuth);
  assert.ok(document.paths['/v1/actions/{id}/execute'].post.responses['428']);
  assert.ok(
    document.paths['/v1/actions/{id}/execute'].post.responses['428']
      .headers['Receipt-Required'],
  );
  assert.ok(document.components.schemas.ActionStatus.enum.includes('indeterminate'));
  assert.match(
    document.components.schemas.Indeterminate.description,
    /must not be retried automatically/i,
  );
  for (const path of [
    '/v1/actions',
    '/v1/actions/{id}',
    '/v1/actions/{id}/execute',
    '/v1/evidence/head',
    '/v1/evidence/records/{recordId}',
    '/v1/evidence/history',
    '/v1/evidence/verify',
    '/v1/evidence/export',
    '/v1/metrics',
  ]) {
    const operation = document.paths[path].get ?? document.paths[path].post;
    assert.deepEqual(operation.security, [{ bearerAuth: [] }], `${path} must require bearer auth`);
  }
});

test('deployment probes and the E2E harness use production service contracts', async () => {
  const [compose, helmValues, terraform, deploymentGuide, e2eConfig, dockerfile, ciWorkflow] = await Promise.all([
    fs.readFile(new URL('../../../docker-compose.gate-e2e.yml', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../packages/gate/deploy/helm/emilia-gate-service/values.yaml', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../packages/gate/deploy/terraform/service/main.tf', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../docs/EMILIA-GATE-DEPLOYMENT.md', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../packages/gate/deploy/helm/emilia-gate-service/tests/fixtures/gate.config.mjs', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../Dockerfile.gate', import.meta.url), 'utf8'),
    fs.readFile(new URL('../../../.github/workflows/ci.yml', import.meta.url), 'utf8'),
  ]);

  for (const deployment of [compose, helmValues, terraform, deploymentGuide]) {
    assert.doesNotMatch(deployment, /\/v1\/health/, 'deployment must not probe an undefined route');
  }
  assert.match(compose, /\/v1\/ready/);
  assert.equal((helmValues.match(/path: \/v1\/live/g) ?? []).length, 2);
  assert.equal((helmValues.match(/path: \/v1\/ready/g) ?? []).length, 1);
  assert.equal((terraform.match(/path = "\/v1\/live"/g) ?? []).length, 2);
  assert.equal((terraform.match(/path = "\/v1\/ready"/g) ?? []).length, 1);
  assert.match(e2eConfig, /createProductionGateConfig/);
  assert.doesNotMatch(e2eConfig, /createAtomicEvidenceLog|createPostgresBackend/);
  assert.match(
    dockerfile,
    /ARG NODE_IMAGE=node:22\.23\.1-alpine3\.24@sha256:[0-9a-f]{64}/,
    'runtime base must be versioned and digest-pinned',
  );
  for (const runtimeTool of [
    '/usr/local/lib/node_modules/npm',
    '/usr/local/lib/node_modules/corepack',
    '/usr/local/bin/npm',
    '/usr/local/bin/npx',
    '/usr/local/bin/corepack',
    '/usr/local/bin/yarn',
    '/usr/local/bin/yarnpkg',
  ]) {
    assert.match(
      dockerfile,
      new RegExp(`rm (?:-rf|-f)[\\s\\S]*${runtimeTool.replaceAll('/', '\\/')}`),
      `runtime image must remove ${runtimeTool}`,
    );
  }
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(ciWorkflow, /aquasecurity\/trivy-action@[0-9a-f]{40}/);
  assert.match(ciWorkflow, /version: v0\.72\.0/);
  assert.match(ciWorkflow, /severity: HIGH,CRITICAL/);
  assert.doesNotMatch(ciWorkflow, /ignore-unfixed: true/);
  assert.match(ciWorkflow, /exit-code: '1'/);
  for (const packageName of ['gate', 'require-receipt', 'verify']) {
    assert.match(
      dockerfile,
      new RegExp(`ln -s \\.\\.\\/\\.\\.\\/packages\\/${packageName} \\/app\\/node_modules\\/@emilia-protocol\\/${packageName}`),
      `runtime image must resolve @emilia-protocol/${packageName} from the exact copied source`,
    );
  }
});

test('service package, chart, and OpenAPI share one release identity', async () => {
  const [packageDocument, chart, openapiDocument] = await Promise.all([
    fs.readFile(new URL('../package.json', import.meta.url), 'utf8').then(JSON.parse),
    fs.readFile(new URL('../../../packages/gate/deploy/helm/emilia-gate-service/Chart.yaml', import.meta.url), 'utf8'),
    fs.readFile(new URL('../openapi.json', import.meta.url), 'utf8').then(JSON.parse),
  ]);
  const chartVersion = chart.match(/^version: (\S+)$/m)?.[1];
  const appVersion = chart.match(/^appVersion: "(\S+)"$/m)?.[1];

  assert.equal(chartVersion, packageDocument.version);
  assert.equal(appVersion, packageDocument.version);
  assert.equal(openapiDocument.info.version, packageDocument.version);
});
