import fs from 'node:fs';
import { createProductionGateConfig } from '/app/apps/gate-service/src/production-config.js';

function readSecret(variable) {
  const file = process.env[variable];
  if (!file) throw new Error(`${variable}_required`);
  const value = fs.readFileSync(file, 'utf8').trim();
  if (!value) throw new Error(`${variable}_empty`);
  return value;
}

const password = readSecret('EMILIA_GATE_RUNTIME_POSTGRES_PASSWORD_FILE');
const githubToken = readSecret('GITHUB_TOKEN_FILE');
const apiToken = readSecret('EMILIA_GATE_API_TOKEN_FILE');
const trust = readSecret('EP_GATE_ISSUER_ROOTS_FILE');

export default await createProductionGateConfig({
  environment: {
    EMILIA_GATE_DATABASE_URL: `postgresql://gate_runtime:${encodeURIComponent(password)}@postgres:5432/gate_e2e`,
    EMILIA_GATE_API_TOKEN: apiToken,
    EMILIA_GATE_PRINCIPAL_ID: 'operator:e2e',
    EMILIA_GATE_TENANT_ID: 'gate-e2e-tenant',
    EMILIA_GATE_ID: 'gate-e2e-service',
    EMILIA_GATE_EVIDENCE_STREAM_ID: 'gate-e2e',
    EMILIA_GATE_TRUST_JSON: trust,
    EMILIA_GATE_ALLOWED_REPOSITORIES: 'emilia-e2e/disposable-repository',
    GITHUB_TOKEN: githubToken,
  },
});
