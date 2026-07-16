import fs from 'node:fs';
import pg from 'pg';
import {
  createAtomicEvidenceLog,
  createDurableConsumptionStore,
} from '/app/packages/gate/index.js';
import { createPostgresBackend } from '/app/packages/gate/store-postgres.js';
import { createPostgresEvidenceBackend } from '/app/packages/gate/evidence-postgres.js';
import { createGithubRestConnector } from '/app/apps/gate-service/src/github-client.js';

const { Pool } = pg;

function readSecret(variable) {
  const file = process.env[variable];
  if (!file) throw new Error(`${variable}_required`);
  const value = fs.readFileSync(file, 'utf8').trim();
  if (!value) throw new Error(`${variable}_empty`);
  return value;
}

const password = readSecret('EMILIA_GATE_POSTGRES_PASSWORD_FILE');
const githubToken = readSecret('GITHUB_TOKEN_FILE');
readSecret('EP_KMS_KEY_ID_FILE');
const trust = JSON.parse(readSecret('EP_GATE_ISSUER_ROOTS_FILE'));
const databaseUrl = `postgresql://gate:${encodeURIComponent(password)}@postgres:5432/gate_e2e`;
const pool = new Pool({ connectionString: databaseUrl, max: 10 });
await pool.query('SELECT 1');

const query = pool.query.bind(pool);
const consumptionStore = createDurableConsumptionStore(
  createPostgresBackend({ query }),
);

const evidenceBackend = createPostgresEvidenceBackend({
  query,
  tenantId: 'gate-e2e-tenant',
  gateId: 'gate-e2e-service',
});

const actionStore = {
  durable: true,
  async create(record) {
    const result = await query(
      'INSERT INTO ep_gate_actions (id, record) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO NOTHING',
      [record.id, JSON.stringify(record)],
    );
    return result.rowCount === 1;
  },
  async update(id, patch) {
    const result = await query(
      'UPDATE ep_gate_actions SET record = record || $2::jsonb, updated_at = now() WHERE id = $1',
      [id, JSON.stringify(patch)],
    );
    return result.rowCount === 1;
  },
  async get(id) {
    const result = await query('SELECT record FROM ep_gate_actions WHERE id = $1', [id]);
    return result.rowCount === 0 ? null : result.rows[0].record;
  },
};

export default {
  connector: createGithubRestConnector({ token: githubToken }),
  consumptionStore,
  evidenceLog: createAtomicEvidenceLog(evidenceBackend, { streamId: 'gate-e2e' }),
  actionStore,
  trustedKeys: trust.trustedKeys,
  approverKeys: trust.approverKeys,
  rpId: trust.rpId,
  allowedOrigins: trust.allowedOrigins,
};
