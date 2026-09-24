#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Gate-wrapped release plus read-only reconciliation over stdio MCP. */
import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import {
  createDurableConsumptionStore,
  createTrustedActionFirewall,
} from '../../packages/gate/index.js';
import { strictJsonGate } from '../../packages/verify/strict-json.js';
import {
  ADAPTER_VERSION,
  PAYMENT_RELEASE_MANIFEST,
  createOutcomeSigner,
  createPaymentReconciliationTool,
  createPaymentReleaseTool,
} from './adapter.mjs';
import { createFileKvBackend } from './file-backend.mjs';

export const TOOLS = Object.freeze([Object.freeze({
  name: 'release_payment',
  description: 'Release one exact payment behind EMILIA Gate. Requires a signed, unused Class-A EP receipt bound to payee, account, amount, currency, and operation.',
  inputSchema: {
    type: 'object',
    properties: {
      payee: { type: 'string', minLength: 1, description: 'Exact payee identifier.' },
      account: { type: 'string', minLength: 1, description: 'Exact normalized beneficiary account identifier; Gate hashes it into CAID content.' },
      amount: { type: 'string', pattern: '^(?:0|[1-9][0-9]{0,17})(?:\\.[0-9]{1,2})?$', description: 'Positive canonical decimal string.' },
      currency: { type: 'string', pattern: '^[A-Z]{3}$' },
      operation: { type: 'string', minLength: 1, description: 'Stable payment instruction/idempotency identifier.' },
      _emilia_receipt: { type: 'object', description: 'EP-RECEIPT-v1 authorizing this exact action.' },
    },
    required: ['payee', 'account', 'amount', 'currency', 'operation', '_emilia_receipt'],
    additionalProperties: false,
  },
}), Object.freeze({
  name: 'reconcile_payment',
  description: 'Query the credential-owning provider for an authenticated disposition after an INDETERMINATE payment result. This never retries or restores the consumed authority.',
  inputSchema: {
    type: 'object',
    properties: {
      payee: { type: 'string', minLength: 1 },
      account: { type: 'string', minLength: 1 },
      amount: { type: 'string', pattern: '^(?:0|[1-9][0-9]{0,17})(?:\\.[0-9]{1,2})?$' },
      currency: { type: 'string', pattern: '^[A-Z]{3}$' },
      operation: { type: 'string', minLength: 1 },
      _emilia_outcome_receipt: { type: 'object', description: 'Gate-signed INDETERMINATE outcome for this exact action.' },
    },
    required: ['payee', 'account', 'amount', 'currency', 'operation', '_emilia_outcome_receipt'],
    additionalProperties: false,
  },
})]);

function mcpError(reason) {
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ error: reason }) }],
    _emilia: { gate: 'refused', reason },
  };
}

/**
 * @param {any} request
 * @param {{ invoke?: (input: any) => any, reconcile?: (input: any) => any }} [options]
 */
export async function handleToolRequest(request, { invoke, reconcile } = {}) {
  if (request?.params?.name === 'release_payment') {
    if (typeof invoke !== 'function') return mcpError('payment_gate_unavailable');
    return invoke(request.params.arguments ?? {});
  }
  if (request?.params?.name === 'reconcile_payment') {
    if (typeof reconcile !== 'function') return mcpError('payment_reconciliation_unavailable');
    return reconcile(request.params.arguments ?? {});
  }
  return mcpError('unknown_tool');
}

/** @param {{ invoke: (input: any) => any, reconcile: (input: any) => any }} options */
export function createServer({ invoke, reconcile }) {
  const server = new Server(
    { name: 'emilia-payment-gate', version: ADAPTER_VERSION },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(
    CallToolRequestSchema,
    (request) => handleToolRequest(request, { invoke, reconcile }),
  );
  return server;
}

function requireRecord(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name}_required`);
  return value;
}

export async function loadConfig(path) {
  if (typeof path !== 'string' || path.length === 0) throw new TypeError('EMILIA_MUSE_GATE_CONFIG is required');
  const raw = await readFile(path, 'utf8');
  const strict = strictJsonGate(raw);
  if (!strict.ok) throw new TypeError(`config_json_refused:${strict.reason}`);
  const config = JSON.parse(raw);
  requireRecord(config, 'config');
  if (!['EP-MUSE-CODE-GATE-CONFIG-v1', 'EP-MUSE-CODE-GATE-CONFIG-v2'].includes(config['@version'])) {
    throw new TypeError('unsupported_config_version');
  }
  if (!Array.isArray(config.trusted_issuer_keys) || config.trusted_issuer_keys.length === 0) {
    throw new TypeError('trusted_issuer_keys_required');
  }
  requireRecord(config.approver_keys, 'approver_keys');
  requireRecord(config.outcome_signing_key, 'outcome_signing_key');
  for (const field of ['state_file', 'provider_ledger_file', 'rp_id']) {
    if (typeof config[field] !== 'string' || config[field].length === 0) throw new TypeError(`${field}_required`);
  }
  if (!Array.isArray(config.allowed_origins) || config.allowed_origins.length === 0) {
    throw new TypeError('allowed_origins_required');
  }
  return config;
}

/**
 * Build the exact Gate/provider boundary used by the stdio server.
 * @param {any} config
 * @param {{ providerMode?: string }} [options]
 */
export async function createServerRuntime(config, {
  providerMode = process.env.EMILIA_MUSE_PROVIDER_MODE ?? 'success',
} = {}) {
  const backend = await createFileKvBackend(config.state_file);
  const reconciliationStore = await createFileKvBackend(
    config.reconciliation_store_file ?? `${config.state_file}.reconciliation`,
  );
  const store = createDurableConsumptionStore(backend);
  const gate = createTrustedActionFirewall({
    manifest: PAYMENT_RELEASE_MANIFEST,
    trustedKeys: config.trusted_issuer_keys,
    approverKeys: config.approver_keys,
    rpId: config.rp_id,
    allowedOrigins: config.allowed_origins,
    quorumPolicy: config.quorum_policy ?? null,
    maxAgeSec: config.max_age_sec ?? 900,
    store,
  });
  const outcomeSigner = createOutcomeSigner({
    privateKey: config.outcome_signing_key.private_key_pkcs8_b64u,
    publicKey: config.outcome_signing_key.public_key_spki_b64u,
    keyId: config.outcome_signing_key.key_id,
  });
  const operationDigest = (operation) => `sha256:${createHash('sha256').update(operation, 'utf8').digest('hex')}`;
  const provider = async (payment, context) => {
    // This append is the demo provider-entry boundary. A real integration
    // replaces this function with the credential-owning payment SDK call.
    const providerRecord = {
      observed_at: new Date().toISOString(),
      operation_digest: operationDigest(payment.operation),
      caid: context.caid,
      provider_status: providerMode === 'decline_agent_access' ? 'DECLINED' : 'ACCEPTED',
      ...(providerMode === 'decline_agent_access'
        ? { reason_code: 'AGENT_ACCESS_DENIED' }
        : {}),
    };
    await appendFile(config.provider_ledger_file, `${JSON.stringify(providerRecord)}\n`, { encoding: 'utf8', mode: 0o600 });
    if (providerMode === 'decline_agent_access') {
      return {
        provider_status: 'DECLINED',
        reason_code: 'AGENT_ACCESS_DENIED',
        provider_reference: `demo-ledger:${providerRecord.operation_digest}`,
      };
    }
    if (providerMode === 'throw_after_entry') {
      throw new Error('demo provider response lost after entry');
    }
    return {
      provider_status: 'ACCEPTED',
      provider_reference: `demo-ledger:${providerRecord.operation_digest}`,
    };
  };
  const invoke = createPaymentReleaseTool({ gate, provider, outcomeSigner });
  const providerReconcile = async ({ operation, caid }) => {
    let records = [];
    try {
      records = (await readFile(config.provider_ledger_file, 'utf8'))
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line));
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const matched = [...records].reverse().find((record) => (
      record?.operation_digest === operationDigest(operation) && record?.caid === caid
    ));
    if (!matched) {
      return {
        authenticated: true,
        authoritative: true,
        provider_status: 'NOT_ACCEPTED',
        reason_code: 'NO_PROVIDER_RECORD',
      };
    }
    if (matched.provider_status === 'DECLINED') {
      return {
        authenticated: true,
        authoritative: true,
        provider_status: 'NOT_ACCEPTED',
        reason_code: matched.reason_code,
      };
    }
    if (matched.provider_status === 'ACCEPTED') {
      return {
        authenticated: true,
        provider_status: 'ACCEPTED',
        provider_reference: `demo-ledger:${matched.operation_digest}`,
      };
    }
    return { authenticated: true, provider_status: 'UNKNOWN' };
  };
  const reconcile = createPaymentReconciliationTool({
    reconcile: providerReconcile,
    outcomeSigner,
    reconciliationStore,
  });
  return Object.freeze({ gate, invoke, reconcile, outcomePublicKey: outcomeSigner.publicKey });
}

export async function startServer({ configPath = process.env.EMILIA_MUSE_GATE_CONFIG } = {}) {
  const config = await loadConfig(configPath);
  const runtime = await createServerRuntime(config);
  await createServer({ invoke: runtime.invoke, reconcile: runtime.reconcile })
    .connect(new StdioServerTransport());
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startServer();
}
