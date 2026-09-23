#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Dependency-light stdio MCP server whose release_payment handler is Gate-wrapped. */
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
})]);

function mcpError(reason) {
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ error: reason }) }],
    _emilia: { gate: 'refused', reason },
  };
}

export async function handleToolRequest(request, { invoke } = {}) {
  if (request?.params?.name !== 'release_payment') return mcpError('unknown_tool');
  if (typeof invoke !== 'function') return mcpError('payment_gate_unavailable');
  return invoke(request.params.arguments ?? {});
}

export function createServer({ invoke }) {
  const server = new Server(
    { name: 'emilia-payment-gate', version: ADAPTER_VERSION },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, (request) => handleToolRequest(request, { invoke }));
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
  if (config['@version'] !== 'EP-MUSE-CODE-GATE-CONFIG-v1') throw new TypeError('unsupported_config_version');
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

/** Build the exact Gate/provider boundary used by the stdio server. */
export async function createServerRuntime(config, {
  providerMode = process.env.EMILIA_MUSE_PROVIDER_MODE ?? 'success',
} = {}) {
  const backend = await createFileKvBackend(config.state_file);
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
  const provider = async (payment, context) => {
    // This append is the demo provider-entry boundary. A real integration
    // replaces this function with the credential-owning payment SDK call.
    const providerRecord = {
      accepted_at: new Date().toISOString(),
      operation: payment.operation,
      caid: context.caid,
      payment,
    };
    await appendFile(config.provider_ledger_file, `${JSON.stringify(providerRecord)}\n`, { encoding: 'utf8', mode: 0o600 });
    if (providerMode === 'throw_after_entry') {
      throw new Error('demo provider response lost after entry');
    }
    return {
      content: [{ type: 'text', text: JSON.stringify({ accepted: true, operation: payment.operation, caid: context.caid }) }],
      accepted: true,
      provider_reference: `demo-ledger:${payment.operation}`,
    };
  };
  const invoke = createPaymentReleaseTool({ gate, provider, outcomeSigner });
  return Object.freeze({ gate, invoke, outcomePublicKey: outcomeSigner.publicKey });
}

export async function startServer({ configPath = process.env.EMILIA_MUSE_GATE_CONFIG } = {}) {
  const config = await loadConfig(configPath);
  const runtime = await createServerRuntime(config);
  await createServer({ invoke: runtime.invoke }).connect(new StdioServerTransport());
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startServer();
}

