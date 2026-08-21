#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';

import { createProtectionPlan } from '../../packages/gate/protection-plan.js';
import {
  signProtectionActivation,
  verifyProtectionActivation,
} from '../../packages/gate/protection-activation.js';
import {
  ProvenanceLedger,
  withCustomerOwnedProtectionGateway,
} from '../../packages/mcp-guard/index.js';

const NOW = '2026-08-20T18:00:00.000Z';

function durableConsumptionStore() {
  return {
    durable: true,
    async reserve() { return { ok: true, token: 'synthetic-reservation' }; },
    async commit() { return { ok: true }; },
    async release() { return { ok: true }; },
  };
}

async function durableLedger() {
  const entries = [];
  return ProvenanceLedger.open({
    store: {
      durable: true,
      async load() { return structuredClone(entries); },
      async append({ expectedSequence, expectedPreviousHash, entry }) {
        if (expectedSequence !== entries.length
            || expectedPreviousHash !== (entries.at(-1)?.entry_hash ?? '')) {
          return { ok: false, reason: 'head_conflict' };
        }
        entries.push(structuredClone(entry));
        return { ok: true };
      },
    },
  });
}

export async function runCustomerOwnedMcpGateway() {
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const activation = signProtectionActivation({
    activation_id: 'activation:customer-mcp-reference:01',
    tenant_id: 'tenant:customer-reference',
    gateway_id: 'gateway:customer-reference:mcp',
    epoch: 1,
    issued_at: '2026-08-20T17:55:00.000Z',
    valid_from: '2026-08-20T17:56:00.000Z',
    expires_at: '2026-08-21T18:00:00.000Z',
    plan: createProtectionPlan({
      planId: 'customer-mcp-reference',
      ownerLabel: 'Reference customer',
      createdAt: '2026-08-20T17:54:00.000Z',
      selections: [{ presetId: 'spend-money' }, { presetId: 'publish-code' }],
    }),
  }, {
    issuer_id: 'customer:reference',
    key_id: 'key:customer-reference',
    private_key: keys.privateKey,
  });
  const verified = verifyProtectionActivation(activation, {
    trusted_keys: {
      'key:customer-reference': { issuer_id: 'customer:reference', public_key: publicKey },
    },
    expected: {
      activation_id: 'activation:customer-mcp-reference:01',
      tenant_id: 'tenant:customer-reference',
      gateway_id: 'gateway:customer-reference:mcp',
      authorizer_id: 'customer:reference',
    },
    now: NOW,
  });
  let providerCalls = 0;
  const gateway = withCustomerOwnedProtectionGateway(async (name, args) => {
    providerCalls += 1;
    return { name, args };
  }, {
    verifiedActivation: verified,
    expectedActivationDigest: verified.activation_digest,
    expectedOwnerId: 'customer:reference',
    expectedOwnerKeyId: 'key:customer-reference',
    tenantId: 'tenant:customer-reference',
    gatewayId: 'gateway:customer-reference:mcp',
    ledger: await durableLedger(),
    store: durableConsumptionStore(),
    readOnlyTools: ['get_balance'],
  });

  const selected = await gateway('release_payment', { amount_usd: 10 });
  const unknown = await gateway('install_unknown_package', { package: 'attacker' });
  const readOnly = await gateway('get_balance', {});
  return {
    '@version': 'EP-CUSTOMER-OWNED-MCP-GATEWAY-REFERENCE-v1',
    network_requests: 0,
    provider_credentials_received_by_gateway: false,
    selected_tool: {
      admitted: selected.ep_refused !== true,
      status: selected.status,
      action_family: selected.required.action.split(':sha256:')[0],
    },
    unknown_mutation: {
      admitted: unknown.ep_refused !== true,
      status: unknown.status,
    },
    read_only: { admitted: readOnly.name === 'get_balance' },
    provider_calls: providerCalls,
    protection: gateway.protection,
  };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  console.log(JSON.stringify(await runCustomerOwnedMcpGateway(), null, 2));
}
