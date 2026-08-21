// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';

import { runCustomerOwnedMcpGateway } from './run.mjs';

test('customer-owned MCP gateway applies the signed plan without claiming deployment', async () => {
  const report = await runCustomerOwnedMcpGateway();
  assert.equal(report.network_requests, 0);
  assert.equal(report.provider_credentials_received_by_gateway, false);
  assert.deepEqual(report.selected_tool, {
    admitted: false,
    status: 402,
    action_family: 'payment.release',
  });
  assert.deepEqual(report.unknown_mutation, { admitted: false, status: 402 });
  assert.deepEqual(report.read_only, { admitted: true });
  assert.equal(report.provider_calls, 1);
  assert.deepEqual(report.protection.selected_mcp_tools, [
    'deploy_production',
    'release_payment',
  ]);
});
