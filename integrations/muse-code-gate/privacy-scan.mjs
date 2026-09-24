#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Standalone canary scan for the Muse Gate receipt and log boundary. */
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createDemoPaymentReleaseFixture } from './adapter.mjs';
import { generateDemoConfig } from './demo-config.mjs';
import { processMuseHookEvent } from './hook.mjs';
import { createServerRuntime } from './server.mjs';

const PROFILE = 'EP-MUSE-CODE-GATE-PRIVACY-SCAN-v1';

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function artifactCheck(name, value, forbidden) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const leaked = forbidden.filter((secret) => text.includes(secret));
  return {
    artifact: name,
    passed: leaked.length === 0,
    bytes: Buffer.byteLength(text, 'utf8'),
    artifact_digest: digest(text),
    leaked_canary_digests: leaked.map(digest),
  };
}

export async function runPrivacyScan() {
  const directory = await mkdtemp(join(tmpdir(), 'emilia-muse-privacy-scan-'));
  const input = {
    payee: 'vendor:privacy-scan',
    account: 'acct:privacy-canary-0001842',
    amount: '17.25',
    currency: 'USD',
    operation: 'privacy-scan-operation',
  };
  const providerCredential = 'provider-credential-canary-do-not-log';
  const hookError = 'provider-error-canary-do-not-log';
  try {
    const generated = await generateDemoConfig(join(directory, 'runtime'), { input });
    const runtime = await createServerRuntime(generated.config);
    const runtimeResult = await runtime.invoke(generated.call.arguments);
    const providerLedger = await readFile(generated.config.provider_ledger_file, 'utf8');

    const fixture = createDemoPaymentReleaseFixture({
      input,
      provider: async () => ({
        provider_status: 'ACCEPTED',
        provider_reference: 'privacy-scan-safe-reference',
        credential: providerCredential,
        raw_provider_payload: { account: input.account },
      }),
    });
    const projectedResult = await fixture.tool({
      ...input,
      _emilia_receipt: fixture.mintReceipt(),
    });

    const failureHook = await processMuseHookEvent({
      hook_event_name: 'PostToolUseFailure',
      tool_name: 'mcp__emilia_payment_gate__release_payment',
      tool_input: input,
      tool_error: hookError,
    });
    const forbidden = [
      input.account,
      providerCredential,
      hookError,
      generated.config.outcome_signing_key.private_key_pkcs8_b64u,
      generated.call.arguments._emilia_receipt.signature.value,
    ];
    const checks = [
      artifactCheck('outcome_receipt', runtimeResult._emilia.outcome_receipt, forbidden),
      artifactCheck('mcp_response', projectedResult, forbidden),
      artifactCheck('provider_ledger', providerLedger, forbidden),
      artifactCheck('post_tool_failure_observation', failureHook.observation, forbidden),
    ];
    return {
      profile: PROFILE,
      result: checks.every((check) => check.passed) ? 'PASS' : 'FAIL',
      scope: 'synthetic_canaries_only',
      canary_digests: forbidden.map(digest),
      checks,
      limitations: [
        'Does not inspect a real payment provider, real Muse account, or external telemetry sink.',
        'A pass proves only that the tested adapter receipts, MCP projection, demo ledger, and failure-hook observation omit these canaries.',
      ],
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const artifact = await runPrivacyScan();
  process.stdout.write(`${JSON.stringify(artifact, null, 2)}\n`);
  if (artifact.result !== 'PASS') process.exitCode = 1;
}
