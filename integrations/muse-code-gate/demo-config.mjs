#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Generate ephemeral local keys plus one exact, short-lived demo authorization. */
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createEg1Harness } from '../../packages/gate/index.js';
import {
  canonicalizePaymentRelease,
  createOutcomeSigner,
} from './adapter.mjs';

export const DEMO_INPUT = Object.freeze({
  payee: 'vendor:acme',
  account: 'acct:us:0001842',
  amount: '1250.00',
  currency: 'USD',
  operation: 'invoice-1842',
});

async function writePrivateJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

export async function generateDemoConfig(outputDirectory, { input = DEMO_INPUT, now = Date.now } = {}) {
  const directory = resolve(outputDirectory);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const canonical = canonicalizePaymentRelease(input);
  const harness = createEg1Harness({ action: canonical.action, now, idPrefix: 'muse-live-demo' });
  const outcomeSigner = createOutcomeSigner();
  const configPath = resolve(directory, 'gate-config.json');
  const callPath = resolve(directory, 'authorized-call.json');
  const config = {
    '@version': 'EP-MUSE-CODE-GATE-CONFIG-v1',
    trusted_issuer_keys: [harness.publicKey],
    approver_keys: harness.approverKeys,
    rp_id: harness.rpId,
    allowed_origins: harness.allowedOrigins,
    max_age_sec: 900,
    state_file: resolve(directory, 'consumption-state.json'),
    provider_ledger_file: resolve(directory, 'demo-provider-ledger.jsonl'),
    outcome_signing_key: {
      key_id: 'ep:key:muse-gate-demo-outcome',
      private_key_pkcs8_b64u: outcomeSigner.privateKey
        .export({ type: 'pkcs8', format: 'der' }).toString('base64url'),
      public_key_spki_b64u: outcomeSigner.publicKey,
    },
  };
  const call = {
    tool: 'release_payment',
    arguments: { ...input, _emilia_receipt: harness.mint({ outcome: 'allow_with_signoff' }) },
    expected_caid: canonical.caid,
    outcome_verification_key: outcomeSigner.publicKey,
    warning: 'Local demo authorization; short-lived, single-use, and not a production key-custody pattern.',
  };
  await writePrivateJson(configPath, config);
  await writePrivateJson(callPath, call);
  return Object.freeze({ directory, configPath, callPath, config, call });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const outputDirectory = process.argv[2];
  if (!outputDirectory) {
    process.stderr.write('Usage: node demo-config.mjs <private-output-directory>\n');
    process.exitCode = 2;
  } else {
    const generated = await generateDemoConfig(outputDirectory);
    process.stdout.write(`${JSON.stringify({
      config: generated.configPath,
      authorized_call: generated.callPath,
      caid: generated.call.expected_caid,
      outcome_verification_key: generated.call.outcome_verification_key,
    }, null, 2)}\n`);
  }
}
