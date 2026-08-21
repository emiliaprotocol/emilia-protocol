#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { signProtectionActivation } from '../protection-activation.js';

const USAGE = 'Usage: ep-protect activate <plan.json> --private-key <owner.pem> --tenant <id> --gateway <id> --authorizer <id> --key-id <id> [--out activation.json] [--hours 24]';

function flag(args: string[], name: string): string | null {
  const index = args.indexOf(`--${name}`);
  if (index < 0 || index + 1 >= args.length || args[index + 1].startsWith('--')) return null;
  return args[index + 1];
}

export function activateProtectionPlan(args: string[], now: Date = new Date()): {
  output: string;
  activation: Record<string, unknown>;
} {
  if (args[0] !== 'activate') throw new TypeError(USAGE);
  const planPath = args[1];
  const privateKeyPath = flag(args, 'private-key');
  const tenantId = flag(args, 'tenant');
  const gatewayId = flag(args, 'gateway');
  const authorizerId = flag(args, 'authorizer');
  const keyId = flag(args, 'key-id');
  const outPath = flag(args, 'out');
  const hours = Number(flag(args, 'hours') || '24');
  if (!planPath || !privateKeyPath || !tenantId || !gatewayId || !authorizerId || !keyId
      || !Number.isInteger(hours) || hours < 1 || hours > 720) throw new TypeError(USAGE);

  const rawPlan = readFileSync(planPath, 'utf8');
  const strict = strictJsonGate(rawPlan);
  if (!strict.ok) throw new TypeError(`strict JSON required: ${strict.reason}`);
  const plan = JSON.parse(rawPlan);
  const activation = signProtectionActivation({
    activation_id: `activation-${randomUUID()}`,
    tenant_id: tenantId,
    gateway_id: gatewayId,
    epoch: 1,
    issued_at: now.toISOString(),
    valid_from: now.toISOString(),
    expires_at: new Date(now.getTime() + hours * 60 * 60 * 1000).toISOString(),
    plan,
  }, {
    issuer_id: authorizerId,
    key_id: keyId,
    private_key: readFileSync(privateKeyPath, 'utf8'),
  });
  const rendered = `${JSON.stringify(activation, null, 2)}\n`;
  if (outPath) writeFileSync(outPath, rendered, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  return { output: outPath || '-', activation };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const result = activateProtectionPlan(process.argv.slice(2));
    if (result.output === '-') process.stdout.write(`${JSON.stringify(result.activation, null, 2)}\n`);
    else process.stdout.write(`${JSON.stringify({ status: 'ACTIVATED', output: result.output, activation_id: result.activation.activation_id })}\n`);
  } catch (error) {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : 'protection activation failed'}\n`);
    process.exitCode = 1;
  }
}
