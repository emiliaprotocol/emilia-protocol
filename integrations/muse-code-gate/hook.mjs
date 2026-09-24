#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Muse Code hook compatibility layer. Not the authorization boundary. */
import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { paymentProviderInput } from './adapter.mjs';
import { strictJsonGate } from '../../packages/verify/strict-json.js';

const MAX_STDIN_BYTES = 1024 * 1024;

function denial(reason) {
  return {
    exitCode: 2,
    output: {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: `EMILIA Gate: ${reason}`,
      },
    },
  };
}

function eventName(event) {
  return event?.hook_event_name ?? event?.hookEventName ?? null;
}

function isPaymentTool(name) {
  return typeof name === 'string'
    && (name === 'release_payment' || name.endsWith('__release_payment'));
}

function hasOneReceiptCarrier(input) {
  const carriers = ['_emilia_receipt', 'emilia_receipt', '_emilia_receipt_b64']
    .filter((field) => Object.hasOwn(input, field));
  if (carriers.length !== 1) return false;
  const value = input[carriers[0]];
  return (typeof value === 'string' && value.length > 0)
    || (value !== null && typeof value === 'object' && !Array.isArray(value));
}

/**
 * Fixture-friendly event processor. An allow verdict means only "well-shaped
 * enough to reach the real MCP Gate"; it is never an authorization decision.
 */
export async function processMuseHookEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return denial('malformed_hook_event');
  }
  const name = eventName(event);
  const toolName = event.tool_name ?? event.toolName;
  if (!isPaymentTool(toolName)) return { exitCode: 0, output: null };

  if (name === 'PreToolUse') {
    try {
      const input = event.tool_input ?? event.toolInput;
      paymentProviderInput(input, { allowReceiptCarrier: true });
      if (!hasOneReceiptCarrier(input)) return denial('authorization_receipt_required');
      // Current Muse Code rejects a bare allow object unless updatedInput is
      // supplied. Silence plus exit 0 is its documented/observed allow path.
      return { exitCode: 0, output: null };
    } catch (error) {
      return denial(error instanceof Error ? error.message : 'payment_input_invalid');
    }
  }

  if (name === 'PostToolUse') {
    const response = event.tool_response ?? event.toolResponse ?? null;
    const outcome = response?._emilia?.outcome;
    const observation = {
      observed_at: new Date().toISOString(),
      hook_event_name: 'PostToolUse',
      tool_name: toolName,
      state: ['EXECUTED', 'INDETERMINATE'].includes(outcome) ? outcome : 'UNVERIFIED',
      caid: typeof response?._emilia?.caid === 'string' ? response._emilia.caid : null,
      note: 'observational_only',
    };
    return { exitCode: 0, output: null, observation };
  }

  if (name === 'PostToolUseFailure') {
    // Muse documents this event as observational. Deliberately exclude the
    // request, provider error, and tool payload: each may carry credentials or
    // payment data and none establishes whether a provider accepted the call.
    return {
      exitCode: 0,
      output: null,
      observation: {
        observed_at: new Date().toISOString(),
        hook_event_name: 'PostToolUseFailure',
        tool_name: toolName,
        state: 'MUSE_TOOL_FAILURE_UNVERIFIED',
        note: 'observational_only_reconcile_at_provider',
      },
    };
  }

  return denial('unsupported_hook_event');
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_STDIN_BYTES) throw new Error('hook_input_too_large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  const checked = strictJsonGate(raw);
  if (!checked.ok) throw new Error(`hook_json_refused:${checked.reason}`);
  return JSON.parse(raw);
}

export async function runHookCli({ observationFile = process.env.EMILIA_MUSE_OBSERVATION_FILE } = {}) {
  let result;
  try {
    result = await processMuseHookEvent(await readStdin());
  } catch (error) {
    result = denial(error instanceof Error ? error.message : 'hook_failed_closed');
  }
  if (result.observation && observationFile) {
    await appendFile(observationFile, `${JSON.stringify(result.observation)}\n`, { encoding: 'utf8', mode: 0o600 });
  }
  if (result.output) process.stdout.write(`${JSON.stringify(result.output)}\n`);
  process.exitCode = result.exitCode;
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await runHookCli();
}
