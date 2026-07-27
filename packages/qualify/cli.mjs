#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * ep-qualify — evaluate one Gate Qualification v2 bundle offline.
 *
 * Input is exactly { bundle, context }. The CLI does not fetch evidence,
 * contact providers, infer trust, authorize an action, or mutate state.
 */
import {
  closeSync,
  fstatSync,
  openSync,
  readSync,
} from 'node:fs';

const USAGE = 'usage: ep-qualify <qualification.json|->';
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;
const DECISIONS = new Set(['QUALIFIED', 'NOT_QUALIFIED', 'INDETERMINATE']);
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });

class CliError extends Error {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
  }
}

function indeterminate(reason, error) {
  return {
    decision: 'INDETERMINATE',
    reason,
    verification: 'NOT_VERIFIED',
    acceptance: 'NOT_ACCEPTED',
    ...(error ? { error } : {}),
  };
}

function emit(detail) {
  const decision = detail?.decision;
  if (!DECISIONS.has(decision)) {
    throw new CliError('invalid_verifier_result', 'evaluator returned an invalid decision');
  }
  const line = JSON.stringify(detail);
  process.stdout.write(`${decision}\n${line}\n`);
  process.exitCode = decision === 'QUALIFIED' ? 0 : 1;
}

function readBoundedDescriptor(fd) {
  const chunks = [];
  let total = 0;
  while (true) {
    const remaining = MAX_INPUT_BYTES + 1 - total;
    const chunk = Buffer.allocUnsafe(Math.min(READ_CHUNK_BYTES, remaining));
    const count = readSync(fd, chunk, 0, chunk.length, null);
    if (count === 0) break;
    total += count;
    if (total > MAX_INPUT_BYTES) {
      throw new CliError('input_too_large', `input exceeds ${MAX_INPUT_BYTES} bytes`);
    }
    chunks.push(chunk.subarray(0, count));
  }
  try {
    return FATAL_UTF8.decode(Buffer.concat(chunks, total));
  } catch {
    throw new CliError('malformed_json', 'input is not valid UTF-8');
  }
}

function readInput(path) {
  if (path === '-') return readBoundedDescriptor(0);

  let fd;
  try {
    fd = openSync(path, 'r');
    const stat = fstatSync(fd);
    if (!Number.isSafeInteger(stat.size) || stat.size > MAX_INPUT_BYTES) {
      throw new CliError('input_too_large', `input exceeds ${MAX_INPUT_BYTES} bytes`);
    }
    return readBoundedDescriptor(fd);
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw new CliError('unreadable_input', String(error?.message ?? error));
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

async function loadStrictJsonGate() {
  try {
    const module = await import('@emilia-protocol/verify/strict-json');
    if (typeof module.strictJsonGate === 'function') return module.strictJsonGate;
  } catch {
    // Source-checkout fallback below.
  }
  const fallback = await import('../verify/strict-json.js');
  if (typeof fallback.strictJsonGate !== 'function') {
    throw new CliError('internal_error', 'strict JSON gate is unavailable');
  }
  return fallback.strictJsonGate;
}

async function loadEvaluator() {
  for (const specifier of [
    '@emilia-protocol/verify/gate-qualification',
    '@emilia-protocol/verify',
  ]) {
    try {
      const module = await import(specifier);
      if (typeof module.evaluateQualification === 'function') return module.evaluateQualification;
    } catch {
      // Published-package alternatives and source-checkout fallbacks follow.
    }
  }

  try {
    const built = await import('../verify/dist/gate-qualification.js');
    if (typeof built.evaluateQualification === 'function') return built.evaluateQualification;
  } catch {
    // The source checkout may not have built this new module yet.
  }

  const source = await import('../verify/src/gate-qualification.ts');
  if (typeof source.evaluateQualification !== 'function') {
    throw new CliError('internal_error', 'qualification evaluator is unavailable');
  }
  return source.evaluateQualification;
}

function exactInput(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 2
    && Object.prototype.hasOwnProperty.call(value, 'bundle')
    && Object.prototype.hasOwnProperty.call(value, 'context');
}

async function run() {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] === '--help' || args[0] === '-h') {
    throw new CliError('usage_error', USAGE);
  }

  const raw = readInput(args[0]);
  const strictJsonGate = await loadStrictJsonGate();
  const gate = strictJsonGate(raw);
  if (!gate?.ok) throw new CliError('malformed_json', gate?.reason ?? 'strict JSON required');

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    throw new CliError('malformed_json', 'invalid JSON syntax');
  }
  if (!exactInput(input)) {
    throw new CliError('invalid_cli_input', 'input must be exactly an object containing bundle and context');
  }

  const evaluateQualification = await loadEvaluator();
  const result = evaluateQualification(input.bundle, input.context);
  emit(result);
}

try {
  await run();
} catch (error) {
  const reason = error instanceof CliError ? error.reason : 'internal_error';
  const message = String(error?.message ?? error);
  try {
    emit(indeterminate(reason, message));
  } catch {
    process.stdout.write('INDETERMINATE\n{"decision":"INDETERMINATE","reason":"internal_error"}\n');
    process.exitCode = 1;
  }
}
