// SPDX-License-Identifier: Apache-2.0
/**
 * Bounded subprocess transport for EMILIA protocol Referee runners.
 *
 * The caller pins an absolute executable, its SHA-256 byte digest, and the
 * complete argument vector.  The child receives only a closed JSON request on
 * stdin and must return one closed JSON output on stdout.  This is a bounded,
 * no-shell subprocess self-test harness; it is not an OS sandbox and does not
 * claim to confine a hostile executable's filesystem or network access.
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';

import {
  REFEREE_EVALUATION_VERSION,
  RefereeValidationError,
  createIndeterminateRefereeResult,
  evaluateReferee,
  parseRefereeRunnerOutput,
  parseRefereeRunnerPin,
  parseRefereeRunnerRequest,
  type RefereeResultV1,
  type RefereeRunnerOutputV1,
  type RefereeRunnerPinV1,
  type RefereeRunnerRequestV1,
} from './referee.js';
import { strictJsonGate } from './strict-json.js';

export const REFEREE_RUNNER_MAX_INPUT_BYTES = 8 * 1024 * 1024;
export const REFEREE_RUNNER_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
export const REFEREE_RUNNER_MAX_TIMEOUT_MS = 300_000;

const FORCE_KILL_AFTER_MS = 100;
const INVOCATION_KEYS = Object.freeze([
  'runner_pin', 'request', 'timeout_ms',
] as const);
const OPTION_KEYS = new Set(['signal']);

export type RefereeRunnerFailureCode =
  | 'ABORTED'
  | 'INPUT_TOO_LARGE'
  | 'OUTPUT_TOO_LARGE'
  | 'TIMEOUT'
  | 'EXECUTABLE_DIGEST_MISMATCH'
  | 'SPAWN_FAILED'
  | 'NONZERO_EXIT'
  | 'MALFORMED_OUTPUT'
  | 'INVALID_OUTPUT_SCHEMA';

export interface RefereeRunnerInvocationV1 {
  readonly runner_pin: RefereeRunnerPinV1;
  readonly request: RefereeRunnerRequestV1;
  readonly timeout_ms: number;
}

export interface RefereeRunnerOptions {
  readonly signal?: AbortSignal;
}

export type RefereeRunnerExecutionResult =
  | Readonly<{
      ok: true;
      output: Readonly<RefereeRunnerOutputV1>;
    }>
  | Readonly<{
      ok: false;
      code: RefereeRunnerFailureCode;
    }>;

function fail(code: string): never {
  throw new RefereeValidationError(code);
}

function plain(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactInvocation(value: unknown): Record<(typeof INVOCATION_KEYS)[number], unknown> {
  if (!plain(value)) fail('invalid_schema');
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail('unknown_key');
  const expected = new Set<string>(INVOCATION_KEYS);
  for (const key of ownKeys as string[]) {
    if (!expected.has(key)) fail('unknown_key');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('invalid_schema');
  }
  for (const key of INVOCATION_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail('missing_key');
  }
  return value as Record<(typeof INVOCATION_KEYS)[number], unknown>;
}

function parseOptions(value: unknown): Readonly<RefereeRunnerOptions> {
  if (value === undefined) return Object.freeze({});
  if (!plain(value)) fail('invalid_options');
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string' || !OPTION_KEYS.has(key))) {
    fail('unknown_key');
  }
  let signal: unknown;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) {
      fail('invalid_options');
    }
    if (key === 'signal') signal = descriptor.value;
  }
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    fail('invalid_signal');
  }
  return Object.freeze(signal === undefined ? {} : { signal });
}

export function parseRefereeRunnerInvocation(
  value: unknown,
): Readonly<RefereeRunnerInvocationV1> {
  const object = exactInvocation(value);
  if (!Number.isSafeInteger(object.timeout_ms)
    || (object.timeout_ms as number) < 1
    || (object.timeout_ms as number) > REFEREE_RUNNER_MAX_TIMEOUT_MS) {
    fail('invalid_timeout');
  }
  return Object.freeze({
    runner_pin: parseRefereeRunnerPin(object.runner_pin),
    request: parseRefereeRunnerRequest(object.request),
    timeout_ms: object.timeout_ms as number,
  });
}

function frozenFailure(code: RefereeRunnerFailureCode): RefereeRunnerExecutionResult {
  return Object.freeze({ ok: false as const, code });
}

function frozenSuccess(
  output: Readonly<RefereeRunnerOutputV1>,
): RefereeRunnerExecutionResult {
  return Object.freeze({ ok: true as const, output });
}

function decodeRunnerOutput(bytes: Buffer): RefereeRunnerExecutionResult {
  let raw: string;
  try {
    raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return frozenFailure('MALFORMED_OUTPUT');
  }
  const gate = strictJsonGate(raw);
  if (!gate.ok) return frozenFailure('MALFORMED_OUTPUT');

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return frozenFailure('MALFORMED_OUTPUT');
  }
  try {
    return frozenSuccess(parseRefereeRunnerOutput(parsed));
  } catch (error) {
    if (error instanceof RefereeValidationError) {
      return frozenFailure('INVALID_OUTPUT_SCHEMA');
    }
    return frozenFailure('INVALID_OUTPUT_SCHEMA');
  }
}

function serializeRequest(
  request: Readonly<RefereeRunnerRequestV1>,
): string {
  // parseRefereeRunnerRequest has already established an exact JSON tree, so
  // JSON.stringify cannot silently drop or coerce any member here.
  return JSON.stringify(request);
}

async function digestExecutable(
  executable: string,
  signal?: AbortSignal,
): Promise<string | null> {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    const stream = createReadStream(executable, { signal });
    let complete = false;
    const finish = (value: string | null) => {
      if (complete) return;
      complete = true;
      resolve(value);
    };
    stream.on('data', (chunk) => hash.update(chunk));
    stream.once('error', () => finish(null));
    stream.once('end', () => finish(`sha256:${hash.digest('hex')}`));
  });
}

async function executeParsed(
  invocation: Readonly<RefereeRunnerInvocationV1>,
  options: Readonly<RefereeRunnerOptions>,
): Promise<RefereeRunnerExecutionResult> {
  const serialized = serializeRequest(invocation.request);
  if (Buffer.byteLength(serialized, 'utf8') > REFEREE_RUNNER_MAX_INPUT_BYTES) {
    return frozenFailure('INPUT_TOO_LARGE');
  }
  if (options.signal?.aborted) return frozenFailure('ABORTED');

  // This is intentionally the last asynchronous operation before spawn.  It
  // establishes byte equality with the relying party's pin; it does not turn
  // this portable harness into a complete OS-level execution sandbox.
  const observedExecutableDigest = await digestExecutable(
    invocation.runner_pin.executable,
    options.signal,
  );
  if (options.signal?.aborted) return frozenFailure('ABORTED');
  if (observedExecutableDigest === null) return frozenFailure('SPAWN_FAILED');
  if (observedExecutableDigest !== invocation.runner_pin.executable_sha256) {
    return frozenFailure('EXECUTABLE_DIGEST_MISMATCH');
  }

  return new Promise<RefereeRunnerExecutionResult>((resolve) => {
    const detached = process.platform !== 'win32';
    let child;
    try {
      child = spawn(invocation.runner_pin.executable, [...invocation.runner_pin.args], {
        cwd: path.parse(invocation.runner_pin.executable).root,
        detached,
        env: {},
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch {
      resolve(frozenFailure('SPAWN_FAILED'));
      return;
    }

    let settled = false;
    let selectedFailure: RefereeRunnerFailureCode | null = null;
    let totalOutputBytes = 0;
    let stdoutBytes = 0;
    const stdoutChunks: Buffer[] = [];
    let forceKillTimer: ReturnType<typeof setTimeout> | null = null;

    const sendSignal = (signal: NodeJS.Signals) => {
      if (child.pid !== undefined && detached) {
        try {
          process.kill(-child.pid, signal);
          return;
        } catch {
          // The process may have exited between the event and this signal.
        }
      }
      try {
        child.kill(signal);
      } catch {
        // close/error remains the authoritative completion event.
      }
    };

    const timeout = setTimeout(() => {
      terminate('TIMEOUT');
    }, invocation.timeout_ms);
    timeout.unref?.();

    const abort = () => terminate('ABORTED');
    options.signal?.addEventListener('abort', abort, { once: true });

    const cleanup = () => {
      clearTimeout(timeout);
      if (forceKillTimer !== null) clearTimeout(forceKillTimer);
      options.signal?.removeEventListener('abort', abort);
    };

    const finish = (result: RefereeRunnerExecutionResult) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    function terminate(code: RefereeRunnerFailureCode) {
      if (settled || selectedFailure !== null) return;
      selectedFailure = code;
      sendSignal('SIGTERM');
      forceKillTimer = setTimeout(() => sendSignal('SIGKILL'), FORCE_KILL_AFTER_MS);
      forceKillTimer.unref?.();
    }

    const accountOutput = (chunk: Buffer | string, capture: boolean) => {
      if (settled || selectedFailure !== null) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalOutputBytes += bytes.byteLength;
      if (totalOutputBytes > REFEREE_RUNNER_MAX_OUTPUT_BYTES) {
        terminate('OUTPUT_TOO_LARGE');
        return;
      }
      if (capture) {
        stdoutBytes += bytes.byteLength;
        stdoutChunks.push(bytes);
      }
    };

    child.stdout.on('data', (chunk: Buffer) => accountOutput(chunk, true));
    child.stderr.on('data', (chunk: Buffer) => accountOutput(chunk, false));
    child.stdin.on('error', () => {
      // EPIPE is resolved by the child's close/error result, never by ambient
      // error text or timing.
    });
    child.once('error', () => finish(frozenFailure(
      selectedFailure ?? 'SPAWN_FAILED',
    )));
    child.once('close', (code) => {
      if (selectedFailure !== null) {
        finish(frozenFailure(selectedFailure));
        return;
      }
      if (code !== 0) {
        finish(frozenFailure('NONZERO_EXIT'));
        return;
      }
      finish(decodeRunnerOutput(Buffer.concat(stdoutChunks, stdoutBytes)));
    });

    child.stdin.end(serialized, 'utf8');
  });
}

/** Execute a caller-pinned protocol runner without shell or ambient config. */
export async function runPinnedProtocolRunner(
  value: unknown,
  rawOptions?: unknown,
): Promise<RefereeRunnerExecutionResult> {
  const invocation = parseRefereeRunnerInvocation(value);
  const options = parseOptions(rawOptions);
  return executeParsed(invocation, options);
}

/** Execute and evaluate one self-test, mapping every runner failure to no-claim. */
export async function runReferee(
  value: unknown,
  rawOptions?: unknown,
): Promise<Readonly<RefereeResultV1>> {
  // Snapshot every caller-controlled field before the first asynchronous edge.
  const invocation = parseRefereeRunnerInvocation(value);
  const options = parseOptions(rawOptions);
  const execution = await executeParsed(invocation, options);
  if (!execution.ok) {
    return createIndeterminateRefereeResult({
      runner_pin: invocation.runner_pin,
      request: invocation.request,
      reason_code: `runner_${execution.code.toLowerCase()}`,
    });
  }
  return evaluateReferee({
    version: REFEREE_EVALUATION_VERSION,
    runner_pin: invocation.runner_pin,
    request: invocation.request,
    output: execution.output,
  });
}
