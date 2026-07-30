#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Authenticated TLC oracle for EP-BOUNDED-EXECUTION-PROGRAM-v1.
 *
 * The safe model must exhaust cleanly and exercise the load-bearing admission,
 * budget, indeterminate-dependency, occurrence-ceiling, and signed-supersession
 * actions. Separate unsafe modules must activate an unsigned successor and
 * register over an ordinary reservation, falsifying exactly their expected
 * invariants. Missing coverage or a different TLC failure fails closed.
 */

import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TLC_VERSION = '2.19';
const TLA_TOOLS_VERSION = 'v1.7.4';
const TLC_REVISION = '5a47802';
const TLC_JAR_SHA256 =
  '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88';
const EXPECTED_UNSAFE_INVARIANT = 'OnlySignedProgramsCanBeActive';
const EXPECTED_AUTHORIZATION_FENCE_INVARIANT = 'AuthorizationFenceConsistent';

const REQUIRED_SAFE_ACTION_COVERAGE = [
  { action: 'ReserveOrdinaryAuthorization', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'RegisterOriginalProgram', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'ReserveOccurrence', minimumDistinct: 1, minimumGenerated: 1 },
  {
    action: 'WitnessDependentReachable',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'WitnessLeafReachable',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  { action: 'ReleaseOccurrence', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'BeginInvocation', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'MarkIndeterminate', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'DeactivateProgram', minimumDistinct: 1, minimumGenerated: 1 },
  { action: 'ExpireProgram', minimumDistinct: 1, minimumGenerated: 1 },
  {
    action: 'ReconcileSupersededIndeterminate',
    minimumGenerated: 1,
  },
  { action: 'SupersedeSigned', minimumDistinct: 1, minimumGenerated: 1 },
  {
    action: 'RejectIndeterminateDependency',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectOccurrenceCeiling',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectBudgetExhaustion',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectUnsignedSupersession',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectReusedSupersessionContext',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'WitnessSuspendedProgram',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'WitnessRevokedProgram',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'WitnessExpiredProgram',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'WitnessUnavailableAfterProviderEntry',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectRelinkedAdmission',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectOrdinaryPathForLinkedAdmission',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectRegistrationWithOrdinaryReservation',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
  {
    action: 'RejectOrdinaryReserveAfterRegistration',
    maximumDistinct: 0,
    minimumGenerated: 1,
  },
];

const formalDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(formalDir, '..');
const resultsDir = resolve(formalDir, 'results');
const safeModelPath = resolve(formalDir, 'ep_bounded_execution_program_v1.tla');
const configPath = resolve(formalDir, 'ep_bounded_execution_program_v1.cfg');
const unsafeModelPath = resolve(
  formalDir,
  'ep_bounded_execution_program_v1_unsafe.tla',
);
const authorizationFenceUnsafeModelPath = resolve(
  formalDir,
  'ep_bounded_execution_program_v1_authorization_fence_unsafe.tla',
);
const checkerPath = fileURLToPath(import.meta.url);
const jsonResultPath = resolve(
  resultsDir,
  'bounded-execution-program-v1.tlc.json',
);
const summaryResultPath = resolve(
  resultsDir,
  'bounded-execution-program-v1.tlc.summary.txt',
);

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function stableResult(result) {
  const copy = structuredClone(result);
  delete copy.execution_timestamp;
  return copy;
}

function stableSummary(summary) {
  return summary.replace(
    /^Execution timestamp: .*$/m,
    'Execution timestamp: <run-specific>',
  );
}

function parseInteger(value) {
  return Number.parseInt(value.replaceAll(',', ''), 10);
}

function parseTlcOutput(output) {
  const stateRows = [
    ...output.matchAll(
      /([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue\./g,
    ),
  ];
  const finalStateRow = stateRows.at(-1);
  const depthMatch = output.match(
    /The depth of the complete state graph search is ([\d,]+)\./,
  );
  const versionMatch = output.match(
    /TLC2 Version ([^\s]+).*?\(rev: ([^)]+)\)/,
  );
  const traceStates = [
    ...output.matchAll(/^State ([\d,]+):/gm),
  ].map((match) => parseInteger(match[1]));
  const invariantMatch = output.match(/Invariant ([A-Za-z0-9_]+) is violated/);
  const actionCoverage = Object.fromEntries([
    ...output.matchAll(
      /^<([A-Za-z0-9_]+) [^\n>]+>:\s*([\d,]+):([\d,]+)$/gm,
    ),
  ].map((match) => [
    match[1],
    {
      distinct_successor_states: parseInteger(match[2]),
      generated_successor_states: parseInteger(match[3]),
    },
  ]));

  if (!versionMatch || !finalStateRow || !depthMatch) {
    throw new Error('TLC output did not contain complete version/state/depth data');
  }

  return {
    tlc_version: versionMatch[1],
    tlc_revision: versionMatch[2],
    generated_states: parseInteger(finalStateRow[1]),
    distinct_states: parseInteger(finalStateRow[2]),
    queued_states: parseInteger(finalStateRow[3]),
    depth: parseInteger(depthMatch[1]),
    violation: invariantMatch?.[1] ?? null,
    counterexample_states: traceStates.length === 0 ? 0 : Math.max(...traceStates),
    action_coverage: actionCoverage,
  };
}

function hasRequiredCoverage(parsed) {
  return REQUIRED_SAFE_ACTION_COVERAGE.every((requirement) => {
    const coverage = parsed.action_coverage[requirement.action];
    if (!coverage) return false;
    if (coverage.generated_successor_states < requirement.minimumGenerated) return false;
    if (requirement.minimumDistinct !== undefined
        && coverage.distinct_successor_states < requirement.minimumDistinct) return false;
    if (requirement.maximumDistinct !== undefined
        && coverage.distinct_successor_states > requirement.maximumDistinct) return false;
    return true;
  });
}

function runTlc({ jarPath, modelPath }) {
  const metadataDir = mkdtempSync(join(tmpdir(), 'ep-bounded-execution-tlc-'));
  let result;
  try {
    result = spawnSync(
      process.env.JAVA ?? 'java',
      [
        '-Xmx2G',
        '-XX:+UseParallelGC',
        '-jar',
        jarPath,
        '-workers',
        '1',
        '-seed',
        '1',
        '-coverage',
        '1',
        '-metadir',
        metadataDir,
        '-config',
        configPath,
        modelPath,
      ],
      {
        cwd: formalDir,
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
      },
    );
  } finally {
    rmSync(metadataDir, { recursive: true, force: true });
  }
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  try {
    return { exit_code: result.status, output, parsed: parseTlcOutput(output) };
  } catch (error) {
    process.stderr.write(output);
    throw new Error(`${basename(modelPath)}: ${error.message}`);
  }
}

function assertPinnedJar(jarPath) {
  if (!existsSync(jarPath)) {
    throw new Error(
      `Pinned TLC JAR not found at ${jarPath}. `
      + 'Set TLA2TOOLS_JAR or pass --tlc-jar.',
    );
  }
  const actual = sha256(jarPath);
  if (actual !== TLC_JAR_SHA256) {
    throw new Error(
      `TLC JAR checksum mismatch: expected ${TLC_JAR_SHA256}, got ${actual}`,
    );
  }
}

function checkedObligations() {
  const config = readFileSync(configPath, 'utf8');
  return {
    invariants: [
      ...config.matchAll(/^INVARIANT\s+([A-Za-z0-9_]+)/gm),
    ].map((match) => match[1]),
    properties: [
      ...config.matchAll(/^PROPERTY\s+([A-Za-z0-9_]+)/gm),
    ].map((match) => match[1]),
  };
}

function formatSummary(result) {
  const safe = result.safe;
  const unsafe = result.unsafe;
  const authorizationFenceUnsafe = result.authorization_fence_unsafe;
  const coverage = REQUIRED_SAFE_ACTION_COVERAGE.map(({ action }) => {
    const row = safe.action_coverage[action];
    return `${action}=${row.distinct_successor_states}:${row.generated_successor_states}`;
  }).join('; ');

  return [
    'EP-BOUNDED-EXECUTION-PROGRAM-v1 bounded TLC result',
    `Execution timestamp: ${result.execution_timestamp}`,
    `Checker: TLC ${TLC_VERSION} (TLA+ tools ${TLA_TOOLS_VERSION}, rev ${TLC_REVISION})`,
    `Tool SHA-256: ${TLC_JAR_SHA256}`,
    '',
    'Safe configuration: ep_bounded_execution_program_v1.cfg',
    'Safe module: ep_bounded_execution_program_v1.tla',
    'Result: Model checking completed. No error has been found.',
    `States: ${safe.generated_states.toLocaleString('en-US')} generated; `
      + `${safe.distinct_states.toLocaleString('en-US')} distinct; `
      + `${safe.queued_states.toLocaleString('en-US')} left on queue; `
      + `complete depth ${safe.depth}.`,
    `Checked: ${result.obligations.invariants.length} state invariants and `
      + `${result.obligations.properties.length} transition properties.`,
    `Required action coverage: ${coverage}.`,
    '',
    'Deliberately unsafe module: ep_bounded_execution_program_v1_unsafe.tla',
    `Expected result: Invariant ${unsafe.violation} is violated.`,
    `States before counterexample: ${unsafe.generated_states.toLocaleString('en-US')} generated; `
      + `${unsafe.distinct_states.toLocaleString('en-US')} distinct; `
      + `${unsafe.queued_states.toLocaleString('en-US')} left on queue; `
      + `reported depth ${unsafe.depth}.`,
    `Counterexample trace: ${unsafe.counterexample_states} states. The unsafe `
      + 'transition activates a predecessor-bound but unsigned successor.',
    '',
    'Authorization-fence unsafe module: '
      + 'ep_bounded_execution_program_v1_authorization_fence_unsafe.tla',
    `Expected result: Invariant ${authorizationFenceUnsafe.violation} is violated.`,
    `States before counterexample: ${authorizationFenceUnsafe.generated_states.toLocaleString('en-US')} generated; `
      + `${authorizationFenceUnsafe.distinct_states.toLocaleString('en-US')} distinct; `
      + `${authorizationFenceUnsafe.queued_states.toLocaleString('en-US')} left on queue; `
      + `reported depth ${authorizationFenceUnsafe.depth}.`,
    `Counterexample trace: ${authorizationFenceUnsafe.counterexample_states} states. `
      + 'The unsafe transition registers a program while an ordinary reservation '
      + 'still owns the same tenant and authorization digest.',
    '',
    `Safe model SHA-256: ${result.hashes.safe_model}`,
    `Configuration SHA-256: ${result.hashes.configuration}`,
    `Unsafe model SHA-256: ${result.hashes.unsafe_model}`,
    `Authorization-fence unsafe model SHA-256: ${result.hashes.authorization_fence_unsafe_model}`,
    `Checker SHA-256: ${result.hashes.checker}`,
    '',
    'Scope: one closed three-node DAG; outcome-specific reachability; per-node '
      + 'occurrence ceilings; two-dimensional atomic reserve, consume, and '
      + 'pre-entry release accounting; consumed INDETERMINATE attempts that '
      + 'cannot satisfy dependencies; deterministic immutable AdmissionSnapshot '
      + 'program bindings with relink and ordinary-path refusal; atomic tenant '
      + 'plus authorization-digest registration fencing, pre-existing ordinary '
      + 'reservation refusal, and post-registration ordinary-reserve refusal; '
      + 'pre-entry SUSPENDED, REVOKED, and expiry release with post-entry '
      + 'consumption preservation; admission-to-program expiry clamping; a '
      + 'configured total occurrence bound; fresh-context supersession; terminal reconciliation after '
      + 'supersession; and trusted-signature plus exact predecessor/version '
      + 'binding for fresh-budget supersession.',
    'Boundary: finite same-team control abstraction only. This is not an '
      + 'implementation refinement or evidence that cryptography, provider '
      + 'truth, clocks, storage, deployment, or arbitrary concurrency are correct. '
      + 'Store-pinned trust-root retrieval, structured resource-digest byte '
      + 'construction, and runtime index implementation are outside refinement.',
    '',
  ].join('\n');
}

function main() {
  const jarPath = resolve(
    argumentValue('--tlc-jar')
      ?? process.env.TLA2TOOLS_JAR
      ?? resolve(repositoryRoot, 'tla2tools.jar'),
  );
  assertPinnedJar(jarPath);

  const safeRun = runTlc({ jarPath, modelPath: safeModelPath });
  const unsafeRun = runTlc({ jarPath, modelPath: unsafeModelPath });
  const authorizationFenceUnsafeRun = runTlc({
    jarPath,
    modelPath: authorizationFenceUnsafeModelPath,
  });

  const expectedOracle = (run) =>
    run.parsed.tlc_version === TLC_VERSION
    && run.parsed.tlc_revision === TLC_REVISION;

  const safePassed =
    safeRun.exit_code === 0
    && expectedOracle(safeRun)
    && safeRun.output.includes('Model checking completed. No error has been found.')
    && safeRun.parsed.violation === null
    && safeRun.parsed.queued_states === 0
    && hasRequiredCoverage(safeRun.parsed);
  const unsafeDetected =
    unsafeRun.exit_code !== 0
    && expectedOracle(unsafeRun)
    && unsafeRun.parsed.violation === EXPECTED_UNSAFE_INVARIANT
    && unsafeRun.parsed.counterexample_states > 0;
  const authorizationFenceUnsafeDetected =
    authorizationFenceUnsafeRun.exit_code !== 0
    && expectedOracle(authorizationFenceUnsafeRun)
    && authorizationFenceUnsafeRun.parsed.violation
      === EXPECTED_AUTHORIZATION_FENCE_INVARIANT
    && authorizationFenceUnsafeRun.parsed.counterexample_states > 0;

  if (!safePassed) {
    process.stderr.write(safeRun.output);
    throw new Error('Safe bounded-execution-program model did not exhaust cleanly');
  }
  if (!unsafeDetected) {
    process.stderr.write(unsafeRun.output);
    throw new Error(
      `Unsafe model did not falsify ${EXPECTED_UNSAFE_INVARIANT}`,
    );
  }
  if (!authorizationFenceUnsafeDetected) {
    process.stderr.write(authorizationFenceUnsafeRun.output);
    throw new Error(
      'Authorization-fence unsafe model did not falsify '
      + EXPECTED_AUTHORIZATION_FENCE_INVARIANT,
    );
  }

  const result = {
    model: 'EP-BOUNDED-EXECUTION-PROGRAM-V1-TLC-BOUNDED-v1',
    method: 'authenticated_tlc_exhaustive_bounded_state_exploration',
    execution_timestamp: new Date().toISOString(),
    oracle: {
      tla_tools_version: TLA_TOOLS_VERSION,
      tlc_version: TLC_VERSION,
      revision: TLC_REVISION,
      jar_sha256: TLC_JAR_SHA256,
      workers: 1,
      seed: 1,
      coverage_interval_minutes: 1,
    },
    safe: {
      module: 'ep_bounded_execution_program_v1.tla',
      configuration: 'ep_bounded_execution_program_v1.cfg',
      result: 'no_error',
      exit_code: safeRun.exit_code,
      ...safeRun.parsed,
    },
    unsafe: {
      module: 'ep_bounded_execution_program_v1_unsafe.tla',
      configuration: 'ep_bounded_execution_program_v1.cfg',
      result: 'expected_invariant_violation',
      exit_code: unsafeRun.exit_code,
      ...unsafeRun.parsed,
    },
    authorization_fence_unsafe: {
      module: 'ep_bounded_execution_program_v1_authorization_fence_unsafe.tla',
      configuration: 'ep_bounded_execution_program_v1.cfg',
      result: 'expected_invariant_violation',
      exit_code: authorizationFenceUnsafeRun.exit_code,
      ...authorizationFenceUnsafeRun.parsed,
    },
    obligations: checkedObligations(),
    coverage_obligations: REQUIRED_SAFE_ACTION_COVERAGE.map((entry) => ({
      action: entry.action,
      ...(entry.minimumDistinct === undefined
        ? {}
        : { minimum_distinct_successor_states: entry.minimumDistinct }),
      ...(entry.maximumDistinct === undefined
        ? {}
        : { maximum_distinct_successor_states: entry.maximumDistinct }),
      minimum_generated_successor_states: entry.minimumGenerated,
    })),
    hashes: {
      safe_model: sha256(safeModelPath),
      configuration: sha256(configPath),
      unsafe_model: sha256(unsafeModelPath),
      authorization_fence_unsafe_model: sha256(
        authorizationFenceUnsafeModelPath,
      ),
      checker: sha256(checkerPath),
    },
    verified: true,
    limitations: [
      'Finite same-team control abstraction, not an unbounded theorem.',
      'No mechanized refinement to the TypeScript AdmissionStore or provider implementation.',
      'Signature validity, canonical predecessor digests, clocks, and linearizable durable storage are abstract inputs.',
      'Fresh supersession verification is modeled with opaque context identities; store-pinned key retrieval and trust-root contents are not modeled.',
      'Structured execution-program resource-digest byte construction and concrete runtime occurrence indexes are not modeled; only binding equality and configured occurrence bounds are checked.',
      'The scope has one tenant, one authorization digest, three program versions, three DAG nodes, two budget dimensions, two expiry values, and four occurrence identifiers.',
    ],
  };

  if (process.argv.includes('--check')) {
    if (!existsSync(jsonResultPath) || !existsSync(summaryResultPath)) {
      throw new Error('committed bounded-execution-program evidence is missing');
    }
    const committed = JSON.parse(readFileSync(jsonResultPath, 'utf8'));
    if (JSON.stringify(stableResult(committed)) !== JSON.stringify(stableResult(result))) {
      throw new Error(
        'committed bounded-execution-program JSON evidence is stale; rerun with --emit',
      );
    }
    const committedSummary = readFileSync(summaryResultPath, 'utf8');
    if (stableSummary(committedSummary) !== stableSummary(formatSummary(result))) {
      throw new Error(
        'committed bounded-execution-program summary evidence is stale; rerun with --emit',
      );
    }
  }

  if (process.argv.includes('--emit')) {
    mkdirSync(resultsDir, { recursive: true });
    writeFileSync(jsonResultPath, `${JSON.stringify(result, null, 2)}\n`);
    writeFileSync(summaryResultPath, formatSummary(result));
  }

  if (process.argv.includes('--json')) {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else {
    process.stdout.write(
      `${result.model}: PASS\n`
      + `safe: ${result.safe.generated_states} generated / `
      + `${result.safe.distinct_states} distinct / `
      + `${result.safe.queued_states} queued / depth ${result.safe.depth}\n`
      + `unsafe: ${result.unsafe.violation} violated at trace state `
      + `${result.unsafe.counterexample_states} `
      + `(${result.unsafe.generated_states} generated / `
      + `${result.unsafe.distinct_states} distinct / `
      + `${result.unsafe.queued_states} queued / depth ${result.unsafe.depth})\n`
      + `authorization-fence unsafe: `
      + `${result.authorization_fence_unsafe.violation} violated at trace state `
      + `${result.authorization_fence_unsafe.counterexample_states} `
      + `(${result.authorization_fence_unsafe.generated_states} generated / `
      + `${result.authorization_fence_unsafe.distinct_states} distinct / `
      + `${result.authorization_fence_unsafe.queued_states} queued / `
      + `depth ${result.authorization_fence_unsafe.depth})\n`,
    );
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(
    `Bounded execution program TLC check failed: ${error.message}\n`,
  );
  process.exitCode = 1;
}
