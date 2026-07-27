#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Authenticated TLC oracle for the bounded Gate Qualification v2 lifecycle.
 *
 * The safe model must exhaust its configured graph without an error. The
 * paired unsafe module must fail specifically because post-entry supersession
 * violates SupersessionOnlyWhileReserved. The safe run must also cover the
 * explicit COMMITTED+DIVERGED finalization action. A successful negative-
 * control exit, a missing reachability witness, or a different TLC failure
 * fails this checker closed.
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TLC_VERSION = '2.19';
const TLA_TOOLS_VERSION = 'v1.7.4';
const TLC_REVISION = '5a47802';
const TLC_JAR_SHA256 =
  '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88';
const EXPECTED_UNSAFE_INVARIANT = 'SupersessionOnlyWhileReserved';
const EXPECTED_REACHABILITY_ACTION = 'FinalizeCommittedDiverged';
const REQUIRED_SAFE_ACTION_COVERAGE = [
  {
    action: 'SupersedeReserved',
    minimum_distinct_successor_states: 1,
    minimum_generated_successor_states: 1,
  },
  {
    action: 'RejectSupersessionIdentityConflict',
    maximum_distinct_successor_states: 0,
    minimum_generated_successor_states: 1,
  },
  {
    action: 'AdmitRemedy',
    minimum_distinct_successor_states: 1,
    minimum_generated_successor_states: 1,
  },
  {
    action: 'AcceptNotEnteredProviderEvidence',
    minimum_distinct_successor_states: 1,
    minimum_generated_successor_states: 1,
  },
  {
    action: 'AcceptNotEnteredEffectEvidence',
    minimum_distinct_successor_states: 1,
    minimum_generated_successor_states: 1,
  },
  {
    action: EXPECTED_REACHABILITY_ACTION,
    minimum_distinct_successor_states: 1,
    minimum_generated_successor_states: 1,
  },
];

const formalDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(formalDir, '..');
const resultsDir = resolve(formalDir, 'results');
const safeModelPath = resolve(formalDir, 'ep_gate_qualification_v2.tla');
const configPath = resolve(formalDir, 'ep_gate_qualification_v2.cfg');
const unsafeModelPath = resolve(formalDir, 'ep_gate_qualification_v2_unsafe.tla');
const checkerPath = fileURLToPath(import.meta.url);
const jsonResultPath = resolve(
  resultsDir,
  'gate-qualification-v2.tlc.json',
);
const summaryResultPath = resolve(
  resultsDir,
  'gate-qualification-v2.tlc.summary.txt',
);

function argumentValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
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
  const reachabilityCoverage =
    actionCoverage[EXPECTED_REACHABILITY_ACTION] ?? null;

  if (!finalStateRow || !depthMatch || !versionMatch) {
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
    counterexample_states: traceStates.length === 0
      ? 0
      : Math.max(...traceStates),
    action_coverage: actionCoverage,
    reachability: reachabilityCoverage === null
      ? null
      : {
          action: EXPECTED_REACHABILITY_ACTION,
          ...reachabilityCoverage,
        },
  };
}

function requiredSafeCoveragePresent(parsed) {
  return REQUIRED_SAFE_ACTION_COVERAGE.every((requirement) => {
    const coverage = parsed.action_coverage[requirement.action];
    if (!coverage) return false;
    if (coverage.generated_successor_states
        < requirement.minimum_generated_successor_states) return false;
    if (requirement.minimum_distinct_successor_states !== undefined
        && coverage.distinct_successor_states
          < requirement.minimum_distinct_successor_states) return false;
    if (requirement.maximum_distinct_successor_states !== undefined
        && coverage.distinct_successor_states
          > requirement.maximum_distinct_successor_states) return false;
    return true;
  });
}

function runTlc({ jarPath, modelPath }) {
  const result = spawnSync(
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
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  return {
    exit_code: result.status,
    output,
    parsed: parseTlcOutput(output),
  };
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
  const invariants = [
    ...config.matchAll(/^INVARIANT\s+([A-Za-z0-9_]+)/gm),
  ].map((match) => match[1]);
  const properties = [
    ...config.matchAll(/^PROPERTY\s+([A-Za-z0-9_]+)/gm),
  ].map((match) => match[1]);
  return { invariants, properties };
}

function formatSummary(result) {
  const safe = result.safe;
  const unsafe = result.unsafe;
  return [
    'EMILIA Gate Qualification v2 bounded TLC result',
    `Execution timestamp: ${result.execution_timestamp}`,
    `Checker: TLC ${TLC_VERSION} (TLA+ tools ${TLA_TOOLS_VERSION}, rev ${TLC_REVISION})`,
    `Tool SHA-256: ${TLC_JAR_SHA256}`,
    '',
    'Safe configuration: ep_gate_qualification_v2.cfg',
    'Safe module: ep_gate_qualification_v2.tla',
    'Result: Model checking completed. No error has been found.',
    `States: ${safe.generated_states.toLocaleString('en-US')} generated; `
      + `${safe.distinct_states.toLocaleString('en-US')} distinct; `
      + `${safe.queued_states.toLocaleString('en-US')} left on queue; `
      + `complete depth ${safe.depth}.`,
    `Checked: ${result.obligations.invariants.length} state invariants and `
      + `${result.obligations.properties.length} transition properties.`,
    `Reachability witness: ${safe.reachability.action} reached `
      + `${safe.reachability.distinct_successor_states.toLocaleString('en-US')} `
      + 'distinct successor states across '
      + `${safe.reachability.generated_successor_states.toLocaleString('en-US')} `
      + 'generated successors; COMMITTED+DIVERGED is represented.',
    'Architecture coverage: '
      + REQUIRED_SAFE_ACTION_COVERAGE.map(({ action }) => {
        const coverage = safe.action_coverage[action];
        return `${action}=${coverage.distinct_successor_states}:`
          + `${coverage.generated_successor_states}`;
      }).join('; ')
      + '.',
    '',
    'Deliberately unsafe module: ep_gate_qualification_v2_unsafe.tla',
    `Expected result: Invariant ${unsafe.violation} is violated.`,
    `States before counterexample: ${unsafe.generated_states.toLocaleString('en-US')} generated; `
      + `${unsafe.distinct_states.toLocaleString('en-US')} distinct; `
      + `${unsafe.queued_states.toLocaleString('en-US')} left on queue; `
      + `reported depth ${unsafe.depth}.`,
    `Counterexample trace: ${unsafe.counterexample_states} states. The unsafe `
      + 'transition supersedes an already-entered INDETERMINATE qualification.',
    '',
    `Safe model SHA-256: ${result.hashes.safe_model}`,
    `Configuration SHA-256: ${result.hashes.configuration}`,
    `Unsafe model SHA-256: ${result.hashes.unsafe_model}`,
    `Checker SHA-256: ${result.hashes.checker}`,
    '',
    'Scope: accepted/current qualification, atomic tenant+operation reserve, '
      + 'NOT_ENTERED pre-provider state, authority consumption before INVOKING, '
      + 'post-entry INDETERMINATE fencing, no blind retry, exact authenticated '
      + 'provider/effect evidence, RESERVED-only supersession, one live '
      + 'tenant+operation, supersession with a new admission but the same '
      + 'operation/CAID/canonical action/request/authorization, refusal of '
      + 'same-operation identity conflicts, independent provider/effect axes '
      + '(including COMMITTED+DIVERGED), accepted NOT_ENTERED evidence fencing, '
      + 'and a separately authorized remedy with a new operation and CAID.',
    'Boundary: finite same-team control abstraction only. This is not an '
      + 'implementation refinement or evidence that cryptography, provider '
      + 'truth, clocks, storage, deployment, or arbitrary concurrency are correct.',
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

  const safePassed =
    safeRun.exit_code === 0
    && safeRun.output.includes(
      'Model checking completed. No error has been found.',
    )
    && safeRun.parsed.violation === null
    && safeRun.parsed.queued_states === 0
    && safeRun.parsed.reachability !== null
    && safeRun.parsed.reachability.distinct_successor_states > 0
    && safeRun.parsed.reachability.generated_successor_states > 0
    && requiredSafeCoveragePresent(safeRun.parsed);
  const unsafeDetected =
    unsafeRun.exit_code !== 0
    && unsafeRun.parsed.violation === EXPECTED_UNSAFE_INVARIANT
    && unsafeRun.parsed.counterexample_states > 0;

  if (!safePassed) {
    process.stderr.write(safeRun.output);
    throw new Error('Safe Gate Qualification v2 model did not exhaust cleanly');
  }
  if (!unsafeDetected) {
    process.stderr.write(unsafeRun.output);
    throw new Error(
      `Unsafe model did not falsify ${EXPECTED_UNSAFE_INVARIANT}`,
    );
  }

  const result = {
    model: 'EP-GATE-QUALIFICATION-V2-TLC-BOUNDED-v2',
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
      module: 'ep_gate_qualification_v2.tla',
      configuration: 'ep_gate_qualification_v2.cfg',
      result: 'no_error',
      exit_code: safeRun.exit_code,
      ...safeRun.parsed,
    },
    unsafe: {
      module: 'ep_gate_qualification_v2_unsafe.tla',
      configuration: 'ep_gate_qualification_v2.cfg',
      result: 'expected_invariant_violation',
      exit_code: unsafeRun.exit_code,
      ...unsafeRun.parsed,
    },
    obligations: checkedObligations(),
    coverage_obligations: REQUIRED_SAFE_ACTION_COVERAGE,
    hashes: {
      safe_model: sha256(safeModelPath),
      configuration: sha256(configPath),
      unsafe_model: sha256(unsafeModelPath),
      checker: sha256(checkerPath),
    },
    verified: true,
    limitations: [
      'Finite same-team control abstraction, not an unbounded theorem.',
      'No mechanized refinement to the TypeScript, SQL, provider, or deployment implementation.',
      'Evidence authentication, cryptography, provider truth, clocks, and durable atomic storage are abstract inputs.',
      'The scope has three qualification records, one tenant, two operations, three CAIDs, two canonical actions, three canonical requests, two authorizations, seven admissions, and twelve evidence values.',
    ],
  };

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
      + `witness: ${result.safe.reachability.action} `
      + `${result.safe.reachability.distinct_successor_states}:`
      + `${result.safe.reachability.generated_successor_states}\n`
      + `unsafe: ${result.unsafe.violation} violated at trace state `
      + `${result.unsafe.counterexample_states} `
      + `(${result.unsafe.generated_states} generated / `
      + `${result.unsafe.distinct_states} distinct / `
      + `${result.unsafe.queued_states} queued / depth `
      + `${result.unsafe.depth})\n`,
    );
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(
    `Gate Qualification v2 TLC check failed: ${error.message}\n`,
  );
  process.exitCode = 1;
}
