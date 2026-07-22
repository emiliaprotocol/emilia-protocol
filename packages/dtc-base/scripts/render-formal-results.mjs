import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const RESULTS_ROOT = resolve(PACKAGE_ROOT, 'formal/results');

function parseArguments(argv) {
  const values = new Map();
  let write = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--write') {
      write = true;
      continue;
    }
    if (!argument?.startsWith('--')) throw new Error(`unexpected argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`missing value for ${argument}`);
    values.set(argument, value);
    index += 1;
  }
  return { values, write };
}

function requiredOption(values, name) {
  const value = values.get(name);
  if (!value) throw new Error(`missing required option ${name}`);
  return value;
}

function requiredMatch(text, expression, label) {
  const match = text.match(expression);
  if (!match) throw new Error(`formal output is missing ${label}`);
  return match;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function configEntries(config, directive) {
  return [...config.matchAll(new RegExp(`^\\s*${directive}\\s+([A-Za-z][A-Za-z0-9_]*)\\s*$`, 'gm'))]
    .map((match) => match[1]);
}

function renderTlc({ output, release, releaseSha256 }) {
  if (!output.includes('Model checking completed. No error has been found.')) {
    throw new Error('TLC did not report a clean model-checking completion');
  }
  const version = requiredMatch(output, /^TLC2 Version (.+)$/m, 'the TLC version')[1];
  const states = requiredMatch(
    output,
    /(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue\./,
    'the TLC state totals',
  );
  if (Number(states[3]) !== 0) throw new Error('TLC left states on the queue');

  const modelPath = resolve(PACKAGE_ROOT, 'formal/dtc_base_settlement.tla');
  const configPath = resolve(PACKAGE_ROOT, 'formal/dtc_base_settlement.cfg');
  const config = readFileSync(configPath, 'utf8');
  const invariants = configEntries(config, 'INVARIANT');
  const properties = configEntries(config, 'PROPERTY');
  if (invariants.length === 0 || properties.length === 0) {
    throw new Error('TLC config must declare at least one invariant and one property');
  }

  return `DTC Base settlement TLA+ bounded-model summary
Tool: TLC ${version}
Pinned release: ${release} (download SHA-256 ${releaseSha256})
Model SHA-256: ${sha256(modelPath)}
Config SHA-256: ${sha256(configPath)}

Result: PASS - no error found
States generated: ${states[1]}
Distinct states: ${states[2]}
States left on queue: ${states[3]}

Traversal depth is intentionally omitted: parallel TLC may report a different
breadth-first discovery depth for the same complete state set. The stable
evidence is the generated/distinct totals, empty queue, and clean completion.

Checked invariants (${invariants.length}):
${invariants.map((name) => `- ${name}`).join('\n')}

Checked temporal properties (${properties.length}):
${properties.map((name) => `- ${name}`).join('\n')}

Deadlock checking is disabled because a fully withdrawn terminal state is an
intentional quiescent endpoint. This is a bounded model check, not a proof of
the compiled EVM bytecode.
`;
}

function renderAlloy({ output, release, releaseSha256 }) {
  if (!output.includes('OK: all assertions hold, all predicates consistent.')) {
    throw new Error('Alloy did not report a clean completion');
  }
  if (output.includes('COUNTEREXAMPLE FOUND') || output.includes('model is VACUOUS')) {
    throw new Error('Alloy output contains a counterexample or vacuous scenario');
  }
  const totals = requiredMatch(
    output,
    /Results: checks (\d+)\/(\d+) held, runs (\d+)\/(\d+) satisfiable/,
    'the Alloy command totals',
  );
  const assertions = [...output.matchAll(/^\s*check\s+(\S+)\s+No counterexample found\. OK\s*$/gm)]
    .map((match) => match[1]);
  if (assertions.length !== Number(totals[2]) || totals[1] !== totals[2]) {
    throw new Error('Alloy assertion totals do not match the successful check output');
  }
  if (totals[3] !== totals[4]) throw new Error('Alloy did not find every required scenario');

  const modelPath = resolve(PACKAGE_ROOT, 'formal/dtc_base_escrow.als');
  return `DTC Base escrow Alloy bounded-model summary
Tool: Alloy ${release.replace(/^v/, '')} with SAT4J
Pinned release: ${release} (download SHA-256 ${releaseSha256})
Model SHA-256: ${sha256(modelPath)}

Result: PASS
Assertions: ${totals[1]}/${totals[2]} held with no counterexample
Scenarios: ${totals[3]}/${totals[4]} satisfiable (non-vacuous)

Checked assertions (${assertions.length}):
${assertions.map((name) => `- ${name}`).join('\n')}

This is a bounded relational model, not a proof of the compiled EVM bytecode.
`;
}

function writeOrVerify(path, expected, write) {
  if (write) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, expected, 'utf8');
    process.stdout.write(`refreshed ${path}\n`);
    return true;
  }
  let actual;
  try {
    actual = readFileSync(path, 'utf8');
  } catch {
    console.error(`missing checked-in formal summary: ${path}`);
    return false;
  }
  if (actual !== expected) {
    console.error(`stale checked-in formal summary: ${path}`);
    return false;
  }
  process.stdout.write(`verified ${path}\n`);
  return true;
}

const { values, write } = parseArguments(process.argv.slice(2));
const tlcOutput = readFileSync(requiredOption(values, '--tlc-output'), 'utf8');
const alloyOutput = readFileSync(requiredOption(values, '--alloy-output'), 'utf8');
const tlcSummary = renderTlc({
  output: tlcOutput,
  release: requiredOption(values, '--tla-release'),
  releaseSha256: requiredOption(values, '--tla-sha256'),
});
const alloySummary = renderAlloy({
  output: alloyOutput,
  release: requiredOption(values, '--alloy-release'),
  releaseSha256: requiredOption(values, '--alloy-sha256'),
});

const results = [
  writeOrVerify(resolve(RESULTS_ROOT, 'tlc.summary.txt'), tlcSummary, write),
  writeOrVerify(resolve(RESULTS_ROOT, 'alloy.summary.txt'), alloySummary, write),
];
if (results.includes(false)) {
  console.error('formal summary drift detected; run npm run evidence:refresh and review the diff');
  process.exit(1);
}
