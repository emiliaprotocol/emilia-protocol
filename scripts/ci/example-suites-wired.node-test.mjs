// SPDX-License-Identifier: Apache-2.0
//
// Every examples/ test suite must be executed by some CI job.
//
// vitest excludes examples/**, so an example's node:test suite runs only when
// a workflow names it, directly or through an npm script (or a node script)
// that a workflow invokes. That list was kept by hand, and by 2026-10-05
// sixteen example suites ran in no runner at all, robot-sidecar's
// fail-closed tests among them: a README could say "fails closed" while the
// tests behind it never executed. This test turns that silent shrinkage into
// a failure that names the file.
//
// A suite counts as wired when the CI-reachable text names its path (or the
// .ts/.mts source it is generated from), a glob over its directory, or one of
// its ancestor directories as an `npm --prefix` / `working-directory` target.

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * Suites deliberately not executed in CI, each with the reason. Adding an
 * entry is a decision someone has to write down; a stale entry fails below.
 */
const NOT_IN_CI = {};

const SUITE_FILE = /(?:\.test\.(?:m?js|cjs)|\.node-test\.mjs|(?:^|\/)self-test\.mjs)$/;

function listSuites(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) listSuites(abs, out);
    else if (SUITE_FILE.test(abs)) out.push(abs.slice(ROOT.length + 1).split('\\').join('/'));
  }
  return out;
}

/**
 * Tokenize enough shell syntax to find commands without asking a regular
 * expression to decide whether each option owns the word after it. Newlines
 * and shell control operators end a command; quotes and escaped characters
 * stay in the word they protect.
 */
function shellCommands(text) {
  const commands = [];
  let command = [];
  let word = '';
  let quote = '';

  const finishWord = () => {
    if (word.length > 0) command.push(word);
    word = '';
  };
  const finishCommand = () => {
    finishWord();
    if (command.length > 0) commands.push(command);
    command = [];
  };

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (char === '\\' && quote !== "'") {
      const next = text[i + 1];
      if (next === '\n') {
        i += 1;
      } else if (next !== undefined) {
        word += next;
        i += 1;
      } else {
        word += char;
      }
    } else if (char === '\n') {
      // The input also contains YAML and JavaScript source, not only shell.
      // Do not let an unmatched quote in either language absorb later lines.
      quote = '';
      finishCommand();
    } else if (quote) {
      if (char === quote) quote = '';
      else word += char;
    } else if (char === "'" || char === '"') {
      quote = char;
    } else if (char === ';' || char === '|' || char === '&') {
      finishCommand();
    } else if (/\s/.test(char)) {
      finishWord();
    } else {
      word += char;
    }
  }
  finishCommand();
  return commands;
}

function invokedNodeScripts(text) {
  const invoked = new Set();
  for (const words of shellCommands(text)) {
    for (let i = 0; i < words.length; i += 1) {
      if (words[i] !== 'node' && words[i] !== 'tsx') continue;
      for (let j = i + 1; j < words.length; j += 1) {
        const candidate = words[j];
        if (/^[\w./-]+\.m?[jt]s$/.test(candidate)) {
          invoked.add(candidate);
          break;
        }
      }
    }
  }
  return invoked;
}

/** Workflow text plus every npm script and node script it reaches. */
function ciReachableText() {
  const workflowsDir = join(ROOT, '.github/workflows');
  const workflows = readdirSync(workflowsDir)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => readFileSync(join(workflowsDir, name), 'utf8'))
    .join('\n')
    // A path named only in a YAML comment is not executed.
    .replace(/^\s*#.*$/gm, '');
  const scripts = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).scripts ?? {};

  const npmRun = /\bnpm\s+run(?:-script)?\s+(?:--?[\w-]+(?:=\S+)?\s+)*([\w:.-]+)/g;
  const reached = new Set();
  const queue = [...workflows.matchAll(npmRun)].map((m) => m[1]);
  while (queue.length > 0) {
    const name = queue.pop();
    if (reached.has(name) || scripts[name] === undefined) continue;
    reached.add(name);
    for (const m of scripts[name].matchAll(npmRun)) queue.push(m[1]);
    for (const hook of [`pre${name}`, `post${name}`]) if (scripts[hook] !== undefined) queue.push(hook);
  }
  const text = [workflows, ...[...reached].map((name) => scripts[name])].join('\n');

  // One level into the node scripts that text runs: a proof runner such as
  // scripts/run-gate-reference-proof.mjs may execute an example suite itself.
  const invoked = invokedNodeScripts(text);
  const scriptBodies = [...invoked]
    .map((rel) => join(ROOT, rel))
    .filter((abs) => abs.startsWith(ROOT) && existsSync(abs))
    .map((abs) => readFileSync(abs, 'utf8').replace(/^\s*(?:\/\/|\/?\*).*$/gm, ''));
  return [text, ...scriptBodies].join('\n');
}

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function isWired(suite, text) {
  const source = suite.replace(/\.mjs$/, '.mts').replace(/\.js$/, '.ts');
  if (text.includes(suite) || text.includes(source)) return true;
  const dir = suite.slice(0, suite.lastIndexOf('/'));
  // A glob over the directory, or the directory itself as a `node --test` argument.
  if (text.includes(`${dir}/*`)) return true;
  if (new RegExp(`(?:^|\\s)${escapeRegExp(dir)}/?(?=\\s|$)`, 'm').test(text)) return true;
  // The suite's package, run through its own `npm test`.
  for (let d = dir; d.includes('/'); d = d.slice(0, d.lastIndexOf('/'))) {
    const at = escapeRegExp(d);
    if (new RegExp(`--prefix\\s+${at}/?\\s+(?:run\\s+)?test\\b|working-directory:\\s+${at}/?$`, 'm').test(text)) return true;
  }
  return false;
}

const suites = listSuites(join(ROOT, 'examples')).sort();
const text = ciReachableText();

test('node-script command parsing is bounded and respects command boundaries', () => {
  const adversarialOptions = '-- -'.repeat(10_000);
  assert.deepEqual(
    [...invokedNodeScripts([
      'node --no-warnings "scripts/run-one.mjs" && echo scripts/not-run.mjs',
      'npx tsx --tsconfig tsconfig.json scripts/run-two.ts',
      `node ${adversarialOptions} scripts/run-three.js`,
      'node --version; printf scripts/also-not-run.mjs',
    ].join('\n'))],
    ['scripts/run-one.mjs', 'scripts/run-two.ts', 'scripts/run-three.js'],
  );
});

test('discovery is not vacuous', () => {
  assert.ok(suites.length >= 20, `found only ${suites.length} example suites; the walker is broken`);
  assert.ok(isWired('examples/action-escrow/scenario.test.mjs', text), 'a suite CI is known to run was not detected');
  assert.ok(!isWired('examples/__not-a-real-example__/x.test.mjs', text), 'the matcher accepts anything');
});

test('every examples/ suite is executed by a CI job', () => {
  const unwired = suites.filter((suite) => !(suite in NOT_IN_CI) && !isWired(suite, text));
  assert.deepEqual(
    unwired,
    [],
    'These example suites run in no CI job. Name each in .github/workflows/ci.yml '
      + '(the "Gate the documented standalone example runs on minimum Node" step for Node 20 '
      + 'suites), or in an npm script a workflow runs, or record why not in NOT_IN_CI in '
      + 'scripts/ci/example-suites-wired.node-test.mjs.',
  );
});

test('NOT_IN_CI has no stale entries', () => {
  for (const [suite, reason] of Object.entries(NOT_IN_CI)) {
    assert.ok(suites.includes(suite), `${suite} is listed in NOT_IN_CI but no longer exists`);
    assert.ok(!isWired(suite, text), `${suite} is listed in NOT_IN_CI but CI now runs it`);
    assert.ok(typeof reason === 'string' && reason.length > 0, `${suite} needs a reason`);
  }
});
