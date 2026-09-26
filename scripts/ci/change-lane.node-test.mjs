// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/change-lane.mjs. The `changes` job in ci.yml runs
// this before classifying; a failure there leaves the lane output empty,
// which every gated job treats as `full`.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  DOCS_LANE,
  FULL_LANE,
  SKIP_CONDITION,
  bindingReference,
  classify,
  extractProseReferences,
  isAuditedSource,
  isDocsCandidate,
  jobBlocks,
  parseRawDiff,
  reachableKeptCheckers,
  run,
  skippedJobClosure,
} from './change-lane.mjs';

const modified = (path, mode = '100644') => ({ path, status: 'M', oldMode: mode, newMode: mode });
const audit = (sources = [], violations = []) => () => ({ sources, violations });

test('prose candidates: docs, standards and papers prose plus root markdown only', () => {
  for (const path of [
    'docs/EP-SYNC-INTEROP.md',
    'docs/media/diagram.svg',
    'standards/staged/NEXT-AEB-07/README.md',
    'standards/staged/NEXT-AEB-07/SHA256SUMS.txt',
    'standards/staged/NEXT-AEB-05/SHA256SUMS',
    'standards/staged/NEXT-AEB-07/UPLOAD-THIS/draft-schrock-action-evidence-boundary-07.xml',
    'standards/staged/NEXT-AEB-07/RENDERS/draft-schrock-action-evidence-boundary-07.html',
    'papers/preprint/main.tex',
    'README.md',
    'CONTRIBUTING.md',
  ]) {
    assert.equal(isDocsCandidate(path), true, path);
  }
  for (const path of [
    'AI_CONTEXT.md',
    'standards/STATUS.json',
    'standards/aiuc/incident-fields-v0/validate.selftest.mjs',
    'docs/ai/context-source.v1.json',
    'docs/api/govguard-v1.yaml',
    'packages/gate/README.md',
    'public/llms.txt',
    'package-lock.json',
    'lib/proof-stats.json',
    '.github/workflows/ci.yml',
    'docs/../lib/x.md',
    'docs//x.md',
    'docs/./x.md',
    'LICENSE',
    '',
  ]) {
    assert.equal(isDocsCandidate(path), false, path);
  }
});

test('prose candidates: a segment outside [A-Za-z0-9_.@+-] is never prose', () => {
  // Reference extraction cannot see such names, and `git ls-tree` parsers in
  // the security case reject line terminators, so they must run everything.
  for (const path of [
    'docs/protocol/new\nfile.md',
    'docs/protocol/new\rfile.md',
    'docs/protocol/new\u2028file.md',
    'docs/protocol/new\u2029file.md',
    'docs/protocol/new file.md',
    'docs/pr\u00f6tocol/x.md',
    'docs/protocol/caf\u00e9.md',
    'standards/staged/\tx.md',
    'docs\\x.md',
    'README\n.md',
  ]) {
    assert.equal(isDocsCandidate(path), false, JSON.stringify(path));
    const decision = classify([modified(path)], audit());
    assert.equal(decision.lane, FULL_LANE, JSON.stringify(path));
    assert.ok(decision.reasons[0].endsWith('not a prose path'), decision.reasons[0]);
  }
  assert.equal(isDocsCandidate('docs/release@1.2+build_x-y.md'), true);
});

test('audited sources: code a skipped job may run, not trees only kept jobs read', () => {
  for (const path of [
    'packages/gate/src/index.ts',
    'lib/envelope/descriptors.ts',
    'conformance/clean-room/specification-bundle.v1.json',
    'scripts/verify-security-case.mjs',
    'tests/postgres-integration.test.ts',
    'tests/benchmark.test.ts',
    'deploy/consequence-control-cloud-run/build-release-images.sh',
    'Dockerfile.gate',
  ]) {
    assert.equal(isAuditedSource(path), true, path);
  }
  for (const path of [
    '.github/workflows/ci.yml',
    '.github/workflows/mobile-apps.yml',
    'package.json',
    'tests/public-claims.test.ts',
    'app/spec/page.tsx',
    'docs/x.md',
    'standards/aiuc/incident-fields-v0/validate.selftest.mjs',
    'scripts/check-standards-staged.mjs',
    'scripts/check-ae-challenge-08.mjs',
    'scripts/check-artifact-lifecycle.mjs',
    'scripts/generate-proof-stats.mts',
    'integrations/github-merge-gate-action/tests/merge-gate.node-test.mjs',
    '.gitleaks.toml',
    'packages/gate/node_modules/x/index.js',
    'packages/gate/README.md',
  ]) {
    assert.equal(isAuditedSource(path), false, path);
  }
});

test('references: file paths, directory operands and variable roots bind', () => {
  const refs = (path, text, root = []) => [...extractProseReferences(path, text, root)].sort();
  assert.deepEqual(refs('lib/a.ts', "readFileSync('docs/protocol/pq.md')"), ['docs/protocol/pq.md']);
  assert.deepEqual(refs('lib/a.ts', '// see docs/protocol/pq.md.'), ['docs/protocol/pq.md']);
  assert.deepEqual(refs('lib/a.ts', 'const dir = `${ROOT}/standards/staged/${name}`;'), ['standards/staged']);
  assert.deepEqual(refs('lib/a.ts', "glob('docs/*')"), ['docs']);
  assert.deepEqual(refs('lib/a.ts', "const p = 'docs/'"), ['docs']);
  assert.deepEqual(refs('lib/a.ts', "join(__dirname, '..', 'docs')"), ['docs']);
  assert.deepEqual(refs('lib/a.ts', "join(ROOT, 'standards', 'staged', name)"), ['standards/staged']);
  assert.deepEqual(refs('lib/a.ts', "join(ROOT, 'standards', 'posted', 'd.xml')"), ['standards/posted/d.xml']);
  assert.deepEqual(refs('lib/a.ts', "ROOT + 'docs'"), ['docs']);
  assert.deepEqual(refs('lib/a.ts', "const DOCS_DIR = 'docs';"), ['docs']);
  assert.deepEqual(refs('lib/a.ts', "const config = { dir: 'standards' };"), ['standards']);
  assert.deepEqual(refs('tool.py', 'target = ROOT / "papers" / name'), ['papers']);
  assert.deepEqual(refs('x.sh', 'cp "$GITHUB_WORKSPACE/docs/api/g.yaml" "$STAGE/"'), ['docs/api/g.yaml']);
  assert.deepEqual(refs('x.sh', 'find standards -name "*.xml"'), ['standards']);
  assert.deepEqual(refs('lib/a.ts', "readFileSync('README.md')", ['README.md']), ['README.md']);
});

test('references: array and list elements bind the whole directory', () => {
  const refs = (path, text) => [...extractProseReferences(path, text)].sort();
  // scripts/check-artifact-lifecycle.mjs walks its roots from such a list.
  assert.deepEqual(refs('lib/a.ts', "const keywords = ['docs', 'standards'];"), ['docs', 'standards']);
  assert.deepEqual(refs('lib/a.mjs', "  documentationDirectories = ['docs', 'standards', 'PIPs'],"), ['docs', 'standards']);
  assert.deepEqual(refs('lib/a.ts', "for (const d of ['papers']) walk(d);"), ['papers']);
  assert.deepEqual(refs('tool.py', 'for root in ["docs", "standards"]:'), ['docs', 'standards']);
  assert.deepEqual(refs('tool.py', 'ROOTS = {"papers", "docs"}'), ['docs', 'papers']);
  assert.deepEqual(refs('cmd/main.go', 'roots := []string{"standards"}'), ['standards']);
  assert.deepEqual(refs('lib/a.ts', "walk(['standards', 'docs'])"), ['docs', 'standards']);
  // A subscript or a mapping key is not a list element.
  assert.deepEqual(refs('tool.py', 'digest(v["docs"], v["opts"])'), []);
  assert.deepEqual(refs('lib/a.ts', "rows[0]['docs'] + call()['standards']"), []);
  assert.deepEqual(refs('tool.py', "counts = {'docs': 1, 'papers': 2}"), []);
});

test('references: URLs, routes inside longer paths and prose do not bind', () => {
  const refs = (path, text, root = []) => [...extractProseReferences(path, text, root)];
  assert.deepEqual(refs('lib/a.ts', "fetch('https://emiliaprotocol.ai/docs/api')"), []);
  assert.deepEqual(refs('lib/a.ts', "readFileSync('apps/x/docs/y.md')"), []);
  assert.deepEqual(refs('lib/a.ts', '// every standards effort in the landscape'), []);
  assert.deepEqual(refs('lib/a.ts', 'meta: { docs: { description: "x" } }'), []);
  assert.deepEqual(refs('cmd/main.go', 'Documents []string `json:"docs"`'), []);
  assert.deepEqual(refs('lib/a.ts', 'see docs/ for details'), []);
  assert.deepEqual(refs('x.sh', '# the docs lane skips this'), []);
  assert.deepEqual(refs('packages/x/package.json', '{"files": ["README.md"]}', ['README.md']), []);
  assert.deepEqual(refs('lib/a.ts', "readFileSync('packages/x/README.md')", ['README.md']), []);
});

test('binding follows ancestors so a directory operand binds everything under it', () => {
  const refs = new Set(['standards/staged', 'docs/protocol/pq.md']);
  assert.equal(bindingReference('standards/staged/NEXT-AEB-07/README.md', refs), 'standards/staged/');
  assert.equal(bindingReference('docs/protocol/pq.md', refs), 'docs/protocol/pq.md');
  assert.equal(bindingReference('docs/protocol/other.md', refs), null);
  assert.equal(bindingReference('standards/posted/x.txt', refs), null);
});

test('classify: prose no skipped job names is the docs lane', () => {
  const decision = classify(
    [modified('docs/EP-SYNC-INTEROP.md'), modified('standards/staged/NEXT-AEB-07/README.md')],
    audit([{ path: 'packages/gate/src/a.ts', text: "readFileSync('docs/protocol/pq.md')" }]),
  );
  assert.equal(decision.lane, DOCS_LANE);
});

test('classify: anything else is the full lane, with the reason', () => {
  const cases = [
    [[], 'no changed paths'],
    [[modified('docs/x.md'), modified('lib/x.ts')], 'lib/x.ts: not a prose path'],
    [[modified('package-lock.json')], 'package-lock.json: not a prose path'],
    [[modified('docs/x.md', '120000')], 'symlink or submodule'],
    [[modified('docs/x.md', '160000')], 'symlink or submodule'],
  ];
  for (const [changes, reason] of cases) {
    const decision = classify(changes, audit());
    assert.equal(decision.lane, FULL_LANE);
    assert.ok(decision.reasons.some((r) => r.includes(reason)), `${reason}: ${decision.reasons}`);
  }
  const named = classify(
    [modified('docs/protocol/pq.md')],
    audit([{ path: 'packages/verify/src/index.ts', text: "readFileSync('docs/protocol/pq.md')" }]),
  );
  assert.equal(named.lane, FULL_LANE);
  assert.match(named.reasons[0], /packages\/verify\/src\/index\.ts names docs\/protocol\/pq\.md/);
  const directory = classify(
    [modified('standards/staged/NEXT-X/README.md')],
    audit([{ path: 'conformance/run.mjs', text: 'const d = `standards/staged/${name}`;' }]),
  );
  assert.equal(directory.lane, FULL_LANE);
  const violation = classify([modified('docs/x.md')], audit([], ['checker reachable']));
  assert.deepEqual(violation, { lane: FULL_LANE, reasons: ['checker reachable'], changed: 1 });
});

test('ci.yml closure: skipped jobs, their npm scripts and entered packages', () => {
  const workflow = [
    'on: push',
    'jobs:',
    '  changes:',
    '    runs-on: ubuntu-latest',
    '  test:',
    '    steps:',
    '      - run: npm run check:standards-staged',
    '  security-case:',
    '    needs: [changes]',
    `    if: \${{ !cancelled() && ${SKIP_CONDITION} }}`,
    '    steps:',
    '      - run: npm run check:security-case',
    '      - working-directory: packages/gate',
    '        run: npm test',
    '',
  ].join('\n');
  assert.deepEqual([...jobBlocks(workflow).keys()], ['changes', 'test', 'security-case']);
  const files = {
    'package.json': JSON.stringify({
      scripts: {
        'check:security-case': 'npm run inner && node scripts/verify-security-case.mjs',
        inner: 'node scripts/inner.mjs',
        'check:standards-staged': 'node scripts/check-standards-staged.mjs',
      },
    }),
    'packages/gate/package.json': JSON.stringify({ scripts: { test: 'node --test gate.test.js' } }),
    'scripts/verify-security-case.mjs': "spawn('node', ['scripts/other.mjs'])",
  };
  const read = (path) => files[path] ?? null;
  const closure = skippedJobClosure(workflow, read);
  assert.deepEqual(closure.jobs, ['security-case']);
  assert.match(closure.text, /scripts\/verify-security-case\.mjs/);
  assert.match(closure.text, /scripts\/inner\.mjs/);
  assert.match(closure.text, /gate\.test\.js/);
  assert.doesNotMatch(closure.text, /check-standards-staged/);
  assert.doesNotMatch(closure.text, /'docs'/);

  const tracked = ['scripts/check-standards-staged.mjs', 'scripts/check-ae-challenge-08.mjs', 'scripts/verify-security-case.mjs'];
  assert.deepEqual(reachableKeptCheckers(tracked, closure.text, read), []);
  files['scripts/verify-security-case.mjs'] = "spawnSync('node', ['scripts/check-standards-staged.mjs'])";
  assert.deepEqual(reachableKeptCheckers(tracked, closure.text, read), ['scripts/check-standards-staged.mjs']);
  assert.deepEqual(
    reachableKeptCheckers(tracked, `${closure.text}\nnpm run check:ae-challenge-08 # check-ae-challenge-08`, read),
    ['scripts/check-standards-staged.mjs', 'scripts/check-ae-challenge-08.mjs'],
  );
});

test('raw diff parsing is strict', () => {
  const raw = ':100644 100644 aaaa bbbb M\0docs/a.md\0:000000 120000 0000 cccc A\0docs/link\0';
  assert.deepEqual(parseRawDiff(raw), [
    { oldMode: '100644', newMode: '100644', status: 'M', path: 'docs/a.md' },
    { oldMode: '000000', newMode: '120000', status: 'A', path: 'docs/link' },
  ]);
  assert.deepEqual(parseRawDiff(''), []);
  assert.throws(() => parseRawDiff('garbage\0docs/a.md\0'), /unparseable/);
});

test('end to end on a pull_request merge commit, failing closed on anything odd', () => {
  const repo = mkdtempSync(join(tmpdir(), 'change-lane-'));
  const git = (...args) => execFileSync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Lane Test',
      GIT_AUTHOR_EMAIL: 'lane@example.com',
      GIT_COMMITTER_NAME: 'Lane Test',
      GIT_COMMITTER_EMAIL: 'lane@example.com',
    },
  });
  const write = (path, text) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  };
  const output = join(repo, '..', `${repo.split('/').pop()}-output`);
  // run() appends to GITHUB_STEP_SUMMARY when it is set; in CI that would
  // put these fixture decisions in the job summary above the real one.
  const lane = (args, expectedOutput, summary) => {
    writeFileSync(output, '');
    const originalWrite = process.stdout.write;
    const originalSummary = process.env.GITHUB_STEP_SUMMARY;
    process.stdout.write = () => true;
    if (summary === undefined) delete process.env.GITHUB_STEP_SUMMARY;
    else process.env.GITHUB_STEP_SUMMARY = summary;
    try {
      const decision = run([...args, '--github-output', output], repo);
      assert.equal(readFileSync(output, 'utf8'), expectedOutput ?? `lane=${decision.lane}\n`);
      return decision;
    } finally {
      process.stdout.write = originalWrite;
      if (originalSummary === undefined) delete process.env.GITHUB_STEP_SUMMARY;
      else process.env.GITHUB_STEP_SUMMARY = originalSummary;
    }
  };
  const mergePullRequest = (branch, edit) => {
    git('checkout', '-q', '-b', branch, 'main');
    edit();
    git('add', '-A');
    git('commit', '-q', '-m', branch);
    git('checkout', '-q', '--detach', 'main');
    git('merge', '-q', '--no-ff', '-m', `merge ${branch}`, branch);
  };
  try {
    git('init', '-q', '-b', 'main');
    write('.github/workflows/ci.yml', [
      'jobs:',
      '  changes:',
      '    runs-on: ubuntu-latest',
      '  security-case:',
      '    needs: [changes]',
      `    if: \${{ !cancelled() && ${SKIP_CONDITION} }}`,
      '    steps:',
      '      - run: npm run check:security-case',
      '',
    ].join('\n'));
    write('package.json', JSON.stringify({ scripts: { 'check:security-case': 'node scripts/case.mjs' } }));
    write('scripts/case.mjs', "readFileSync('docs/bound.md');\n");
    write('docs/free.md', 'free\n');
    write('docs/bound.md', 'bound\n');
    write('lib/code.ts', 'export {};\n');
    git('add', '-A');
    git('commit', '-q', '-m', 'base');

    mergePullRequest('prose', () => write('docs/free.md', 'free, edited\n'));
    assert.equal(lane(['--event', 'pull_request']).lane, DOCS_LANE);
    // The lane is written last: a summary that cannot be written throws
    // before it, and the empty output reads as the full lane.
    assert.throws(() => lane(['--event', 'pull_request'], '', tmpdir()), /EISDIR|illegal operation/);
    assert.equal(readFileSync(output, 'utf8'), '');
    assert.equal(lane(['--event', 'local', '--base', 'main', '--head', 'prose']).lane, DOCS_LANE);
    assert.equal(lane(['--event', 'push']).lane, FULL_LANE);
    assert.equal(lane(['--event', 'merge_group']).lane, FULL_LANE);

    mergePullRequest('bound', () => write('docs/bound.md', 'bound, edited\n'));
    assert.equal(lane(['--event', 'pull_request']).lane, FULL_LANE);

    mergePullRequest('newline', () => write('docs/new\nline.md', 'free\n'));
    const newline = lane(['--event', 'pull_request']);
    assert.equal(newline.lane, FULL_LANE);
    assert.match(newline.reasons[0], /not a prose path/);

    mergePullRequest('code', () => write('lib/code.ts', 'export const x = 1;\n'));
    assert.equal(lane(['--event', 'pull_request']).lane, FULL_LANE);
    assert.equal(lane(['--event', 'local', '--base', 'main', '--head', 'code']).lane, FULL_LANE);

    git('checkout', '-q', '--detach', 'prose');
    const notMerge = lane(['--event', 'pull_request']);
    assert.equal(notMerge.lane, FULL_LANE);
    assert.match(notMerge.reasons[0], /classifier error, failing closed/);
    // Unparseable arguments cannot name the output file: the output stays
    // empty, which every gated job reads as the full lane.
    const malformed = lane(['--event'], '');
    assert.equal(malformed.lane, FULL_LANE);
    assert.match(malformed.reasons[0], /classifier error, failing closed/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
    rmSync(output, { force: true });
  }
});
