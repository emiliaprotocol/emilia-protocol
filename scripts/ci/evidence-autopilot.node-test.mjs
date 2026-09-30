// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/evidence-autopilot.mjs: the bundle may carry only
// derived evidence, a tampered or mis-addressed bundle is refused before a
// request is built, and the request is a compare-and-swap commit onto the
// exact source commit. The clean-room bundles, reviewed files with one
// derived field, accept exactly sync:clean-room-pins' output and nothing
// else, in the publisher (inspect) and in dco.yml's rule (verify-commit).

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  BUNDLE_VERSION,
  COMMIT_TRAILER,
  DEPENDABOT_SKIP,
  DERIVED_EVIDENCE,
  DERIVED_FIELDS,
  SOURCE_FILES,
  collect,
  commitRequest,
  inspect,
  main,
  verifyCommit,
} from './evidence-autopilot.mjs';
import { planCurrentCleanRoomPinRefresh } from '../sync-current-clean-room-pins.mjs';

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const RUN_URL = `https://github.com/${REPOSITORY}/actions/runs/123456789`;
const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const MANIFEST = 'conformance/conformance-manifest.json';
const BUNDLES = Object.keys(DERIVED_FIELDS);
// Hand-authored files that carried a copy of the manifest pin until the
// bundles' source_manifest became the only one. The bot may not touch them.
const HAND_AUTHORED = [
  'papers/preprint/main.tex',
  'docs/conformance/CLEAN-ROOM-V2.md',
  'scripts/verify-clean-room-submission-v2.mts',
  'scripts/verify-clean-room-submission-v2.mjs',
];
const REFUSED = /is not its source-commit version with only its derived fields recomputed/;

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/**
 * A git repository with every derived-evidence path. With `real`, the
 * manifest, the clean-room bundles and the formerly pinned hand-authored
 * files are this repository's own.
 */
function fixture({ real = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'evidence-autopilot-'));
  const repo = join(root, 'repo');
  mkdirSync(repo);
  const git = (...args) => execFileSync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Autopilot Test',
      GIT_AUTHOR_EMAIL: 'autopilot@example.com',
      GIT_COMMITTER_NAME: 'Autopilot Test',
      GIT_COMMITTER_EMAIL: 'autopilot@example.com',
    },
  }).trim();
  const write = (path, text) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  };
  git('init', '-q', '-b', 'main');
  for (const path of DERIVED_EVIDENCE) write(path, path.endsWith('.json') ? '{"v":1}\n' : 'v1\n');
  if (real) for (const path of [...SOURCE_FILES, ...HAND_AUTHORED]) write(path, readFileSync(join(ROOT, path)));
  write('lib/code.ts', 'export {};\n');
  git('add', '-A');
  git('commit', '-q', '-m', 'source');
  const source = git('rev-parse', 'HEAD');
  const read = (path) => readFileSync(join(repo, path));
  const at = (commit) => (path) => execFileSync('git', ['cat-file', 'blob', `${commit}:${path}`], { cwd: repo });
  return { root, repo, git, write, read, at, source, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

/** A packages/verify change: the implementation digests and the claim move, the corpus does not. */
function moveManifest(f, claim = 'e'.repeat(64)) {
  const manifest = JSON.parse(f.read(MANIFEST).toString('utf8'));
  manifest.implementations[0].source.tree_sha256 = 'd'.repeat(64);
  manifest.manifest_sha256 = claim;
  f.write(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
}

/** Runs the official writer, sync:clean-room-pins, on the fixture. */
function repin(f) {
  for (const [path, content] of planCurrentCleanRoomPinRefresh(f.repo)) f.write(path, content);
}

/** Replaces one bundled file and keeps the bundle's own manifest consistent. */
function forge(bundle, path, bytes) {
  const manifestPath = join(bundle, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const entry = manifest.files.find((file) => file.path === path);
  writeFileSync(join(bundle, 'files', path), bytes);
  entry.sha256 = sha256(bytes);
  entry.bytes = bytes.length;
  writeFileSync(manifestPath, JSON.stringify(manifest));
}

/** Every leaf of a JSON value, as a key path. */
function leaves(value, at = []) {
  if (value === null || typeof value !== 'object') return [at];
  return Object.entries(value).flatMap(([key, child]) => leaves(child, [...at, key]));
}

/** The value with the leaf at `path` changed, keeping its type (and a digest a digest). */
function withLeafChanged(value, path) {
  const copy = structuredClone(value);
  const parent = path.slice(0, -1).reduce((node, key) => node[key], copy);
  const leaf = parent[path.at(-1)];
  parent[path.at(-1)] = typeof leaf === 'string'
    ? (/^[0-9a-f]{64}$/.test(leaf) ? `${leaf.slice(0, -1)}${leaf.endsWith('0') ? '1' : '0'}` : `${leaf}x`)
    : typeof leaf === 'number' ? leaf + 1 : typeof leaf === 'boolean' ? !leaf : 'x';
  return copy;
}

const serialize = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

test('collect bundles only changed derived evidence', () => {
  const f = fixture();
  try {
    f.write('lib/proof-stats.json', '{"v":2}\n');
    f.write('public/.well-known/emilia-context.json', '{"v":2}\n');
    f.git('commit', '-qam', 'local writer checkpoint');
    const out = join(f.root, 'bundle');
    const manifest = collect({ repo: f.repo, sourceSha: f.source, out });
    assert.equal(manifest['@version'], BUNDLE_VERSION);
    assert.deepEqual(manifest.files.map((file) => file.path), ['lib/proof-stats.json', 'public/.well-known/emilia-context.json']);
    assert.equal(readFileSync(join(out, 'files/lib/proof-stats.json'), 'utf8'), '{"v":2}\n');

    const empty = collect({ repo: f.repo, sourceSha: f.git('rev-parse', 'HEAD'), out: join(f.root, 'empty') });
    assert.deepEqual(empty.files, []);
  } finally {
    f.cleanup();
  }
});

test('collect refuses code changes, dirty trees and invalid evidence', () => {
  const f = fixture();
  try {
    f.write('lib/code.ts', 'export const x = 1;\n');
    f.git('commit', '-qam', 'writer touched code');
    assert.throws(() => collect({ repo: f.repo, sourceSha: f.source, out: join(f.root, 'a') }), /outside the derived-evidence allowlist:\nlib\/code\.ts/);

    const g = fixture();
    try {
      g.write('lib/proof-stats.json', '{"v":2}\n');
      assert.throws(() => collect({ repo: g.repo, sourceSha: g.source, out: join(g.root, 'b') }), /uncommitted tracked changes/);
      g.write('lib/proof-stats.json', '{broken');
      g.git('commit', '-qam', 'broken json');
      assert.throws(() => collect({ repo: g.repo, sourceSha: g.source, out: join(g.root, 'c') }), /JSON/);
    } finally {
      g.cleanup();
    }
    assert.throws(() => collect({ repo: f.repo, sourceSha: 'HEAD', out: join(f.root, 'd') }), /40-character/);
  } finally {
    f.cleanup();
  }
});

test('request is a compare-and-swap createCommitOnBranch onto the exact source commit', () => {
  const f = fixture();
  try {
    f.write('security/security-case.json', '{"v":3}\n');
    f.write('AI_CONTEXT.md', 'v3\n');
    f.git('commit', '-qam', 'checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    const request = commitRequest({ bundle, sourceSha: f.source, repository: REPOSITORY, branch: 'dependabot/npm_and_yarn/x-1.2.3', runUrl: RUN_URL });
    assert.match(request.query, /createCommitOnBranch\(input: \$input\)/);
    const { input } = request.variables;
    assert.deepEqual(input.branch, { repositoryNameWithOwner: REPOSITORY, branchName: 'dependabot/npm_and_yarn/x-1.2.3' });
    assert.equal(input.expectedHeadOid, f.source);
    assert.deepEqual(Object.keys(input.fileChanges), ['additions']);
    assert.deepEqual(
      input.fileChanges.additions.map((file) => [file.path, Buffer.from(file.contents, 'base64').toString('utf8')]),
      [['security/security-case.json', '{"v":3}\n'], ['AI_CONTEXT.md', 'v3\n']],
    );
    assert.equal(input.message.headline, `chore(evidence): regenerate derived evidence for ${f.source.slice(0, 12)}`);
    const lines = input.message.body.split('\n');
    assert.ok(lines.includes(DEPENDABOT_SKIP));
    assert.ok(lines.includes(COMMIT_TRAILER));
    assert.ok(lines.includes(`Evidence-Autopilot-Run: ${RUN_URL}`));
    assert.match(input.message.body, /shape and transit integrity/);
    // Trailers close the message, after the Dependabot marker.
    assert.ok(lines.indexOf(COMMIT_TRAILER) > lines.indexOf(DEPENDABOT_SKIP));
  } finally {
    f.cleanup();
  }
});

test('request refuses unsafe targets and an empty bundle', () => {
  const f = fixture();
  try {
    f.write('lib/proof-stats.json', '{"v":2}\n');
    f.git('commit', '-qam', 'checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    const request = (overrides) => commitRequest({ bundle, sourceSha: f.source, repository: REPOSITORY, branch: 'feature/x', runUrl: RUN_URL, ...overrides });
    assert.equal(request({}).variables.input.expectedHeadOid, f.source);
    for (const branch of ['main', '-x', 'a..b', 'a b', 'a/', '/a', 'a//b', 'x.lock', '', 'a\nb']) {
      assert.throws(() => request({ branch }), /refusing branch/, JSON.stringify(branch));
    }
    for (const repository of ['', 'x', 'a/b/c', 'a b/c', '-a/b']) {
      assert.throws(() => request({ repository }), /refusing repository/, repository);
    }
    for (const runUrl of ['', 'https://evil.example/actions/runs/1', `https://github.com/other/repo/actions/runs/1`, `${RUN_URL}x`, `${RUN_URL}/attempts/`]) {
      assert.throws(() => request({ runUrl }), /refusing run URL/, runUrl);
    }
    assert.doesNotThrow(() => request({ runUrl: `${RUN_URL}/attempts/2` }));
    assert.throws(() => request({ sourceSha: f.git('rev-parse', 'HEAD') }), /generated from/);

    const empty = join(f.root, 'empty');
    collect({ repo: f.repo, sourceSha: f.git('rev-parse', 'HEAD'), out: empty });
    assert.throws(
      () => commitRequest({ bundle: empty, sourceSha: f.git('rev-parse', 'HEAD'), repository: REPOSITORY, branch: 'feature/x', runUrl: RUN_URL }),
      /nothing to publish/,
    );
  } finally {
    f.cleanup();
  }
});

test('inspect and request refuse tampered, foreign or mis-addressed bundles', () => {
  const f = fixture();
  try {
    f.write('lib/proof-stats.json', '{"v":2}\n');
    f.git('commit', '-qam', 'checkpoint');
    const head = f.git('rev-parse', 'HEAD');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    const manifestPath = join(bundle, 'manifest.json');
    const pristine = readFileSync(manifestPath, 'utf8');
    const withManifest = (mutate) => {
      const manifest = JSON.parse(pristine);
      mutate(manifest);
      writeFileSync(manifestPath, JSON.stringify(manifest));
    };
    const request = () => commitRequest({ bundle, sourceSha: f.source, repository: REPOSITORY, branch: 'feature/x', runUrl: RUN_URL });

    assert.throws(() => inspect({ bundle, sourceSha: head }), /generated from/);
    withManifest((m) => { m.files[0].path = 'lib/code.ts'; });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /not a derived-evidence path/);
    assert.throws(request, /not a derived-evidence path/);
    withManifest((m) => { m.files[0].path = '../outside.json'; });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /not a derived-evidence path/);
    withManifest((m) => { m.files.push({ ...m.files[0] }); });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /listed twice/);
    withManifest((m) => { m.extra = true; });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /unexpected manifest fields/);
    withManifest((m) => { m['@version'] = 'other'; });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /unsupported bundle version/);
    writeFileSync(manifestPath, pristine);

    writeFileSync(join(bundle, 'files/lib/proof-stats.json'), '{"v":9}\n');
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /sha256 differs/);
    assert.throws(request, /sha256 differs/);
    writeFileSync(join(bundle, 'files/lib/proof-stats.json'), '{"v":2}\n');
    rmSync(join(bundle, 'files/lib/proof-stats.json'));
    symlinkSync(join(f.repo, 'lib/proof-stats.json'), join(bundle, 'files/lib/proof-stats.json'));
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /not a regular file/);
    rmSync(join(bundle, 'files/lib/proof-stats.json'));
    writeFileSync(join(bundle, 'files/lib/proof-stats.json'), '{"v":2}\n');
    assert.equal(request().variables.input.expectedHeadOid, f.source);
  } finally {
    f.cleanup();
  }
});

test('the official pin writer\'s output is exactly what collect, inspect and verify-commit accept', () => {
  const f = fixture({ real: true });
  try {
    moveManifest(f);
    repin(f);
    f.git('commit', '-qam', 'writer checkpoint');
    const bundle = join(f.root, 'bundle');
    const manifest = collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    assert.deepEqual(manifest.files.map((file) => file.path), [MANIFEST, ...BUNDLES]);

    const { contents } = inspect({ bundle, sourceSha: f.source, source: f.at(f.source) });
    for (const path of BUNDLES) {
      assert.deepEqual(JSON.parse(contents.get(path).toString('utf8')).source_manifest, {
        path: MANIFEST,
        sha256: sha256(contents.get(MANIFEST)),
        manifest_sha256: 'e'.repeat(64),
      });
    }
    const request = commitRequest({
      bundle, sourceSha: f.source, repository: REPOSITORY, branch: 'dependabot/npm_and_yarn/x-1.2.3', runUrl: RUN_URL,
      source: f.at(f.source),
    });
    assert.deepEqual(request.variables.input.fileChanges.additions.map((file) => file.path), [MANIFEST, ...BUNDLES]);
    assert.deepEqual(verifyCommit({ repo: f.repo, commit: f.git('rev-parse', 'HEAD') }).sort(), [MANIFEST, ...BUNDLES].sort());
  } finally {
    f.cleanup();
  }
});

test('a re-pin against a manifest already on the source commit reads that manifest from the source', () => {
  const f = fixture({ real: true });
  try {
    moveManifest(f);
    f.git('commit', '-qam', 'packages/verify change whose author did not re-pin');
    const source = f.git('rev-parse', 'HEAD');
    repin(f);
    f.git('commit', '-qam', 'writer checkpoint');
    const bundle = join(f.root, 'bundle');
    assert.deepEqual(collect({ repo: f.repo, sourceSha: source, out: bundle }).files.map((file) => file.path), BUNDLES);
    assert.doesNotThrow(() => inspect({ bundle, sourceSha: source, source: f.at(source) }));
    // Pinned to any other manifest (here the one before the source commit), refused.
    assert.throws(() => inspect({
      bundle,
      sourceSha: source,
      source: (path) => (path === MANIFEST ? f.at(f.source)(path) : f.at(source)(path)),
    }), REFUSED);
  } finally {
    f.cleanup();
  }
});

test('inspect accepts no clean-room bundle but the writer\'s: every field, digest and line is fixed', () => {
  const f = fixture({ real: true });
  try {
    moveManifest(f);
    repin(f);
    f.git('commit', '-qam', 'writer checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    const copies = new Map(SOURCE_FILES.map((path) => [path, f.at(f.source)(path)]));
    const check = () => inspect({ bundle, sourceSha: f.source, source: (path) => copies.get(path) });
    for (const path of BUNDLES) {
      const legit = f.read(path);
      const value = JSON.parse(legit.toString('utf8'));
      const forgeries = [];
      // Every single leaf, source_manifest's own digests and path included.
      for (const leaf of leaves(value)) forgeries.push([`leaf ${leaf.join('.')}`, serialize(withLeafChanged(value, leaf))]);
      // Every line, by whitespace alone.
      const lines = legit.toString('utf8').split('\n');
      for (let index = 0; index < lines.length - 1; index += 1) {
        const edited = [...lines];
        edited[index] = `${edited[index]} `;
        forgeries.push([`line ${index + 1}`, Buffer.from(edited.join('\n'))]);
      }
      const { source_manifest: pin, ...rest } = value;
      forgeries.push(
        ['a stale pin (the source commit\'s bundle)', f.at(f.source)(path)],
        ['the two digests swapped', serialize({ ...value, source_manifest: { ...pin, sha256: pin.manifest_sha256, manifest_sha256: pin.sha256 } })],
        ['an added field', serialize({ ...value, note: 'derived' })],
        ['source_manifest moved to the end', serialize({ ...rest, source_manifest: pin })],
        ['four-space indentation', Buffer.from(`${JSON.stringify(value, null, 4)}\n`)],
        ['no final newline', Buffer.from(JSON.stringify(value, null, 2))],
        ['CRLF line ends', Buffer.from(legit.toString('utf8').replaceAll('\n', '\r\n'))],
      );
      assert.ok(forgeries.length > 100, `${path}: ${forgeries.length} forgeries`);
      for (const [label, bytes] of forgeries) {
        forge(bundle, path, bytes);
        assert.throws(check, REFUSED, `${path}: ${label}`);
      }
      forge(bundle, path, legit);
      assert.doesNotThrow(check);
    }
  } finally {
    f.cleanup();
  }
});

test('inspect needs the source commit\'s copies, and reads only the files it names', () => {
  const f = fixture({ real: true });
  try {
    moveManifest(f);
    repin(f);
    f.git('commit', '-qam', 'writer checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /needs the source commit's files \(--source-files\)/);
    assert.throws(
      () => commitRequest({ bundle, sourceSha: f.source, repository: REPOSITORY, branch: 'feature/x', runUrl: RUN_URL }),
      /needs the source commit's files/,
    );

    const copies = join(f.root, 'source');
    for (const path of SOURCE_FILES) {
      mkdirSync(dirname(join(copies, path)), { recursive: true });
      writeFileSync(join(copies, path), f.at(f.source)(path));
    }
    const log = console.log;
    const printed = [];
    console.log = (line) => printed.push(line);
    try {
      assert.equal(main(['source-files']), 0);
      assert.equal(main(['inspect', '--bundle', bundle, '--source-sha', f.source, '--source-files', copies]), 0);
    } finally {
      console.log = log;
    }
    assert.equal(printed[0], SOURCE_FILES.join('\n'));
    // A source copy that is not a regular file is refused, not followed.
    rmSync(join(copies, BUNDLES[0]));
    symlinkSync(join(f.repo, BUNDLES[0]), join(copies, BUNDLES[0]));
    assert.throws(() => main(['inspect', '--bundle', bundle, '--source-sha', f.source, '--source-files', copies]), /not a regular file/);
  } finally {
    f.cleanup();
  }
});

test('collect refuses a writer that edits a clean-room bundle beyond its pin', () => {
  const f = fixture({ real: true });
  try {
    moveManifest(f);
    repin(f);
    const value = JSON.parse(f.read(BUNDLES[0]).toString('utf8'));
    f.write(BUNDLES[0], serialize({ ...value, claim_scope: `${value.claim_scope} Independently verified.` }));
    f.git('commit', '-qam', 'writer checkpoint');
    assert.throws(() => collect({ repo: f.repo, sourceSha: f.source, out: join(f.root, 'bundle') }), REFUSED);
  } finally {
    f.cleanup();
  }
});

test('verify-commit, dco.yml\'s rule, refuses everything but single-parent derived evidence', () => {
  const f = fixture({ real: true });
  try {
    const commitWith = (message, change) => {
      f.git('checkout', '-q', '--detach', f.source);
      change();
      f.git('add', '-A');
      f.git('commit', '-q', '--allow-empty', '-m', message);
      return f.git('rev-parse', 'HEAD');
    };
    const repinned = commitWith('re-pin', () => { moveManifest(f); repin(f); });
    assert.deepEqual(verifyCommit({ repo: f.repo, commit: repinned }).sort(), [MANIFEST, ...BUNDLES].sort());

    // The formerly pinned hand-authored files are not derived evidence, so
    // not even a digest-only edit to them is exempt.
    for (const path of HAND_AUTHORED) {
      const edited = commitWith(`edit ${path}`, () => {
        moveManifest(f);
        repin(f);
        f.write(path, f.read(path).toString('utf8').replace(/[0-9a-f]{64}/, 'f'.repeat(64)));
      });
      assert.throws(() => verifyCommit({ repo: f.repo, commit: edited }), new RegExp(`changes ${path.replaceAll('.', '\\.')}, which is not derived evidence`));
    }

    const value = JSON.parse(f.at(repinned)(BUNDLES[1]).toString('utf8'));
    for (const [label, bytes] of [
      ['claim scope', serialize({ ...value, claim_scope: 'independent implementation evidence' })],
      ['suite digest', serialize(withLeafChanged(value, ['suites', '0', 'sha256']))],
      ['arbitrary pin', serialize({ ...value, source_manifest: { ...value.source_manifest, sha256: 'f'.repeat(64) } })],
      ['whitespace', Buffer.from(`${JSON.stringify(value, null, 2)} \n`)],
    ]) {
      const forged = commitWith(label, () => { moveManifest(f); repin(f); f.write(BUNDLES[1], bytes); });
      assert.throws(() => verifyCommit({ repo: f.repo, commit: forged }), REFUSED, label);
    }

    const deleted = commitWith('delete', () => rmSync(join(f.repo, 'public/llms.txt')));
    assert.throws(() => verifyCommit({ repo: f.repo, commit: deleted }), /deletes public\/llms\.txt/);
    const executable = commitWith('chmod', () => chmodSync(join(f.repo, 'public/llms.txt'), 0o755));
    assert.throws(() => verifyCommit({ repo: f.repo, commit: executable }), /changes the type or mode of public\/llms\.txt/);
    const outside = commitWith('code', () => f.write('lib/code.ts', 'export const x = 1;\n'));
    assert.throws(() => verifyCommit({ repo: f.repo, commit: outside }), /changes lib\/code\.ts, which is not derived evidence/);

    f.git('checkout', '-q', '--detach', repinned);
    f.git('merge', '-q', '--no-ff', '--no-edit', outside);
    assert.throws(() => verifyCommit({ repo: f.repo, commit: f.git('rev-parse', 'HEAD') }), /has 2 parents/);
    assert.throws(() => verifyCommit({ repo: f.repo, commit: 'HEAD' }), /40-character/);

    // dco.yml runs a copy of the base branch's file from $RUNNER_TEMP in the checkout.
    const copy = join(f.root, 'evidence-autopilot-rule.mjs');
    copyFileSync(fileURLToPath(new URL('./evidence-autopilot.mjs', import.meta.url)), copy);
    const run = (commit) => execFileSync(process.execPath, [copy, 'verify-commit', '--commit', commit], { cwd: f.repo, encoding: 'utf8', stdio: 'pipe' });
    assert.match(run(repinned), /changes only derived evidence/);
    assert.throws(() => run(outside), /not derived evidence/);
  } finally {
    f.cleanup();
  }
});

test('the workflows run the pin writer, hold bundles to GitHub\'s source copies and keep one rule', () => {
  const workflow = (name) => readFileSync(join(ROOT, '.github/workflows', name), 'utf8');
  const autopilot = workflow('evidence-autopilot.yml');
  const staged = /git add -- \\\n([\s\S]*?)\n\s*git commit/.exec(autopilot)?.[1]
    .split('\\').map((path) => path.trim()).filter(Boolean);
  assert.deepEqual(staged?.sort(), [...DERIVED_EVIDENCE].sort());
  const order = ['npm run conformance:manifest\n', 'npm run sync:clean-room-pins', "checkpoint 'formal traces"]
    .map((step) => autopilot.indexOf(step));
  assert.ok(order.every((index, i) => index > 0 && (i === 0 || index > order[i - 1])), 'sync:clean-room-pins runs after the manifest writer');
  assert.match(autopilot, /npm run check:clean-room-pins/);
  // A labeled event the gate skips must not share the pull request's
  // cancel-in-progress group, or Dependabot's own labels cancel the opened
  // run. The no-op condition is the exact complement of the gate's.
  assert.ok(autopilot.includes("(github.event.action != 'labeled' || github.event.label.name == 'evidence-autopilot')"));
  const group = /\nconcurrency:\n\s+group: (.*)\n\s+cancel-in-progress: true\n/.exec(autopilot)?.[1];
  assert.equal(group, "evidence-autopilot-${{ github.event.pull_request.number }}${{ (github.event.action == 'labeled' && github.event.label.name != 'evidence-autopilot') && format('-noop-{0}', github.run_id) || '' }}");

  const publish = workflow('evidence-autopilot-publish.yml');
  assert.equal(publish.match(/evidence-autopilot\.mjs source-files\)/g)?.length, 2);
  assert.equal(publish.match(/--source-files source\n/g)?.length, 2);
  assert.match(publish, /contents\/\$path\?ref=\$SOURCE_SHA/);

  const dco = workflow('dco.yml');
  assert.match(dco, /git show "\$BASE_SHA:scripts\/ci\/evidence-autopilot\.mjs" > "\$autopilot_rule"/);
  assert.match(dco, /node "\$autopilot_rule" verify-commit --commit "\$commit_sha"/);
  // Exempt on the verdict line main() prints, never on an exit status alone.
  assert.ok(dco.includes('== "EVIDENCE AUTOPILOT: $commit_sha changes only derived evidence:" ]]'));
  // No second path list in the workflow that could drift from DERIVED_EVIDENCE.
  for (const path of DERIVED_EVIDENCE) assert.ok(!dco.includes(path), `dco.yml names ${path}`);
});

test('no hand-authored file pins the current conformance manifest', () => {
  const bytes = readFileSync(join(ROOT, MANIFEST));
  const digests = [sha256(bytes), JSON.parse(bytes.toString('utf8')).manifest_sha256];
  const pinned = execFileSync('git', ['grep', '-l', '-F', ...digests.flatMap((digest) => ['-e', digest])], { cwd: ROOT, encoding: 'utf8' })
    .split('\n').filter(Boolean);
  assert.ok(pinned.includes(MANIFEST) && BUNDLES.every((path) => pinned.includes(path)));
  assert.deepEqual(pinned.filter((path) => !DERIVED_EVIDENCE.includes(path)), []);
});
