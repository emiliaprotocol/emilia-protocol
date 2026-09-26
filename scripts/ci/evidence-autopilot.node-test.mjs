// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/evidence-autopilot.mjs: the bundle may carry only
// derived evidence, a tampered or mis-addressed bundle is refused before a
// request is built, and the request is a compare-and-swap commit onto the
// exact source commit.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import {
  BUNDLE_VERSION,
  COMMIT_TRAILER,
  DEPENDABOT_SKIP,
  DERIVED_EVIDENCE,
  collect,
  commitRequest,
  inspect,
} from './evidence-autopilot.mjs';

const REPOSITORY = 'emiliaprotocol/emilia-protocol';
const RUN_URL = `https://github.com/${REPOSITORY}/actions/runs/123456789`;

function fixture() {
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
  write('lib/code.ts', 'export {};\n');
  git('add', '-A');
  git('commit', '-q', '-m', 'source');
  const source = git('rev-parse', 'HEAD');
  return { root, repo, git, write, source, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

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
