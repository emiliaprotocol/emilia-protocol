// SPDX-License-Identifier: Apache-2.0
//
// Self-test for scripts/ci/evidence-autopilot.mjs: the bundle may carry only
// derived evidence, and a tampered or mis-addressed bundle is refused before
// anything is written.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { BUNDLE_VERSION, DERIVED_EVIDENCE, apply, collect, inspect } from './evidence-autopilot.mjs';

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

test('apply writes a verified bundle onto the exact source commit', () => {
  const f = fixture();
  try {
    f.write('security/security-case.json', '{"v":3}\n');
    f.git('commit', '-qam', 'checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });
    f.git('checkout', '-q', '--detach', f.source);
    assert.deepEqual(apply({ bundle, sourceSha: f.source, repo: f.repo }), ['security/security-case.json']);
    assert.equal(readFileSync(join(f.repo, 'security/security-case.json'), 'utf8'), '{"v":3}\n');
  } finally {
    f.cleanup();
  }
});

test('inspect and apply refuse tampered, foreign or mis-addressed bundles', () => {
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

    assert.throws(() => inspect({ bundle, sourceSha: head }), /generated from/);
    withManifest((m) => { m.files[0].path = 'lib/code.ts'; });
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /not a derived-evidence path/);
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
    writeFileSync(join(bundle, 'files/lib/proof-stats.json'), '{"v":2}\n');
    rmSync(join(bundle, 'files/lib/proof-stats.json'));
    symlinkSync(join(f.repo, 'lib/proof-stats.json'), join(bundle, 'files/lib/proof-stats.json'));
    assert.throws(() => inspect({ bundle, sourceSha: f.source }), /not a regular file/);
    rmSync(join(bundle, 'files/lib/proof-stats.json'));
    writeFileSync(join(bundle, 'files/lib/proof-stats.json'), '{"v":2}\n');

    // The bundle is sound but the checkout is not at its source commit.
    assert.throws(() => apply({ bundle, sourceSha: f.source, repo: f.repo }), /checkout is at/);
    f.git('checkout', '-q', '--detach', f.source);
    rmSync(join(f.repo, 'lib'), { recursive: true });
    symlinkSync(join(f.root), join(f.repo, 'lib'));
    assert.throws(() => apply({ bundle, sourceSha: f.source, repo: f.repo }), /not a plain directory|not clean/);
  } finally {
    f.cleanup();
  }
});

test('apply never writes through a committed symlinked directory', () => {
  const f = fixture();
  try {
    f.write('public/.well-known/emilia-context.json', '{"v":2}\n');
    f.git('commit', '-qam', 'checkpoint');
    const bundle = join(f.root, 'bundle');
    collect({ repo: f.repo, sourceSha: f.source, out: bundle });

    f.git('checkout', '-q', '--detach', f.source);
    rmSync(join(f.repo, 'public/.well-known'), { recursive: true });
    symlinkSync('../lib', join(f.repo, 'public/.well-known'));
    f.git('add', '-A');
    f.git('commit', '-q', '-m', 'symlinked evidence directory');
    const symlinked = f.git('rev-parse', 'HEAD');
    const manifest = JSON.parse(readFileSync(join(bundle, 'manifest.json'), 'utf8'));
    manifest.source_sha = symlinked;
    writeFileSync(join(bundle, 'manifest.json'), JSON.stringify(manifest));

    assert.throws(() => apply({ bundle, sourceSha: symlinked, repo: f.repo }), /an ancestor is not a plain directory/);
    assert.throws(() => readFileSync(join(f.repo, 'lib/emilia-context.json')), /ENOENT/);
  } finally {
    f.cleanup();
  }
});
