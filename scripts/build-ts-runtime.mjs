#!/usr/bin/env node
/** Build the small non-package TypeScript runtime boundaries used by the app. */
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const root = process.cwd();
const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const builds = [
  ['lib/strict-json.ts', 'lib', 'lib/dist'],
  ['packages/gate/action-control-manifest.ts', 'packages/gate', 'packages/gate/dist'],
];

for (const [entry, rootDir, outDir] of builds) {
  const result = spawnSync(process.execPath, [
    tsc, entry,
    '--target', 'es2022',
    '--module', 'nodenext',
    '--moduleResolution', 'nodenext',
    '--strict',
    '--skipLibCheck',
    '--allowJs', '--checkJs', 'false',
    '--declaration', '--declarationMap', '--sourceMap',
    '--outDir', outDir, '--rootDir', rootDir,
  ], { cwd: root, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
