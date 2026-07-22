import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const MANIFEST_PATH = resolve(PACKAGE_ROOT, 'security/results/artifact-manifest.txt');
const TOP_LEVEL_FILES = [
  '.env.example',
  '.gitignore',
  '.solhint.json',
  'README.md',
  'SECURITY_REVIEW.md',
  'hardhat.config.cjs',
  'package-lock.json',
  'package.json',
  'tsconfig.json',
];
const SOURCE_DIRECTORIES = ['contracts', 'formal', 'lib', 'scripts', 'test'];

function portablePath(path) {
  return relative(PACKAGE_ROOT, path).split(sep).join('/');
}

function collectDirectory(path, collected) {
  for (const entry of readdirSync(path, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const entryPath = resolve(path, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`refusing symlink in artifact input: ${portablePath(entryPath)}`);
    if (entry.isDirectory()) {
      collectDirectory(entryPath, collected);
    } else if (entry.isFile()) {
      collected.push(entryPath);
    } else {
      throw new Error(`refusing non-regular artifact input: ${portablePath(entryPath)}`);
    }
  }
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function renderManifest() {
  const files = TOP_LEVEL_FILES.map((path) => resolve(PACKAGE_ROOT, path));
  for (const directory of SOURCE_DIRECTORIES) collectDirectory(resolve(PACKAGE_ROOT, directory), files);
  const sorted = files.sort((left, right) => portablePath(left).localeCompare(portablePath(right)));
  for (const path of sorted) {
    if (!lstatSync(path).isFile()) throw new Error(`artifact input is not a regular file: ${portablePath(path)}`);
  }

  return `DTC Base experimental source artifact manifest
Format: SHA-256 digest followed by repository-package-relative path
Files: ${sorted.length}
Generated deterministically by npm run artifacts:refresh; timestamps are intentionally omitted.

${sorted.map((path) => `${sha256(path)}  ${portablePath(path)}`).join('\n')}

Claim boundary: this manifest records source integrity only. It is not an
independent audit, a deployment record, or a production-safety claim.
`;
}

const arguments_ = process.argv.slice(2);
const write = arguments_.length === 1 && arguments_[0] === '--write';
if ((!write && arguments_.length > 0) || (write && arguments_.length !== 1)) {
  throw new Error('usage: node scripts/verify-artifact-manifest.mjs [--write]');
}

const expected = renderManifest();
if (write) {
  mkdirSync(dirname(MANIFEST_PATH), { recursive: true });
  writeFileSync(MANIFEST_PATH, expected, 'utf8');
  process.stdout.write(`refreshed ${MANIFEST_PATH}\n`);
} else {
  let actual;
  try {
    actual = readFileSync(MANIFEST_PATH, 'utf8');
  } catch {
    console.error(`missing checked-in artifact manifest: ${MANIFEST_PATH}`);
    process.exit(1);
  }
  if (actual !== expected) {
    console.error('artifact manifest drift detected; run npm run evidence:refresh and review the diff');
    process.exit(1);
  }
  process.stdout.write(`verified ${MANIFEST_PATH}\n`);
}
