#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'release/release-packages.v1.json';
const WORKFLOW_DIR = '.github/workflows';
const REPOSITORY_URL = 'https://github.com/emiliaprotocol/emilia-protocol.git';
const SKIP_DIRS = new Set(['.git', '.next', '.venv', 'node_modules', 'release-artifacts']);

function walkFiles(root, directory = root, files = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) continue;
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || relative.startsWith('conformance/clean-room/frozen-v1/')) continue;
      walkFiles(root, absolute, files);
    } else if (entry.isFile() && (entry.name === 'package.json' || entry.name === 'pyproject.toml')) {
      files.push(absolute);
    }
  }
  return files;
}

function pythonProjectName(text, source) {
  const marker = text.search(/^\[project\]\s*$/m);
  if (marker < 0) throw new Error(`${source} has no [project] table`);
  const remainder = text.slice(marker).replace(/^\[project\]\s*\n?/m, '');
  const nextTable = remainder.search(/^\[/m);
  const section = nextTable >= 0 ? remainder.slice(0, nextTable) : remainder;
  const name = section.match(/^name\s*=\s*["']([^"']+)["']\s*$/m)?.[1];
  if (!name) throw new Error(`${source} has no parseable [project].name`);
  return name;
}

export function discoverReleaseSurfaces(root = ROOT) {
  const surfaces = [];
  for (const absolute of walkFiles(root)) {
    const relativeFile = path.relative(root, absolute).split(path.sep).join('/');
    const packagePath = path.posix.dirname(relativeFile) === '.' ? '.' : path.posix.dirname(relativeFile);
    if (absolute.endsWith('package.json')) {
      const metadata = JSON.parse(fs.readFileSync(absolute, 'utf8'));
      if (metadata.private === true || typeof metadata.name !== 'string') continue;
      surfaces.push({ ecosystem: 'npm', package: metadata.name, path: packagePath });
    } else {
      const text = fs.readFileSync(absolute, 'utf8');
      surfaces.push({ ecosystem: 'pypi', package: pythonProjectName(text, relativeFile), path: packagePath });
    }
  }
  return surfaces.sort((a, b) => `${a.ecosystem}:${a.package}`.localeCompare(`${b.ecosystem}:${b.package}`));
}

function requireText(text, needles, label) {
  const missing = needles.filter((needle) => !text.includes(needle));
  if (missing.length) throw new Error(`${label} is missing release controls: ${missing.join(', ')}`);
}

function forbidCredentialInjection(text, label) {
  if (/^\s*(?:NPM_TOKEN|NODE_AUTH_TOKEN|TWINE_PASSWORD|PYPI_API_TOKEN)\s*:/m.test(text)
    || /^\s*password\s*:/m.test(text)) {
    throw new Error(`${label} injects a long-lived publication credential`);
  }
}

function validateManualPublisher(text, label, { direct }) {
  if (/^[ \t]{2}push:/m.test(text)) throw new Error(`${label} publishes from an automatic push trigger`);
  requireText(text, [
    'workflow_dispatch:',
    'release_tag:',
    'confirmation:',
    'environment: registry-publishing-approval',
    'needs: approval',
  ], label);
  if (direct) {
    requireText(text, [
      'ref: ${{ inputs.release_tag }}',
      'fetch-depth: 0',
      'persist-credentials: false',
      'scripts/require-release-approval.mjs',
      '--allowed-actor FutureEnterprises',
      'concurrency:',
      'cancel-in-progress: false',
    ], label);
  }
}

export function validateReusableNpmWorkflowText(text) {
  requireText(text, [
    'npm run security-case:emit',
    'npm run conformance:manifest',
    'verify-reproducible-package.mjs',
    'run: npm test',
    'actions/attest@',
    'subject-path: ${{ steps.pack.outputs.tarball }}',
    'npm publish "${{ steps.pack.outputs.tarball }}" --access public --provenance',
    'cmp "$TESTED_TARBALL" "registry-copy/$REGISTRY_TARBALL"',
    'ref: ${{ inputs.release_tag }}',
    'persist-credentials: false',
    'scripts/require-release-approval.mjs',
    '--allowed-actor FutureEnterprises',
    'group: registry-publish-${{ inputs.package_name }}',
  ], 'reusable npm workflow');
  forbidCredentialInjection(text, 'reusable npm workflow');
  return true;
}

export function validateReusablePypiWorkflowText(text) {
  requireText(text, [
    'npm run security-case:emit',
    'npm run conformance:manifest',
    'verify-reproducible-wheel.mjs',
    'python -m pytest',
    'actions/attest@',
    'subject-path: ${{ steps.build.outputs.wheel }}',
    'subject-path: ${{ steps.build.outputs.sdist }}',
    'gh-action-pypi-publish@',
    'cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"',
    'cmp "${{ steps.build.outputs.sdist }}" "$REGISTRY_SDIST"',
    'scripts/require-release-approval.mjs',
    'group: registry-publish-pypi-${{ inputs.package_name }}',
  ], 'reusable PyPI workflow');
  forbidCredentialInjection(text, 'reusable PyPI workflow');
  return true;
}

export function validateCredentialRotationGuideText(text) {
  const normalized = text.replace(/\s+/g, ' ');
  requireText(normalized, [
    'A local or CI write token is not a supported fallback.',
    'Do not create a replacement publish token.',
    "npm config delete //registry.npmjs.org/:_authToken --location=user",
    'A broken OIDC relationship must fail closed.',
  ], 'credential rotation guide');
  if (/Create a fresh[^\n]*Access Token/i.test(text)
    || /_authToken=NEW_TOKEN/i.test(text)
    || /New granular token created/i.test(text)) {
    throw new Error('credential rotation guide reintroduces a publication-token fallback');
  }
  return true;
}

function validateNpmDirect(text, label) {
  requireText(text, [
    'npm run security-case:emit',
    'npm run conformance:manifest',
    'release:verify:reproducible',
    'run: npm test',
    'actions/attest@',
    'subject-path: release-artifacts/${{ steps.pack.outputs.tarball }}',
    'npm publish "../../release-artifacts/${{ steps.pack.outputs.tarball }}" --access public --provenance',
    'cmp "../../release-artifacts/${{ steps.pack.outputs.tarball }}" "../../registry-copy/$REGISTRY_TARBALL"',
    'scripts/require-release-approval.mjs',
  ], label);
  validateManualPublisher(text, label, { direct: true });
  forbidCredentialInjection(text, label);
}

function validatePypiDirect(text, label) {
  requireText(text, [
    'npm run security-case:emit',
    'npm run conformance:manifest',
    'verify-reproducible-wheel.mjs',
    'python -m pytest',
    'subject-path: ${{ steps.build.outputs.wheel }}',
    'subject-path: ${{ steps.build.outputs.sdist }}',
    'gh-action-pypi-publish@',
    'cmp "${{ steps.build.outputs.wheel }}" "$REGISTRY_WHEEL"',
    'cmp "${{ steps.build.outputs.sdist }}" "$REGISTRY_SDIST"',
    'scripts/require-release-approval.mjs',
  ], label);
  validateManualPublisher(text, label, { direct: true });
  forbidCredentialInjection(text, label);
}

function exactInput(text, key, value) {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^\\s*${key}:\\s*['\"]?${escaped}['\"]?\\s*$`, 'm').test(text);
}

export function validateNpmLockData(metadata, lock, label) {
  const root = lock?.packages?.[''];
  if (!root || lock.lockfileVersion !== 3) throw new Error(`${label} is not an npm lockfile v3`);
  if (lock.name !== metadata.name || lock.version !== metadata.version
      || root.name !== metadata.name || root.version !== metadata.version) {
    throw new Error(`${label} package identity/version differs from package.json`);
  }
  for (const field of ['dependencies', 'optionalDependencies', 'devDependencies']) {
    const declared = metadata[field] ?? {};
    const locked = root[field] ?? {};
    if (JSON.stringify(declared) !== JSON.stringify(locked)) {
      throw new Error(`${label} ${field} differs from package.json`);
    }
  }
  for (const [dependency, range] of Object.entries({
    ...(metadata.dependencies ?? {}),
    ...(metadata.optionalDependencies ?? {}),
  })) {
    if (!dependency.startsWith('@emilia-protocol/')) continue;
    const pinnedFloor = typeof range === 'string' ? range.replace(/^[~^]/, '') : null;
    const resolved = lock.packages[`node_modules/${dependency}`]?.version;
    if (!pinnedFloor || resolved !== pinnedFloor) {
      throw new Error(`${label} does not lock ${dependency} to its declared security floor ${range}`);
    }
  }
  return true;
}

export function auditReleaseChain(root = ROOT) {
  if (fs.existsSync(path.join(root, 'scripts/publish-verify.sh'))) {
    throw new Error('direct local npm publication script is forbidden');
  }
  const pythonReadme = fs.readFileSync(path.join(root, 'packages/python-verify/README.md'), 'utf8');
  if (/\btwine\s+upload\b/.test(pythonReadme)) throw new Error('direct local PyPI upload instructions are forbidden');
  validateCredentialRotationGuideText(fs.readFileSync(
    path.join(root, 'docs/operations/CREDENTIAL-ROTATION-CHECKLIST.md'),
    'utf8',
  ));
  const registryPath = path.join(root, REGISTRY);
  const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  if (registry['@version'] !== 'EP-RELEASE-PACKAGE-REGISTRY-v1' || !Array.isArray(registry.packages)) {
    throw new Error('release package registry is malformed');
  }
  const reusablePath = path.join(root, WORKFLOW_DIR, '_publish-npm-package.yml');
  validateReusableNpmWorkflowText(fs.readFileSync(reusablePath, 'utf8'));

  const seenPackages = new Set();
  const seenWorkflows = new Set();
  const seenTagPrefixes = new Set();
  for (const entry of registry.packages) {
    if (!entry || typeof entry.package !== 'string' || typeof entry.path !== 'string'
      || typeof entry.workflow !== 'string' || typeof entry.tag_prefix !== 'string'
      || !/^[a-z0-9-]+-v$/.test(entry.tag_prefix)
      || !['npm_direct', 'npm_reusable', 'pypi_direct', 'pypi_reusable'].includes(entry.mode)) {
      throw new Error('release registry contains a malformed entry');
    }
    if (seenPackages.has(`${entry.ecosystem}:${entry.package}`)) throw new Error(`duplicate release package: ${entry.package}`);
    if (seenWorkflows.has(entry.workflow)) throw new Error(`duplicate release workflow: ${entry.workflow}`);
    if (seenTagPrefixes.has(entry.tag_prefix)) throw new Error(`duplicate release tag prefix: ${entry.tag_prefix}`);
    seenPackages.add(`${entry.ecosystem}:${entry.package}`);
    seenWorkflows.add(entry.workflow);
    seenTagPrefixes.add(entry.tag_prefix);

    const workflowPath = path.join(root, WORKFLOW_DIR, entry.workflow);
    const packagePath = path.join(root, entry.path);
    if (!fs.statSync(workflowPath).isFile() || !fs.statSync(packagePath).isDirectory()) throw new Error(`missing release input for ${entry.package}`);
    const workflow = fs.readFileSync(workflowPath, 'utf8');
    if (entry.mode === 'npm_reusable') {
      requireText(workflow, ['uses: ./.github/workflows/_publish-npm-package.yml'], entry.workflow);
      validateManualPublisher(workflow, entry.workflow, { direct: false });
      if (!exactInput(workflow, 'package_dir', entry.path) || !exactInput(workflow, 'package_name', entry.package)
        || !exactInput(workflow, 'tag_prefix', entry.tag_prefix)) {
        throw new Error(`${entry.workflow} does not bind the declared package path, name, and tag prefix`);
      }
    } else if (entry.mode === 'npm_direct') {
      validateNpmDirect(workflow, entry.workflow);
    } else if (entry.mode === 'pypi_direct') {
      validatePypiDirect(workflow, entry.workflow);
    } else {
      requireText(workflow, ['uses: ./.github/workflows/_publish-pypi-package.yml'], entry.workflow);
      validateManualPublisher(workflow, entry.workflow, { direct: false });
      if (!exactInput(workflow, 'package_dir', entry.path) || !exactInput(workflow, 'package_name', entry.package)
        || !exactInput(workflow, 'tag_prefix', entry.tag_prefix)) {
        throw new Error(`${entry.workflow} does not bind the declared package path, name, and tag prefix`);
      }
    }
    if (!workflow.includes(`--tag-prefix ${entry.tag_prefix}`) && !entry.mode.endsWith('_reusable')) {
      throw new Error(`${entry.workflow} does not bind release tag prefix ${entry.tag_prefix}`);
    }

    if (entry.ecosystem === 'npm') {
      const metadata = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json'), 'utf8'));
      if (metadata.name !== entry.package || metadata.repository?.url !== REPOSITORY_URL) {
        throw new Error(`${entry.package} package metadata is not bound to the EMILIA GitHub repository`);
      }
      if (typeof metadata.scripts?.test !== 'string' || !metadata.scripts.test.trim()) {
        throw new Error(`${entry.package} has no executable package test command`);
      }
      const lockPath = path.join(packagePath, 'package-lock.json');
      if (fs.existsSync(lockPath)) {
        validateNpmLockData(metadata, JSON.parse(fs.readFileSync(lockPath, 'utf8')), path.relative(root, lockPath));
      }
    } else {
      const pyproject = fs.readFileSync(path.join(packagePath, 'pyproject.toml'), 'utf8');
      if (!/requires\s*=\s*\["hatchling==1\.27\.0"\]/.test(pyproject)) {
        throw new Error(`${entry.package} does not pin its Python build backend`);
      }
    }
  }

  validateReusablePypiWorkflowText(fs.readFileSync(
    path.join(root, WORKFLOW_DIR, '_publish-pypi-package.yml'),
    'utf8',
  ));

  const discoveredSurfaces = discoverReleaseSurfaces(root);
  const declaredSurfaces = registry.packages
    .map(({ ecosystem, package: packageName, path: packagePath }) => ({ ecosystem, package: packageName, path: packagePath }))
    .sort((a, b) => `${a.ecosystem}:${a.package}`.localeCompare(`${b.ecosystem}:${b.package}`));
  if (JSON.stringify(discoveredSurfaces) !== JSON.stringify(declaredSurfaces)) {
    throw new Error(`release surface omission/drift: declared=${JSON.stringify(declaredSurfaces)} discovered=${JSON.stringify(discoveredSurfaces)}`);
  }

  const discovered = fs.readdirSync(path.join(root, WORKFLOW_DIR))
    .filter((name) => /^publish-.*\.ya?ml$/.test(name))
    .sort();
  const declared = [...seenWorkflows].sort();
  if (JSON.stringify(discovered) !== JSON.stringify(declared)) {
    throw new Error(`release registry/workflow drift: declared=${declared.join(',')} discovered=${discovered.join(',')}`);
  }
  return { packages: registry.packages.length, npm: registry.packages.filter((entry) => entry.ecosystem === 'npm').length, pypi: registry.packages.filter((entry) => entry.ecosystem === 'pypi').length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = auditReleaseChain();
    console.log(`RELEASE CHAIN: PASS (${result.packages} packages; npm=${result.npm}; pypi=${result.pypi})`);
  } catch (error) {
    console.error(`RELEASE CHAIN: FAIL (${error.message})`);
    process.exitCode = 1;
  }
}
