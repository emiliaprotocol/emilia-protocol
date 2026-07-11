#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = 'release/release-packages.v1.json';
const WORKFLOW_DIR = '.github/workflows';
const REPOSITORY_URL = 'https://github.com/emiliaprotocol/emilia-protocol.git';

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

export function auditReleaseChain(root = ROOT) {
  if (fs.existsSync(path.join(root, 'scripts/publish-verify.sh'))) {
    throw new Error('direct local npm publication script is forbidden');
  }
  const pythonReadme = fs.readFileSync(path.join(root, 'packages/python-verify/README.md'), 'utf8');
  if (/\btwine\s+upload\b/.test(pythonReadme)) throw new Error('direct local PyPI upload instructions are forbidden');
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
      || !['npm_direct', 'npm_reusable', 'pypi_direct'].includes(entry.mode)) {
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
    } else {
      validatePypiDirect(workflow, entry.workflow);
    }
    if (!workflow.includes(`--tag-prefix ${entry.tag_prefix}`) && entry.mode !== 'npm_reusable') {
      throw new Error(`${entry.workflow} does not bind release tag prefix ${entry.tag_prefix}`);
    }

    if (entry.ecosystem === 'npm') {
      const metadata = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json'), 'utf8'));
      if (metadata.name !== entry.package || metadata.repository?.url !== REPOSITORY_URL) {
        throw new Error(`${entry.package} package metadata is not bound to the EMILIA GitHub repository`);
      }
    } else {
      const pyproject = fs.readFileSync(path.join(packagePath, 'pyproject.toml'), 'utf8');
      if (!/requires\s*=\s*\["hatchling==1\.27\.0"\]/.test(pyproject)) {
        throw new Error(`${entry.package} does not pin its Python build backend`);
      }
    }
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
