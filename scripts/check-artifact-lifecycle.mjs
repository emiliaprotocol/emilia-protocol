#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFile, readdir } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const TAG = /\bEP-[A-Z][A-Z0-9-]*-v[0-9]+(?:\.[0-9]+)?\b/g;
const TEXT_EXT = /\.(?:cjs|html|js|json|jsx|md|mjs|mts|ts|tsx|txt|xml|ya?ml)$/;
const STATUSES = new Set([
  'spec_only',
  'document_only',
  'experimental_profile',
  'proposed',
  'retired',
  'procedure_label',
  'data_artifact',
]);

async function filesUnder(path) {
  const out = [];
  let entries = [];
  try { entries = await readdir(path, { withFileTypes: true }); } catch (error) {
    if (error?.code === 'ENOENT') return out;
    throw error;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const child = resolve(path, entry.name);
    if (entry.isDirectory()) out.push(...await filesUnder(child));
    else if (entry.isFile() && TEXT_EXT.test(entry.name)) out.push(child);
  }
  return out;
}

export async function collectArtifactTags(root, directories) {
  const occurrences = new Map();
  for (const directory of directories) {
    for (const path of await filesUnder(resolve(root, directory))) {
      const text = await readFile(path, 'utf8');
      for (const tag of text.match(TAG) ?? []) {
        const paths = occurrences.get(tag) ?? new Set();
        paths.add(relative(root, path));
        occurrences.set(tag, paths);
      }
    }
  }
  return occurrences;
}

export async function checkArtifactLifecycle({
  root,
  documentationDirectories = ['docs', 'standards', 'PIPs'],
  implementationDirectories = [
    'packages', 'lib', 'app', 'apps', 'integrations', 'sdks',
    'conformance', 'examples', 'scripts',
  ],
  registryPath = 'governance/artifact-lifecycle.v1.json',
}) {
  const [documented, implemented, registryText] = await Promise.all([
    collectArtifactTags(root, documentationDirectories),
    collectArtifactTags(root, implementationDirectories),
    readFile(resolve(root, registryPath), 'utf8'),
  ]);
  const registry = JSON.parse(registryText);
  if (registry?.['@version'] !== 'EP-ARTIFACT-LIFECYCLE-REGISTRY-v1'
      || registry?.claim_boundary !== 'repository_name_classification_not_runtime_existence_conformance_adoption_or_deployment'
      || !Array.isArray(registry.entries)) {
    throw new Error('artifact lifecycle registry shape is invalid');
  }
  const docOnly = [...documented.keys()].filter((tag) => !implemented.has(tag)).sort();
  const entries = new Map();
  const errors = [];
  for (const entry of registry.entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || typeof entry.tag !== 'string' || !STATUSES.has(entry.status)
        || !Array.isArray(entry.evidence_paths) || entry.evidence_paths.length < 1
        || new Set(entry.evidence_paths).size !== entry.evidence_paths.length) {
      errors.push(`invalid registry entry: ${JSON.stringify(entry)}`);
      continue;
    }
    if (entries.has(entry.tag)) errors.push(`duplicate registry tag: ${entry.tag}`);
    entries.set(entry.tag, entry);
    for (const evidencePath of entry.evidence_paths) {
      let evidence = '';
      try { evidence = await readFile(resolve(root, evidencePath), 'utf8'); } catch {
        errors.push(`${entry.tag}: evidence path missing: ${evidencePath}`);
        continue;
      }
      if (!evidence.includes(entry.tag)) {
        errors.push(`${entry.tag}: evidence path does not contain tag: ${evidencePath}`);
      }
    }
  }
  for (const tag of docOnly) {
    if (!entries.has(tag)) errors.push(`unclassified documentation-only artifact: ${tag}`);
  }
  for (const [tag, entry] of entries) {
    if (!docOnly.includes(tag)) errors.push(`stale lifecycle classification for code-backed or absent tag: ${tag}`);
    if (entry.status === 'retired') {
      const allowed = new Set(entry.allowed_paths ?? []);
      if (allowed.size < 1) errors.push(`${tag}: retired entry requires allowed_paths`);
      for (const path of documented.get(tag) ?? []) {
        if (!allowed.has(path)) errors.push(`${tag}: retired tag escaped historical paths into ${path}`);
      }
    }
  }
  return {
    ok: errors.length === 0,
    documented: documented.size,
    implemented: implemented.size,
    documentation_only: docOnly.length,
    classified: entries.size,
    errors,
  };
}

const scriptPath = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const root = resolve(new URL('..', import.meta.url).pathname);
  const report = await checkArtifactLifecycle({ root });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.ok) process.exitCode = 1;
}
