#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SEARCH_ROOTS = ['app', 'examples', 'integrations', 'lib', 'mcp-server', 'packages'];
const SKIP_DIRECTORIES = new Set(['dist', 'node_modules', '.next', 'coverage']);
const TARGETS = new Set(['providerEntryContext', 'createOrganizationStatusProviderEntryGuard']);
const ALLOWED_CONTEXT_FILES = new Set([
  'packages/gate/src/capability-receipt.ts',
  'packages/gate/src/index.ts',
]);

function sourceFiles(directory, files = []) {
  if (!fs.existsSync(directory)) return files;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (SKIP_DIRECTORIES.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) sourceFiles(absolute, files);
    else if (/\.(?:ts|tsx|mts)$/u.test(entry.name)
        && !/\.(?:test|spec)\.(?:ts|tsx|mts)$/u.test(entry.name)) files.push(absolute);
  }
  return files;
}

function calleeName(expression) {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return null;
}

function explicitNowProperty(object) {
  if (!object || !ts.isObjectLiteralExpression(object)) return null;
  return object.properties.find((property) => (
    (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property))
      && property.name?.getText() === 'now'
  )) ?? null;
}

const errors = [];
let contextCalls = 0;
const observedContextFiles = new Set();
for (const file of SEARCH_ROOTS.flatMap((root) => sourceFiles(path.join(ROOT, root)))) {
  const relative = path.relative(ROOT, file).split(path.sep).join('/');
  const source = fs.readFileSync(file, 'utf8');
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  function visit(node) {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node.expression);
      if (name === null || !TARGETS.has(name)) {
        ts.forEachChild(node, visit);
        return;
      }
      const nowProperty = explicitNowProperty(node.arguments[0]);
      if (name === 'providerEntryContext') {
        contextCalls += 1;
        observedContextFiles.add(relative);
        const allowed = ALLOWED_CONTEXT_FILES.has(relative)
          && nowProperty !== null
          && ts.isShorthandPropertyAssignment(nowProperty)
          && nowProperty.name.text === 'now';
        if (!allowed) errors.push(`${relative}:${ast.getLineAndCharacterOfPosition(node.pos).line + 1} has an unreviewed provider-entry clock`);
      } else if (nowProperty !== null) {
        errors.push(`${relative}:${ast.getLineAndCharacterOfPosition(node.pos).line + 1} injects an explicit organization-status clock in production code`);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
}

if (contextCalls !== ALLOWED_CONTEXT_FILES.size) {
  errors.push(`expected ${ALLOWED_CONTEXT_FILES.size} reviewed providerEntryContext calls; found ${contextCalls}`);
}
for (const file of ALLOWED_CONTEXT_FILES) {
  if (!observedContextFiles.has(file)) errors.push(`${file} is missing its reviewed provider-entry context`);
}
if (errors.length > 0) {
  console.error(`PROVIDER ENTRY TIME WIRING: FAIL\n${errors.join('\n')}`);
  process.exit(1);
}
console.log('PROVIDER ENTRY TIME WIRING: PASS (constructor-owned clock only)');
