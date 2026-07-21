#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// The v1 clean-room bundle is historical evidence, not the live protocol
// suite. Current ports intentionally reject its old terminal-revocation
// expiry rule, so this gate verifies the frozen bytes and their historical
// manifest without pretending the current ports still implement that rule.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_PATH: string = path.join(ROOT, 'conformance/clean-room/conformance-manifest.v1.json');
const BUNDLE_PATH: string = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const FROZEN_ROOT: string = path.join(ROOT, 'conformance/clean-room/frozen-v1');
const FROZEN_MANIFEST_SHA256: string = '2fcc8f5a5823f414f4ab505601891c98c4f2bf4180e658d97b0db36be3a99147';

const sha256 = (bytes: Buffer | Uint8Array): string => crypto.createHash('sha256').update(bytes).digest('hex');

interface ReadStrictJsonResult {
  bytes: Buffer;
  value: any;
}

function readStrictJson(file: string, label: string): ReadStrictJsonResult {
  const bytes: Buffer = fs.readFileSync(file);
  const text: string = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const gate: any = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  return { bytes, value: JSON.parse(text) };
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`frozen clean-room baseline: ${message}`);
}

const manifestInput: ReadStrictJsonResult = readStrictJson(MANIFEST_PATH, 'manifest');
const bundleInput: ReadStrictJsonResult = readStrictJson(BUNDLE_PATH, 'bundle');
const manifest: any = manifestInput.value;
const bundle: any = bundleInput.value;

assert(sha256(manifestInput.bytes) === FROZEN_MANIFEST_SHA256, 'historical manifest bytes drifted');
assert(manifest['@version'] === 'EP-CONFORMANCE-MANIFEST-v1', 'unsupported manifest version');
assert(bundle['@version'] === 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1', 'unsupported bundle version');
assert(manifest.vector_bundle?.path === 'conformance/clean-room/bundle.v1.json', 'bundle path drifted');
assert(manifest.vector_bundle?.sha256 === sha256(bundleInput.bytes), 'bundle hash mismatch');

const withoutHash: any = structuredClone(manifest);
delete withoutHash.manifest_sha256;
assert(
  manifest.manifest_sha256 === sha256(Buffer.from(canonicalize(withoutHash), 'utf8')),
  'manifest self-hash mismatch',
);

const manifestSuites: Map<string, any> = new Map(manifest.suites.map((suite: any) => [suite.path, suite]));
let vectors: number = 0;
for (const suite of bundle.suites) {
  const file: string = path.resolve(FROZEN_ROOT, suite.path);
  assert(file.startsWith(`${FROZEN_ROOT}${path.sep}`), `${suite.path} escapes the frozen root`);
  const { bytes, value: parsed }: ReadStrictJsonResult = readStrictJson(file, suite.path);
  const recorded: any = manifestSuites.get(suite.path);
  assert(sha256(bytes) === suite.sha256, `${suite.path} bytes drifted`);
  assert(recorded?.sha256 === suite.sha256, `${suite.path} manifest hash drifted`);
  assert(recorded?.vectors === parsed.vectors?.length, `${suite.path} vector count drifted`);
  vectors += parsed.vectors.length;
}

assert(manifestSuites.size === bundle.suites.length, 'manifest suite set differs from bundle');
assert(manifest.totals?.suites === bundle.suites.length, 'suite total mismatch');
assert(manifest.totals?.vectors === vectors, 'vector total mismatch');
assert(manifest.totals?.implementations === manifest.implementations?.length, 'implementation total mismatch');
assert(manifest.implementations.every((item) => item.status === 'pass'), 'historical port result was not pass');

console.log(`FROZEN CLEAN-ROOM BASELINE: PASS (${bundle.suites.length} suites, ${vectors} historical vectors; current live semantics are checked separately)`);
