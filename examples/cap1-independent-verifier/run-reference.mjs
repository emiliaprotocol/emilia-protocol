#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { CAP1_SOURCE_LOCK, verifyCap1 } from './verify.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UPSTREAM = path.join(HERE, 'vectors', 'upstream');

async function json(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

export async function buildReferenceReport() {
  const manifestBytes = await readFile(path.join(UPSTREAM, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const cases = [];
  for (const entry of manifest) {
    const bytes = await readFile(path.join(UPSTREAM, `${entry.id}.json`));
    const result = verifyCap1(JSON.parse(bytes.toString('utf8')));
    cases.push({
      id: entry.id,
      kind: entry.kind,
      expected: entry.expect,
      expected_rule: entry.rule ?? null,
      vector_sha256: createHash('sha256').update(bytes).digest('hex'),
      document_digest: result.document_digest,
      verdict: result.verdict,
      primary_rule: result.primary_rule,
      observed_rules: result.violations.map((violation) => violation.rule),
      passed: result.verdict === (entry.expect === 'conform' ? 'CONFORMS' : 'REFUSES')
        && (!entry.rule || result.primary_rule === entry.rule),
    });
  }
  const lock = await json(path.join(HERE, 'source-lock.json'));
  return {
    artifact: 'EMILIA-CAP1-INDEPENDENT-RUN-v1',
    source: CAP1_SOURCE_LOCK,
    implementation_lock_sha256: lock.implementation_lock_sha256,
    vector_scope: 'fifteen vector objects observed at the pinned Certisyn commit; not a bundle normatively identified by the Internet-Draft',
    observed_manifest_sha256: createHash('sha256').update(manifestBytes).digest('hex'),
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    summary: {
      total: cases.length,
      passed: cases.filter((entry) => entry.passed).length,
      positive: cases.filter((entry) => entry.kind === 'positive').length,
      negative: cases.filter((entry) => entry.kind === 'negative').length,
    },
    cases,
    claim_boundary: [
      'CAP-1 conformance is internal consistency, not source-population completeness or truth.',
      'This verifier is independent of the Certisyn verifier code, but it was run by the EMILIA team.',
      'The document digest uses EMILIA recursively key-sorted JSON, not a native CAP-1 canonicalization.',
    ],
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = await buildReferenceReport();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.summary.passed !== report.summary.total) process.exitCode = 1;
}
