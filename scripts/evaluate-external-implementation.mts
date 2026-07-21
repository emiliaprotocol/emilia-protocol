#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../packages/verify/index.js';
import { verifyExternalVerificationStatement } from '../packages/gate/reports/external-verification.js';
import { strictParseGate } from '../conformance/runners/strict-json.mjs';

const ROOT: string = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BUNDLE_PATH: string = path.join(ROOT, 'conformance/clean-room/bundle.v1.json');
const argv: string[] = process.argv.slice(2);
const option = (name: string): string | null => {
  const index: number = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const pinPath: string | null = option('--pin');
const sourcePath: string | null = option('--source');
const runnerPath: string | null = option('--runner');
const emitPath: string | null = option('--emit');
const bundlePath: string = option('--bundle') || BUNDLE_PATH;
const suiteRootPath: string = option('--suite-root') || ROOT;
if (!pinPath || !sourcePath || !runnerPath || !emitPath) {
  console.error('usage: evaluate-external-implementation --pin FILE --source CHECKOUT --runner EXECUTABLE --emit FILE [--bundle FILE --suite-root DIR]');
  process.exit(2);
}

const sha256 = (bytes: Buffer): string => crypto.createHash('sha256').update(bytes).digest('hex');
interface JsonResult {
  bytes: Buffer;
  value: any;
}
function readStrictJson(target: string, label: string): JsonResult {
  const bytes: Buffer = fs.readFileSync(target);
  const text: string = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const gate: any = strictParseGate(text);
  if (!gate.ok) throw new Error(`${label}: ${gate.reason}`);
  return { bytes, value: JSON.parse(text) };
}

const pinAbsolute: string = path.resolve(pinPath as string);
const sourceAbsolute: string = path.resolve(sourcePath as string);
const runnerAbsolute: string = path.resolve(runnerPath as string);
const { bytes: pinBytes, value: pin }: JsonResult = readStrictJson(pinAbsolute, 'external implementation pin');
if (pin['@version'] !== 'EP-EXTERNAL-IMPLEMENTATION-PIN-v1') throw new Error('unsupported external implementation pin');
if (!/^[0-9a-f]{40}$/.test(pin.source?.commit || '') || !/^[0-9a-f]{40}$/.test(pin.source?.tree_oid || '')) {
  throw new Error('external source commit and tree must be immutable Git object IDs');
}
const sourceReal: string = fs.realpathSync(sourceAbsolute);
const implementationRoot: string = fs.realpathSync(path.resolve(sourceReal, pin.source.tree_path));
const runnerReal: string = fs.realpathSync(runnerAbsolute);
if (!fs.statSync(runnerReal).isFile()) throw new Error('external runner is not a file');
if (runnerReal !== implementationRoot && !runnerReal.startsWith(`${implementationRoot}${path.sep}`)) {
  throw new Error('external runner is outside the pinned implementation tree');
}

const git = (...args: string[]): string => execFileSync('git', ['-C', sourceReal, ...args], { encoding: 'utf8' }).trim();
const sourceCommit: string = git('rev-parse', 'HEAD');
if (sourceCommit !== pin.source.commit) throw new Error(`external source commit drift: ${sourceCommit}`);
const sourceTree: string = git('rev-parse', `${sourceCommit}:${pin.source.tree_path}`);
if (sourceTree !== pin.source.tree_oid) throw new Error(`external source tree drift: ${sourceTree}`);

interface EvidenceFileResult {
  target: string;
  bytes: Buffer;
}
function pinnedEvidenceFile(relativePath: string, expectedHash: string, label: string): EvidenceFileResult {
  const target: string = path.resolve(ROOT, relativePath || '');
  if (target !== ROOT && !target.startsWith(`${ROOT}${path.sep}`)) throw new Error(`${label} escapes the evaluator repository`);
  const bytes: Buffer = fs.readFileSync(target);
  if (sha256(bytes) !== expectedHash) throw new Error(`${label} hash mismatch`);
  return { target, bytes };
}

const statementFile: EvidenceFileResult = pinnedEvidenceFile(
  pin.construction_evidence?.statement,
  pin.construction_evidence?.statement_sha256,
  'construction statement',
);
const publicKeyFile: EvidenceFileResult = pinnedEvidenceFile(
  pin.construction_evidence?.public_key,
  pin.construction_evidence?.public_key_sha256,
  'construction statement public key',
);
const statementGate: any = strictParseGate(statementFile.bytes.toString('utf8'));
if (!statementGate.ok) throw new Error(`construction statement: ${statementGate.reason}`);
const statement: any = JSON.parse(statementFile.bytes.toString('utf8'));
const statementVerification: any = verifyExternalVerificationStatement(statement, {
  pinnedVerifierKeys: [{
    verifier_id: pin.construction_evidence.verifier_id,
    key_id: pin.construction_evidence.key_id,
    public_key: publicKeyFile.bytes.toString('utf8').trim(),
  }],
});
if (!statementVerification.accepted || statement.result?.status !== 'verified'
  || statement.verifier?.organization !== pin.implementation.organization) {
  throw new Error(`construction statement refused: ${statementVerification.reason || statement.result?.status || 'organization_mismatch'}`);
}

const bundleAbsolute: string = path.resolve(bundlePath);
const suiteRootAbsolute: string = fs.realpathSync(path.resolve(suiteRootPath));
const { bytes: bundleBytes, value: bundle }: JsonResult = readStrictJson(bundleAbsolute, 'vector bundle');
if (bundle['@version'] !== 'EP-CLEAN-ROOM-VECTOR-BUNDLE-v1' || !Array.isArray(bundle.suites)) {
  throw new Error('unsupported vector bundle');
}
const suites: any[] = [];
let vectorCount: number = 0;
for (const suiteRef of bundle.suites) {
  const suiteCandidate: string = path.resolve(suiteRootAbsolute, suiteRef.path);
  if (suiteCandidate !== suiteRootAbsolute && !suiteCandidate.startsWith(`${suiteRootAbsolute}${path.sep}`)) {
    throw new Error(`vector suite escapes the pinned suite root: ${suiteRef.path}`);
  }
  const suitePath: string = fs.realpathSync(suiteCandidate);
  if (suitePath !== suiteRootAbsolute && !suitePath.startsWith(`${suiteRootAbsolute}${path.sep}`)) {
    throw new Error(`vector suite resolves outside the pinned suite root: ${suiteRef.path}`);
  }
  const { bytes, value: suite }: JsonResult = readStrictJson(suitePath, `suite ${suiteRef.path}`);
  if (sha256(bytes) !== suiteRef.sha256) throw new Error(`vector bundle drift: ${suiteRef.path}`);
  let stdout: string;
  try {
    stdout = execFileSync(runnerReal, [suitePath], {
      cwd: implementationRoot,
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error: any) {
    throw new Error(`external runner failed ${suiteRef.path}: ${error.stderr || error.message}`);
  }
  const outputGate: any = strictParseGate(stdout);
  if (!outputGate.ok) throw new Error(`external runner output ${suiteRef.path}: ${outputGate.reason}`);
  const results: any[] = JSON.parse(stdout);
  const expected: Map<string, boolean> = new Map(suite.vectors.map((vector: any) => [vector.id, vector.expect.valid]));
  if (!Array.isArray(results) || results.length !== expected.size) {
    throw new Error(`external runner returned the wrong result count for ${suiteRef.path}`);
  }
  const seen: Set<string> = new Set();
  for (const result of results) {
    if (!result || typeof result !== 'object' || Array.isArray(result)
      || Object.keys(result).length !== 2 || typeof result.id !== 'string'
      || typeof result.valid !== 'boolean' || seen.has(result.id) || !expected.has(result.id)) {
      throw new Error(`external runner emitted a malformed result for ${suiteRef.path}`);
    }
    if (result.valid !== expected.get(result.id)) throw new Error(`external divergence ${suiteRef.path}#${result.id}`);
    seen.add(result.id);
  }
  vectorCount += expected.size;
  suites.push({ path: suiteRef.path, sha256: suiteRef.sha256, vectors: expected.size, status: 'pass' });
}

const evaluatorCommit: string = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const report: any = {
  '@version': 'EP-EXTERNAL-CONFORMANCE-EVALUATION-v1',
  status: 'pass',
  implementation: pin.implementation,
  source: { ...pin.source, verified: true },
  build: {
    ...pin.build,
    runner_sha256: sha256(fs.readFileSync(runnerReal)),
  },
  construction_evidence: {
    ...pin.construction_evidence,
    signature_verified: true,
    signed_result_status: statement.result.status,
    signed_vectors: statement.subject?.vectors ?? null,
    statement_digest: statementVerification.statement_digest,
  },
  evaluator: {
    repository: 'https://github.com/emiliaprotocol/emilia-protocol',
    commit: evaluatorCommit,
    pin_sha256: sha256(pinBytes),
  },
  conformance: {
    bundle: bundle['@version'],
    bundle_sha256: sha256(bundleBytes),
    suites: suites.length,
    vectors: vectorCount,
    status: 'pass',
  },
  suites,
};
report.report_sha256 = sha256(Buffer.from(canonicalize(report), 'utf8'));
const target: string = path.resolve(emitPath as string);
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`);
console.log(`EXTERNAL CONFORMANCE: PASS (${suites.length} suites, ${vectorCount} vectors; source ${sourceCommit}; sha256:${report.report_sha256})`);
