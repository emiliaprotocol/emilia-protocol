// SPDX-License-Identifier: Apache-2.0
/** Produce or check the deterministic Pinto CBAP-1 Crossing Lab reference report. */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runCrossingLab } from '../../../packages/verify/dist/crossing-lab.js';
import { digestJson, verifyCbap1 } from './workspace/adapter.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKSPACE = join(HERE, 'workspace');
const REFERENCE = join(HERE, 'report.reference.json');

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function requireSourceAndMapping(workspace, sourceLock, mapping) {
  const adapter = workspace.config.adapters[workspace.adapter.id];
  if (sourceLock['@version'] !== 'PINTO-CBAP1-AEB-SOURCE-LOCK-v0.1'
      || sourceLock.draft.name !== 'draft-pinto-agent-authz-contestability'
      || sourceLock.draft.revision !== '00'
      || sourceLock.draft.txt.sha256 !== adapter.config.source_txt_sha256
      || sourceLock.draft.txt.bytes !== 167000
      || sourceLock.draft.xml.sha256 !== 'fab13608e4146a152bc3612618ce7882b93f35aeaf2e40c4f8fcf2e8f3718e52'
      || sourceLock.draft.xml.bytes !== 224643) throw new Error('source lock does not match the adapter pin');
  const profile = workspace.config.profiles[workspace.evaluation.profile_id];
  if (mapping.profile_id !== workspace.evaluation.profile_id
      || mapping.adapter_id !== workspace.adapter.id
      || mapping.native_protocol !== profile.definition.native_protocol
      || mapping.source_txt_sha256 !== adapter.config.source_txt_sha256
      || mapping.aeb_role.evidence_role !== profile.definition.evidence_role
      || mapping.aeb_role.authorization_semantics !== false
      || mapping.aeb_role.claim_scope !== 'historical-contestability-binding-only') {
    throw new Error('mapping record does not match the sealed workspace');
  }
}

export function buildReport() {
  const workspace = readJson(join(WORKSPACE, 'workspace.json'));
  const artifact = readJson(join(WORKSPACE, workspace.artifact));
  const sourceLock = readJson(join(HERE, 'source-lock.json'));
  const mapping = readJson(join(HERE, 'mapping-profile.json'));
  requireSourceAndMapping(workspace, sourceLock, mapping);
  const adapter = workspace.config.adapters[workspace.adapter.id];
  const native = verifyCbap1({
    artifact,
    trust_roots: adapter.trust_roots,
    adapter_config: adapter.config,
    verification_time: Math.floor(Date.parse(workspace.evaluated_at) / 1_000),
  });
  if (!native.ok) throw new Error(`native fixture verification failed: ${native.reason}`);
  const crossingLab = runCrossingLab(WORKSPACE);
  if (!crossingLab.lab_passed) throw new Error('Crossing Lab did not pass');

  const body = {
    '@version': 'PINTO-CBAP1-AEB-REFERENCE-REPORT-v0.1',
    profile: {
      id: mapping.profile_id,
      adapter_id: mapping.adapter_id,
      native_protocol: mapping.native_protocol,
      source_revision: sourceLock.draft.revision,
      source_txt_sha256: sourceLock.draft.txt.sha256,
      source_xml_sha256: sourceLock.draft.xml.sha256,
    },
    claim_boundary: {
      evidence_role: 'contestability-binding',
      claim_scope: 'historical-contestability-binding-only',
      subject_kind: 'system',
      execution_authority: false,
      independent_implementation: false,
      native_author_endorsement: false,
      certification: false,
    },
    native_verification: native,
    crossing_lab: crossingLab,
  };
  return { ...body, report_digest: digestJson(body) };
}

function serializedReport() {
  return `${JSON.stringify(buildReport(), null, 2)}\n`;
}

function main() {
  const mode = process.argv[2] ?? '--print';
  const serialized = serializedReport();
  if (mode === '--print') process.stdout.write(serialized);
  else if (mode === '--write-reference') {
    writeFileSync(REFERENCE, serialized, { flag: 'wx', mode: 0o600 });
    process.stdout.write(`wrote ${REFERENCE}\n`);
  } else if (mode === '--check') {
    if (!existsSync(REFERENCE)) throw new Error('reference report is missing');
    if (readFileSync(REFERENCE, 'utf8') !== serialized) throw new Error('reference report differs from deterministic run');
    process.stdout.write('Pinto CBAP-1 reference report check passed\n');
  } else {
    process.stderr.write('usage: node run.mjs [--print|--write-reference|--check]\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
