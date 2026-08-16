// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FIELD_ORIGIN_CLAIM_BOUNDARY,
  createGate,
  hashCanonical,
  MemoryConsumptionStore,
  verifyFieldOriginEvidence,
} from '../../../packages/gate/index.js';
import { verifyEvidenceRecord } from '../../../packages/gate/evidence.js';

const HERE = dirname(fileURLToPath(import.meta.url));

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function sha256(bytes: Buffer): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export async function verifyPilotKit(bundleDirectory: string) {
  const bundle = resolve(bundleDirectory);
  const manifest = readJson(resolve(bundle, 'bundle-manifest.json'));
  const failures: string[] = [];
  if (manifest?.['@version'] !== 'EP-M01-PAID-PILOT-BUNDLE-v0.1') {
    failures.push('bundle_manifest_version_invalid');
  }
  if (!/^[0-9a-f]{40}$/.test(manifest?.source_commit ?? '')) {
    failures.push('source_commit_invalid');
  } else {
    try {
      const verifierCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: HERE,
        encoding: 'utf8',
      }).trim();
      if (verifierCommit !== manifest.source_commit) failures.push('source_commit_mismatch');
    } catch {
      failures.push('source_commit_unavailable');
    }
  }
  const listed = Array.isArray(manifest?.files) ? manifest.files : [];
  const listedNames = listed.map((entry) => entry?.name).sort();
  const actualNames = readdirSync(bundle)
    .filter((name) => name !== 'bundle-manifest.json')
    .sort();
  if (JSON.stringify(listedNames) !== JSON.stringify(actualNames)) {
    failures.push('bundle_file_set_mismatch');
  }
  for (const entry of listed) {
    if (!entry || typeof entry.name !== 'string') {
      failures.push('bundle_manifest_entry_invalid');
      continue;
    }
    let bytes: Buffer;
    try { bytes = readFileSync(resolve(bundle, entry.name)); } catch {
      failures.push(`bundle_file_missing:${entry.name}`);
      continue;
    }
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) {
      failures.push(`bundle_file_digest_mismatch:${entry.name}`);
    }
  }

  const action = readJson(resolve(bundle, 'observed-action.json'));
  const profile = readJson(resolve(bundle, 'field-origin-profile.json'));
  const trustedKeys = readJson(resolve(bundle, 'field-origin-trusted-keys.json'));
  const fieldEvidence = readJson(resolve(bundle, 'field-origin-evidence.json'));
  const approvalReceipt = readJson(resolve(bundle, 'approval-receipt.json'));
  const receiptTrust = readJson(resolve(bundle, 'receipt-trust-config.json'));
  const actionManifest = readJson(resolve(bundle, 'action-risk-manifest.json'));
  const selector = readJson(resolve(bundle, 'selector.json'));
  const executionProgram = readJson(resolve(bundle, 'bounded-execution-program.json'));
  const executionProgramVerification = readJson(
    resolve(bundle, 'bounded-execution-program-verification.json'),
  );
  const fieldOrigin = verifyFieldOriginEvidence(fieldEvidence, {
    trusted_keys: trustedKeys,
    pinned_profile: profile,
    expected_relying_party_id: profile.relying_party_id,
    observed_action: action,
    now: new Date(Math.max(Date.now(), Date.parse(fieldEvidence.observed_at))).toISOString(),
  });
  if (!fieldOrigin.accepted) failures.push(`field_origin_refused:${fieldOrigin.reason}`);
  if (fieldOrigin.claim_boundary !== FIELD_ORIGIN_CLAIM_BOUNDARY) {
    failures.push('field_origin_claim_boundary_mismatch');
  }
  const memo = Array.isArray(fieldOrigin.fields)
    ? fieldOrigin.fields.find((field) => field.path === '/memo')
    : null;
  if (memo?.origin_class !== 'untrusted_bounded') {
    failures.push('bounded_memo_origin_missing');
  }

  try {
    const receiptTime = Date.parse(approvalReceipt?.payload?.created_at);
    const verificationGate = createGate({
      manifest: actionManifest,
      trustedKeys: receiptTrust.trusted_keys,
      approverKeys: receiptTrust.approver_keys,
      rpId: receiptTrust.rp_id,
      allowedOrigins: receiptTrust.allowed_origins,
      quorumPolicy: receiptTrust.quorum_policy,
      store: new MemoryConsumptionStore(),
      allowEphemeralStore: true,
      now: () => receiptTime + 1,
      requiredFieldOriginProfile: profile,
      fieldOriginTrustedKeys: trustedKeys,
      fieldOriginExecutionProgram: {
        artifact: executionProgram,
        verification_options: executionProgramVerification.verification_options,
        node_id: executionProgramVerification.node_id,
      },
    });
    const decision = await verificationGate.check({
      selector,
      receipt: approvalReceipt,
      observedAction: action,
      fieldOriginEvidence: fieldEvidence,
      consumptionMode: 'none',
    });
    if (!decision.allow) failures.push(`offline_gate_refused:${decision.reason}`);
    if (!decision.evidence?.field_origin_program_binding?.program_digest) {
      failures.push('bounded_execution_program_binding_missing');
    }
  } catch (error) {
    failures.push(`offline_gate_verification_failed:${String((error as Error)?.message ?? error)}`);
  }

  const report = readJson(resolve(bundle, 'gap6-report.json'));
  const { results_digest: statedDigest, ...deterministic } = report;
  const computedDigest = `sha256:${hashCanonical(deterministic)}`;
  if (computedDigest !== statedDigest || statedDigest !== manifest.source_results_digest) {
    failures.push('gap6_results_digest_mismatch');
  }
  if (report?.claim_model?.field_origin?.claim_boundary !== FIELD_ORIGIN_CLAIM_BOUNDARY) {
    failures.push('gap6_claim_boundary_mismatch');
  }

  const log = readJson(resolve(bundle, 'gate-evidence-log.json'));
  let previous = 'genesis';
  if (!Array.isArray(log)) failures.push('gate_evidence_log_invalid');
  else {
    for (const [index, record] of log.entries()) {
      if (record?.seq !== index || record?.prev_hash !== previous || !verifyEvidenceRecord(record)) {
        failures.push(`gate_evidence_chain_invalid:${index}`);
        break;
      }
      previous = record.hash;
    }
  }

  const requiredReasons = new Set([
    'field_origin_control_untrusted:/vendor_id',
    'field_origin_control_untrusted:/erp',
    'field_origin_transform_unpinned:/new_account_digest',
    'field_origin_unknown:/change_ticket',
    'field_origin_profile_mismatch',
  ]);
  const observedReasons = new Set(
    Array.isArray(report?.cases) ? report.cases.map((item) => item.boundary_reason) : [],
  );
  for (const reason of requiredReasons) {
    if (!observedReasons.has(reason)) failures.push(`m01_case_missing:${reason}`);
  }
  const positive = Array.isArray(report?.cases)
    ? report.cases.find((item) => item.id === 'm01-bounded-untrusted-memo-admitted')
    : null;
  if (positive?.admission?.verdict !== 'admitted' || positive?.execution?.verdict !== 'executed') {
    failures.push('m01_positive_case_missing');
  }

  return {
    ok: failures.length === 0,
    failures,
    bundle_version: manifest?.['@version'] ?? null,
    gap6_results_digest: statedDigest ?? null,
    field_origin_artifact_digest: fieldOrigin.artifact_digest ?? null,
    evidence_chain_length: Array.isArray(log) ? log.length : 0,
    evidence_chain_head: Array.isArray(log) && log.length ? log[log.length - 1].hash : null,
  };
}

export function parseBundleDirectory(args: string[]): string {
  if (args.length === 1 && args[0] && !args[0].startsWith('-')) return args[0];
  if (args.length === 2 && args[0] === '--bundle' && args[1]) return args[1];
  if (args.length === 1 && args[0]?.startsWith('--bundle=')) {
    const directory = args[0].slice('--bundle='.length);
    if (directory) return directory;
  }
  throw new Error('usage: verify-pilot-kit.mjs --bundle <bundle-directory>');
}

const isMain = process.argv[1]
  && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const directory = parseBundleDirectory(process.argv.slice(2));
  const result = await verifyPilotKit(directory);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) process.exitCode = 1;
}
