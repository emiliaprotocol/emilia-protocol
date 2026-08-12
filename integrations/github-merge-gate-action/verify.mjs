// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { canonicalize, verifyReceipt } from '../../packages/verify/index.js';
import { strictJsonGate } from '../../packages/verify/strict-json.js';

const SHA = /^[0-9a-f]{40}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const BASE_REF = /^refs\/heads\/[A-Za-z0-9._/-]{1,240}$/;
const MANDATE_VERSION = 'EP-GITHUB-MERGE-MANDATE-v1';
const ACTION_TYPE = 'github.pull-request.merge.1';
const MANDATE_FIELDS = new Set([
  '@version',
  'repository',
  'allowed_base_refs',
  'allowed_path_prefixes',
  'denied_path_prefixes',
  'max_changed_files',
  'max_additions',
  'max_deletions',
  'max_changed_bytes',
  'max_receipt_age_seconds',
  'issuer_id',
  'issuer_key_id',
]);
const CLAIM_FIELDS = new Set([
  'action_type',
  'repository',
  'base_ref',
  'base_sha',
  'head_sha',
  'mandate_digest',
  'caid',
  'decision',
]);

function refuse(reason, details = {}) {
  return { admitted: false, reason, ...details };
}

function parseStrictJson(raw, kind) {
  const gate = strictJsonGate(raw);
  if (!gate.ok) return { error: `${kind}_invalid_json`, detail: gate.reason };
  try {
    return { value: JSON.parse(raw) };
  } catch {
    return { error: `${kind}_invalid_json`, detail: 'invalid JSON syntax' };
  }
}

function git(workspace, arguments_, encoding = 'utf8') {
  return execFileSync('git', arguments_, {
    cwd: workspace,
    encoding,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function gitWithInput(workspace, arguments_, input) {
  return execFileSync('git', arguments_, {
    cwd: workspace,
    encoding: 'utf8',
    input,
    maxBuffer: 16 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

function safePrefix(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 240
    && !value.startsWith('/')
    && !value.includes('\\')
    && !value.split('/').includes('..');
}

function validateMandate(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuse('mandate_invalid_shape');
  for (const key of Object.keys(value)) {
    if (!MANDATE_FIELDS.has(key)) return refuse('mandate_unknown_field', { field: key });
  }
  if (value['@version'] !== MANDATE_VERSION) return refuse('mandate_version_unsupported');
  if (typeof value.repository !== 'string' || !REPOSITORY.test(value.repository)) return refuse('mandate_repository_invalid');
  for (const field of ['allowed_base_refs', 'allowed_path_prefixes', 'denied_path_prefixes']) {
    if (!Array.isArray(value[field]) || value[field].length > 100 || new Set(value[field]).size !== value[field].length) {
      return refuse(`mandate_${field}_invalid`);
    }
  }
  if (value.allowed_base_refs.length === 0
      || !value.allowed_base_refs.every((item) => typeof item === 'string' && BASE_REF.test(item))) {
    return refuse('mandate_allowed_base_refs_invalid');
  }
  if (value.allowed_path_prefixes.length === 0 || !value.allowed_path_prefixes.every(safePrefix)) {
    return refuse('mandate_allowed_path_prefixes_invalid');
  }
  if (!value.denied_path_prefixes.every(safePrefix)) return refuse('mandate_denied_path_prefixes_invalid');
  for (const field of ['max_changed_files', 'max_additions', 'max_deletions', 'max_changed_bytes', 'max_receipt_age_seconds']) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 1 || value[field] > 1_000_000) {
      return refuse(`mandate_${field}_invalid`);
    }
  }
  for (const field of ['issuer_id', 'issuer_key_id']) {
    if (typeof value[field] !== 'string' || value[field].length < 1 || value[field].length > 200) {
      return refuse(`mandate_${field}_invalid`);
    }
  }
  return { admitted: true, mandate: value };
}

function mandateAtBase(workspace, baseSha, mandatePath) {
  if (typeof mandatePath !== 'string' || !safePrefix(mandatePath) || mandatePath.endsWith('/')) {
    return refuse('mandate_path_invalid');
  }
  let raw;
  try {
    raw = git(workspace, ['show', `${baseSha}:${mandatePath}`], 'buffer');
  } catch {
    return refuse('mandate_missing_at_base');
  }
  if (raw.length > 64 * 1024) return refuse('mandate_too_large');
  const decoded = raw.toString('utf8');
  if (!Buffer.from(decoded, 'utf8').equals(raw)) return refuse('mandate_invalid_utf8');
  const parsed = parseStrictJson(decoded, 'mandate');
  if (parsed.error) return refuse(parsed.error, { detail: parsed.detail });
  return validateMandate(parsed.value);
}

function parseDiff(workspace, baseSha, headSha) {
  let raw;
  try {
    raw = git(workspace, ['diff', '--numstat', '--no-renames', '-z', baseSha, headSha, '--'], 'buffer');
  } catch {
    return refuse('git_diff_unavailable');
  }
  const decoded = raw.toString('utf8');
  if (!Buffer.from(decoded, 'utf8').equals(raw)) return refuse('git_diff_invalid_utf8');
  const records = decoded.split('\0').filter(Boolean);
  const files = [];
  for (const record of records) {
    const match = /^([^\t]+)\t([^\t]+)\t([\s\S]+)$/.exec(record);
    if (!match) return refuse('git_diff_ambiguous');
    const [, additionsRaw, deletionsRaw, file] = match;
    if (!safePrefix(file) || file.endsWith('/')) return refuse('git_diff_path_invalid');
    if (additionsRaw === '-' || deletionsRaw === '-') return refuse('binary_diff_indeterminate', { path: file });
    const additions = Number(additionsRaw);
    const deletions = Number(deletionsRaw);
    if (!Number.isSafeInteger(additions) || !Number.isSafeInteger(deletions)) return refuse('git_diff_count_invalid');
    files.push({ path: file, additions, deletions });
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  if (files.length === 0) return refuse('empty_diff');

  let rawModes;
  try {
    rawModes = git(workspace, ['diff', '--raw', '--no-renames', '--no-abbrev', '-z', baseSha, headSha, '--'], 'buffer');
  } catch {
    return refuse('git_raw_diff_unavailable');
  }
  const decodedModes = rawModes.toString('utf8');
  if (!Buffer.from(decodedModes, 'utf8').equals(rawModes)) return refuse('git_diff_invalid_utf8');
  const parts = decodedModes.split('\0').filter(Boolean);
  if (parts.length % 2 !== 0) return refuse('git_raw_diff_ambiguous');
  const modePaths = [];
  const liveObjectIds = [];
  for (let index = 0; index < parts.length; index += 2) {
    const metadata = /^:(\d{6}) (\d{6}) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])$/.exec(parts[index]);
    const file = parts[index + 1];
    if (!metadata || !safePrefix(file) || file.endsWith('/')) return refuse('git_raw_diff_ambiguous');
    const [, oldMode, newMode, , newObjectId] = metadata;
    const supportedModes = new Set(['000000', '100644', '100755']);
    if (!supportedModes.has(oldMode) || !supportedModes.has(newMode)) {
      return refuse('git_object_mode_unsupported', { path: file, old_mode: oldMode, new_mode: newMode });
    }
    if (newMode !== '000000') liveObjectIds.push(newObjectId);
    modePaths.push(file);
  }
  modePaths.sort((left, right) => left.localeCompare(right));
  if (modePaths.length !== files.length || modePaths.some((file, index) => file !== files[index].path)) {
    return refuse('git_diff_views_disagree');
  }
  let changedBytes = 0;
  if (liveObjectIds.length > 0) {
    let objectRows;
    try {
      objectRows = gitWithInput(
        workspace,
        ['cat-file', '--batch-check=%(objecttype) %(objectsize)'],
        `${liveObjectIds.join('\n')}\n`,
      ).trim().split('\n');
    } catch {
      return refuse('git_object_size_unavailable');
    }
    if (objectRows.length !== liveObjectIds.length) return refuse('git_object_size_ambiguous');
    for (const row of objectRows) {
      const match = /^blob ([0-9]+)$/.exec(row);
      if (!match) return refuse('git_object_type_unsupported');
      const size = Number(match[1]);
      if (!Number.isSafeInteger(size)) return refuse('git_object_size_invalid');
      changedBytes += size;
      if (!Number.isSafeInteger(changedBytes)) return refuse('git_object_size_invalid');
    }
  }
  return {
    admitted: true,
    diff: {
      changed_files: files.length,
      additions: files.reduce((total, file) => total + file.additions, 0),
      deletions: files.reduce((total, file) => total + file.deletions, 0),
      changed_bytes: changedBytes,
      paths: files.map((file) => file.path),
    },
  };
}

function checkDiff(diff, mandate) {
  if (diff.changed_files > mandate.max_changed_files) return refuse('changed_files_limit_exceeded');
  if (diff.additions > mandate.max_additions) return refuse('additions_limit_exceeded');
  if (diff.deletions > mandate.max_deletions) return refuse('deletions_limit_exceeded');
  if (diff.changed_bytes > mandate.max_changed_bytes) return refuse('changed_bytes_limit_exceeded');
  for (const file of diff.paths) {
    if (mandate.denied_path_prefixes.some((prefix) => file.startsWith(prefix))) {
      return refuse('path_denied', { path: file });
    }
    if (!mandate.allowed_path_prefixes.some((prefix) => file.startsWith(prefix))) {
      return refuse('path_outside_mandate', { path: file });
    }
  }
  return { admitted: true };
}

function digest(value, encoding = 'hex') {
  return crypto.createHash('sha256').update(canonicalize(value)).digest(encoding);
}

function actionFor({ repository, baseRef, baseSha, headSha, mandateDigest }) {
  return {
    action_type: ACTION_TYPE,
    repository,
    base_ref: baseRef,
    base_sha: baseSha,
    head_sha: headSha,
    mandate_digest: mandateDigest,
  };
}

function strictTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function verifyMergeReceipt({ raw, issuerPublicKey, expected, now, maxAgeSeconds, issuerId, issuerKeyId }) {
  const parsed = parseStrictJson(raw, 'receipt');
  if (parsed.error) return refuse(parsed.error, { detail: parsed.detail });
  if (parsed.value?.signature?.algorithm !== 'Ed25519') {
    return refuse('receipt_algorithm_unsupported');
  }
  const verified = verifyReceipt(parsed.value, issuerPublicKey);
  if (!verified.valid) return refuse('receipt_signature_invalid', { detail: verified.error ?? null });
  const payload = parsed.value.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return refuse('receipt_payload_invalid');
  if (typeof payload.receipt_id !== 'string' || payload.receipt_id.length < 1 || payload.receipt_id.length > 240) {
    return refuse('receipt_id_invalid');
  }
  if (payload.issuer !== issuerId) return refuse('receipt_issuer_mismatch');
  if (payload.issuer_key_id !== issuerKeyId) return refuse('receipt_issuer_key_id_mismatch');
  const issuedAt = strictTimestamp(payload.issued_at);
  const expiresAt = strictTimestamp(payload.expires_at);
  const evaluationTime = strictTimestamp(now);
  if (![issuedAt, expiresAt, evaluationTime].every(Number.isFinite) || expiresAt <= issuedAt) return refuse('receipt_time_invalid');
  if (evaluationTime < issuedAt) return refuse('receipt_not_yet_valid');
  if (evaluationTime > expiresAt) return refuse('receipt_expired');
  if (expiresAt - issuedAt > maxAgeSeconds * 1000) return refuse('receipt_validity_window_too_long');
  const claim = payload.claim;
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) return refuse('receipt_claim_invalid');
  for (const field of Object.keys(claim)) {
    if (!CLAIM_FIELDS.has(field)) return refuse('receipt_claim_unknown_field', { field });
  }
  for (const field of CLAIM_FIELDS) {
    if (!Object.hasOwn(claim, field)) return refuse('receipt_claim_missing_field', { field });
  }
  const fieldReasons = {
    action_type: 'receipt_action_type_mismatch',
    repository: 'receipt_repository_mismatch',
    base_ref: 'receipt_base_ref_mismatch',
    base_sha: 'receipt_base_sha_mismatch',
    head_sha: 'receipt_head_sha_mismatch',
    mandate_digest: 'receipt_mandate_digest_mismatch',
    caid: 'receipt_caid_mismatch',
    decision: 'receipt_decision_not_authorized',
  };
  for (const [field, expectedValue] of Object.entries(expected)) {
    if (claim[field] !== expectedValue) return refuse(fieldReasons[field] ?? 'receipt_claim_mismatch', { field });
  }
  return { admitted: true, receipt_id: payload.receipt_id ?? null };
}

export async function evaluateMergeGate({
  workspace,
  baseSha,
  headSha,
  repository,
  baseRef,
  mandatePath,
  receiptPath,
  issuerPublicKey,
  now,
} = {}) {
  if (typeof workspace !== 'string' || workspace.length === 0) return refuse('workspace_required');
  if (!SHA.test(baseSha ?? '')) return refuse('base_sha_invalid');
  if (!SHA.test(headSha ?? '')) return refuse('head_sha_invalid');
  if (!REPOSITORY.test(repository ?? '')) return refuse('repository_invalid');
  if (!BASE_REF.test(baseRef ?? '')) return refuse('base_ref_invalid');
  if (typeof issuerPublicKey !== 'string' || issuerPublicKey.length < 32) return refuse('issuer_public_key_required');
  if (!Number.isFinite(Date.parse(now))) return refuse('evaluation_time_invalid');
  try {
    git(workspace, ['cat-file', '-e', `${baseSha}^{commit}`]);
    git(workspace, ['cat-file', '-e', `${headSha}^{commit}`]);
  } catch {
    return refuse('commit_unavailable');
  }
  try {
    git(workspace, ['merge-base', '--is-ancestor', baseSha, headSha]);
  } catch {
    return refuse('base_not_ancestor_of_head');
  }
  const loadedMandate = mandateAtBase(workspace, baseSha, mandatePath);
  if (!loadedMandate.admitted) return loadedMandate;
  const mandate = loadedMandate.mandate;
  if (mandate.repository !== repository) return refuse('mandate_repository_mismatch');
  if (!mandate.allowed_base_refs.includes(baseRef)) return refuse('base_ref_outside_mandate');
  const mandateDigest = `sha256:${digest(mandate)}`;
  const diffResult = parseDiff(workspace, baseSha, headSha);
  if (!diffResult.admitted) return diffResult;
  const policyResult = checkDiff(diffResult.diff, mandate);
  if (!policyResult.admitted) return policyResult;
  const action = actionFor({ repository, baseRef, baseSha, headSha, mandateDigest });
  const caid = `caid:1:${ACTION_TYPE}:jcs-sha256:${digest(action, 'base64url')}`;
  let receiptRaw;
  try {
    const resolvedReceiptPath = path.isAbsolute(receiptPath ?? '')
      ? receiptPath
      : path.resolve(workspace, receiptPath ?? '');
    const receiptInfo = await stat(resolvedReceiptPath);
    if (!receiptInfo.isFile()) return refuse('receipt_not_regular_file');
    if (receiptInfo.size > 1024 * 1024) return refuse('receipt_too_large');
    receiptRaw = await readFile(resolvedReceiptPath, 'utf8');
  } catch {
    return refuse('receipt_unavailable');
  }
  const receiptResult = verifyMergeReceipt({
    raw: receiptRaw,
    issuerPublicKey,
    now,
    maxAgeSeconds: mandate.max_receipt_age_seconds,
    issuerId: mandate.issuer_id,
    issuerKeyId: mandate.issuer_key_id,
    expected: { ...action, caid, decision: 'AUTHORIZED' },
  });
  if (!receiptResult.admitted) return receiptResult;
  return {
    admitted: true,
    reason: 'admitted',
    repository,
    base_ref: baseRef,
    base_sha: baseSha,
    head_sha: headSha,
    mandate_digest: mandateDigest,
    caid,
    receipt_id: receiptResult.receipt_id,
    diff: diffResult.diff,
    boundary: {
      merges_pull_request: false,
      requires_required_status_check: true,
      receipt_consumption_claimed: false,
    },
  };
}
