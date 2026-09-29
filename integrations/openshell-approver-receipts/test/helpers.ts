// SPDX-License-Identifier: Apache-2.0
// Shared builders for the unit tests. Payload shapes follow what the OpenShell
// gateway actually delivered to the observer in the live end-to-end run
// (protobuf JSON lowerCamelCase names, numbers as JSON numbers, fields at
// their default value omitted).

import crypto from 'node:crypto';
import { GENESIS } from '../src/log.ts';
import { b64u, ruleDigest, sha256Hex } from '../src/canonical.ts';
import { buildPayload, signEs256 } from '../src/receipt.ts';
import type { ApprovalPayload, Receipt } from '../src/receipt.ts';
import { CHAIN_FORMAT, PINS_FORMAT } from '../src/check.ts';

export const PRINCIPAL = {
  display_name: 'Unauthenticated Local Dev',
  kind: 'user',
  provider: 'local_dev',
  roles: 'openshell-user,openshell-admin',
  scopes: 'openshell:all',
  subject: 'unauthenticated-local-dev',
};

export const RULE = {
  binaries: [{ path: '/usr/bin/bash' }],
  endpoints: [{ advisor_proposed: true, host: 'example.com', port: 443, ports: [443] }],
  name: 'allow_example_com_443',
};

export function hex(seed: string): string {
  return sha256Hex(seed);
}

export function ruleDigestOf(rule: object): string {
  const digest = ruleDigest(rule);
  if (!digest.ok) throw new Error(digest.reason);
  return digest.value;
}

export const T0 = Date.parse('2026-09-29T07:00:00.000Z');
export const at = (ms: number): string => new Date(T0 + ms).toISOString();

/** Serialize records into a hash-chained log exactly as AppendOnlyLog does. */
export function logText(records: Record<string, unknown>[]): string {
  let prev = GENESIS;
  const lines: string[] = [];
  records.forEach((record, index) => {
    const { t, kind, ...rest } = record as { t?: string; kind: string };
    const line = JSON.stringify({ seq: index + 1, prev, t: t ?? at(index), kind, ...rest });
    lines.push(line);
    prev = sha256Hex(line);
  });
  return `${lines.join('\n')}\n`;
}

export const start = (gatewayJwt: unknown = { gateway_id: 'gw', public_key_sha256: hex('gw') }) => ({
  kind: 'observer_start', t: at(0), format: 'emilia.openshell.observer-log.v1', gateway_jwt: gatewayJwt, gateway_reads: true,
});

const auth = { mode: 'verified', jti: 'j', iss: 'openshell-gateway:gw', exp: 2_000_000_000 };

export function validate(ms: number, opts: { sandbox?: string; chunkId: string; token: string; workspace?: string; requestId?: string; principal?: object; auth?: object }) {
  return {
    kind: 'evaluation', t: at(ms), phase: 'validate', service: 'openshell.v1.OpenShell', method: 'ApproveDraftChunk',
    binding_id: 'observe-ApproveDraftChunk', interceptor_name: 'emilia-observer', principal: opts.principal ?? PRINCIPAL, gateway_auth: opts.auth ?? auth,
    payload: {
      chunkId: opts.chunkId, reviewToken: opts.token, sandbox: opts.sandbox ?? 'sb', workspaceScope: { workspace: opts.workspace ?? 'default' },
      ...(opts.requestId ? { requestId: opts.requestId } : {}),
    },
  };
}

export function validateBulk(ms: number, opts: { sandbox?: string; approvals: { chunkId: string; reviewToken: string }[] }) {
  return {
    kind: 'evaluation', t: at(ms), phase: 'validate', service: 'openshell.v1.OpenShell', method: 'ApproveAllDraftChunks',
    binding_id: 'observe-ApproveAllDraftChunks', interceptor_name: 'emilia-observer', principal: PRINCIPAL, gateway_auth: auth,
    payload: { approvals: opts.approvals, sandbox: opts.sandbox ?? 'sb', workspaceScope: { workspace: 'default' } },
  };
}

export function postCommit(ms: number, opts: { version: number; hash: string; method?: string; approved?: number; skipped?: number; principal?: object }) {
  const method = opts.method ?? 'ApproveDraftChunk';
  const payload: Record<string, unknown> = {};
  if (opts.hash) payload.policyHash = opts.hash;
  if (opts.version) payload.policyVersion = opts.version;
  if (method === 'ApproveAllDraftChunks') {
    if (opts.approved) payload.chunksApproved = opts.approved;
    if (opts.skipped) payload.chunksSkipped = opts.skipped;
  }
  return {
    kind: 'evaluation', t: at(ms), phase: 'post_commit', service: 'openshell.v1.OpenShell', method,
    binding_id: `observe-${method}`, interceptor_name: 'emilia-observer', principal: opts.principal ?? PRINCIPAL, gateway_auth: auth, payload,
  };
}

export interface ReadChunkSpec { id: string; status?: string; token: string; rule?: object; ruleName?: string }

export function read(ms: number, forSeq: number, opts: { sandbox?: string; chunks: ReadChunkSpec[]; revisions: [number, string][]; sandboxId?: string }) {
  return {
    kind: 'gateway_read', t: at(ms), for_seq: forSeq, workspace: 'default', sandbox: opts.sandbox ?? 'sb', sandbox_id: opts.sandboxId ?? `id-${opts.sandbox ?? 'sb'}`,
    chunks: opts.chunks.map((c) => ({
      chunk_id: c.id, status: c.status ?? 'approved', rule_name: c.ruleName ?? (c.rule as { name?: string } | undefined)?.name ?? RULE.name, review_token: c.token,
      candidate_effective_policy_hash: hex('cand'), current_effective_policy_hash: hex('cur'), security_notes: '', decided_time: at(ms),
      proposed_rule: c.rule ?? RULE, rule_digest: ruleDigestOf(c.rule ?? RULE),
    })),
    revisions: opts.revisions.map(([version, policy_hash]) => ({ version, policy_hash, status: 'POLICY_STATUS_LOADED' })),
  };
}

export function newApprover() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return { privateKey, publicKey, spki, spkiB64u: b64u(spki) };
}

export function receiptFor(
  approver: ReturnType<typeof newApprover>,
  opts: { chunkId: string; token: string; sandbox?: string; workspace?: string; rule?: object; ruleName?: string; issuedAt?: Date },
): Receipt {
  const rule = opts.rule ?? RULE;
  const payload = buildPayload({
    workspace: opts.workspace ?? 'default',
    sandbox: opts.sandbox ?? 'sb',
    chunk: { chunk_id: opts.chunkId, review_token: opts.token, rule_name: opts.ruleName ?? (rule as { name: string }).name, rule_digest: ruleDigestOf(rule), candidate_effective_policy_hash: hex('cand') },
    publicKeySpkiDer: approver.spki,
    issuedAt: opts.issuedAt ?? new Date(T0),
  });
  if (!payload.ok) throw new Error(payload.reason);
  return signEs256(payload.value, approver.privateKey);
}

export function resign(receipt: Receipt, approver: ReturnType<typeof newApprover>, change: Partial<ApprovalPayload>): Receipt {
  return signEs256({ ...receipt.payload, ...change }, approver.privateKey);
}

export function pins(entries: { spkiB64u: string; workspaces?: string[]; label?: string; webauthn?: object }[]): string {
  return JSON.stringify({
    format: PINS_FORMAT,
    approvers: entries.map((e) => ({ label: e.label ?? 'approver', public_key_spki: e.spkiB64u, workspaces: e.workspaces ?? ['default'], ...(e.webauthn ? { webauthn: e.webauthn } : {}) })),
  });
}

export function chain(revisions: [number, string][], opts: { sandbox?: string; sandboxId?: string } = {}): string {
  return JSON.stringify({
    format: CHAIN_FORMAT, workspace: 'default', sandbox: opts.sandbox ?? 'sb', sandbox_id: opts.sandboxId ?? `id-${opts.sandbox ?? 'sb'}`,
    read_at: at(100_000), revisions: revisions.map(([version, policy_hash]) => ({ version, policy_hash, status: 'POLICY_STATUS_LOADED' })),
  });
}

export function configLine(sandboxId: string, state: string, message: string, tags: string): string {
  return `2026-09-29T07:27:04.801024Z  INFO ocsf: sandbox_id=${sandboxId} CONFIG:${state} [INFO] ${message} [${tags}]`;
}
