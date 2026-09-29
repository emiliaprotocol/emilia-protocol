// SPDX-License-Identifier: Apache-2.0
// Generated from helpers.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Shared builders for the unit tests. Payload shapes follow what the OpenShell
// gateway actually delivered to the observer in the live end-to-end run
// (protobuf JSON lowerCamelCase names, numbers as JSON numbers, fields at
// their default value omitted).
import crypto from 'node:crypto';
import { GENESIS } from '../src/log.ts';
import { b64u, ruleDigest, sha256Hex } from '../src/canonical.ts';
import { approvalDigest, buildPayload, signEs256 } from '../src/receipt.ts';
import { CHAIN_FORMAT, INVENTORY_FORMAT, PINS_FORMAT } from '../src/check.ts';
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
export function hex(seed) {
    return sha256Hex(seed);
}
export function ruleDigestOf(rule) {
    const digest = ruleDigest(rule);
    if (!digest.ok)
        throw new Error(digest.reason);
    return digest.value;
}
export const T0 = Date.parse('2026-09-29T07:00:00.000Z');
export const at = (ms) => new Date(T0 + ms).toISOString();
/** Serialize records into a hash-chained log exactly as AppendOnlyLog does. */
export function logText(records) {
    let prev = GENESIS;
    const lines = [];
    records.forEach((record, index) => {
        const { t, kind, ...rest } = record;
        const line = JSON.stringify({ seq: index + 1, prev, t: t ?? at(index), kind, ...rest });
        lines.push(line);
        prev = sha256Hex(line);
    });
    return `${lines.join('\n')}\n`;
}
export const start = (gatewayJwt = { gateway_id: 'gw', public_key_sha256: hex('gw') }) => ({
    kind: 'observer_start', t: at(0), format: 'emilia.openshell.observer-log.v1', gateway_jwt: gatewayJwt, gateway_reads: true,
});
const auth = { mode: 'verified', jti: 'j', iss: 'openshell-gateway:gw', exp: 2_000_000_000 };
export function validate(ms, opts) {
    return {
        kind: 'evaluation', t: at(ms), phase: 'validate', service: 'openshell.v1.OpenShell', method: 'ApproveDraftChunk',
        binding_id: 'observe-ApproveDraftChunk', interceptor_name: 'emilia-observer', principal: opts.principal ?? PRINCIPAL, gateway_auth: opts.auth ?? auth,
        payload: {
            chunkId: opts.chunkId, reviewToken: opts.token, sandbox: opts.sandbox ?? 'sb', workspaceScope: { workspace: opts.workspace ?? 'default' },
            ...(opts.requestId ? { requestId: opts.requestId } : {}),
        },
    };
}
export function validateBulk(ms, opts) {
    return {
        kind: 'evaluation', t: at(ms), phase: 'validate', service: 'openshell.v1.OpenShell', method: 'ApproveAllDraftChunks',
        binding_id: 'observe-ApproveAllDraftChunks', interceptor_name: 'emilia-observer', principal: PRINCIPAL, gateway_auth: auth,
        payload: { approvals: opts.approvals, sandbox: opts.sandbox ?? 'sb', workspaceScope: { workspace: 'default' } },
    };
}
export function postCommit(ms, opts) {
    const method = opts.method ?? 'ApproveDraftChunk';
    const payload = {};
    if (opts.hash)
        payload.policyHash = opts.hash;
    if (opts.version)
        payload.policyVersion = opts.version;
    if (method === 'ApproveAllDraftChunks') {
        if (opts.approved)
            payload.chunksApproved = opts.approved;
        if (opts.skipped)
            payload.chunksSkipped = opts.skipped;
    }
    return {
        kind: 'evaluation', t: at(ms), phase: 'post_commit', service: 'openshell.v1.OpenShell', method,
        binding_id: `observe-${method}`, interceptor_name: 'emilia-observer', principal: opts.principal ?? PRINCIPAL, gateway_auth: auth, payload,
    };
}
export function read(ms, forSeq, opts) {
    return {
        kind: 'gateway_read', t: at(ms), for_seq: forSeq, workspace: 'default', sandbox: opts.sandbox ?? 'sb', sandbox_id: opts.sandboxId ?? `id-${opts.sandbox ?? 'sb'}`,
        chunks: opts.chunks.map((c) => ({
            chunk_id: c.id, status: c.status ?? 'approved', rule_name: c.ruleName ?? c.rule?.name ?? RULE.name, review_token: c.token,
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
export function receiptFor(approver, opts) {
    const rule = opts.rule ?? RULE;
    const payload = buildPayload({
        workspace: opts.workspace ?? 'default',
        sandbox: opts.sandbox ?? 'sb',
        chunk: { chunk_id: opts.chunkId, review_token: opts.token, rule_name: opts.ruleName ?? rule.name, rule_digest: ruleDigestOf(rule), candidate_effective_policy_hash: hex('cand') },
        publicKeySpkiDer: approver.spki,
        issuedAt: opts.issuedAt ?? new Date(T0),
    });
    if (!payload.ok)
        throw new Error(payload.reason);
    return signEs256(payload.value, approver.privateKey);
}
export function resign(receipt, approver, change) {
    return signEs256({ ...receipt.payload, ...change }, approver.privateKey);
}
export function pins(entries) {
    return JSON.stringify({
        format: PINS_FORMAT,
        approvers: entries.map((e) => ({
            label: e.label ?? 'approver', public_key_spki: e.spkiB64u, workspaces: e.workspaces ?? ['default'],
            ...(e.webauthn ? { webauthn: e.webauthn } : {}), ...(e.formats ? { formats: e.formats } : {}),
        })),
    });
}
export function chain(revisions, opts = {}) {
    return JSON.stringify({
        format: CHAIN_FORMAT, workspace: 'default', sandbox: opts.sandbox ?? 'sb', sandbox_id: opts.sandboxId ?? `id-${opts.sandbox ?? 'sb'}`,
        read_at: at(100_000), revisions: revisions.map(([version, policy_hash]) => ({ version, policy_hash, status: 'POLICY_STATUS_LOADED' })),
    });
}
/** A `chain --all` sandbox inventory for workspace default. */
export function inventory(sandboxes = [['sb', 'id-sb']]) {
    return JSON.stringify({ format: INVENTORY_FORMAT, workspace: 'default', read_at: at(100_000), sandboxes: sandboxes.map(([sandbox, sandbox_id]) => ({ sandbox, sandbox_id })) });
}
export function configLine(sandboxId, state, message, tags) {
    return `2026-09-29T07:27:04.801024Z  INFO ocsf: sandbox_id=${sandboxId} CONFIG:${state} [INFO] ${message} [${tags}]`;
}
/**
 * A WebAuthn assertion over an existing receipt's payload, synthesized in the
 * authenticator format with the approver's software key (no real passkey).
 */
export function webauthnReceiptFor(approver, base, opts = {}) {
    const challenge = b64u(approvalDigest(base.payload));
    const clientData = JSON.stringify({ type: 'webauthn.get', challenge, origin: opts.origin ?? 'https://approve.example.com', crossOrigin: opts.crossOrigin ?? false });
    const authData = Buffer.concat([crypto.createHash('sha256').update(opts.rpId ?? 'approve.example.com').digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
    const signature = crypto.sign('sha256', Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]), approver.privateKey);
    return {
        payload: base.payload,
        proof: { format: 'webauthn', public_key_spki: approver.spkiB64u, authenticator_data: b64u(authData), client_data_json: b64u(Buffer.from(clientData)), signature: b64u(signature) },
    };
}
