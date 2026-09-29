// SPDX-License-Identifier: Apache-2.0
// The observer over real gRPC on a unix socket. The test plays the gateway
// (it calls Describe and Evaluate with a gateway-shaped bearer JWT) and also
// serves a stand-in OpenShell API for the observer's post-commit reads. This
// is not a substitute for the live run in e2e/; it pins the observer's
// contract so CI can hold it without Docker.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import grpc from '@grpc/grpc-js';
import { b64u } from '../src/canonical.ts';
import { check } from '../src/check.ts';
import { GatewayClient } from '../src/gateway-client.ts';
import { parseLog } from '../src/log.ts';
import { startObserver } from '../src/observer.ts';
import type { RunningObserver } from '../src/observer.ts';
import { INTERCEPTOR_SERVICE, OPENSHELL_SERVICE, lookupType, serviceDefinition } from '../src/protos.ts';
import { PRINCIPAL, RULE, chain, hex, inventory, newApprover, pins, receiptFor } from './helpers.ts';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oar-obs-'));
const socket = path.join(dir, 'obs.sock');
const apiSocket = path.join(dir, 'api.sock');
const logPath = path.join(dir, 'observer.jsonl');
const gw = crypto.generateKeyPairSync('ed25519');
const AUDIENCE = 'urn:openshell:extension:interceptor:emilia-observer';
const TOKEN = hex('token-c1');
const H1 = hex('v1');
const H2 = hex('v2');

function bearer(overrides: Record<string, unknown> = {}, key: crypto.KeyObject = gw.privateKey): string {
  const now = Math.floor(Date.now() / 1000);
  const h = b64u(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'openshell-ext+jwt', kid: 'k' })));
  const c = b64u(Buffer.from(JSON.stringify({ iss: 'openshell-gateway:gw', aud: AUDIENCE, caller_kind: 'gateway', jti: crypto.randomUUID(), iat: now, exp: now + 900, ...overrides })));
  return `Bearer ${h}.${c}.${b64u(crypto.sign(null, Buffer.from(`${h}.${c}`), key))}`;
}

// Stand-in OpenShell API: one sandbox `sb`, chunk c1 approved at v2.
let chunkStatus = 'pending';
const api = new grpc.Server();
api.addService(serviceDefinition(OPENSHELL_SERVICE), {
  GetSandbox: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, { sandbox: { metadata: { id: 'id-sb', name: 'sb' } } }),
  GetDraftPolicy: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, {
    chunks: [{ id: 'c1', status: chunkStatus, rule_name: RULE.name, proposed_rule: RULE, review_token: TOKEN, candidate_effective_policy_hash: hex('cand') }],
  }),
  ListSandboxPolicies: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, {
    revisions: [{ version: 2, policy_hash: H2, status: 'POLICY_STATUS_LOADED' }, { version: 1, policy_hash: H1, status: 'POLICY_STATUS_SUPERSEDED' }],
  }),
} as unknown as grpc.UntypedServiceImplementation);

let observer: RunningObserver;
let gateway: grpc.Client;
let evaluationType: ReturnType<typeof lookupType>;

function call(method: 'Describe' | 'Evaluate', request: object, auth?: string): Promise<{ error: grpc.ServiceError | null; value: Record<string, unknown> | undefined }> {
  const def = (serviceDefinition(INTERCEPTOR_SERVICE) as unknown as Record<string, { path: string; requestSerialize: (v: object) => Buffer; responseDeserialize: (b: Buffer) => unknown }>)[method];
  const md = new grpc.Metadata();
  if (auth) md.set('authorization', auth);
  return new Promise((resolve) => {
    gateway.makeUnaryRequest(def.path, def.requestSerialize, def.responseDeserialize, request, md, (error, value) => resolve({ error: error ?? null, value: value as Record<string, unknown> | undefined }));
  });
}

function struct(value: Record<string, unknown>): object {
  const toValue = (v: unknown): object => {
    if (v === null) return { nullValue: 'NULL_VALUE' };
    if (typeof v === 'string') return { stringValue: v };
    if (typeof v === 'number') return { numberValue: v };
    if (typeof v === 'boolean') return { boolValue: v };
    if (Array.isArray(v)) return { listValue: { values: v.map(toValue) } };
    return { structValue: struct(v as Record<string, unknown>) };
  };
  return { fields: Object.fromEntries(Object.entries(value).map(([k, v]) => [k, toValue(v)])) };
}

before(async () => {
  await new Promise<void>((resolve, reject) => api.bindAsync(`unix://${apiSocket}`, grpc.ServerCredentials.createInsecure(), (e) => (e ? reject(e) : resolve())));
  observer = await startObserver({
    listen: `unix://${socket}`,
    logPath,
    gatewayJwt: { publicKeyPem: gw.publicKey.export({ format: 'pem', type: 'spki' }) as string, gatewayId: 'gw' },
    reader: new GatewayClient({ endpoint: `unix://${apiSocket}` }),
  });
  gateway = new grpc.Client(`unix://${socket}`, grpc.credentials.createInsecure());
  evaluationType = lookupType('openshell.gateway_interceptor.v1.InterceptorEvaluation');
});

after(async () => {
  gateway.close();
  await observer.close();
  api.forceShutdown();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Describe: observe-only manifest for the two approval RPCs', async () => {
  const { error, value } = await call('Describe', { gateway: { protocol_version: { major: 1 }, implementation_name: 'openshell/gateway', supported_capabilities: ['openshell.gateway-interceptor.contract'], required_capabilities: ['openshell.gateway-interceptor.contract'] } }, bearer());
  assert.equal(error, null);
  const manifest = value as Record<string, any>;
  assert.equal(manifest.name, 'emilia-observer');
  assert.equal(manifest.failure_policy, 'fail_open');
  assert.equal(manifest.expected_audience, AUDIENCE);
  assert.deepEqual(manifest.bindings.map((b: any) => [b.selector.rpc, b.phases, b.failure_policy]), [
    ['openshell.v1.OpenShell/ApproveDraftChunk', ['GATEWAY_INTERCEPTOR_PHASE_VALIDATE', 'GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT'], 'fail_open'],
    ['openshell.v1.OpenShell/ApproveAllDraftChunks', ['GATEWAY_INTERCEPTOR_PHASE_VALIDATE', 'GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT'], 'fail_open'],
  ]);
  assert.deepEqual(manifest.extension.protocol_version, { major: 1 });
  assert.deepEqual(manifest.extension.supported_capabilities, ['openshell.gateway-interceptor.contract']);
});

test('Describe: refuses an unauthenticated peer and unmet protocol requirements', async () => {
  const wrongKey = crypto.generateKeyPairSync('ed25519');
  assert.equal((await call('Describe', {}, bearer({}, wrongKey.privateKey))).error?.code, grpc.status.UNAUTHENTICATED);
  assert.equal((await call('Describe', {})).error?.code, grpc.status.UNAUTHENTICATED);
  assert.equal((await call('Describe', { gateway: { protocol_version: { major: 2 } } }, bearer())).error?.code, grpc.status.FAILED_PRECONDITION);
  assert.equal((await call('Describe', { gateway: { protocol_version: { major: 1 }, required_capabilities: ['x.unknown'] } }, bearer())).error?.code, grpc.status.FAILED_PRECONDITION);
});

const evaluation = (phase: 'validate' | 'post_commit' | 'modify_operation', method: string, payload: Record<string, unknown>) => ({
  interceptor_name: 'emilia-observer', binding_id: `observe-${method}`, service: 'openshell.v1.OpenShell', method, principal: PRINCIPAL,
  [phase]: phase === 'post_commit' ? { committed_response: struct(payload) } : { proposed_operation: struct(payload) },
});

test('Evaluate: always allowed, never patched, annotated with the log sequence', async () => {
  const validate = await call('Evaluate', evaluation('validate', 'ApproveDraftChunk', { chunkId: 'c1', reviewToken: TOKEN, sandbox: 'sb', workspaceScope: { workspace: 'default' } }), bearer());
  assert.equal(validate.error, null);
  assert.equal(validate.value?.allowed, true);
  assert.equal(validate.value?.patches, undefined);
  assert.match(String((validate.value?.log_annotations as Record<string, string>).emilia_observer_seq), /^\d+$/);
  chunkStatus = 'approved';
  const commit = await call('Evaluate', evaluation('post_commit', 'ApproveDraftChunk', { policyHash: H2, policyVersion: 2 }), bearer());
  assert.equal(commit.value?.allowed, true);
  await observer.idle();
  const { records, problems } = parseLog(fs.readFileSync(logPath, 'utf8'));
  assert.deepEqual(problems, []);
  const readRecord = records.find((r) => r.kind === 'gateway_read') as Record<string, any>;
  assert.equal(readRecord.sandbox_id, 'id-sb');
  assert.equal(readRecord.chunks[0].review_token, TOKEN);
  assert.match(readRecord.chunks[0].rule_digest, /^sha256:[0-9a-f]{64}$/);

  // The log the observer wrote, plus a receipt, passes the offline check.
  const alice = newApprover();
  const report = check({
    logText: fs.readFileSync(logPath, 'utf8'),
    receiptTexts: [JSON.stringify(receiptFor(alice, { chunkId: 'c1', token: TOKEN }))],
    pinsText: pins([{ spkiB64u: alice.spkiB64u }]),
    chainTexts: [chain([[1, H1], [2, H2]])],
    inventoryTexts: [inventory()],
  });
  assert.equal(report.result, 'pass', JSON.stringify(report.findings));
  assert.deepEqual([report.approvals[0].verified, report.approvals[0].accepted], [true, true]);
});

test('Evaluate: hostile or unexpected input is still allowed and logged with a reason', async () => {
  const before = parseLog(fs.readFileSync(logPath, 'utf8')).records.length;
  const cases: [object, string | undefined][] = [
    [evaluation('validate', 'ApproveDraftChunk', { chunkId: 'c1' }), undefined],
    [evaluation('validate', 'ApproveDraftChunk', { chunkId: 'c1' }), bearer({ caller_kind: 'user' })],
    [evaluation('validate', 'ApproveDraftChunk', { chunkId: 'c1' }), 'Bearer garbage'],
    [evaluation('modify_operation', 'ApproveDraftChunk', { chunkId: 'c1' }), bearer()],
    [evaluation('validate', 'DeleteSandbox', { name: 'sb' }), bearer()],
    [{ method: 'ApproveDraftChunk' }, bearer()],
    [{ ...evaluation('validate', 'ApproveDraftChunk', {}), validate: { proposed_operation: { fields: { x: {} } } } }, bearer()],
  ];
  for (const [request, auth] of cases) {
    const result = await call('Evaluate', request, auth);
    assert.equal(result.error, null);
    assert.equal(result.value?.allowed, true);
    assert.equal(result.value?.patches, undefined);
  }
  // Raw bytes that are not an InterceptorEvaluation at all.
  const raw = await new Promise<{ error: grpc.ServiceError | null; value?: Record<string, unknown> }>((resolve) => {
    const def = (serviceDefinition(INTERCEPTOR_SERVICE) as unknown as Record<string, { path: string; responseDeserialize: (b: Buffer) => unknown }>).Evaluate;
    gateway.makeUnaryRequest(def.path, (b: Buffer) => b, def.responseDeserialize, Buffer.from([0x0a, 0xff, 0xff, 0xff]), new grpc.Metadata(), (error, value) => resolve({ error: error ?? null, value: value as Record<string, unknown> }));
  });
  assert.ok(raw.error === null ? raw.value?.allowed === true : raw.error.code !== grpc.status.PERMISSION_DENIED);
  const { records, problems } = parseLog(fs.readFileSync(logPath, 'utf8'));
  assert.deepEqual(problems, []);
  const added = records.slice(before).filter((r) => r.kind === 'evaluation') as Record<string, any>[];
  assert.equal(added.filter((r) => r.gateway_auth.mode === 'failed').length, 3);
  assert.ok(added.some((r) => typeof r.payload_error === 'string'));
  assert.ok(evaluationType);
});

test('log resumes its hash chain across an observer restart', async () => {
  const other = path.join(dir, 'resume.jsonl');
  const first = await startObserver({ listen: `unix://${path.join(dir, 'r1.sock')}`, logPath: other });
  await first.close();
  fs.appendFileSync(other, '{"torn":');
  const second = await startObserver({ listen: `unix://${path.join(dir, 'r2.sock')}`, logPath: other });
  await second.close();
  const { records, problems } = parseLog(fs.readFileSync(other, 'utf8'));
  assert.equal(records.length, 2);
  assert.deepEqual(problems.map((p) => p.code), ['log_malformed_line']);
  assert.equal(records[1].seq, 3, 'the torn line keeps its place in the sequence');
});
