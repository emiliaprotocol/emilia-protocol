// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';
import grpc from '@grpc/grpc-js';
import { OPENSHELL_SERVICE, serviceDefinition } from '../src/protos.ts';
import { RULE, T0, chain, hex, inventory, logText, postCommit, read, start, validate } from './helpers.ts';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oar-cli-'));
const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', cwd: dir });
const TOKEN = hex('token-c1');
after(() => fs.rmSync(dir, { recursive: true, force: true }));

test('keygen, pubkey, sign from a GetDraftPolicy export, check: exit codes 0 / 1 / 3 / 2', () => {
  const key = path.join(dir, 'approver.key.pem');
  const gen = run('keygen', '--out', key);
  assert.equal(gen.status, 0, gen.stderr);
  const { kid, public_key_spki } = JSON.parse(gen.stdout) as { kid: string; public_key_spki: string };
  assert.equal((fs.statSync(key).mode & 0o777).toString(8), '600');
  assert.deepEqual(JSON.parse(run('pubkey', '--key', key).stdout), { kid, public_key_spki });
  assert.equal(run('keygen', '--out', key).status, 2, 'never overwrites a key');

  // The shape a GetDraftPolicy client prints (original proto field names).
  const drafts = path.join(dir, 'drafts.json');
  fs.writeFileSync(drafts, JSON.stringify({ chunks: [{ id: 'c1', status: 'pending', rule_name: RULE.name, proposed_rule: RULE, review_token: TOKEN, candidate_effective_policy_hash: hex('cand') }] }));
  const receiptPath = path.join(dir, 'receipt.json');
  const signed = run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts, '--yes', '--out', receiptPath);
  assert.equal(signed.status, 0, signed.stderr);
  assert.match(signed.stderr, /sandbox rule\s+allow_example_com_443/);
  assert.match(signed.stderr, /endpoint\s+\{"advisor_proposed":true,"host":"example.com"/);
  assert.equal(JSON.parse(fs.readFileSync(receiptPath, 'utf8')).payload.approver_kid, kid);
  assert.equal(run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts).status, 2, 'no TTY and no --yes: refuses');

  const H1 = hex('v1');
  const H2 = hex('v2');
  // The commit happens after the receipt was signed, as it would live.
  const now = Date.now() - T0 + 5_000;
  fs.writeFileSync(path.join(dir, 'log.jsonl'), logText([
    start(), validate(now, { chunkId: 'c1', token: TOKEN }), postCommit(now + 5, { version: 2, hash: H2 }),
    read(now + 10, 3, { chunks: [{ id: 'c1', token: TOKEN }], revisions: [[1, H1], [2, H2]] }),
  ]));
  fs.writeFileSync(path.join(dir, 'pins.json'), JSON.stringify({ format: 'emilia.openshell.approver-pins.v1', approvers: [{ public_key_spki, workspaces: ['default'] }] }));
  fs.writeFileSync(path.join(dir, 'chain.json'), chain([[1, H1], [2, H2]]));
  fs.writeFileSync(path.join(dir, 'inventory.json'), inventory());
  const pass = run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--receipts', 'receipt.json', '--chain', 'chain.json', '--inventory', 'inventory.json');
  assert.equal(pass.status, 0, pass.stdout);
  assert.equal(JSON.parse(pass.stdout).result, 'pass');
  assert.equal(run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--receipts', 'receipt.json', '--inventory', 'inventory.json').status, 3, 'no chain');
  assert.equal(run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--receipts', 'receipt.json', '--chain', 'chain.json').status, 3, 'no inventory');
  assert.equal(run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--chain', 'chain.json', '--trust-gateway-log').status, 2, '--trust-gateway-log needs --gateway-log');
  const fail = run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--chain', 'chain.json', '--inventory', 'inventory.json');
  assert.equal(fail.status, 1);
  assert.deepEqual(JSON.parse(fail.stdout).findings.map((f: { code: string }) => f.code), ['approval_without_receipt']);

  assert.equal(run('check', '--pins', 'pins.json').status, 2);
  assert.match(run('check', '--log', 'missing.jsonl', '--pins', 'pins.json').stderr, /refused: cannot read/);
  assert.equal(run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--window-ms', '-1').status, 2);
  assert.equal(run('bogus').status, 2);
  assert.equal(run('check', '--nope').status, 2);
  const p384 = path.join(dir, 'p384.pem');
  fs.writeFileSync(p384, crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey.export({ format: 'pem', type: 'pkcs8' }));
  assert.match(run('pubkey', '--key', p384).stderr, /P-256/);
  fs.writeFileSync(drafts, JSON.stringify({ chunks: [{ id: 'c1', status: 'approved', rule_name: 'r', proposed_rule: { name: 'r', bogus: 1 }, review_token: TOKEN }] }));
  assert.match(run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts, '--yes').stderr, /not a field/);
});

const ESC = '\u001b';
// Characters a terminal acts on or reorders: C0, DEL, C1, bidi and line separators.
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

test('sign: the prompt shows no terminal control or bidi characters, and never an offline export\'s security notes', () => {
  const key = path.join(dir, 'escape.key.pem');
  assert.equal(run('keygen', '--out', key).status, 0);
  // Notes that redraw the two lines above them as a harmless rule.
  const notes = `(none)${ESC}[2K\r${ESC}[2A${ESC}[2K  endpoint       {"host":"api.github.com","port":443}\n${ESC}[2K  binary         {"path":"/usr/bin/git"}\n${ESC}[2K  security notes (none)`;
  const drafts = path.join(dir, 'hostile-drafts.json');
  fs.writeFileSync(drafts, JSON.stringify({ chunks: [{
    id: 'c1', status: 'pending', rule_name: 'allow_api_github_com_443', review_token: TOKEN, security_notes: notes,
    proposed_rule: {
      name: 'allow_api_github_com_443',
      endpoints: [{ host: '*.attacker.example\u202e', ports: [443], allow_uninspected_credentials: true, allowed_ips: ['10.0.0.0/8'] }],
      binaries: [{ path: `/bin/bash\u009b2A${ESC}]0;x\u0007` }],
    },
  }] }));
  const out = path.join(dir, 'escape-receipt.json');
  const signed = run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts, '--yes', '--out', out);
  assert.equal(signed.status, 0, signed.stderr);
  assert.doesNotMatch(signed.stderr, UNSAFE);
  assert.ok(!signed.stderr.includes(ESC));
  assert.doesNotMatch(signed.stderr, /api\.github\.com|\/usr\/bin\/git/, 'the export\'s notes are not shown');
  assert.match(signed.stderr, /\\u202e/, 'the bidi override is shown escaped');
  assert.match(signed.stderr, /\\u009b/);
  assert.match(signed.stderr, /security notes\s+not shown/);
  assert.match(signed.stderr, /wildcard host/);
  assert.match(signed.stderr, /allow_uninspected_credentials/);
  assert.match(signed.stderr, /allowed_ips/);
  // A rule name the receipt cannot carry is refused before anything is shown.
  fs.writeFileSync(drafts, JSON.stringify({ chunks: [{ id: 'c1', status: 'pending', rule_name: `x${ESC}[2Ay`, review_token: TOKEN, proposed_rule: RULE }] }));
  const refused = run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts, '--yes');
  assert.equal(refused.status, 2);
  assert.doesNotMatch(refused.stderr, UNSAFE);
  assert.doesNotMatch(refused.stderr, /Approving in/);
  // Status text from the export is escaped in the refusal too.
  fs.writeFileSync(drafts, JSON.stringify({ chunks: [{ id: 'c1', status: `approved${ESC}[2K`, rule_name: RULE.name, review_token: TOKEN, proposed_rule: RULE }] }));
  const badStatus = run('sign', '--key', key, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--draft-json', drafts, '--yes');
  assert.equal(badStatus.status, 2);
  assert.doesNotMatch(badStatus.stderr, UNSAFE);
});

function runAsync(...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: dir });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

test('sign --gateway: refuses a review token that predates the newest policy revision', async () => {
  const H1 = hex('v1');
  const H2 = hex('v2');
  // Stand-in OpenShell API. The chunk was evaluated at v1; another approval then made v2.
  const state = { current: H1, providers: [] as string[] };
  const apiSocket = path.join(dir, 'sign-api.sock');
  const api = new grpc.Server();
  api.addService(serviceDefinition(OPENSHELL_SERVICE), {
    GetSandbox: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, { sandbox: { metadata: { id: 'id-sb', name: 'sb' }, spec: { providers: state.providers } } }),
    GetDraftPolicy: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, {
      chunks: [{ id: 'c1', status: 'pending', rule_name: RULE.name, proposed_rule: RULE, review_token: TOKEN, current_effective_policy_hash: state.current, candidate_effective_policy_hash: hex('cand') }],
    }),
    ListSandboxPolicies: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, {
      revisions: [{ version: 2, policy_hash: H2, status: 'POLICY_STATUS_LOADED' }, { version: 1, policy_hash: H1, status: 'POLICY_STATUS_SUPERSEDED' }],
    }),
    ListSandboxes: (_call: unknown, cb: grpc.sendUnaryData<object>) => cb(null, { sandboxes: [{ metadata: { id: 'id-sb', name: 'sb' } }] }),
  } as unknown as grpc.UntypedServiceImplementation);
  await new Promise<void>((resolve, reject) => api.bindAsync(`unix://${apiSocket}`, grpc.ServerCredentials.createInsecure(), (e) => (e ? reject(e) : resolve())));
  try {
    const key = path.join(dir, 'gw.key.pem');
    assert.equal(run('keygen', '--out', key).status, 0);
    const sign = (out: string, ...extra: string[]) => runAsync('sign', '--key', key, '--gateway', `unix://${apiSocket}`, '--workspace', 'default', '--sandbox', 'sb', '--chunk-id', 'c1', '--yes', '--out', path.join(dir, out), ...extra);

    const stale = await sign('stale.json');
    assert.equal(stale.status, 2, stale.stderr);
    assert.match(stale.stderr, /predates policy v2/);
    assert.match(stale.stderr, /openshell rule approve sb --chunk-id c1/);
    assert.equal(fs.existsSync(path.join(dir, 'stale.json')), false);

    const forced = await sign('forced.json', '--allow-policy-hash-mismatch');
    assert.equal(forced.status, 0, forced.stderr);
    assert.match(forced.stderr, /warning: .*predates policy v2/);

    state.providers = ['github'];
    const layered = await sign('layered.json');
    assert.equal(layered.status, 2);
    assert.match(layered.stderr, /provider layers/);

    state.providers = [];
    state.current = H2;
    const fresh = await sign('fresh.json');
    assert.equal(fresh.status, 0, fresh.stderr);
    assert.doesNotMatch(fresh.stderr, /warning/);
    assert.match(fresh.stderr, /token freshness\s+current/);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'fresh.json'), 'utf8')).payload.review_token, TOKEN);

    // chain --all: the workspace inventory plus one chain per sandbox.
    const all = await runAsync('chain', '--gateway', `unix://${apiSocket}`, '--workspace', 'default', '--all', '--out-dir', path.join(dir, 'chains'));
    assert.equal(all.status, 0, all.stderr);
    const inv = JSON.parse(fs.readFileSync(path.join(dir, 'chains', 'inventory.json'), 'utf8'));
    assert.deepEqual([inv.format, inv.workspace, inv.sandboxes], ['emilia.openshell.sandbox-inventory.v1', 'default', [{ sandbox: 'sb', sandbox_id: 'id-sb' }]]);
    const exported = JSON.parse(fs.readFileSync(path.join(dir, 'chains', 'chain-sb.json'), 'utf8'));
    assert.deepEqual([exported.sandbox_id, exported.revisions.map((r: { version: number }) => r.version)], ['id-sb', [1, 2]]);
    // check --chains-dir reads exactly what chain --all wrote.
    const chainsLog = logText([
      start(), validate(Date.now() - T0, { chunkId: 'c1', token: TOKEN }), postCommit(Date.now() - T0 + 5, { version: 2, hash: H2 }),
      read(Date.now() - T0 + 10, 3, { chunks: [{ id: 'c1', token: TOKEN }], revisions: [[1, H1], [2, H2]] }),
    ]);
    fs.writeFileSync(path.join(dir, 'chains-log.jsonl'), chainsLog);
    fs.writeFileSync(path.join(dir, 'chains-pins.json'), JSON.stringify({ format: 'emilia.openshell.approver-pins.v1', approvers: [{ public_key_spki: JSON.parse(run('pubkey', '--key', key).stdout).public_key_spki, workspaces: ['default'] }] }));
    const viaDir = run('check', '--log', 'chains-log.jsonl', '--pins', 'chains-pins.json', '--receipts', 'fresh.json', '--chains-dir', 'chains');
    assert.equal(viaDir.status, 0, viaDir.stdout);
    assert.deepEqual(JSON.parse(viaDir.stdout).completeness.inventoried_workspaces, ['default']);
    assert.equal(run('check', '--log', 'chains-log.jsonl', '--pins', 'chains-pins.json', '--chains-dir', 'nowhere').status, 2);
    assert.equal((await runAsync('chain', '--gateway', `unix://${apiSocket}`, '--workspace', 'default')).status, 2, 'needs --sandbox or --all');
    assert.equal((await runAsync('chain', '--gateway', `unix://${apiSocket}`, '--workspace', 'default', '--all')).status, 2, '--all needs --out-dir');
  } finally {
    api.forceShutdown();
  }
});
