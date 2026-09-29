// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { RULE, T0, chain, hex, logText, postCommit, read, start, validate } from './helpers.ts';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oar-cli-'));
const run = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', cwd: dir });
const TOKEN = hex('token-c1');

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
  const pass = run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--receipts', 'receipt.json', '--chain', 'chain.json');
  assert.equal(pass.status, 0, pass.stdout);
  assert.equal(JSON.parse(pass.stdout).result, 'pass');
  assert.equal(run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--receipts', 'receipt.json').status, 3);
  const fail = run('check', '--log', 'log.jsonl', '--pins', 'pins.json', '--chain', 'chain.json');
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
  fs.rmSync(dir, { recursive: true, force: true });
});
