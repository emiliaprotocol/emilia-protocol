// SPDX-License-Identifier: Apache-2.0
// End-to-end run against a real local OpenShell gateway with the Docker
// compute driver. Skipped unless OPENSHELL_BIN_DIR names a directory holding
// the official `openshell` and `openshell-gateway` release binaries and
// Docker is running. Everything it writes goes to E2E_WORK_DIR (or a new
// temporary directory), which it keeps as evidence.
//
// Scenario A (sandbox oar-a): three draft chunks from real denied
// connections, each signed by the pinned approver key, approved with the
// official CLI (`rule approve`, then `rule approve-all`). The check must pass.
//
// Scenario B (sandbox oar-b): a receipt from an unpinned key, an approval
// with no receipt, a receipt made stale by an intervening approval, an
// approval made while the observer is down, an operator `policy update`, and
// an operator `policy set`. The check must fail with exactly those findings.
//
// Scenario C (sandbox oar-c): --approval-mode auto. The auto-approval must be
// reported as its own category, not as a missing receipt.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { GatewayClient } from '../src/gateway-client.ts';
import type { ChunkView } from '../src/gateway-client.ts';
import { buildPayload, signEs256 } from '../src/receipt.ts';
import { b64u } from '../src/canonical.ts';
import { CHAIN_FORMAT, check } from '../src/check.ts';
import type { Report } from '../src/check.ts';

const BIN_DIR = process.env.OPENSHELL_BIN_DIR;
const dockerUp = spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8' }).status === 0;
const skip = !BIN_DIR
  ? 'set OPENSHELL_BIN_DIR to a directory with the openshell and openshell-gateway release binaries'
  : !dockerUp ? 'Docker is not running' : false;

const WORKSPACE = 'default';
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts');

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor<T>(what: string, fn: () => Promise<T | null> | T | null, timeoutMs: number, intervalMs = 1000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      if (value !== null && value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }
  throw new Error(`timed out waiting for ${what}${lastError ? `: ${String(lastError)}` : ''}`);
}

test('live OpenShell gateway: observe, sign, approve, check', { skip, timeout: 20 * 60_000 }, async () => {
  const work = process.env.E2E_WORK_DIR ?? fs.mkdtempSync(path.join(os.tmpdir(), 'oar-e2e-'));
  fs.mkdirSync(work, { recursive: true });
  // macOS caps unix socket paths at 104 bytes, so the socket gets a short directory.
  const sockDir = fs.mkdtempSync('/tmp/oar-');
  const socketPath = path.join(sockDir, 'obs.sock');
  const port = Number(process.env.E2E_PORT ?? 27690);
  const endpoint = `127.0.0.1:${port}`;
  const transcript: string[] = [];
  const note = (line: string) => {
    transcript.push(line);
    fs.appendFileSync(path.join(work, 'transcript.txt'), `${line}\n`);
  };

  // Gateway JWT key (Ed25519) and the observer's pin of its public half.
  const jwtDir = path.join(work, 'jwt');
  fs.mkdirSync(jwtDir, { recursive: true });
  const gatewayKeys = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(path.join(jwtDir, 'signing.pem'), gatewayKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  const gatewayPublicPem = gatewayKeys.publicKey.export({ format: 'pem', type: 'spki' }) as string;
  fs.writeFileSync(path.join(jwtDir, 'public.pem'), gatewayPublicPem);
  fs.writeFileSync(path.join(jwtDir, 'kid'), 'oar-e2e-kid\n');

  // Approver keys: one the reader pins, one it does not.
  const approver = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const stranger = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const approverSpki = approver.publicKey.export({ format: 'der', type: 'spki' });
  const strangerSpki = stranger.publicKey.export({ format: 'der', type: 'spki' });
  const pinsText = JSON.stringify({
    format: 'emilia.openshell.approver-pins.v1',
    approvers: [{ label: 'approver (demo local key)', public_key_spki: b64u(approverSpki), workspaces: [WORKSPACE] }],
  }, null, 2);
  fs.writeFileSync(path.join(work, 'pins.json'), `${pinsText}\n`);

  const logPath = path.join(work, 'observer.jsonl');
  const reader = new GatewayClient({ endpoint });
  // The observer runs as its own process, as it would in a deployment. (In
  // the test process, spawnSync of the CLI would block its event loop and the
  // gateway would time the evaluations out and fail open.)
  const startObserverProcess = async (): Promise<ChildProcess> => {
    const stderrFd = fs.openSync(path.join(work, 'observer.stderr'), 'a');
    const child = spawn(process.execPath, [
      CLI, 'observe', '--listen', `unix://${socketPath}`, '--log', logPath, '--name', 'emilia-observer',
      '--gateway-public-key', path.join(jwtDir, 'public.pem'), '--gateway-id', 'oar-e2e', '--gateway', endpoint,
    ], { stdio: ['ignore', 'ignore', stderrFd] });
    fs.closeSync(stderrFd);
    await waitFor('the observer socket', () => (fs.existsSync(socketPath) ? true : null), 20_000, 100);
    note(`observer pid ${child.pid} on unix://${socketPath}`);
    return child;
  };
  const stopObserverProcess = async (child: ChildProcess): Promise<void> => {
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGTERM');
    await Promise.race([exited, sleep(10_000)]);
  };
  // Every post_commit in the log gets a gateway_read record right after it.
  const waitForReads = () => waitFor('the observer to log its post-commit gateway reads', () => {
    const records = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
    const commits = records.filter((r) => r.kind === 'evaluation' && r.phase === 'post_commit').map((r) => r.seq);
    const read = new Set(records.filter((r) => r.kind === 'gateway_read').map((r) => r.for_seq));
    return commits.every((seq) => read.has(seq)) ? true : null;
  }, 20_000, 200);
  let observer: ChildProcess | null = await startObserverProcess();

  const dockerEndpoint = process.env.E2E_DOCKER_GRPC_ENDPOINT ?? (process.platform === 'darwin' ? `http://host.docker.internal:${port}` : '');
  const toml = `[openshell]
version = 2

[openshell.gateway]
compute_driver = "docker"

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${path.join(jwtDir, 'signing.pem')}"
public_key_path = "${path.join(jwtDir, 'public.pem')}"
kid_path = "${path.join(jwtDir, 'kid')}"
gateway_id = "oar-e2e"

[[openshell.gateway.interceptors]]
name = "emilia-observer"
grpc_endpoint = "unix://${socketPath}"
failure_policy = "fail_open"
binding_policy = "allowlist"
timeout = "500ms"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ApproveDraftChunk"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ApproveAllDraftChunks"
phases = ["validate", "post_commit"]
${dockerEndpoint ? `\n[openshell.drivers.docker]\ngrpc_endpoint = "${dockerEndpoint}"\n` : ''}`;
  fs.writeFileSync(path.join(work, 'gateway.toml'), toml);

  const gatewayLogPath = path.join(work, 'gateway.log');
  const gatewayLogFd = fs.openSync(gatewayLogPath, 'a');
  const gateway = spawn(path.join(BIN_DIR as string, 'openshell-gateway'), [
    '--config', path.join(work, 'gateway.toml'), '--port', String(port), '--health-port', String(port + 1),
    '--disable-tls', '--db-url', `sqlite:${path.join(work, 'gw.db')}`,
  ], { stdio: ['ignore', gatewayLogFd, gatewayLogFd], env: { ...process.env, NO_COLOR: '1' } });
  note(`gateway pid ${gateway.pid} on ${endpoint}`);

  const xdg = path.join(work, 'xdg');
  const cliEnv = { ...process.env, XDG_CONFIG_HOME: `${xdg}/config`, XDG_STATE_HOME: `${xdg}/state`, XDG_DATA_HOME: `${xdg}/data`, XDG_CACHE_HOME: `${xdg}/cache`, NO_COLOR: '1' };
  delete (cliEnv as Record<string, string | undefined>).OPENSHELL_GATEWAY;
  delete (cliEnv as Record<string, string | undefined>).OPENSHELL_SANDBOX_POLICY;
  const cli = (args: string[], timeoutMs = 120_000) => {
    const result = spawnSync(path.join(BIN_DIR as string, 'openshell'), ['--gateway-endpoint', `http://${endpoint}`, ...args], { env: cliEnv, encoding: 'utf8', timeout: timeoutMs });
    note(`$ openshell ${args.join(' ')}  -> exit ${result.status}`);
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
    if (output) note(output.split('\n').slice(0, 12).map((l) => `    ${l}`).join('\n'));
    return result;
  };

  const receiptsA: string[] = [];
  const receiptsB: string[] = [];
  const sandboxes: string[] = [];
  const pendingChunk = async (sandbox: string, host: string): Promise<ChunkView> => waitFor(`a pending chunk for ${host} in ${sandbox}`, async () => {
    const chunks = await reader.getDraftChunks(WORKSPACE, sandbox, 'pending');
    return chunks.find((c) => JSON.stringify(c.proposed_rule ?? {}).includes(`"host":"${host}"`)) ?? null;
  }, 90_000, 2000);
  const deny = (sandbox: string, host: string) => cli(['sandbox', 'exec', '--name', sandbox, '--', 'bash', '-c', `(exec 3<>/dev/tcp/${host}/443) 2>/dev/null; true`]);
  const sign = (sandbox: string, chunk: ChunkView, key: crypto.KeyObject, spki: Buffer): string => {
    const payload = buildPayload({ workspace: WORKSPACE, sandbox, chunk, publicKeySpkiDer: spki });
    assert.ok(payload.ok, payload.ok ? '' : payload.reason);
    const receipt = JSON.stringify(signEs256(payload.value, key));
    note(`signed receipt for ${sandbox}/${chunk.chunk_id} rule=${chunk.rule_name} digest=${chunk.rule_digest} token=${chunk.review_token.slice(0, 12)}...`);
    return receipt;
  };
  // The gateway refreshes a review token lazily: an approval sent with a token
  // made stale by an earlier approval is refused with "proposal inputs
  // changed; evaluation refreshed, refetch and review again". The CLI does not
  // retry, so the test does, the way a reviewing client would.
  const approve = (sandbox: string, chunkId: string): void => {
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      if (cli(['rule', 'approve', sandbox, '--chunk-id', chunkId]).status === 0) return;
    }
    assert.fail(`approving ${chunkId} failed three times`);
  };
  const createSandbox = async (name: string, extra: string[] = []) => {
    const created = cli(['sandbox', 'create', '--name', name, '--no-auto-providers', '--no-tty', '--detach', ...extra, '--', 'sleep', '3600'], 300_000);
    assert.equal(created.status, 0, `sandbox create ${name} failed`);
    sandboxes.push(name);
    await waitFor(`${name} to run commands`, () => (spawnSync(path.join(BIN_DIR as string, 'openshell'), ['--gateway-endpoint', `http://${endpoint}`, 'sandbox', 'exec', '--name', name, '--', 'true'], { env: cliEnv, timeout: 30_000 }).status === 0 ? true : null), 180_000, 2000);
  };
  const exportChain = async (sandbox: string): Promise<string> => {
    const doc = {
      format: CHAIN_FORMAT, workspace: WORKSPACE, sandbox,
      sandbox_id: await reader.getSandboxId(WORKSPACE, sandbox),
      read_at: new Date().toISOString(),
      revisions: await reader.listPolicyRevisions(WORKSPACE, sandbox),
    };
    const text = `${JSON.stringify(doc, null, 2)}\n`;
    fs.writeFileSync(path.join(work, `chain-${sandbox}.json`), text);
    note(`chain ${sandbox}: ${doc.revisions.map((r) => `v${r.version}:${r.policy_hash.slice(0, 12)}`).join(' ')}`);
    return text;
  };
  const writeReport = (name: string, report: Report) => {
    fs.writeFileSync(path.join(work, name), `${JSON.stringify(report, null, 2)}\n`);
    note(`${name}: result=${report.result} summary=${JSON.stringify(report.summary)}`);
    for (const f of report.findings) note(`    finding ${f.code}: ${f.message}`);
    for (const t of report.chain) note(`    chain ${t.sandbox} v${t.version} ${t.classification}`);
  };

  try {
    await waitFor('the gateway to answer', () => (cli(['sandbox', 'list'], 10_000).status === 0 ? true : null), 90_000, 1500);

    // Scenario A: everything receipted.
    await createSandbox('oar-a');
    deny('oar-a', 'example.com');
    const a1 = await pendingChunk('oar-a', 'example.com');
    receiptsA.push(sign('oar-a', a1, approver.privateKey, approverSpki));
    approve('oar-a', a1.chunk_id);
    deny('oar-a', 'example.org');
    deny('oar-a', 'iana.org');
    const a2 = await pendingChunk('oar-a', 'example.org');
    const a3 = await pendingChunk('oar-a', 'iana.org');
    receiptsA.push(sign('oar-a', a2, approver.privateKey, approverSpki));
    receiptsA.push(sign('oar-a', a3, approver.privateKey, approverSpki));
    assert.equal(cli(['rule', 'approve-all', 'oar-a']).status, 0);
    await waitForReads();
    fs.writeFileSync(path.join(work, 'receipts-a.jsonl'), `${receiptsA.join('\n')}\n`);
    fs.copyFileSync(logPath, path.join(work, 'observer-after-a.jsonl'));
    fs.copyFileSync(gatewayLogPath, path.join(work, 'gateway-after-a.log'));
    const chainA = await exportChain('oar-a');
    const reportA = check({
      logText: fs.readFileSync(path.join(work, 'observer-after-a.jsonl'), 'utf8'),
      receiptTexts: [receiptsA.join('\n')],
      pinsText,
      chainTexts: [chainA],
      gatewayLogText: fs.readFileSync(path.join(work, 'gateway-after-a.log'), 'utf8'),
    });
    writeReport('report-a.json', reportA);
    assert.equal(reportA.result, 'pass', JSON.stringify(reportA.findings, null, 2));
    assert.equal(reportA.summary.committed_approvals, 3);
    assert.equal(reportA.summary.accepted, 3);
    assert.ok(reportA.approvals.every((a) => a.verified && a.accepted && a.pairing === 'confirmed'));

    // Scenario B: every way it should fail.
    await createSandbox('oar-b');
    deny('oar-b', 'example.net');
    deny('oar-b', 'www.w3.org');
    deny('oar-b', 'www.ietf.org');
    const b1 = await pendingChunk('oar-b', 'example.net');
    const b2 = await pendingChunk('oar-b', 'www.w3.org');
    const b3 = await pendingChunk('oar-b', 'www.ietf.org');
    receiptsB.push(sign('oar-b', b1, stranger.privateKey, strangerSpki)); // not pinned
    approve('oar-b', b1.chunk_id);
    const b2Now = (await reader.getDraftChunks(WORKSPACE, 'oar-b', 'pending')).find((c) => c.chunk_id === b2.chunk_id) ?? b2;
    receiptsB.push(sign('oar-b', b2Now, approver.privateKey, approverSpki)); // goes stale below
    approve('oar-b', b3.chunk_id); // no receipt at all
    approve('oar-b', b2.chunk_id); // commits under a newer token than the one signed
    deny('oar-b', 'www.rfc-editor.org');
    const b4 = await pendingChunk('oar-b', 'www.rfc-editor.org');
    receiptsB.push(sign('oar-b', b4, approver.privateKey, approverSpki));
    await waitForReads();
    await stopObserverProcess(observer);
    observer = null;
    note('observer stopped');
    approve('oar-b', b4.chunk_id); // must commit while the observer is down
    assert.equal(cli(['policy', 'update', 'oar-b', '--add-endpoint', 'example.edu:443', '--binary', '/usr/bin/bash', '--rule-name', 'operator_update', '--wait', '--timeout', '60']).status, 0);
    const policyFile = path.join(work, 'policy-set.yaml');
    fs.writeFileSync(policyFile, `version: 1
filesystem_policy:
  include_workdir: true
  read_only:
    - /bin
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /etc
    - /var/log
  read_write:
    - /tmp
    - /dev/null
landlock:
  compatibility: best_effort
network_policies:
  operator_direct_widen:
    name: operator_direct_widen
    endpoints:
      - host: www.python.org
        port: 443
    binaries:
      - path: /usr/bin/bash
`);
    assert.equal(cli(['policy', 'set', 'oar-b', '--policy', policyFile, '--yes', '--wait', '--timeout', '60']).status, 0);
    fs.writeFileSync(path.join(work, 'receipts-b.jsonl'), `${receiptsB.join('\n')}\n`);
    const chainB = await exportChain('oar-b');

    // Scenario C: auto-approval.
    await createSandbox('oar-c', ['--approval-mode', 'auto']);
    deny('oar-c', 'example.com');
    const chainC = await waitFor('an auto-approved version in oar-c', async () => {
      const revisions = await reader.listPolicyRevisions(WORKSPACE, 'oar-c');
      return revisions.length >= 2 ? true : null;
    }, 90_000, 2000).then(() => exportChain('oar-c'));

    await sleep(500);
    const full = check({
      logText: fs.readFileSync(logPath, 'utf8'),
      receiptTexts: [receiptsA.join('\n'), receiptsB.join('\n')],
      pinsText,
      chainTexts: [chainA, chainB, chainC],
      gatewayLogText: fs.readFileSync(gatewayLogPath, 'utf8'),
    });
    writeReport('report-full.json', full);
    assert.equal(full.result, 'fail');
    const codes = full.findings.map((f) => f.code).sort();
    assert.deepEqual(codes, [
      'approval_not_observed',
      'approval_without_receipt',
      'policy_change_without_approval',
      'receipt_key_not_accepted',
      'receipt_token_mismatch',
      'receipt_without_committed_approval',
      'unexplained_policy_change',
    ]);
    assert.equal(full.approvals.filter((a) => a.accepted).length, 3);
    assert.ok(full.chain.some((t) => t.sandbox === 'oar-c' && t.classification === 'auto_approval'));
    const byChunk = new Map(full.approvals.map((a) => [a.chunk_id, a]));
    assert.equal(byChunk.get(b1.chunk_id)?.verified, true);
    assert.equal(byChunk.get(b1.chunk_id)?.accepted, false);
    assert.equal(byChunk.get(b2.chunk_id)?.verified, false);
    assert.equal(byChunk.get(b3.chunk_id)?.receipts.length, 0);
    assert.equal(byChunk.has(b4.chunk_id), false);
  } finally {
    for (const name of sandboxes) cli(['sandbox', 'delete', name], 120_000);
    gateway.kill('SIGTERM');
    await new Promise((resolve) => { gateway.once('exit', resolve); setTimeout(resolve, 10_000); });
    fs.closeSync(gatewayLogFd);
    if (observer) await stopObserverProcess(observer);
    reader.close();
    fs.rmSync(sockDir, { recursive: true, force: true });
    note(`evidence kept in ${work}`);
  }
});
