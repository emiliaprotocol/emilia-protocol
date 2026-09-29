#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// openshell-approver-receipts: observe | keygen | pubkey | drafts | sign | chain | check

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { startObserver } from './observer.ts';
import { GatewayClient } from './gateway-client.ts';
import type { ChunkView } from './gateway-client.ts';
import { buildPayload, keyIdFromSpki, signEs256 } from './receipt.ts';
import { b64u, canonicalRule, ruleDigest } from './canonical.ts';
import { CHAIN_FORMAT, INVENTORY_FORMAT, check } from './check.ts';
import { describeRule, displaySafe, safeJson, tokenFreshness } from './display.ts';
import type { Freshness } from './display.ts';

const USAGE = `usage: openshell-approver-receipts <command> [options]

  observe  --listen unix:///path.sock --log observer.jsonl
           [--name emilia-observer] [--audience urn:...]
           [--gateway-public-key gateway-jwt.pub.pem --gateway-id <id>]
           [--gateway <endpoint> [--gateway-token-file f] [--gateway-ca f]]
           [--tls-cert f --tls-key f] [--read-window-ms 30000]
  keygen   --out approver.key.pem             (demo only: a local P-256 key)
  pubkey   --key approver.key.pem
  drafts   --gateway <endpoint> --workspace default --sandbox <name> [--status pending]
  sign     --key approver.key.pem --workspace default --sandbox <name> --chunk-id <id>
           (--gateway <endpoint> | --draft-json chunks.json) [--out receipt.json] [--yes]
           [--allow-policy-hash-mismatch]
  chain    --gateway <endpoint> --workspace default --sandbox <name> [--out chain.json]
  chain    --gateway <endpoint> --workspace default --all --out-dir dir
           (writes dir/inventory.json and dir/chain-<sandbox>.json for every sandbox)
  check    --log observer.jsonl --pins pins.json [--receipts r.json ...]
           [--chains-dir dir | --chain chain.json ... --inventory inventory.json ...]
           [--gateway-log gateway.log [--trust-gateway-log]]
           [--window-ms 30000] [--skew-seconds 300]

exit codes (check): 0 pass, 1 findings, 3 incomplete (a policy chain or sandbox
inventory is missing, or a version is explained only by the unauthenticated
gateway log), 2 refused input`;

class Refusal extends Error {}

function need(values: Record<string, unknown>, ...names: string[]): void {
  const missing = names.filter((n) => values[n] === undefined || values[n] === '');
  if (missing.length > 0) throw new Refusal(`missing --${missing.join(', --')}`);
}

function positiveInt(raw: string | undefined, name: string): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Refusal(`--${name} must be a positive integer`);
  return n;
}

function readText(file: string): string {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new Refusal(`cannot read ${file}: ${(error as Error).message}`);
  }
}

function gatewayClient(values: Record<string, unknown>): GatewayClient {
  need(values, 'gateway');
  return GatewayClient.fromCli(values.gateway as string, values['gateway-token-file'] as string | undefined, values['gateway-ca'] as string | undefined);
}

function loadPrivateKey(file: string): crypto.KeyObject {
  const key = crypto.createPrivateKey(readText(file));
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Refusal('approver key must be an EC P-256 private key');
  return key;
}

function chunkFromDraftJson(text: string, chunkId: string): ChunkView {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { throw new Refusal('--draft-json is not JSON'); }
  const list = Array.isArray(doc) ? doc : (doc as { chunks?: unknown }).chunks;
  if (!Array.isArray(list)) throw new Refusal('--draft-json must be a list of chunks or {"chunks": [...]}');
  const raw = list.find((c) => c && typeof c === 'object' && ((c as Record<string, unknown>).chunk_id === chunkId || (c as Record<string, unknown>).id === chunkId)) as Record<string, unknown> | undefined;
  if (!raw) throw new Refusal(`chunk ${chunkId} is not in --draft-json`);
  const rule = canonicalRule(raw.proposed_rule);
  if (!rule.ok) throw new Refusal(rule.reason);
  const digest = ruleDigest(rule.value);
  if (!digest.ok) throw new Refusal(digest.reason);
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  return {
    chunk_id: chunkId, status: str(raw.status), rule_name: str(raw.rule_name), review_token: str(raw.review_token),
    candidate_effective_policy_hash: str(raw.candidate_effective_policy_hash), current_effective_policy_hash: str(raw.current_effective_policy_hash),
    // The export's security_notes are ignored: the receipt does not cover them,
    // and whoever produced the file chose them.
    security_notes: '', decided_time: null, proposed_rule: rule.value, rule_digest: digest.value,
  };
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  const { values } = parseArgs({
    args: rest,
    strict: true,
    options: {
      listen: { type: 'string' }, log: { type: 'string' }, name: { type: 'string' }, audience: { type: 'string' },
      'gateway-public-key': { type: 'string' }, 'gateway-id': { type: 'string' },
      gateway: { type: 'string' }, 'gateway-token-file': { type: 'string' }, 'gateway-ca': { type: 'string' },
      'tls-cert': { type: 'string' }, 'tls-key': { type: 'string' }, 'read-window-ms': { type: 'string' },
      out: { type: 'string' }, key: { type: 'string' }, workspace: { type: 'string' }, sandbox: { type: 'string' },
      status: { type: 'string' }, 'chunk-id': { type: 'string' }, 'draft-json': { type: 'string' }, yes: { type: 'boolean' },
      'allow-policy-hash-mismatch': { type: 'boolean' },
      pins: { type: 'string' }, receipts: { type: 'string', multiple: true }, chain: { type: 'string', multiple: true },
      inventory: { type: 'string', multiple: true }, all: { type: 'boolean' }, 'out-dir': { type: 'string' }, 'chains-dir': { type: 'string' },
      'gateway-log': { type: 'string' }, 'trust-gateway-log': { type: 'boolean' }, 'window-ms': { type: 'string' }, 'skew-seconds': { type: 'string' },
      help: { type: 'boolean' },
    },
  });
  if (!command || values.help || command === 'help') {
    process.stdout.write(`${USAGE}\n`);
    return command ? 0 : 2;
  }

  switch (command) {
    case 'observe': {
      need(values, 'listen', 'log');
      if (Boolean(values['gateway-public-key']) !== Boolean(values['gateway-id'])) throw new Refusal('--gateway-public-key and --gateway-id go together');
      if (Boolean(values['tls-cert']) !== Boolean(values['tls-key'])) throw new Refusal('--tls-cert and --tls-key go together');
      const observer = await startObserver({
        listen: values.listen as string,
        logPath: values.log as string,
        name: values.name,
        audience: values.audience,
        gatewayJwt: values['gateway-public-key'] ? { publicKeyPem: readText(values['gateway-public-key']), gatewayId: values['gateway-id'] as string } : null,
        reader: values.gateway ? gatewayClient(values) : null,
        tls: values['tls-cert'] ? { certPem: fs.readFileSync(values['tls-cert']), keyPem: fs.readFileSync(values['tls-key'] as string) } : null,
        readWindowMs: positiveInt(values['read-window-ms'], 'read-window-ms'),
      });
      process.stderr.write(`observer listening on ${observer.address}; audience ${observer.audience}; log ${values.log}\n`);
      await new Promise<void>((resolve) => {
        const stop = () => resolve();
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
      });
      await observer.close();
      return 0;
    }
    case 'keygen': {
      need(values, 'out');
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      fs.writeFileSync(values.out as string, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600, flag: 'wx' });
      const spki = publicKey.export({ format: 'der', type: 'spki' });
      process.stdout.write(`${JSON.stringify({ kid: keyIdFromSpki(spki), public_key_spki: b64u(spki) }, null, 2)}\n`);
      return 0;
    }
    case 'pubkey': {
      need(values, 'key');
      const spki = crypto.createPublicKey(loadPrivateKey(values.key as string)).export({ format: 'der', type: 'spki' });
      process.stdout.write(`${JSON.stringify({ kid: keyIdFromSpki(spki), public_key_spki: b64u(spki) }, null, 2)}\n`);
      return 0;
    }
    case 'drafts': {
      need(values, 'workspace', 'sandbox');
      const client = gatewayClient(values);
      try {
        const chunks = await client.getDraftChunks(values.workspace as string, values.sandbox as string, values.status ?? '');
        process.stdout.write(`${safeJson({ chunks })}\n`);
      } finally { client.close(); }
      return 0;
    }
    case 'sign': {
      need(values, 'key', 'workspace', 'sandbox', 'chunk-id');
      const privateKey = loadPrivateKey(values.key as string);
      const workspace = values.workspace as string;
      const sandbox = values.sandbox as string;
      const chunkId = values['chunk-id'] as string;
      let chunk: ChunkView;
      let fresh: Freshness | null = null;
      if (values['draft-json']) {
        chunk = chunkFromDraftJson(readText(values['draft-json']), chunkId);
      } else {
        const client = gatewayClient(values);
        try {
          // The chunk first, then the revisions: an approval that lands in
          // between makes the check refuse rather than pass.
          const chunks = await client.getDraftChunks(workspace, sandbox);
          const revisions = await client.listPolicyRevisions(workspace, sandbox);
          const info = await client.getSandbox(workspace, sandbox);
          const found = chunks.find((c) => c.chunk_id === chunkId);
          if (!found) throw new Refusal(`chunk ${chunkId} is not in ${workspace}/${sandbox}`);
          chunk = found;
          fresh = tokenFreshness(chunk, sandbox, revisions, info.providers);
        } finally { client.close(); }
      }
      if (chunk.rule_error) throw new Refusal(`refusing to sign: ${chunk.rule_error}`);
      if (chunk.status && chunk.status !== 'pending' && chunk.status !== 'rejected') throw new Refusal(`chunk status is ${chunk.status}; only a pending or rejected chunk can be approved`);
      // A token the gateway will refuse makes a receipt that can never verify.
      const warnings: string[] = [];
      if (fresh?.status === 'stale') {
        if (!values['allow-policy-hash-mismatch']) throw new Refusal(fresh.message);
        warnings.push(`warning: ${fresh.message}`);
      } else if (fresh?.status === 'unchecked') {
        warnings.push(`warning: token freshness ${fresh.message}`);
      }
      const freshness = fresh ? fresh.message : 'not checked offline: if another chunk in this sandbox was approved after this export, the gateway refuses this token';
      const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
      // Refuse anything the receipt cannot carry before showing it.
      const preview = buildPayload({ workspace, sandbox, chunk, publicKeySpkiDer: spki });
      if (!preview.ok) throw new Refusal(preview.reason);
      process.stderr.write(`${displaySafe(`Approving in ${workspace}/${sandbox}, chunk ${chunkId}:`)}\n${describeRule(chunk, { notes: values['draft-json'] ? 'offline' : 'gateway', freshness })}\n`);
      for (const w of warnings) process.stderr.write(`${displaySafe(w)}\n`);
      if (!values.yes) {
        if (!process.stdin.isTTY) throw new Refusal('not a terminal: pass --yes to sign without a prompt');
        const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
        const answer = await rl.question('Sign this approval? [y/N] ');
        rl.close();
        if (answer.trim().toLowerCase() !== 'y') throw new Refusal('not signed');
      }
      const payload = buildPayload({ workspace, sandbox, chunk, publicKeySpkiDer: spki });
      if (!payload.ok) throw new Refusal(payload.reason);
      const receipt = signEs256(payload.value, privateKey);
      const text = `${JSON.stringify(receipt, null, 2)}\n`;
      if (values.out) fs.writeFileSync(values.out, text, { flag: 'wx' });
      else process.stdout.write(text);
      return 0;
    }
    case 'chain': {
      need(values, 'workspace');
      const workspace = values.workspace as string;
      if (Boolean(values.all) === Boolean(values.sandbox)) throw new Refusal('chain takes --sandbox <name> or --all');
      if (values.all && !values['out-dir']) throw new Refusal('chain --all needs --out-dir');
      const client = gatewayClient(values);
      const chainDoc = async (sandbox: string, sandboxId?: string) => ({
        format: CHAIN_FORMAT,
        workspace,
        sandbox,
        sandbox_id: sandboxId ?? await client.getSandboxId(workspace, sandbox),
        read_at: new Date().toISOString(),
        revisions: await client.listPolicyRevisions(workspace, sandbox),
      });
      try {
        if (!values.all) {
          const text = `${safeJson(await chainDoc(values.sandbox as string))}\n`;
          if (values.out) fs.writeFileSync(values.out, text);
          else process.stdout.write(text);
          return 0;
        }
        // The inventory is read first: a sandbox created later is not in it,
        // and still needs a chain if either log shows activity in it.
        const outDir = values['out-dir'] as string;
        const readAt = new Date().toISOString();
        const sandboxes = await client.listSandboxes(workspace);
        fs.mkdirSync(outDir, { recursive: true });
        const written: string[] = [];
        const safeName = (name: string, id: string) => (/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name) ? name : `id-${id.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128)}`);
        for (const sb of sandboxes) {
          const file = path.join(outDir, `chain-${safeName(sb.sandbox, sb.sandbox_id)}.json`);
          fs.writeFileSync(file, `${safeJson(await chainDoc(sb.sandbox, sb.sandbox_id))}\n`);
          written.push(file);
        }
        const inventoryFile = path.join(outDir, 'inventory.json');
        fs.writeFileSync(inventoryFile, `${safeJson({ format: INVENTORY_FORMAT, workspace, read_at: readAt, sandboxes })}\n`);
        process.stderr.write(`${displaySafe(`${sandboxes.length} sandbox(es) in ${workspace}: wrote ${[inventoryFile, ...written].join(', ')}`)}\n`);
      } finally { client.close(); }
      return 0;
    }
    case 'check': {
      need(values, 'log', 'pins');
      if (values['trust-gateway-log'] && !values['gateway-log']) throw new Refusal('--trust-gateway-log needs --gateway-log');
      // --chains-dir: what `chain --all --out-dir` wrote.
      const fromChainsDir: { chains: string[]; inventory: string[] } = { chains: [], inventory: [] };
      if (values['chains-dir']) {
        const dir = values['chains-dir'];
        let names: string[];
        try { names = fs.readdirSync(dir).sort(); } catch (error) { throw new Refusal(`cannot read ${dir}: ${(error as Error).message}`); }
        if (!names.includes('inventory.json')) throw new Refusal(`${dir} has no inventory.json (write it with chain --all)`);
        fromChainsDir.inventory.push(path.join(dir, 'inventory.json'));
        fromChainsDir.chains.push(...names.filter((n) => n.startsWith('chain-') && n.endsWith('.json')).map((n) => path.join(dir, n)));
      }
      const numberOpt = (name: string): number | undefined => {
        const raw = values[name as keyof typeof values];
        if (raw === undefined) return undefined;
        const n = Number(raw);
        if (!Number.isSafeInteger(n) || n < 0) throw new Refusal(`--${name} must be a non-negative integer`);
        return n;
      };
      const report = check({
        logText: readText(values.log as string),
        pinsText: readText(values.pins as string),
        receiptTexts: (values.receipts ?? []).map(readText),
        chainTexts: [...(values.chain ?? []), ...fromChainsDir.chains].map(readText),
        inventoryTexts: [...(values.inventory ?? []), ...fromChainsDir.inventory].map(readText),
        gatewayLogText: values['gateway-log'] ? readText(values['gateway-log']) : undefined,
        trustGatewayLog: values['trust-gateway-log'] === true,
        pairingWindowMs: numberOpt('window-ms'),
        issuedAfterCommitSkewSeconds: numberOpt('skew-seconds'),
      });
      process.stdout.write(`${safeJson(report)}\n`);
      return report.result === 'pass' ? 0 : report.result === 'fail' ? 1 : 3;
    }
    default:
      process.stderr.write(`${USAGE}\n`);
      throw new Refusal(`unknown command ${command}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`refused: ${displaySafe(message)}\n`);
    process.exitCode = 2;
  },
);
