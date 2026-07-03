#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * POC approver — mint a named-human authorization receipt bound to ONE exact
 * Claude Code command, for trying the zero-friction wedge end to end. This
 * stands in for the real signing surface (a passkey / Face ID ceremony on the
 * approver's own device); the receipt it produces is byte-compatible with the
 * one that surface emits and is verified by the same gate.
 *
 *   node examples/claude-code/mint-poc-receipt.mjs "rm -rf ./build"
 *
 * On first run it generates and saves a POC approver key to .emilia/poc-key.json
 * and prints the EMILIA_TRUSTED_KEYS line to export. Then it writes the receipt
 * to .emilia/receipt.json, which the PreToolUse hook consumes exactly once.
 *
 * The whole loop, in three commands:
 *   1) node examples/claude-code/mint-poc-receipt.mjs "rm -rf ./build"
 *   2) export EMILIA_TRUSTED_KEYS=<printed value>
 *   3) run Claude Code; `rm -rf ./build` now passes, any OTHER command blocks.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const command = process.argv.slice(2).join(' ').trim();
if (!command) {
  process.stderr.write('usage: mint-poc-receipt.mjs "<the exact command to authorize>"\n');
  process.exit(1);
}

// Match the gate's canonicalization (I-JSON, sorted keys) byte for byte.
function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

const dir = path.join(process.cwd(), '.emilia');
fs.mkdirSync(dir, { recursive: true });

// Persist a POC approver key so EMILIA_TRUSTED_KEYS stays stable across mints.
const keyPath = path.join(dir, 'poc-key.json');
let priv, spkiB64;
if (fs.existsSync(keyPath)) {
  const saved = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
  priv = crypto.createPrivateKey({ key: Buffer.from(saved.pkcs8, 'base64'), format: 'der', type: 'pkcs8' });
  spkiB64 = saved.spki;
} else {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  priv = privateKey;
  spkiB64 = crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64url');
  fs.writeFileSync(keyPath, JSON.stringify({
    pkcs8: priv.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    spki: spkiB64,
  }, null, 2));
}

// Bind the receipt to THIS exact command — the same action id the hook derives.
const cmdDigest = crypto.createHash('sha256').update(command, 'utf8').digest('hex');
const actionType = `claude-code.bash:${cmdDigest.slice(0, 16)}`;

const payload = {
  receipt_id: crypto.randomUUID(),
  subject: 'poc-approver@localhost',
  created_at: new Date().toISOString(),
  claim: {
    action_type: actionType,
    outcome: 'allow',
    // The full command travels in the receipt so an auditor sees WHAT was
    // approved, not only its digest.
    command,
  },
};
const receipt = {
  '@version': 'EP-RECEIPT-v1',
  payload,
  signature: { alg: 'Ed25519', value: crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), priv).toString('base64url') },
};

fs.writeFileSync(path.join(dir, 'receipt.json'), JSON.stringify(receipt, null, 2));
process.stdout.write(
  `Minted receipt for: ${command}\n` +
  `  action: ${actionType}\n` +
  `  written: .emilia/receipt.json (single-use)\n\n` +
  `Export the approver key the hook must trust:\n` +
  `  export EMILIA_TRUSTED_KEYS=${spkiB64}\n`,
);
