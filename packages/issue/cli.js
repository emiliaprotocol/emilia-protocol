#!/usr/bin/env node
/**
 * @emilia-protocol/issue — CLI (ep-issue).
 * @license Apache-2.0
 *
 * Issue EP authorization receipts (EP-RECEIPT-v1; I-D §6.2) locally, signed
 * with your own keys. Verify them anywhere with @emilia-protocol/verify.
 *
 * Subcommands:
 *   keygen  — generate a local Ed25519 issuer bundle (approver + log keys)
 *   issue   — read an action JSON + key bundle → write a signed receipt JSON
 *             (Class B/C software-key signoff; full Merkle log_proof)
 *   demo    — one command, no args: throwaway keys → sample receipt for a
 *             sample irreversible action → verify it with @emilia-protocol/verify
 *
 * Class A (device-bound WebAuthn) signoffs are produced by EP's hosted
 * ceremony, NOT by this CLI. This CLI issues Class B/C software-key signoffs.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {
  generateIssuerKeyBundle,
  issueFromKeyBundle,
  formatLogKeyId,
} from './index.js';
import { strictJsonGate } from './strict-json.js';

const MAX_CLI_JSON_BYTES = 8 * 1024 * 1024;

function usage() {
  console.log(`ep-issue — issue EP authorization receipts locally, verify anywhere.

Usage:
  ep-issue keygen --out issuer-keys.json
      [--approver-id ep:approver:alice] [--approver-key-id ep:key:alice#1]
      [--log-name acme]   (-> log key id ep:log:acme#1)
      [--log-key-id ep:log:acme#1]

  ep-issue issue --keys issuer-keys.json --action action.json --out receipt.json
      [--verification verification.json] [--policy policy.json]
      [--policy-hash sha256:...] [--receipt-id ep:receipt:...] [--expires-in 3600]
      [--attestation attestation.json]
          PIP-007 initiator escalation attestation, copied verbatim into every
          context: { escalation_trigger, policy_basis?, statement? }.
          escalation_trigger is one of irreversibility, magnitude, uncertainty,
          novelty, authority_gap, policy_rule; statement <= 280 chars.

  ep-issue demo
      Generate throwaway keys, issue a sample receipt for a sample irreversible
      action, then verify it with @emilia-protocol/verify (printing the 7 checks).

Class A device-bound (WebAuthn) signoffs require EP's hosted ceremony, not this
CLI. 'issue' produces Class B/C software-key signoffs.`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

function readJson(p) {
  const raw = fs.readFileSync(p, 'utf8');
  if (Buffer.byteLength(raw, 'utf8') > MAX_CLI_JSON_BYTES) throw new Error(`JSON input exceeds ${MAX_CLI_JSON_BYTES} bytes`);
  const strict = strictJsonGate(raw);
  if (!strict.ok) throw new Error(`strict JSON required: ${strict.reason}`);
  return JSON.parse(raw);
}

function writeJson(p, value) {
  fs.writeFileSync(p, `${JSON.stringify(value, null, 2)}\n`);
}

// Print the verifier's 7 checks (or an error) for a verifyTrustReceipt result.
function printChecks(result) {
  for (const [k, v] of Object.entries(result.checks || {})) {
    console.log(`  ${v === true ? '✓' : '✕'} ${k}`);
  }
  for (const err of result.errors || []) {
    console.log(`  reason: ${err}`);
  }
}

async function cmdKeygen(args) {
  if (!args.out) throw new Error('keygen requires --out');
  const logKeyId = args['log-key-id']
    || (args['log-name'] ? formatLogKeyId(String(args['log-name'])) : undefined);
  const bundle = generateIssuerKeyBundle({
    approverId: args['approver-id'],
    approverKeyId: args['approver-key-id'],
    logKeyId,
    validFrom: args['valid-from'],
    validTo: args['valid-to'],
  });
  writeJson(args.out, bundle);
  console.log(`Wrote issuer keys to ${args.out}`);
  console.log(`  approver:    ${bundle.approver.id} (${bundle.approver.key_id}, Class ${bundle.approver.key_class})`);
  console.log(`  log key id:  ${bundle.log.key_id}`);
  console.log('Keep this file secret. Publish only the verification material or the public keys.');
}

async function cmdIssue(args) {
  if (!args.keys || !args.action || !args.out) {
    throw new Error('issue requires --keys, --action, and --out');
  }
  const keys = readJson(args.keys);
  const action = readJson(args.action);
  const policy = args.policy ? readJson(args.policy) : undefined;
  const initiatorAttestation = args.attestation ? readJson(args.attestation) : undefined;
  const expiresInSeconds = args['expires-in'] ? Number(args['expires-in']) : 3600;
  if (!Number.isFinite(expiresInSeconds) || expiresInSeconds <= 0) {
    throw new Error('--expires-in must be a positive number of seconds');
  }

  const { receipt, verification } = await issueFromKeyBundle({
    keys,
    action,
    policy,
    policyHash: args['policy-hash'],
    receiptId: args['receipt-id'],
    expiresInSeconds,
    initiatorAttestation,
  });

  writeJson(args.out, receipt);
  console.log(`Wrote authorization receipt to ${args.out}`);
  if (args.verification) {
    writeJson(args.verification, verification);
    console.log(`Wrote verification material to ${args.verification}`);
  } else {
    console.log('No --verification path supplied; remember to publish the approver keys and the log public key.');
  }
  console.log('Verify it anywhere with @emilia-protocol/verify:');
  console.log("  verifyTrustReceipt(receipt, { approverKeys, logPublicKey }) — supply both from " + (args.verification || 'verification.json') + '.');
}

async function cmdDemo() {
  console.log('@emilia-protocol/issue — demo: issue locally, verify anywhere\n');

  // 1. Throwaway local issuer keys.
  const keys = generateIssuerKeyBundle({
    approverId: 'ep:approver:demo-finance-lead',
    approverKeyId: 'ep:key:demo-finance-lead#1',
    logKeyId: formatLogKeyId('demo'),
  });
  console.log('1. Generated throwaway issuer keys');
  console.log(`     approver:   ${keys.approver.id}`);
  console.log(`     log key id: ${keys.log.key_id}`);

  // 2. A sample irreversible action.
  const action = {
    ep_version: '1.0',
    action_type: 'vendor_bank_account_change',
    target: { system: 'erp.example', resource: 'vendor/acme' },
    parameters: { new_bank_hash: 'sha256:9f2c…', irreversible: true },
    initiator: 'ep:entity:ap-agent',
    policy_id: 'ep:policy:vendor-bank-change@v1',
    requested_at: new Date().toISOString(),
  };
  // PIP-007 initiator escalation attestation: the initiator's own stated reason
  // for asking a human, carried verbatim in every context and so covered by the
  // approver's signature.
  const initiatorAttestation = {
    /** @type {'irreversibility'} */
    escalation_trigger: 'irreversibility',
    policy_basis: action.policy_id,
    statement: 'Vendor bank-account change is irreversible; policy requires a named human approval.',
  };
  console.log('\n2. Issuing a receipt for a sample irreversible action');
  console.log(`     action: ${action.action_type} on ${action.target.resource}`);
  console.log(`     initiator_attestation: trigger=${initiatorAttestation.escalation_trigger}, policy_basis=${initiatorAttestation.policy_basis}`);
  console.log(`       statement: "${initiatorAttestation.statement}"`);

  const { receipt, verification } = await issueFromKeyBundle({ keys, action, initiatorAttestation });
  console.log(`     receipt_id: ${receipt.receipt_id}`);
  console.log(`     log tree_size: ${receipt.log_proof.checkpoint.tree_size}, leaf_index: ${receipt.log_proof.leaf_index}`);

  // 3. Write the artifacts to a temp dir so the user can inspect them.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-issue-demo-'));
  const receiptPath = path.join(dir, 'receipt.json');
  const verificationPath = path.join(dir, 'verification.json');
  writeJson(receiptPath, receipt);
  writeJson(verificationPath, verification);
  console.log(`\n3. Wrote artifacts to ${dir}`);
  console.log(`     ${receiptPath}`);
  console.log(`     ${verificationPath}`);

  // 4. Verify with @emilia-protocol/verify if it resolves; the receipt is the
  //    same with or without it — the package only re-proves what the math says.
  console.log('\n4. Verifying with @emilia-protocol/verify');
  let verifyTrustReceipt;
  try {
    ({ verifyTrustReceipt } = await import('@emilia-protocol/verify'));
  } catch {
    // Fall back to the in-repo sibling so the demo works from a checkout too.
    try {
      ({ verifyTrustReceipt } = await import('../verify/index.js'));
    } catch {
      console.log('   @emilia-protocol/verify is not installed.');
      console.log('   Install it to verify offline:  npm install @emilia-protocol/verify');
      console.log('\n   The receipt above is complete and self-verifying — install verify to see the 7 checks.');
      return;
    }
  }

  const result = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });
  printChecks(result);
  console.log(`\n${result.valid ? '✅ VERIFIED' : '⛔ NOT VERIFIED'} — all 7 §6.3 checks ${result.valid ? 'passed' : 'did not pass'}.`);

  // PIP-007 advisory: the attestation the approver signed, reported back by the
  // verifier (does not affect signature validity).
  if (result.attestation?.present) {
    // cmdDemo issues a single-context receipt and always supplies
    // initiatorAttestation; buildContexts() copies that identical object into
    // every context, so whenever the verifier reports attestation.present,
    // contexts[0].initiator_attestation is provably defined here.
    const att = /** @type {import('./index.js').InitiatorAttestation} */ (receipt.contexts[0].initiator_attestation);
    console.log(`\nInitiator attestation (PIP-007), covered by the approver's signature:`);
    console.log(`  present: ${result.attestation.present}, consistent across contexts: ${result.attestation.consistent}`);
    console.log(`  escalation_trigger: ${att.escalation_trigger}`);
    if (att.policy_basis) console.log(`  policy_basis: ${att.policy_basis}`);
    if (att.statement) console.log(`  statement: "${att.statement}"`);
  }
  console.log('\nIssued locally with your own keys. Verified anywhere. No EP backend.');
  if (!result.valid) process.exit(1);
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);

  if (!command || args.help || args.h) {
    usage();
    return;
  }

  if (command === 'keygen') return cmdKeygen(args);
  if (command === 'issue' || command === 'receipt') return cmdIssue(args);
  if (command === 'demo') return cmdDemo();

  throw new Error(`Unknown command: ${command}`);
}

main().catch((err) => {
  console.error(`ep-issue: ${err.message}`);
  process.exit(1);
});
