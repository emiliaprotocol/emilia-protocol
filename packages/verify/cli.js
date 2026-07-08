#!/usr/bin/env node
/**
 * @emilia-protocol/verify — CLI.
 * @license Apache-2.0
 *
 * `npx @emilia-protocol/verify receipt.json [more.json…]`
 *
 * Auto-detects the document kind (EP-RECEIPT-v1, EP-BUNDLE-v1, EP-PROOF-v1, or
 * a Class-A WebAuthn device signoff), runs the matching verifier from index.js,
 * prints every check, and exits 0 only if every document verifies. Fully
 * offline — the same guarantee as the library.
 */
import { readFileSync } from 'node:fs';
import {
  verifyReceipt,
  verifyReceiptBundle,
  verifyCommitmentProof,
  verifyWebAuthnSignoff,
  verifyTrustReceipt,
  verifyQuorum,
  verifyRevocation,
  verifyProvenanceOffline,
} from './index.js';

const args = process.argv.slice(2);
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`@emilia-protocol/verify — offline verification, no EP server required.

Usage:
  npx @emilia-protocol/verify <file.json> [more.json…]

Accepts: EP-RECEIPT-v1 receipts, EP-BUNDLE-v1 bundles, EP-PROOF-v1 commitment
proofs, Class-A WebAuthn device signoffs ({ context, webauthn, … }), I-D
§6.2 authorization receipts ({ contexts, signoffs, log_proof, … }), and
EP-QUORUM-v1 multi-party documents ({ "@type": "ep.quorum", policy, members, … }).
Self-contained evidence packets embed their public key; otherwise pass
--key <base64url-spki> to supply it. For §6.2 receipts, pass the issuer's
public material with --verification <verification.json>.

For a §6.2 receipt carrying a PIP-007 initiator escalation attestation, the
advisory report (present / consistent across contexts / any §1 issues) is
printed beneath the cryptographic checks. It never affects whether the receipt
verifies.

Subcommands:
  reliance-gap <packet.json> (--profile <profile.json> | --profiles <dir>)
               [--now <rfc3339>] [--out <path>]
    Acceptance preflight: run the reliance kernel over a de-identified action
    packet under one pinned EP-RELIANCE-PROFILE-v1 (or every profile in a
    directory) and emit a deterministic reliance gap report.
    Exit 0 = rely (all rely in --profiles mode); 2 = any do_not_rely_*;
    1 = operational error.
  revocation <statement.json> --target <target.json> --revoker-keys <keys.json>
    Offline revocation check (see below).

Exit code 0 = every document verified; 1 = any failure.`);
  process.exit(args.length === 0 ? 1 : 0);
}

// Subcommand: acceptance preflight. Builds an EP-RELIANCE-GAP-REPORT-v1 (or the
// combined EP-RELIANCE-GAP-MULTI-v1 with --profiles) over a de-identified action
// packet: the kernel verdict, the missing-evidence list, the action and profile
// digests, a plain-language control mapping, and the exact reproduction command.
// Fully offline and deterministic: local files only, no network, no wall clock
// (the evaluation time comes from --now or the packet's evaluated_at).
//   verify reliance-gap <packet.json> --profile <profile.json> [--now <rfc3339>] [--out <path>]
//   verify reliance-gap <packet.json> --profiles <dir>         [--now <rfc3339>] [--out <path>]
// Exit 0 = rely (all rely in multi mode); 2 = any do_not_rely_*; 1 = operational error.
if (args[0] === 'reliance-gap') {
  const { buildRelianceGapReport, buildMultiPartyRelianceGapReport } = await import('./reliance-gap.js');
  const { readdirSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');

  const sub = args.slice(1);
  let packetPath = null; let profilePath = null; let profilesDir = null; let nowStr = null; let outPath = null;
  for (let i = 0; i < sub.length; i++) {
    if (sub[i] === '--profile') profilePath = sub[++i];
    else if (sub[i] === '--profiles') profilesDir = sub[++i];
    else if (sub[i] === '--now') nowStr = sub[++i];
    else if (sub[i] === '--out') outPath = sub[++i];
    else packetPath = sub[i];
  }
  if (!packetPath || (!profilePath && !profilesDir) || (profilePath && profilesDir)) {
    console.error('usage: verify reliance-gap <packet.json> (--profile <profile.json> | --profiles <dir>) [--now <rfc3339>] [--out <path>]');
    process.exit(1);
  }
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  let packet;
  try { packet = load(packetPath); } catch (err) {
    console.error(`error: packet not readable JSON (${err.message})`);
    process.exit(1);
  }

  let report;
  try {
    if (profilePath) {
      const profile = load(profilePath);
      report = buildRelianceGapReport(packet, profile, {
        now: nowStr ?? undefined, packet_path: packetPath, profile_path: profilePath,
      });
    } else {
      const names = readdirSync(profilesDir).filter((f) => f.endsWith('.json')).sort();
      if (names.length === 0) {
        console.error(`error: no .json profiles found in ${profilesDir}`);
        process.exit(1);
      }
      const profiles = names.map((name) => ({
        label: name, profile: load(join(profilesDir, name)), path: join(profilesDir, name),
      }));
      report = buildMultiPartyRelianceGapReport(packet, profiles, {
        now: nowStr ?? undefined, packet_path: packetPath, profiles_path: profilesDir,
      });
    }
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exit(1);
  }
  if (report.refused === true) {
    console.error(`refused: ${report.refusal_reason}`);
    process.exit(1);
  }

  // Human-readable summary. It goes to stderr when the JSON occupies stdout, so
  // pipes and CI capture clean JSON either way.
  const human = [];
  const summarize = (label, r) => {
    human.push(`${r.kernel_verdict === 'rely' ? 'RELY        ' : 'DO NOT RELY '}${label} -> ${r.kernel_verdict}`);
    for (const gap of r.missing_evidence) human.push(`  gap: ${gap.requirement} -- ${gap.how_to_close}`);
  };
  let exitCode;
  if (profilePath) {
    summarize(profilePath, report);
    exitCode = report.kernel_verdict === 'rely' ? 0 : 2;
  } else {
    for (const { label, report: r } of report.reports) summarize(label, r);
    human.push(`${report.all_rely ? 'ALL RELY' : 'GAPS FOUND'}: ${report.summary.filter((s) => s.verdict === 'rely').length}/${report.profiles_evaluated} profiles rely on this packet`);
    exitCode = report.all_rely ? 0 : 2;
  }

  const json = JSON.stringify(report, null, 2) + '\n';
  if (outPath) {
    writeFileSync(outPath, json);
    for (const l of human) console.log(l);
    console.log(`report written to ${outPath}`);
  } else {
    process.stdout.write(json);
    for (const l of human) console.error(l);
  }
  process.exit(exitCode);
}

// Subcommand: offline revocation check. Answers "do these statements revoke the
// authorization I hold?" — FAIL-CLOSED, no EP server. Honest boundary: it cannot
// prove the ABSENCE of a revocation you were never handed (see EP-REVOCATION-SPEC §7).
//   verify revocation <statement.json> --target <target.json> --revoker-keys <keys.json> [--max-age <sec>]
if (args[0] === 'revocation') {
  const sub = args.slice(1);
  let statementPath = null; let targetPath = null; let keysPath = null; let maxAge = null;
  for (let i = 0; i < sub.length; i++) {
    if (sub[i] === '--target') targetPath = sub[++i];
    else if (sub[i] === '--revoker-keys') keysPath = sub[++i];
    else if (sub[i] === '--max-age') maxAge = Number(sub[++i]);
    else statementPath = sub[i];
  }
  if (!statementPath || !targetPath) {
    console.error('usage: verify revocation <statement.json> --target <target.json> --revoker-keys <keys.json> [--max-age <sec>]');
    process.exit(1);
  }
  const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
  let statement; let target; let revokerKeys = {};
  try {
    statement = load(statementPath);
    target = load(targetPath);
    if (keysPath) revokerKeys = load(keysPath);
  } catch (err) {
    console.error(`✕ ${err.message}`);
    process.exit(1);
  }
  const opts = { revokerKeys };
  if (Number.isFinite(maxAge)) opts.maxAgeSeconds = maxAge;
  const r = verifyRevocation(target, statement, opts);
  // A VALID revocation means the held authorization is REVOKED — exit non-zero.
  console.log(`${r.valid ? '⛔ REVOKED' : '○ NOT REVOKED BY THIS STATEMENT'} — target ${target.target_type || ''} ${target.target_id || ''}`.trimEnd());
  printChecks(r.checks);
  for (const e of r.errors || []) console.log(`  reason: ${e}`);
  if (!keysPath) console.log('  note: no --revoker-keys supplied; a revocation from an unpinned key confers nothing.');
  console.log('  note: a NOT-REVOKED result only means THESE statements do not revoke it — not that no revocation exists.');
  process.exit(r.valid ? 1 : 0);
}

let suppliedKey = null;
let verificationPath = null;
let delegationKeysPath = null;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--key') suppliedKey = args[++i];
  else if (args[i] === '--verification') verificationPath = args[++i];
  else if (args[i] === '--delegation-keys') delegationKeysPath = args[++i];
  else files.push(args[i]);
}

let delegationKeys = {};
if (delegationKeysPath) {
  try { delegationKeys = JSON.parse(readFileSync(delegationKeysPath, 'utf8')); }
  catch (err) { console.error(`✕ --delegation-keys not readable JSON (${err.message})`); process.exit(1); }
}

// PIP-007 §2 advisory: print the attestation report when a result carries one.
function printAttestationAdvisory(attestation) {
  if (!attestation || !attestation.present) return;
  console.log(`  attestation: present, ${attestation.consistent ? 'consistent across contexts' : 'INCONSISTENT across contexts'}`);
  for (const issue of attestation.issues || []) {
    console.log(`    advisory: ${issue}`);
  }
}

function findKey(doc, names) {
  for (const n of names) {
    if (typeof doc?.[n] === 'string') return doc[n];
    if (typeof doc?.context?.[n] === 'string') return doc.context[n];
    if (typeof doc?.signer?.[n] === 'string') return doc.signer[n];
  }
  return suppliedKey;
}

function printChecks(checks) {
  for (const [k, v] of Object.entries(checks || {})) {
    if (v === null || v === undefined) continue;
    console.log(`  ${v === true ? '✓' : '✕'} ${k}`);
  }
}

let allValid = true;

for (const file of files) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`✕ ${file}: not readable JSON (${err.message})`);
    allValid = false;
    continue;
  }

  let kind = null;
  let result = null;

  if (doc?.['@version'] === 'EP-PROVENANCE-CHAIN-v1') {
    // EP-PROVENANCE-CHAIN-v1: human-authority root → delegation chain → action.
    // Embedded receipts carry their own verification material; pinned delegator
    // proof keys come from --delegation-keys.
    kind = 'provenance chain (EP-PROVENANCE-CHAIN-v1)';
    result = verifyProvenanceOffline(doc, { delegationKeys });
  } else if (doc?.['@type'] === 'ep.quorum' || (doc?.policy && Array.isArray(doc?.members) && typeof doc?.action_hash === 'string')) {
    // EP-QUORUM-v1 multi-party (two-person rule). Composes the frozen
    // single-signoff verifier once per member, then the fail-closed quorum
    // predicate — same offline guarantee, no EP server.
    kind = 'multi-party quorum (EP-QUORUM-v1)';
    const rpId = doc.rp_id || doc.rpId || undefined;
    result = verifyQuorum(doc, rpId ? { rpId } : {});
  } else if (doc?.['@version'] === 'EP-BUNDLE-v1') {
    kind = 'bundle';
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    result = key
      ? verifyReceiptBundle(doc, key)
      : { valid: false, error: 'no embedded public key — pass --key' };
  } else if (doc?.['@version'] === 'EP-RECEIPT-v1') {
    kind = 'receipt';
    const key = findKey(doc, ['issuer_public_key', 'public_key', 'publicKey']);
    result = key
      ? verifyReceipt(doc, key)
      : { valid: false, error: 'no embedded public key — pass --key' };
  } else if (doc?.['@version'] === 'EP-PROOF-v1') {
    kind = 'commitment proof';
    result = verifyCommitmentProof(doc, findKey(doc, ['public_key', 'publicKey', 'entity_public_key']));
  } else if (doc?.context && doc?.webauthn) {
    kind = 'Class-A device signoff';
    const key = findKey(doc, ['approver_public_key', 'public_key', 'publicKey']);
    const rpId = doc.rp_id || doc.context?.rp_id || undefined;
    result = key
      ? verifyWebAuthnSignoff(doc, key, rpId ? { rpId } : {})
      : { valid: false, error: 'no embedded approver public key — pass --key' };
  } else if (Array.isArray(doc?.contexts) && Array.isArray(doc?.signoffs)) {
    // I-D §6.2 authorization receipt (the shape @emilia-protocol/issue emits).
    kind = 'authorization receipt (§6.2)';
    let verification = null;
    if (verificationPath) {
      try {
        verification = JSON.parse(readFileSync(verificationPath, 'utf8'));
      } catch (err) {
        result = { valid: false, error: `--verification not readable JSON (${err.message})` };
      }
    }
    if (!result) {
      if (verification?.approver_keys && verification?.log_public_key) {
        result = verifyTrustReceipt(doc, {
          approverKeys: verification.approver_keys,
          logPublicKey: verification.log_public_key,
        });
      } else {
        result = { valid: false, error: 'a §6.2 receipt needs --verification <verification.json> (approver_keys + log_public_key)' };
      }
    }
  } else {
    console.error(`✕ ${file}: unrecognized document (expected EP receipt, bundle, proof, device signoff, or §6.2 authorization receipt)`);
    allValid = false;
    continue;
  }

  const ok = result.valid === true;
  allValid = allValid && ok;
  console.log(`${ok ? '✅ VERIFIED' : '⛔ NOT VERIFIED'} — ${kind} — ${file}`);
  printChecks(result.checks);
  printAttestationAdvisory(result.attestation);
  if (Array.isArray(result.members)) {
    for (const m of result.members) {
      console.log(`  ${m.valid ? '✓' : '✕'} signer${m.role ? ` [${m.role}]` : ''} ${m.approver || ''}`.trimEnd());
    }
  }
  if (!ok && result.error) console.log(`  reason: ${result.error}`);
  if (kind === 'bundle' && typeof result.verified === 'number') {
    console.log(`  ${result.verified}/${result.total} documents verified`);
  }
}

process.exit(allValid ? 0 : 1);
