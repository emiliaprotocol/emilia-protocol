#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * ep-assure — re-perform an EMILIA reliance assurance package and emit an auditor
 * workpaper. The independent-assurer CLI: point it at a package (or raw decisions
 * + a pinned profile) and auditor-supplied keys, and it recomputes every reliance
 * verdict offline, validates package/profile integrity, detects drift against the runtime's stated verdicts, maps each
 * to a control objective, and prints the workpaper. Exit code is non-zero when
 * package/profile integrity fails or when it finds a
 * decision that RELIED ON INADMISSIBLE evidence (claimed rely, recomputes to a
 * refusal), so it drops into CI/audit pipelines.
 *
 *   node packages/gate/ep-assure.mjs <input.json> [--json] [--strict]
 *
 * input.json is one of:
 *   { "package": <EP-ASSURANCE-PACKAGE-v1>, "keys": {...}, "now": <iso|ms>,
 *     "expected_package_digest"?: <out-of-band digest>, "expected_profile_hash"?: <out-of-band digest> }
 *   { "decisions": [...], "profile": <EP-RELIANCE-PROFILE-v1>, "keys": {...}, "now": <iso|ms> }
 *
 * keys (auditor-pinned, out of band): { approverKeys, logPublicKey, rpId, allowedOrigins, revokerKeys }
 * --json   print the full EP-ASSURANCE-REPERFORMANCE-v1 document instead of text
 * --strict exit non-zero if ANY drift is found (default: only inadmissible-reliance drift)
 */
import { readFileSync } from 'node:fs';
import { buildAssurancePackage, reperformAssurancePackage, renderAssuranceWorkpaper } from './reports/assurance-package.js';

/** @returns {never} */
function fail(msg) { process.stderr.write(`ep-assure: ${msg}\n`); process.exit(2); }

const args = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const path = args.find((a) => !a.startsWith('--'));
if (!path) fail('usage: ep-assure <input.json> [--json] [--strict]');

let input;
try { input = JSON.parse(readFileSync(path, 'utf8')); } catch (e) { fail(`cannot read ${path}: ${e.message}`); }

const keys = input.keys || {};
const now = input.now != null ? (typeof input.now === 'string' ? Date.parse(input.now) : input.now) : 0;

let pkg = input.package;
if (!pkg) {
  if (!Array.isArray(input.decisions)) fail('input needs a `package` or a `decisions` array');
  pkg = buildAssurancePackage(input.decisions, { profile: input.profile, organization: input.organization || null, now });
}

let doc;
try {
  doc = reperformAssurancePackage(pkg, {
    approverKeys: keys.approverKeys || {}, logPublicKey: keys.logPublicKey || null,
    rpId: keys.rpId || null, allowedOrigins: keys.allowedOrigins || [],
    revokerKeys: keys.revokerKeys || {}, now,
    expectedPackageDigest: input.expected_package_digest ?? null,
    expectedProfileHash: input.expected_profile_hash ?? null,
  });
} catch (e) { fail(e.message); }

if (flags.has('--json')) {
  process.stdout.write(JSON.stringify(doc, null, 2) + '\n');
} else {
  process.stdout.write(renderAssuranceWorkpaper(doc) + '\n');
}

const inadmissibleReliance = doc.population.relied_on_inadmissible_evidence;
const anyDrift = doc.population.drift;
if (doc.integrity_verified !== true) {
  const failures = [];
  if (doc.package_digest_verified !== true) failures.push('package digest mismatch');
  if (doc.profile_hash_verified !== true) failures.push('profile hash mismatch');
  if (doc.expected_package_digest_matches === false) failures.push('out-of-band package pin mismatch');
  if (doc.expected_profile_hash_matches === false) failures.push('out-of-band profile pin mismatch');
  process.stderr.write(`ep-assure: integrity failed — ${failures.join('; ')}\n`);
  process.exit(1);
}
const bad = flags.has('--strict') ? anyDrift : inadmissibleReliance;
if (bad > 0) {
  process.stderr.write(`ep-assure: ${bad} finding(s) — ${flags.has('--strict') ? 'drift' : 'reliance on inadmissible evidence'} detected\n`);
  process.exit(1);
}
process.exit(0);
