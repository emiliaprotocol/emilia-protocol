#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * EP FIPS posture check -- runnable posture reporter for EP-FIPS-MODE-v1.
 *
 * WHAT THIS PROGRAM IS. It reports. It does not certify anything and it does
 * not sign anything. It reads the crypto posture of the process it is running
 * in, prints it, then asks packages/verify/src/fips-mode.ts what that posture
 * permits for the two signature algorithms in the EP-SIG-AGILITY-v1 registry.
 *
 * THE CEILING ON WHAT A GREEN RUN EARNS. A PASS verdict here means one
 * sentence and no more:
 *
 *     "FIPS-based algorithms, with a validated-provider deployment mode."
 *
 * EP is not FIPS compliant and not FIPS validated. No EP package, receipt, or
 * deployment carries a CMVP certificate. A PASS says the process asked OpenSSL
 * for FIPS mode, OpenSSL agreed, and an approved operation actually completed
 * in this process. Whether the provider binary on this host is the exact
 * CMVP-validated build, on a validated platform, at a validated version, is an
 * operator fact read off a security policy, not something any amount of runtime
 * probing can establish. See docs/deployment/FIPS-MODE.md.
 *
 * INACTIVE IS NOT AN ERROR. On an ordinary development machine FIPS mode is
 * off, the run reports INACTIVE, and it exits 0. That is the correct and
 * expected result there. The exit code is non-zero only when the posture is
 * self-contradictory or indeterminate: the FIPS flag is set while OpenSSL
 * cannot service a SHA-256 digest, or the build cannot report a FIPS status at
 * all. Those two states are the ones that would otherwise be reported to a
 * dashboard as "FIPS mode: on" while nothing works.
 *
 * DETERMINISTIC OUTPUT. No timestamps, no randomness, no network. Two runs on
 * the same host with the same environment print the same bytes, so the output
 * can be diffed across machines or pasted into an assurance package.
 *
 * ENVIRONMENT INPUTS (both optional, both ignored unless set to a literal):
 *   EP_FIPS_ED25519_IN_BOUNDARY = "true" | "false"
 *       The operator's declaration, read off their CMVP certificate, of
 *       whether EdDSA/Ed25519 is an Approved algorithm in the provider this
 *       deployment runs. No runtime check can answer this. Anything other than
 *       those two literals leaves the field UNDECLARED, which refuses Ed25519
 *       under an active FIPS mode rather than guessing.
 *
 * Usage:  node examples/fips-deployment/posture-check.mjs
 */

// ---------------------------------------------------------------------------
// Module resolution: the package subpath export first, repo-relative fallback
// ---------------------------------------------------------------------------

/**
 * @emilia-protocol/verify now carries a "./fips-mode" entry in its exports map,
 * so the subpath is the supported way in. The fallbacks exist so this file also
 * runs from a bare checkout with no node_modules links: the root shim first,
 * then the emitted dist module it re-exports.
 */
const IMPORT_CANDIDATES = [
  { specifier: '@emilia-protocol/verify/fips-mode', label: 'package subpath export' },
  { specifier: new URL('../../packages/verify/fips-mode.js', import.meta.url).href, label: 'repo-relative root shim' },
  { specifier: new URL('../../packages/verify/dist/fips-mode.js', import.meta.url).href, label: 'repo-relative dist module' },
];

let fips = null;
let importedVia = null;
const importFailures = [];
for (const candidate of IMPORT_CANDIDATES) {
  try {
    fips = await import(candidate.specifier);
    importedVia = candidate;
    break;
  } catch (err) {
    importFailures.push(`${candidate.specifier}: ${err && err.code ? err.code : 'import failed'}`);
  }
}

if (!fips || !importedVia) {
  process.stdout.write('EP FIPS posture check\n');
  process.stdout.write('VERDICT: UNRESOLVED -- the fips-mode module could not be imported.\n');
  for (const failure of importFailures) process.stdout.write(`  tried ${failure}\n`);
  process.stdout.write('  Build the verify package (npm run build -w packages/verify) or run from the repo root.\n');
  process.exit(2);
}

const {
  getFipsPosture,
  formatFipsPosture,
  assertClassicalFips,
  checkOperationPolicy,
  FIPS_MODE_VERSION,
} = fips;

// ---------------------------------------------------------------------------
// Operator declaration
// ---------------------------------------------------------------------------

const rawDeclaration = process.env.EP_FIPS_ED25519_IN_BOUNDARY;
let ed25519Declaration;
let declarationSource;
if (rawDeclaration === 'true') {
  ed25519Declaration = true;
  declarationSource = 'EP_FIPS_ED25519_IN_BOUNDARY=true';
} else if (rawDeclaration === 'false') {
  ed25519Declaration = false;
  declarationSource = 'EP_FIPS_ED25519_IN_BOUNDARY=false';
} else if (rawDeclaration === undefined) {
  ed25519Declaration = undefined;
  declarationSource = 'unset (UNDECLARED)';
} else {
  ed25519Declaration = undefined;
  declarationSource = `${JSON.stringify(rawDeclaration)} is not the literal "true" or "false", so UNDECLARED`;
}

const postureOptions = ed25519Declaration === undefined
  ? {}
  : { ed25519InValidatedBoundary: ed25519Declaration };

const posture = getFipsPosture(postureOptions);

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

const out = [];
const say = (line = '') => out.push(line);
const rule = () => say('-'.repeat(78));

say(`EP FIPS posture check (${FIPS_MODE_VERSION})`);
say(`module imported via: ${importedVia.label} -- ${importedVia.specifier}`);
rule();

say('PROCESS POSTURE');
say(`  fips_status                   : ${posture.fips_status}`);
say(`  fips_mode_active              : ${posture.fips_mode_active}`);
say(`  node_version                  : ${posture.node_version ?? 'unknown'}`);
say(`  openssl_version               : ${posture.openssl_version ?? 'unknown'}`);
say(`  openssl_operational (probed)  : ${tri(posture.openssl_operational)}`);
say(`  ed25519_operational (probed)  : ${tri(posture.ed25519_operational)}`);
say(`  ed25519_in_validated_boundary : ${posture.ed25519_in_validated_boundary === null
  ? 'undeclared' : String(posture.ed25519_in_validated_boundary)}   [operator declaration: ${declarationSource}]`);
say();
say(`  one-line form: ${formatFipsPosture(posture)}`);
say();

say('WHAT THE TWO PROBES MEAN');
say('  openssl_operational is a liveness measurement, not a coverage claim: an');
say('  actual SHA-256 digest completed in this process. The FIPS flag alone is');
say('  not evidence, because setFips(true) can succeed on a build with no');
say('  provider, after which every EVP operation fails.');
say('  ed25519_operational is necessary and NOT sufficient: OpenSSL 3.0.x signs');
say('  Ed25519 under an active FIPS mode while CMVP certificate #4282 lists it');
say('  as non-Approved. Membership of the boundary is the operator declaration');
say('  above, read off a security policy, never a probe result.');
say();

say('ML-DSA BOUNDARY (hard-coded truth, never probed)');
say(`  mldsa_backend                 : ${posture.mldsa_backend}`);
say(`  mldsa_validated_module        : ${posture.mldsa_validated_module}`);
say('  EP signs ML-DSA-65 in pure JavaScript. That implementation sits inside no');
say('  CMVP certificate, it is not a FIPS-validated module, and running it in a');
say('  process with FIPS mode active does not change that. No option in this');
say('  program, and no setting in the runtime, makes the field above anything');
say('  other than false. The allow_unvalidated_mldsa flag grants PERMISSION; it');
say('  never grants validation.');
rule();

// ---------------------------------------------------------------------------
// Policy matrix, evaluated against the LIVE posture above
// ---------------------------------------------------------------------------

say('OPERATION POLICY MATRIX (evaluated against the live posture above)');
say();
const matrix = [];
for (const alg of ['Ed25519', 'ML-DSA-65']) {
  for (const acknowledged of [false, true]) {
    const result = checkOperationPolicy(alg, posture, { allow_unvalidated_mldsa: acknowledged });
    matrix.push({
      alg,
      flag: acknowledged ? 'allow_unvalidated_mldsa=true' : 'allow_unvalidated_mldsa absent',
      verdict: result.permitted ? 'PERMITTED' : 'REFUSED',
      reason: result.reason ?? '-',
      boundary: result.boundary ?? '-',
    });
  }
}

const headers = ['algorithm', 'acknowledgment flag', 'decision', 'reason', 'boundary'];
const rows = matrix.map((m) => [m.alg, m.flag, m.verdict, m.reason, m.boundary]);
const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
const renderRow = (cells) => ('  ' + cells.map((c, i) => c.padEnd(widths[i])).join('  ')).trimEnd();
say(renderRow(headers));
say('  ' + widths.map((w) => '-'.repeat(w)).join('  '));
for (const row of rows) say(renderRow(row));
say();
if (posture.fips_status === 'inactive') {
  say('  The ML-DSA rows do not vary with the flag here, because fips_status is');
  say('  inactive: there is no FIPS posture to contradict, so the acknowledgment is');
  say('  not armed and ML-DSA is permitted either way. That is exactly why adopting');
  say('  checkOperationPolicy at existing call sites changes nothing for an ordinary');
  say('  non-FIPS deployment.');
} else {
  say(`  fips_status is ${posture.fips_status}, so the ML-DSA acknowledgment is ARMED:`);
  say('  the flag is what separates the two ML-DSA rows. Permission is not validation.');
  say('  An indeterminate posture arms it for the same reason an active one does, since');
  say('  a process that cannot say whether it runs under a validated provider does not');
  say('  get to run unvalidated post-quantum signing by default.');
}
rule();

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

const classical = assertClassicalFips({ posture });
say('CLASSICAL (OpenSSL-backed) ASSERTION');
say(`  ok     : ${classical.ok}`);
say(`  reason : ${classical.reason ?? '-'}`);
say();

let verdict;
let detail;
let exitCode;

if (classical.ok) {
  verdict = 'PASS';
  exitCode = 0;
  detail = [
    'FIPS mode is active in this process and an approved operation completed.',
    'This host is running EP with FIPS-based algorithms, in a validated-provider',
    'deployment mode. That is the whole claim. It is not a compliance finding and',
    'no EP artifact produced here carries a CMVP certificate.',
  ];
  if (posture.ed25519_in_validated_boundary !== true) {
    detail.push('Ed25519 is refused above: declare the boundary from your certificate to permit it.');
  }
} else if (posture.fips_status === 'inactive') {
  verdict = 'INACTIVE';
  exitCode = 0;
  detail = [
    'FIPS mode is verifiably off in this process. On a development machine, a CI',
    'runner, or any ordinary deployment this is the expected result and is NOT an',
    'error, which is why this run exits 0. EP behaves exactly as it always has:',
    'every algorithm in the registry is permitted and no acknowledgment is armed.',
    `Named refusal reason from the module: ${classical.reason}.`,
  ];
} else if (posture.fips_status === 'unavailable') {
  verdict = 'INDETERMINATE';
  exitCode = 1;
  detail = [
    'This build cannot report a FIPS status at all. Indeterminate is not "off":',
    'the module refuses rather than guessing, and so does this check.',
    `Named refusal reason from the module: ${classical.reason}.`,
  ];
} else {
  verdict = 'MISCONFIGURED';
  exitCode = 1;
  detail = [
    'The FIPS flag is set and OpenSSL cannot service a basic approved operation.',
    'This is the trap the posture module exists to catch: a dashboard reading the',
    'flag alone would report this dead process as a hardened one. The usual cause',
    'is --force-fips or setFips(true) on a build with no FIPS provider configured.',
    `Named refusal reason from the module: ${classical.reason}.`,
  ];
}

say(`VERDICT: ${verdict}`);
for (const line of detail) say(`  ${line}`);
say();
say(`exit code: ${exitCode}`);

process.stdout.write(out.join('\n') + '\n');
process.exit(exitCode);

function tri(value) {
  return value === null ? 'unprobed' : String(value);
}
