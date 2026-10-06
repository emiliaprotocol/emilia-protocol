#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Validate the published CAID-05 scheme transition and the current
// implementation profile. The immutable historical packet has its own full
// checker, scripts/check-caid-04.mjs; run both package scripts at the release
// gate. This checker covers every -05 delta: packet checksums, posted
// provenance, Appendix A, current generated sources and corpora, current-only
// issuance, and explicit legacy verification.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packetRel = 'standards/staged/NEXT-CAID-05';
const packet = path.join(root, packetRel);
const doc = 'draft-schrock-canonical-action-identifier-05';
const failures = [];
const check = (condition, message) => { if (!condition) failures.push(message); };
const read = (rel) => readFileSync(path.join(root, rel));
const text = (rel) => read(rel).toString('utf8');
const json = (rel) => JSON.parse(text(rel));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function run(label, command, args) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    const detail = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
    failures.push(`${label} failed (exit ${result.status}): ${detail.slice(0, 4000)}`);
  }
}

run('CAID-05 transition packet', process.execPath, [`${packetRel}/validate.mjs`]);

// Packet checksums are over the retained submission and local review renders.
const checksumLines = text(`${packetRel}/SHA256SUMS.txt`).trim().split('\n');
check(checksumLines.length === 3, 'CAID-05 SHA256SUMS.txt must list exactly XML, TXT and HTML');
for (const line of checksumLines) {
  const match = /^([0-9a-f]{64})  (.+)$/.exec(line);
  if (!match) { failures.push(`malformed CAID-05 checksum line: ${line}`); continue; }
  const [, expected, relative] = match;
  check(sha256(read(`${packetRel}/${relative}`)) === expected, `${relative} does not match CAID-05 SHA256SUMS.txt`);
}

const sourceRel = `${packetRel}/UPLOAD-THIS/${doc}.xml`;
const source = text(sourceRel);
const postedXml = read(`standards/posted/${doc}.xml`);
const postedTxt = read(`standards/posted/${doc}.txt`);
check(postedXml.equals(read(sourceRel)), 'posted CAID-05 XML differs from the retained submission source');
check(postedTxt.equals(read(`${packetRel}/RENDERS/${doc}.txt`)), 'posted CAID-05 TXT differs from the retained packet render');

const status = json('standards/STATUS.json');
const wave = status.october_2_2026_caid_wave;
const item = wave?.items?.find((entry) => entry.draft === doc);
check(wave?.datatracker_posted_at === '2026-10-02T19:53:38Z', 'STATUS.json lacks the CAID-05 Datatracker posting time');
check(wave?.xml_sha256 === sha256(postedXml) && item?.snapshot_sha256 === sha256(postedXml), 'STATUS.json CAID-05 XML digest differs from the posted source');
check(wave?.txt_sha256 === sha256(postedTxt) && item?.txt_sha256 === sha256(postedTxt), 'STATUS.json CAID-05 TXT digest differs from the posted text');
const postedHtml = read(`standards/posted/${doc}.html`);
check(!/\/cdn-cgi\/challenge-platform\/|__CF\$cv\$params/.test(postedHtml.toString('utf8')), 'posted CAID-05 HTML carries Cloudflare challenge markup');
check(wave?.html_sha256 === sha256(postedHtml) && item?.html_sha256 === sha256(postedHtml), 'STATUS.json CAID-05 HTML digest differs from the posted HTML');

const registration = status.october_5_2026_canactid_iana_registration;
check(registration?.scheme === 'canactid' && registration?.status === 'provisional'
  && registration?.reference === doc, 'STATUS.json lacks the provisional canactid registration with CAID-05 as reference');
check(/not permanent registration/i.test(registration?.claim_boundary ?? '')
  && /IETF adoption/i.test(registration?.claim_boundary ?? '')
  && /IETF endorsement/i.test(registration?.claim_boundary ?? ''), 'the provisional-registration claim boundary is incomplete');

const core = json('caid/spec/core.json');
const abnf = text('caid/spec/caid.abnf');
check(core.draft === doc, 'caid/spec/core.json does not name CAID-05');
check(core.identifier?.scheme === 'canactid', 'current spec scheme is not canactid');
check(core.identifier?.legacy_v04_scheme === 'caid', 'current spec does not name the obsolete CAID-04 scheme separately');
check((abnf.match(/%s"canactid"/g) ?? []).length === 1 && !abnf.includes('%s"caid"'), 'current ABNF does not define exactly one canactid scheme literal');
const appendix = source.match(/<sourcecode anchor="abnf-collected"[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/sourcecode>/)?.[1];
check(appendix === `\n${abnf}`, 'CAID-05 Appendix A differs from caid/spec/caid.abnf');

// Generated ports and all current corpora must be reproducible from -05.
run('CAID generated sources', process.execPath, ['caid/spec/gen.mjs', '--check']);
run('CAID core corpus v6', process.execPath, ['caid/conformance/tools/build-core.mjs', '--check']);
run('CAID grammar corpus', process.execPath, ['caid/conformance/tools/build-grammar.mjs', '--check']);
run('CAID mapping corpus v3', process.execPath, ['caid/conformance/tools/build-mapping.mjs', '--check']);
run('CAID historical-corpus carry-forward', process.execPath, ['caid/conformance/check-v4.mjs']);
run('current CANACTID boundary', process.execPath, ['scripts/check-canactid-boundary.mjs']);

const currentCorpora = [
  ['core', json('caid/conformance/vectors.json').vectors],
  ['grammar', json('caid/conformance/grammar-vectors.json').cases],
  ['mapping', json('caid/conformance/mapping-vectors.json').vectors],
];
function obsoleteIdentifiers(value, at = '$', found = []) {
  if (typeof value === 'string') {
    if (value.startsWith('caid:')) found.push(at);
    return found;
  }
  if (Array.isArray(value)) value.forEach((member, index) => obsoleteIdentifiers(member, `${at}[${index}]`, found));
  else if (value && typeof value === 'object') Object.entries(value).forEach(([key, member]) => obsoleteIdentifiers(member, `${at}.${key}`, found));
  return found;
}
for (const [name, value] of currentCorpora) {
  const found = obsoleteIdentifiers(value);
  check(found.length === 0, `${name} current corpus contains obsolete caid: identifiers at ${found.slice(0, 5).join(', ')}`);
}

// One executable boundary check keeps legacy acceptance separate and proves
// that neither parser can silently accept the other's scheme.
try {
  const caid = await import(pathToFileURL(path.join(root, 'caid/impl/js/caid.mjs')).href);
  const definitions = [{ action_type: 't.1', required_fields: [{ name: 's', type: 'string' }] }];
  const action = { action_type: 't.1', s: 'x' };
  const computed = caid.computeCaid(action, { suite: 'jcs-sha256', definitions });
  check(typeof computed.caid === 'string' && computed.caid.startsWith('canactid:1:'), 'current JavaScript issuance did not emit canactid:');
  const legacy = computed.caid?.replace(/^canactid:/, 'caid:');
  check(caid.parseCaid(legacy).ok === false, 'current JavaScript parser silently accepts caid:');
  check(caid.parseLegacyCaidV04(legacy).ok === true, 'explicit JavaScript legacy parser refuses a CAID-04 identifier');
  check(caid.parseLegacyCaidV04(computed.caid).ok === false, 'explicit JavaScript legacy parser accepts current canactid:');
  check(caid.verifyLegacyCaidV04(action, legacy, { definitions }).valid === true, 'explicit JavaScript legacy verification failed');
} catch (error) {
  failures.push(`current/legacy JavaScript boundary check threw: ${error?.stack ?? error}`);
}

if (failures.length) {
  console.error(`CAID-05 packet/current profile: ${failures.length} failure(s)`);
  failures.forEach((failure) => console.error(`  - ${failure}`));
  process.exit(1);
}
console.log('CAID-05: scheme-transition packet, posted provenance, provisional-status boundary, generated sources, current corpora, and explicit legacy verification PASS.');
