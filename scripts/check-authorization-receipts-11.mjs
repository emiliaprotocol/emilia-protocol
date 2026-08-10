import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AUTHORIZATION-RECEIPTS-11/', import.meta.url);
const upload = new URL('UPLOAD-THIS/', root);
const renders = new URL('RENDERS/', root);
const basename = 'draft-schrock-ep-authorization-receipts-11';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const uploadFiles = readdirSync(upload).sort();
invariant(
  JSON.stringify(uploadFiles) === JSON.stringify([`${basename}.xml`]),
  'The -11 upload directory must contain exactly one XML source',
);

const renderFiles = readdirSync(renders).sort();
invariant(
  JSON.stringify(renderFiles) === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'The -11 render directory must contain exactly one HTML and TXT rendering',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const html = readFileSync(new URL(`RENDERS/${basename}.html`, root), 'utf8');
const txtFlat = txt.replace(/\s+/g, ' ');
invariant(xml.includes(`docName="${basename}"`), 'docName must match the -11 filename');
invariant(xml.includes('category="std"'), 'The -11 candidate must be Standards Track');
invariant(!xml.includes('submissionType='), 'An individual draft must not claim an adopted document stream');
invariant(xml.includes('<date year="2026" month="August" day="9"/>'), 'The -11 date must be 9 August 2026');

const normativeStart = xml.indexOf('<name>Normative References</name>');
const informativeStart = xml.indexOf('<name>Informative References</name>');
const caidReference = xml.indexOf('<reference anchor="EP-CAID"');
const oasntReference = xml.indexOf('<reference anchor="I-D.thallapelly-oasnt"');
invariant(normativeStart >= 0 && informativeStart > normativeStart, 'Reference groups are malformed');
invariant(caidReference > normativeStart && caidReference < informativeStart, 'CAID must be normative');
invariant(oasntReference > normativeStart && oasntReference < informativeStart, 'OASNT profile dependency must be normative');
invariant(xml.includes('draft-schrock-canonical-action-identifier-02'), 'Normative CAID reference must pin -02');
invariant(!xml.includes('draft-schrock-canonical-action-identifier-01'), 'Normative CAID reference must not remain on -01');

for (const required of [
  'EP-PRESENTATION-BINDING-v1',
  'display-unbound',
  'display-mismatch',
  'display-untrusted',
  'EP-AUTHORIZATION-RECEIPT-v1',
  'EP-AUTHORIZATION-BUNDLE-v1',
  'Optional Native Authorization Binding',
  'application/ep-authorization-bundle+json',
  'presenter-selected approver set',
  'INDETERMINATE',
]) {
  invariant(xml.includes(required), `Missing -11 requirement: ${required}`);
  invariant(txtFlat.includes(required), `TXT render is stale or missing: ${required}`);
}
invariant(xml.includes('target="RFC9396"'), 'Missing RFC 9396 citation');
invariant(txtFlat.includes('RFC 9396'), 'TXT render is missing RFC 9396 citation');
invariant(xml.includes('draft-rosomakho-oauth-txn-challenge-00'), 'Missing revision-pinned OAuth challenge citation');
invariant(txt.includes('[I-D.rosomakho-oauth-txn-challenge]'), 'TXT render is missing the OAuth challenge citation');
invariant(xml.includes('application/ep-authorization-receipt+json'), 'Missing media-type request');
invariant(xml.includes('application/ep-authorization-bundle+json'), 'Missing Authorization Bundle media-type request');
invariant(txt.includes('ep-authorization-receipt+json'), 'TXT render is missing the media subtype');
invariant(!xml.includes('application/ep-receipt+json'), 'The ambiguous generic media type must not be requested');
invariant(!xml.includes('disclosure_digest'), 'Do not introduce a third profileless display digest');
invariant(txt.includes(basename) && html.includes(basename), 'Renders must identify -11');
invariant(!txt.includes('draft-schrock-ep-authorization-receipts-09'), 'TXT render still identifies -09');

const repoRoot = new URL('../', import.meta.url);
const vectorBytes = readFileSync(new URL('conformance/vectors/authorization-bundle.v1.json', repoRoot));
const vectors = JSON.parse(vectorBytes.toString('utf8'));
invariant(vectors['@version'] === 'EP-AUTHORIZATION-BUNDLE-CASES-v1', 'Wrong bundle vector version');
invariant(vectors.cases?.length === 24, 'Authorization Bundle must publish 24 hostile cases');
invariant(new Set(vectors.cases.map((entry) => entry.id)).size === 24, 'Bundle vector IDs must be unique');
invariant(
  Buffer.compare(vectorBytes, readFileSync(new URL('packages/verify/authorization-bundle.v1.json', repoRoot))) === 0,
  'Packed Authorization Bundle vectors differ from repository source',
);
const verifier = readFileSync(new URL('packages/verify/src/authorization-bundle.ts', repoRoot), 'utf8');
for (const required of [
  'authorization_decision: false',
  'approver_selection_mismatch',
  'current_policy_unavailable_or_stale',
  'bundle_already_bound_to_another_grant',
]) invariant(verifier.includes(required), `Authorization Bundle verifier is missing: ${required}`);
invariant(
  !verifier.includes('EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1'),
  'Neutral Authorization Bundle verifier must not hardcode OAuth/RAR',
);
const oauthProfile = readFileSync(
  new URL('packages/verify/src/oauth-rar-authorization-binding.ts', repoRoot),
  'utf8',
);
invariant(
  oauthProfile.includes('EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1'),
  'Separate OAuth/RAR binding profile is missing',
);

const resources = JSON.parse(readFileSync(new URL('ADDITIONAL-RESOURCES.json', root), 'utf8'));
const resourceRows = resources[basename];
invariant(Array.isArray(resourceRows) && resourceRows.length >= 5, 'Additional Resources are incomplete');
for (const row of resourceRows) {
  invariant(['github_repo', 'related_implementations'].includes(row.tag), `Unexpected resource tag: ${row.tag}`);
  invariant(/^https:\/\//.test(row.url), `Resource URL must be HTTPS: ${row.url}`);
}

const manifest = readFileSync(new URL('SHA256SUMS.txt', root), 'utf8').trim().split('\n');
const expectedPaths = [
  `UPLOAD-THIS/${basename}.xml`,
  `RENDERS/${basename}.html`,
  `RENDERS/${basename}.txt`,
];
invariant(manifest.length === expectedPaths.length, 'Checksum manifest must contain exactly three entries');
for (const [index, relative] of expectedPaths.entries()) {
  const match = /^([a-f0-9]{64})  (.+)$/.exec(manifest[index]);
  invariant(match !== null && match[2] === relative, `Malformed checksum entry for ${relative}`);
  if (match === null) throw new Error(`Malformed checksum entry for ${relative}`);
  invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `Checksum mismatch for ${relative}`);
}

console.log('Authorization Receipts -11: source, renders, bundle vectors, implementation, metadata, and checksums PASS.');
