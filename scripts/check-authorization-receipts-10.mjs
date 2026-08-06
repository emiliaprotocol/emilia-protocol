import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AUTHORIZATION-RECEIPTS-10/', import.meta.url);
const upload = new URL('UPLOAD-THIS/', root);
const renders = new URL('RENDERS/', root);
const basename = 'draft-schrock-ep-authorization-receipts-10';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const uploadFiles = readdirSync(upload).sort();
invariant(
  JSON.stringify(uploadFiles) === JSON.stringify([`${basename}.xml`]),
  'The -10 upload directory must contain exactly one XML source',
);

const renderFiles = readdirSync(renders).sort();
invariant(
  JSON.stringify(renderFiles) === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'The -10 render directory must contain exactly one HTML and TXT rendering',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const html = readFileSync(new URL(`RENDERS/${basename}.html`, root), 'utf8');
invariant(xml.includes(`docName="${basename}"`), 'docName must match the -10 filename');
invariant(xml.includes('category="std"'), 'The -10 candidate must be Standards Track');
invariant(!xml.includes('submissionType='), 'An individual draft must not claim an adopted document stream');
invariant(xml.includes('<date year="2026" month="August" day="6"/>'), 'The -10 date must be 6 August 2026');

const normativeStart = xml.indexOf('<name>Normative References</name>');
const informativeStart = xml.indexOf('<name>Informative References</name>');
const caidReference = xml.indexOf('<reference anchor="EP-CAID"');
const oasntReference = xml.indexOf('<reference anchor="I-D.thallapelly-oasnt"');
invariant(normativeStart >= 0 && informativeStart > normativeStart, 'Reference groups are malformed');
invariant(caidReference > normativeStart && caidReference < informativeStart, 'CAID must be normative');
invariant(oasntReference > normativeStart && oasntReference < informativeStart, 'OASNT profile dependency must be normative');

for (const required of [
  'EP-PRESENTATION-BINDING-v1',
  'display-unbound',
  'display-mismatch',
  'display-untrusted',
  'EP-AUTHORIZATION-RECEIPT-v1',
]) {
  invariant(xml.includes(required), `Missing -10 requirement: ${required}`);
  invariant(txt.includes(required), `TXT render is stale or missing: ${required}`);
}
invariant(xml.includes('application/ep-authorization-receipt+json'), 'Missing media-type request');
invariant(txt.includes('ep-authorization-receipt+json'), 'TXT render is missing the media subtype');
invariant(!xml.includes('application/ep-receipt+json'), 'The ambiguous generic media type must not be requested');
invariant(!xml.includes('disclosure_digest'), 'Do not introduce a third profileless display digest');
invariant(txt.includes(basename) && html.includes(basename), 'Renders must identify -10');
invariant(!txt.includes('draft-schrock-ep-authorization-receipts-09'), 'TXT render still identifies -09');

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

console.log('Authorization Receipts -10: source, renders, profile split, metadata, and checksums PASS.');
