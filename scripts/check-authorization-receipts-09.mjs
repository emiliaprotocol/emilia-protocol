import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AUTHORIZATION-RECEIPTS-09/', import.meta.url);
const upload = new URL('UPLOAD-THIS/', root);
const renders = new URL('RENDERS/', root);
const basename = 'draft-schrock-ep-authorization-receipts-09';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const uploadFiles = readdirSync(upload).sort();
invariant(
  JSON.stringify(uploadFiles) === JSON.stringify([`${basename}.xml`]),
  'The -09 upload directory must contain exactly one XML source',
);

const renderFiles = readdirSync(renders).sort();
invariant(
  JSON.stringify(renderFiles) === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'The -09 render directory must contain exactly one HTML and TXT rendering',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
invariant(xml.includes(`docName="${basename}"`), 'docName must match the -09 filename');
invariant(xml.includes('category="std"'), 'The -09 candidate must be Standards Track');
invariant(!xml.includes('submissionType='), 'An individual draft must not claim an adopted document stream');
invariant(xml.includes('<xref target="EP-CAID"/>'), 'CAID must be cited in the text');
invariant(xml.includes('<xref target="EP-QUORUM"/>'), 'EP-QUORUM must be cited in the text');

const resources = JSON.parse(readFileSync(new URL('ADDITIONAL-RESOURCES.json', root), 'utf8'));
const resourceRows = resources[basename];
invariant(Array.isArray(resourceRows) && resourceRows.length >= 3, 'Additional Resources are incomplete');
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
  invariant(match && match[2] === relative, `Malformed checksum entry for ${relative}`);
  invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `Checksum mismatch for ${relative}`);
}

console.log('Authorization Receipts -09: source, renders, metadata, and checksums PASS.');
