import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

const ROOT = new URL('../standards/staged/', import.meta.url);
const uploadDir = new URL('UPLOAD-THIS/', ROOT);
const renderDir = new URL('RENDERS/', ROOT);
const expectedXml = [
  'draft-schrock-action-evidence-boundary-03.xml',
  'draft-schrock-ep-authorization-evidence-chain-05.xml',
  'draft-schrock-ep-bounded-capability-receipts-01.xml',
  'draft-schrock-ep-bounded-execution-program-00.xml',
  'draft-schrock-ep-reliance-agreement-00.xml',
  'draft-schrock-model-to-matter-03.xml',
].sort();

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const actualXml = readdirSync(uploadDir).filter((name) => name.endsWith('.xml')).sort();
invariant(JSON.stringify(actualXml) === JSON.stringify(expectedXml),
  `UPLOAD-THIS must contain exactly the six governed XML files; found ${actualXml.join(', ')}`);

const expectedArtifacts = [];
for (const filename of expectedXml) {
  const base = filename.slice(0, -4);
  const xml = readFileSync(new URL(filename, uploadDir), 'utf8');
  invariant(xml.includes(`docName="${base}"`), `${filename}: docName must equal filename`);
  invariant(xml.includes('submissionType="IETF"'), `${filename}: submissionType must be IETF`);
  invariant(/<date year="2026" month="August" day="3"\s*\/>/.test(xml),
    `${filename}: source date must be 2026-08-03`);
  expectedArtifacts.push(`UPLOAD-THIS/${filename}`, `RENDERS/${base}.html`, `RENDERS/${base}.txt`);
}

const renderFiles = readdirSync(renderDir).filter((name) => /\.(?:html|txt)$/.test(name)).sort();
const expectedRenders = expectedXml.flatMap((filename) => {
  const base = filename.slice(0, -4);
  return [`${base}.html`, `${base}.txt`];
}).sort();
invariant(JSON.stringify(renderFiles) === JSON.stringify(expectedRenders),
  'RENDERS must contain exactly one HTML and TXT rendering per governed XML');

for (const jsonName of ['ADDITIONAL-RESOURCES.json']) {
  JSON.parse(readFileSync(new URL(jsonName, ROOT), 'utf8'));
}
JSON.parse(readFileSync(new URL('../STATUS.json', ROOT), 'utf8'));

const manifestText = readFileSync(new URL('SHA256SUMS.txt', ROOT), 'utf8').trim();
const manifest = new Map();
for (const line of manifestText.split('\n')) {
  const match = /^([a-f0-9]{64})  (UPLOAD-THIS|RENDERS)\/(.+)$/.exec(line);
  if (!match) throw new Error(`Malformed checksum entry: ${line}`);
  const relative = `${match[2]}/${match[3]}`;
  invariant(!manifest.has(relative), `Duplicate checksum entry: ${relative}`);
  manifest.set(relative, match[1]);
}
invariant(JSON.stringify([...manifest.keys()].sort()) === JSON.stringify(expectedArtifacts.sort()),
  'SHA256SUMS.txt must cover the six XMLs and twelve renders exactly');
for (const [relative, expected] of manifest) {
  const bytes = readFileSync(new URL(relative, ROOT));
  invariant(sha256(bytes) === expected, `${relative}: checksum mismatch`);
}

console.log(`Standards staged packet: ${expectedXml.length} XMLs, ${expectedRenders.length} renders, checksums and metadata PASS.`);
