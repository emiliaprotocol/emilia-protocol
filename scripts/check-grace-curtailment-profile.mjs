import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';

const packet = new URL('../standards/profiles/NEXT-GRID-CURTAILMENT-00/', import.meta.url);
const source = new URL('REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml', packet);
const renderNames = [
  'draft-schrock-kintzele-grid-curtailment-00.html',
  'draft-schrock-kintzele-grid-curtailment-00.pdf',
  'draft-schrock-kintzele-grid-curtailment-00.txt',
];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const xml = readFileSync(source, 'utf8');
const pip = readFileSync(new URL('../PIPs/PIP-014-grid-curtailment-profile.md', import.meta.url), 'utf8');
const exampleReadme = readFileSync(new URL('../examples/grace/README.md', import.meta.url), 'utf8');
const runtime = readFileSync(new URL('../lib/grace/mobile-grid.ts', import.meta.url), 'utf8');
const curtailment = readFileSync(new URL('../lib/grace/curtailment.ts', import.meta.url), 'utf8');
const vectors = JSON.parse(readFileSync(new URL('../conformance/vectors/grace-mobile-grid.v1.json', import.meta.url), 'utf8'));

invariant(xml.includes('docName="draft-schrock-kintzele-grid-curtailment-00"'), 'draft docName mismatch');
invariant(xml.includes('<date year="2026" month="August" day="21"/>'), 'draft date mismatch');
for (const anchor of ['requirements-language', 'privacy', 'security', 'implementation', 'iana']) {
  invariant(xml.includes(`anchor="${anchor}"`), `draft missing ${anchor} section`);
}
for (const value of [
  'EP-FLEX-ENVELOPE-v2',
  'EP-GRACE-CURTAILMENT-ACTION-v1',
  'EP-GRACE-ARTIFACT-SIGNATURE-v2',
  'EP-GRACE-PROOF-OF-CURTAILMENT-v1',
  'EP-GRACE-SETTLE-v1',
  'draft-mih-scitt-agent-action-capsule-02',
]) {
  invariant(xml.includes(value), `draft missing current identifier ${value}`);
  invariant(runtime.includes(value) || curtailment.includes(value), `runtime missing draft identifier ${value}`);
}

const currentProse = `${xml}\n${pip}\n${exampleReadme}`.toLowerCase();
for (const forbidden of ['settlement-grade', 'un-fudgeable', 'what should be paid', 'same event can never']) {
  invariant(!currentProse.includes(forbidden), `current GRACE prose contains overclaim: ${forbidden}`);
}
invariant(/meter statement[\s\S]{0,1200}must not[\s\S]{0,200}baseline_method_hash/i.test(xml),
  'draft must keep market rules out of the meter statement');
invariant(pip.includes('It must not contain `baseline_method_hash`'),
  'PIP must keep market rules out of the meter statement');
invariant(/It does\s+not establish physical meter truth/.test(xml), 'draft missing physical-truth limit');
invariant(/not exactly-once physical payment/.test(xml), 'draft missing settlement limit');
invariant(xml.includes('unregistered_signed_statement'), 'draft missing Action State anchoring limit');
invariant(xml.includes('80 targeted tests pass across four files'), 'draft test receipt is stale');
invariant(Array.isArray(vectors.vectors) && vectors.vectors.length === 6, 'GRACE vector count must remain six');

invariant(!existsSync(new URL('UPLOAD-THIS/', packet)), 'held partner profile must not contain UPLOAD-THIS');
const renderDir = new URL('RENDERS/', packet);
const actualRenders = readdirSync(renderDir).filter((name) => !name.startsWith('.')).sort();
invariant(JSON.stringify(actualRenders) === JSON.stringify(renderNames),
  `unexpected GRACE renders: ${actualRenders.join(', ')}`);

const expected = [
  'REVIEW-SOURCE/draft-schrock-kintzele-grid-curtailment-00.xml',
  ...renderNames.map((name) => `RENDERS/${name}`),
].sort();
const manifest = readFileSync(new URL('SHA256SUMS.txt', packet), 'utf8').trim().split('\n');
const listed = new Map();
for (const line of manifest) {
  const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
  invariant(match, `malformed checksum line: ${line}`);
  listed.set(match[2], match[1]);
}
invariant(JSON.stringify([...listed.keys()].sort()) === JSON.stringify(expected),
  'checksum manifest must cover the XML and three renders exactly');
for (const [relative, digest] of listed) {
  invariant(sha256(readFileSync(new URL(relative, packet))) === digest, `${relative}: checksum mismatch`);
}

console.log('GRACE curtailment profile: claim boundary, current identifiers, six vectors, held status, and artifact checksums PASS.');
