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
const forecastRuntime = readFileSync(new URL('../lib/grace/forecast-evidence.ts', import.meta.url), 'utf8');
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
invariant(forecastRuntime.includes("FORECAST_EVIDENCE_VERSION = 'EP-FORECAST-EVIDENCE-v0.1'"),
  'forecast runtime missing EP-FORECAST-EVIDENCE-v0.1');
invariant(pip.includes('101 passing tests across'), 'PIP forecast test receipt is stale');
invariant(pip.includes('does not imply Google support or endorsement'),
  'PIP must preserve the TimesFM endorsement boundary');
invariant(runtime.includes('forecast_evidence_digest') && runtime.includes('refuse_forecast_evidence'),
  'GRACE runtime missing forecast evidence binding or refusal');

const readme = readFileSync(new URL('README.md', packet), 'utf8');
const validation = readFileSync(new URL('VALIDATION.md', packet), 'utf8');
const standardsStatus = JSON.parse(readFileSync(new URL('../standards/STATUS.json', import.meta.url), 'utf8'));
invariant(readme.includes('explicitly authorized a one-time override'),
  'GRACE publication override is not recorded in README');
invariant(validation.includes('explicitly authorized immediate filing'),
  'GRACE publication authorization is not recorded in validation receipt');
invariant(readme.includes('does not claim that the separate\nnamed-external-implementation exception was satisfied'),
  'GRACE publication override must not imply external implementation');
invariant(readme.includes('Datatracker submission 167956 was accepted and revision `-00` was posted'),
  'GRACE README must distinguish accepted submission from Datatracker posting');
invariant(validation.includes('Datatracker submission 167956 was accepted and revision `-00` was posted'),
  'GRACE validation receipt must record the posted revision');
invariant(!validation.includes('Nothing was submitted to the IETF'),
  'GRACE validation receipt still says the published draft was not submitted');
invariant(validation.includes('0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6'),
  'GRACE validation receipt must pin the IETF archive XML digest');
invariant(validation.includes('8dd61f1f66077d64bb185c3a7a5354f46bb19f0d2f28beb9e2ff728a049adb87'),
  'GRACE validation receipt must pin the IETF archive TXT digest');
const activeGrace = standardsStatus.active_datatracker.find(
  (entry) => entry.draft === 'draft-schrock-kintzele-grid-curtailment',
);
invariant(activeGrace?.revision === '00', 'standards status must list the active GRACE -00 revision');
invariant(activeGrace?.snapshot_sha256 === '0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6',
  'standards status must pin the verified GRACE -00 XML');
invariant(!existsSync(new URL('UPLOAD-THIS/', packet)),
  'single-source upload profile must not contain a drifting UPLOAD-THIS duplicate');
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
  if (!match) {
    continue;
  }
  listed.set(match[2], match[1]);
}
invariant(JSON.stringify([...listed.keys()].sort()) === JSON.stringify(expected),
  'checksum manifest must cover the XML and three renders exactly');
for (const [relative, digest] of listed) {
  invariant(sha256(readFileSync(new URL(relative, packet))) === digest, `${relative}: checksum mismatch`);
}

console.log('GRACE curtailment profile: claim boundary, current identifiers, six vectors, posted revision, and artifact checksums PASS.');
