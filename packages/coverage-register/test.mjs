import test from 'node:test';
import assert from 'node:assert/strict';

import { CATEGORIES, rubricIntegrityProblems } from './rubric.mjs';
import { deriveVerdict, assertVerdictIsDocumentClaim, declarationDigest, declarationText } from './verdict.mjs';
import { buildEdition, selectLatest, canonicalJson, reproduce } from './edition.mjs';

const AS_OF = '2026-08-01';

const row = (name, description, { isLatest = true, publishedAt = '2026-01-01T00:00:00Z', title = null, version = '1' } = {}) => ({
  server: { name, description, title, version },
  _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', isLatest, publishedAt } },
});

const snapshotOf = (rows, asOf = AS_OF) => ({
  '@version': 'EP-COVERAGE-SNAPSHOT-v1',
  provenance: { source: 'test', as_of: asOf, rows_fetched: rows.length, method: 'fixture' },
  rows,
});

const reviewFor = (server, state = 'confirmed', rationale = 'Human review confirmed the machine candidate against the captured declaration.') => ({
  state,
  declaration_digest: deriveVerdict(server, AS_OF).declaration_digest,
  reviewer: 'test:independent-reviewer',
  reviewed_at: '2026-08-01T12:00:00Z',
  rationale,
});

const publicationFor = (assessmentDigest) => ({
  assessment_digest: assessmentDigest,
  approved_by: 'test:publication-owner',
  approved_at: '2026-08-01T13:00:00Z',
  correction_uri: 'mailto:corrections@example.test',
  correction_sla_hours: 24,
});

test('all seven categories can actually match; none is silently dead', () => {
  assert.deepEqual(rubricIntegrityProblems(), []);
  assert.equal(CATEGORIES.length, 7);
});

test('a machine match without authorization language is an unreviewed candidate, not a finding', () => {
  const v = deriveVerdict({ name: 'acme/pay', description: 'Send a wire transfer and settle an invoice.' }, AS_OF);
  assert.equal(v.verdict, 'DECLARATION_SILENT_CANDIDATE');
  assert.equal(v.is_finding, false);
  assert.equal(v.requires_review, true);
  assert.ok(v.categories.includes('money_movement.release'));
  assert.match(v.sentence, /^As published on 2026-08-01,/);
  assert.match(v.sentence, /unreviewed candidate, not a finding\.$/);
  assert.equal(v.remedy, null);
});

test('the same declaration with authorization language is not a finding', () => {
  const v = deriveVerdict(
    { name: 'acme/pay', description: 'Send a wire transfer. Requires approval from a named human before release.' },
    AS_OF,
  );
  assert.equal(v.verdict, 'DECLARED_AUTHORIZATION_SIGNAL');
  assert.equal(v.is_finding, false);
  assert.equal(v.remedy, null);
  assert.ok(v.authorization_evidence.length > 0);
});

test('a read-only declaration is not swept in', () => {
  const v = deriveVerdict({ name: 'acme/weather', description: 'Look up the current forecast for a city.' }, AS_OF);
  assert.equal(v.verdict, 'NO_MATCHING_CATEGORY_SIGNAL');
  assert.equal(v.is_finding, false);
  assert.deepEqual(v.categories, []);
});

test('every candidate carries the exact quoted span that produced it', () => {
  const v = deriveVerdict({ name: 'acme/db', description: 'Purge records and drop table contents on request.' }, AS_OF);
  assert.equal(v.verdict, 'DECLARATION_SILENT_CANDIDATE');
  assert.ok(v.evidence.length > 0);
  for (const e of v.evidence) {
    assert.ok(e.matched && e.quote, 'evidence must name the matched term and quote the surrounding text');
    assert.ok(e.quote.toLowerCase().includes(e.matched.trim()), 'the quote must actually contain the match');
  }
});

test('a verdict is refused without an explicit edition date', () => {
  assert.throws(() => deriveVerdict({ name: 'a', description: 'wire transfer' }), /undated/);
  assert.throws(() => deriveVerdict({ name: 'a', description: 'wire transfer' }, '2026-8-1'), /YYYY-MM-DD/);
});

test('wording guard rejects any sentence that makes a runtime claim', () => {
  for (const bad of [
    'As published on 2026-08-01, this server is vulnerable to unauthorized payments.',
    'As published on 2026-08-01, this target does not require human approval.',
    'As published on 2026-08-01, this surface is insecure.',
  ]) {
    assert.throws(() => assertVerdictIsDocumentClaim(bad), /runtime claim/);
  }
});

test('wording guard requires the dated, scoped opening', () => {
  assert.throws(
    () => assertVerdictIsDocumentClaim('This declaration advertises money movement.'),
    /must open with "As published on/,
  );
});

test('the declaration digest pins the canonical assessed text', () => {
  const a = { name: 'x/y', title: 'T', description: 'wire transfer' };
  const b = { name: 'x/y', title: 'T', description: 'wire transfer ' };
  assert.equal(declarationDigest(declarationText(a)), declarationDigest(declarationText(b)), 'trailing whitespace is normalized');
  const c = { name: 'x/y', title: 'T', description: 'wire transfers' };
  assert.notEqual(declarationDigest(declarationText(a)), declarationDigest(declarationText(c)));
});

test('only the registry-latest row for a target is assessed', () => {
  const rows = [
    row('acme/pay', 'old copy, no consequential capability', { isLatest: false, publishedAt: '2026-01-01T00:00:00Z' }),
    row('acme/pay', 'Send a wire transfer.', { isLatest: true, publishedAt: '2026-02-01T00:00:00Z' }),
  ];
  const latest = selectLatest(rows);
  assert.equal(latest.length, 1);
  assert.match(latest[0].server.description, /wire transfer/);
});

test('a target with no isLatest flag falls back to newest and is never dropped', () => {
  const rows = [
    row('acme/pay', 'older', { isLatest: false, publishedAt: '2026-01-01T00:00:00Z' }),
    row('acme/pay', 'Send a wire transfer.', { isLatest: false, publishedAt: '2026-03-01T00:00:00Z' }),
  ];
  const latest = selectLatest(rows);
  assert.equal(latest.length, 1);
  assert.match(latest[0].server.description, /wire transfer/);
});

test('latest-row selection is deterministic when registry metadata ties', () => {
  const a = row('acme/pay', 'Send a wire transfer A.', { isLatest: true, publishedAt: '2026-03-01T00:00:00Z' });
  const b = row('acme/pay', 'Send a wire transfer B.', { isLatest: true, publishedAt: '2026-03-01T00:00:00Z' });
  assert.deepEqual(selectLatest([a, b]), selectLatest([b, a]));
});

test('an edition is byte-deterministic and independent of input row order', () => {
  const rows = [
    row('b/deploy', 'Deploy to production via terraform.'),
    row('a/pay', 'Send a wire transfer.'),
    row('c/read', 'Read the weather.'),
  ];
  const one = buildEdition(snapshotOf(rows));
  const two = buildEdition(snapshotOf([...rows].reverse()));
  assert.equal(one.edition_digest, two.edition_digest);
  assert.equal(canonicalJson(one), canonicalJson(two));
  assert.deepEqual(one.targets.map((t) => t.target), ['a/pay', 'b/deploy', 'c/read']);
});

test('an edition is refused without provenance', () => {
  assert.throws(() => buildEdition({ rows: [row('a/pay', 'wire transfer')] }), /undated edition/);
});

test('counts and category rollups add up', () => {
  const e = buildEdition(snapshotOf([
    row('a/pay', 'Send a wire transfer.'),
    row('b/pay', 'Send a wire transfer. Requires approval by a human.'),
    row('c/read', 'Read the weather.'),
  ]));
  assert.equal(e.counts.total, 3);
  assert.equal(e.counts.DECLARATION_SILENT_CANDIDATE, 1);
  assert.equal(e.counts.DECLARED_AUTHORIZATION_SIGNAL, 1);
  assert.equal(e.counts.NO_MATCHING_CATEGORY_SIGNAL, 1);
  const money = e.by_category['money_movement.release'];
  assert.equal(money.matching_signal, 2);
  assert.equal(money.authorization_signal, 1);
});

test('reproduce confirms an unchanged edition and reports drift when a declaration changes', () => {
  const rows = [row('a/pay', 'Send a wire transfer.')];
  const published = buildEdition(snapshotOf(rows));
  assert.equal(reproduce(snapshotOf(rows), published).reproduced, true);

  const changed = [row('a/pay', 'Send a wire transfer. Requires approval by a human.')];
  const result = reproduce(snapshotOf(changed), published);
  assert.equal(result.reproduced, false);
  assert.ok(result.drift.some((d) => d.includes('DECLARATION_SILENT_CANDIDATE -> DECLARED_AUTHORIZATION_SIGNAL') || d.includes('verdict')));
});

test('every published sentence in a real edition passes the wording guard', () => {
  const e = buildEdition(snapshotOf([
    row('a/pay', 'Send a wire transfer and delete records.'),
    row('b/x', 'Grant admin permission and export all data.'),
    row('c/read', 'Read status.'),
  ]));
  for (const t of e.targets) assert.ok(assertVerdictIsDocumentClaim(t.sentence));
});

test('a negated capability is not a finding ("no API keys" is not a permission change)', () => {
  const v = deriveVerdict(
    { name: 'x/tools', description: 'Pay-per-call x402 tools, no API keys, USDC on Base.' },
    AS_OF,
  );
  assert.ok(!v.categories.includes('permissions.admin_change'), 'a negated credential mention must not score as a permission change');
});

test('negation guard covers the common phrasings', () => {
  for (const desc of [
    'Query data with no export capability.',
    'Manage state, does not require admin access.',
    'Read-only cluster, without deploy rights.',
    'Analytics only, never grant access to anything.',
  ]) {
    const v = deriveVerdict({ name: 'x/y', description: desc }, AS_OF);
    assert.equal(v.verdict, 'NO_MATCHING_CATEGORY_SIGNAL', `expected no category signal for: ${desc}`);
  }
});

test('a leading capability claim is still caught when a LATER mention is negated', () => {
  // "Deploy previews without deploying to production" advertises a deploy
  // capability in its first word. A preview deploy is a deploy, and the negation
  // guard must not be a loophole for a capability the target genuinely claims.
  const v = deriveVerdict({ name: 'x/y', description: 'Deploy previews without deploying to production.' }, AS_OF);
  assert.equal(v.verdict, 'DECLARATION_SILENT_CANDIDATE');
  assert.ok(v.categories.includes('production.deploy'));
});

test('a genuine mention after a negated one is still caught', () => {
  const v = deriveVerdict(
    { name: 'x/y', description: 'No API keys needed. Can grant access to any repository.' },
    AS_OF,
  );
  assert.ok(v.categories.includes('permissions.admin_change'));
  assert.match(v.evidence[0].matched, /grant access/);
});

test('repeated boilerplate is flagged and counted as one declaration', () => {
  const shared = 'Send a wire transfer via our gateway.';
  const rows = [row('v/one', shared), row('v/two', shared), row('v/three', shared)];
  const review = Object.fromEntries(rows.map(({ server }) => [server.name, reviewFor(server)]));
  const e = buildEdition(snapshotOf(rows), { review });
  assert.equal(e.counts.total, 3);
  assert.equal(e.counts.distinct_declarations, 1);
  assert.equal(e.counts.findings_distinct_declarations, 1);
  for (const t of e.targets) assert.equal(t.declaration_cluster.size, 3);
});

test('the scope limit and correction policy are present in every edition', () => {
  const e = buildEdition(snapshotOf([row('a/pay', 'wire transfer')]));
  assert.match(e.scope_limit, /No target was contacted, probed, or invoked/);
  assert.match(e.scope_limit, /Automated absence/);
  assert.match(e.scope_limit, /Only declaration-bound, human-confirmed gaps are findings/);
  assert.match(e.correction_policy, /Not active/);
});

test('an edition containing unreviewed findings is marked DRAFT and not publishable', () => {
  const e = buildEdition(snapshotOf([row('a/pay', 'Send a wire transfer.'), row('b/read', 'Read the weather.')]));
  assert.match(e.publication_state, /^DRAFT/);
  assert.equal(e.counts.findings_candidate, 1);
  assert.equal(e.counts.publishable, 0);
  assert.equal(e.targets.find((t) => t.target === 'a/pay').review_state, 'candidate');
  assert.equal(e.targets.find((t) => t.target === 'b/read').review_state, 'not_applicable');
});

test('human review promotes a finding but does not authorize publication', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  const e = buildEdition(snap, { review: { 'a/pay': reviewFor(target.server) } });
  assert.match(e.publication_state, /^REVIEWED_NOT_APPROVED/);
  assert.equal(e.counts.publishable, 0);
  assert.equal(e.counts.findings_confirmed, 1);
  assert.equal(e.counts.findings_candidate, 0);
  assert.equal(e.targets[0].verdict, 'DECLARATION_SILENT_CONFIRMED');
  assert.equal(e.targets[0].is_finding, true);
  assert.ok(e.targets[0].remedy);
  assert.equal(reproduce(snap, e).reproduced, true, 'reviewed editions must reproduce with their bound review records');
});

test('publication requires a separate approval bound to the exact reviewed assessment', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  const review = { 'a/pay': reviewFor(target.server) };
  const reviewed = buildEdition(snap, { review });
  const approved = buildEdition(snap, { review, publication: publicationFor(reviewed.assessment_digest) });
  assert.match(approved.publication_state, /^READY_FOR_PUBLICATION/);
  assert.equal(approved.counts.publishable, 1);
  assert.match(approved.correction_policy, /corrections@example\.test/);
  assert.equal(reproduce(snap, approved).reproduced, true);
});

test('a rejected finding blocks nothing and is never published', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  const e = buildEdition(snap, { review: { 'a/pay': reviewFor(target.server, 'rejected', 'The wording describes payment infrastructure but does not advertise executing a payment.') } });
  assert.match(e.publication_state, /^REVIEWED_NOT_APPROVED/);
  assert.equal(e.counts.findings_rejected, 1);
  assert.equal(e.counts.publishable, 0);
  assert.equal(e.targets[0].verdict, 'CANDIDATE_REJECTED');
  assert.equal(e.targets[0].is_finding, false);
  assert.equal(e.targets[0].remedy, null);
  assert.match(e.targets[0].sentence, /no authorization-coverage finding is recorded/);
  assert.equal(reproduce(snap, e).reproduced, true);
});

test('an unknown review state is refused rather than silently ignored', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  assert.throws(
    () => buildEdition(snap, { review: { 'a/pay': { ...reviewFor(target.server), state: 'probably-fine' } } }),
    /unknown review state/,
  );
});

test('a human review is bound to the exact declaration digest and cannot survive drift', () => {
  const original = row('a/pay', 'Send a wire transfer.');
  const review = reviewFor(original.server);
  const changed = row('a/pay', 'Send a wire transfer. Requires approval by a human.');
  assert.throws(
    () => buildEdition(snapshotOf([changed]), { review: { 'a/pay': review } }),
    /stale or unbound/,
  );
});

test('a review requires attributable reviewer, timestamp, and rationale', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  const valid = reviewFor(target.server);
  for (const invalid of [
    { ...valid, reviewer: '' },
    { ...valid, reviewed_at: '2026-08-01' },
    { ...valid, rationale: 'yes' },
  ]) {
    assert.throws(() => buildEdition(snap, { review: { 'a/pay': invalid } }), /review for a\/pay requires/);
  }
});

test('a review cannot be attached to an absent or non-candidate target', () => {
  const candidate = row('a/pay', 'Send a wire transfer.');
  const safe = row('b/read', 'Read the weather.');
  assert.throws(
    () => buildEdition(snapshotOf([safe]), { review: { 'a/pay': reviewFor(candidate.server) } }),
    /absent or non-candidate/,
  );
  assert.throws(
    () => buildEdition(snapshotOf([safe]), { review: { 'b/read': { ...reviewFor(candidate.server), declaration_digest: deriveVerdict(safe.server, AS_OF).declaration_digest } } }),
    /not a candidate/,
  );
});

test('publication approval is refused when stale, incomplete, or candidates remain', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  const review = { 'a/pay': reviewFor(target.server) };
  const reviewed = buildEdition(snap, { review });
  assert.throws(
    () => buildEdition(snap, { review, publication: { ...publicationFor(reviewed.assessment_digest), assessment_digest: 'sha256:stale' } }),
    /stale or unbound/,
  );
  assert.throws(
    () => buildEdition(snap, { review, publication: { ...publicationFor(reviewed.assessment_digest), correction_uri: '' } }),
    /correction_uri/,
  );
  const draft = buildEdition(snap);
  assert.throws(
    () => buildEdition(snap, { publication: publicationFor(draft.assessment_digest) }),
    /unreviewed candidates remain/,
  );
});

test('publication approval is refused for a truncated snapshot', () => {
  const target = row('a/pay', 'Send a wire transfer.');
  const snap = snapshotOf([target]);
  snap.provenance.truncated = true;
  const review = { 'a/pay': reviewFor(target.server) };
  const reviewed = buildEdition(snap, { review });
  assert.match(reviewed.publication_state, /^DRAFT_TRUNCATED/);
  assert.throws(
    () => buildEdition(snap, { review, publication: publicationFor(reviewed.assessment_digest) }),
    /truncated snapshot/,
  );
});

test('review bundle and snapshot date shapes fail closed', () => {
  const snap = snapshotOf([row('a/pay', 'Send a wire transfer.')]);
  assert.throws(() => buildEdition(snap, { review: [] }), /review bundle/);
  assert.throws(() => buildEdition(snapshotOf([], '2026-8-1')), /valid provenance\.as_of/);
});
