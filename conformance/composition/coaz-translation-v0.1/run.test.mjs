// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'vitest';
import {
  DECLARED_RELEASE_PAYMENT_MAPPING,
  DEFAULT_TOOLS_CALL_MAPPING,
  PROFILE,
  canonicalBytes,
  relyingCheck,
  runCorpus,
  toyPdpDecide,
  translate,
  translateWithCaid,
  typedSourceAction,
} from './run.mjs';

const corpus = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
const sourceLock = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
const contribution = readFileSync(new URL('./AUTHZEN-CONTRIBUTION.md', import.meta.url), 'utf8');
const token = corpus.fixtures.token_claims;

test('the complete corpus passes and reports self-reproduction, not independent implementation', () => {
  const report = runCorpus(corpus);
  assert.equal(
    report.passed,
    true,
    JSON.stringify(report.results.filter((entry) => !entry.passed), null, 2),
  );
  assert.equal(report['@profile'], PROFILE);
  assert.equal(report.implementation_owner, 'EMILIA Protocol');
  assert.equal(report.independent_implementation, false);
  assert.equal(report.total, corpus.cases.length);
  assert.equal(report.passed_cases, corpus.cases.length);
});

test('semantic substitution: materially different source actions, byte-identical tuples, both permitted', () => {
  const benign = corpus.fixtures.benign_call;
  const substituted = corpus.fixtures.substituted_call;

  const sourceA = canonicalBytes(typedSourceAction(benign));
  const sourceB = canonicalBytes(typedSourceAction(substituted));
  assert.ok(sourceA.ok && sourceB.ok);
  assert.notEqual(sourceA.canonical, sourceB.canonical, 'source actions must differ');

  for (const mapping of [DEFAULT_TOOLS_CALL_MAPPING, DECLARED_RELEASE_PAYMENT_MAPPING]) {
    const tupleA = translate(mapping, benign, token);
    const tupleB = translate(mapping, substituted, token);
    assert.ok(tupleA.ok && tupleB.ok);
    const bytesA = canonicalBytes(tupleA.request);
    const bytesB = canonicalBytes(tupleB.request);
    assert.ok(bytesA.ok && bytesB.ok);
    assert.equal(bytesA.canonical, bytesB.canonical, 'tuples must be byte-identical');
    assert.equal(toyPdpDecide(tupleA.request).decision, true);
    assert.equal(toyPdpDecide(tupleB.request).decision, true);
  }
});

test('field reclassification: the consequential value rides in an ignored bag, tuple unchanged', () => {
  const baseline = translate(DECLARED_RELEASE_PAYMENT_MAPPING, corpus.fixtures.benign_call, token);
  const reclassified = translate(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    corpus.fixtures.reclassified_call,
    token,
  );
  assert.ok(baseline.ok && reclassified.ok);
  assert.equal(
    canonicalBytes(baseline.request).canonical,
    canonicalBytes(reclassified.request).canonical,
  );
  assert.equal(toyPdpDecide(reclassified.request).decision, true);
});

test('the close: the same translator with a CAID makes the substitution distinguishable and refused by name', () => {
  const benign = translateWithCaid(DECLARED_RELEASE_PAYMENT_MAPPING, corpus.fixtures.benign_call, token);
  const substituted = translateWithCaid(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    corpus.fixtures.substituted_call,
    token,
  );
  assert.ok(benign.ok && substituted.ok);
  assert.equal(benign.caid, corpus.fixtures.expected_caid_benign);
  assert.equal(substituted.caid, corpus.fixtures.expected_caid_substituted);
  assert.notEqual(benign.caid, substituted.caid);

  const approvedAction = typedSourceAction(corpus.fixtures.benign_call);
  assert.deepEqual(
    relyingCheck({
      observedAction: benign.source_action,
      presentedCaid: benign.request.context.caid,
      approvedAction,
    }),
    { allowed: true, reason: null },
  );
  assert.deepEqual(
    relyingCheck({
      observedAction: substituted.source_action,
      presentedCaid: substituted.request.context.caid,
      approvedAction,
    }),
    { allowed: false, reason: 'caid_mismatch:beneficiary_account' },
  );
});

test('fail-closed means refusal with a reason, proven against the bad inputs, never a throw', () => {
  const reclassified = translateWithCaid(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    corpus.fixtures.reclassified_call,
    token,
  );
  assert.equal(reclassified.ok, false);
  assert.equal(reclassified.reason, 'caid_refused:missing_material_field:beneficiary_account');

  const approvedAction = typedSourceAction(corpus.fixtures.benign_call);
  for (const junk of ['caid:junk', '', null, 42, 'caid:1:payment.release.1:jcs-sha256:short']) {
    const check = relyingCheck({
      observedAction: approvedAction,
      presentedCaid: junk,
      approvedAction,
    });
    assert.equal(check.allowed, false, String(junk));
    assert.equal(check.reason, 'caid_invalid:malformed_caid', String(junk));
  }

  // A translator-side expression error is a mapping error, not a permit and
  // not a crash (framework Section 3).
  const missingParams = translate(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    { params: { name: 'release_payment', arguments: {} } },
    token,
  );
  assert.equal(missingParams.ok, false);
  assert.match(missingParams.reason, /^mapping_error:expression_error:no_such_key:/);
});

test('the CAID changes no PDP behavior: identical decisions with and without it', () => {
  const plain = translate(DECLARED_RELEASE_PAYMENT_MAPPING, corpus.fixtures.benign_call, token);
  const withCaid = translateWithCaid(
    DECLARED_RELEASE_PAYMENT_MAPPING,
    corpus.fixtures.benign_call,
    token,
  );
  assert.ok(plain.ok && withCaid.ok);
  assert.equal(toyPdpDecide(plain.request).decision, toyPdpDecide(withCaid.request).decision);
});

test('the source lock pins the exact fetched spec bytes and every local load-bearing file', () => {
  assert.equal(sourceLock['@version'], 'COAZ-TRANSLATION-SOURCE-LOCK-v0.1');
  assert.equal(sourceLock.specs.length >= 2, true);
  for (const spec of sourceLock.specs) {
    assert.match(spec.sha256, /^[0-9a-f]{64}$/, spec.name);
  }
  for (const file of sourceLock.local_files) {
    const bytes = readFileSync(new URL(`../../../${file.path}`, import.meta.url));
    const actual = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(actual, file.sha256, file.path);
  }
});

test('the proposed AuthZEN contribution is source-pinned and does not claim WG acceptance', () => {
  assert.equal(
    sourceLock.upstream_repository.commit,
    'e287920eed842b227e38531c1735b712337ca44d',
  );
  assert.deepEqual(
    sourceLock.upstream_repository.files.map(({ path, sha256 }) => ({ path, sha256 })),
    [
      {
        path: 'profiles/authzen-coaz-framework-1_0.md',
        sha256: 'cfea78ebdc9dfb5bf44ffb88faf64ed9da9252e696625ce729692fbf54ea2f7d',
      },
      {
        path: 'profiles/authzen-coaz-mcp-binding-1_0.md',
        sha256: '7ebd9dd513aed920f6b0020e2542a58cc9e9d6c562b240f22f4bc361dac2b9c1',
      },
    ],
  );
  assert.equal(sourceLock.upstream_issue.number, 603);
  assert.equal(sourceLock.upstream_issue.state_at_fetch, 'open');
  assert.match(contribution, /Status: proposed locally; not submitted to or accepted by OpenID AuthZEN\./);
  assert.match(contribution, /MUST NOT reuse the earlier permit/);
  assert.match(contribution, /was not evaluated by the PDP/);
  assert.doesNotMatch(
    contribution,
    /requested by (?:OpenID|the WG)|WG-approved|Status: accepted/iu,
  );
});
