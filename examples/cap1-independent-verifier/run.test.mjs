import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  cap1ObjectDigest,
  canonicalUnitSetDigest,
  verifyCap1,
  verifyExaminedSetEvidence,
} from './verify.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const UPSTREAM = path.join(HERE, 'vectors', 'upstream');

async function json(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

function copy(value) {
  return structuredClone(value);
}

async function upstreamVector(id) {
  return json(path.join(UPSTREAM, `${id}.json`));
}

function baseTwoUnitDocument() {
  return {
    profile: 'cap/1',
    subject: { kind: 'corpus', ref: 'two-unit-control' },
    strata: [{
      id: 'records',
      population: 'two named records',
      basis: { kind: 'declared' },
      eligible: 2,
      examined: 2,
      unexamined: [],
      supports: ['absence-of-record'],
    }],
    absence_assertions: [{
      assertion: 'No target record was observed.',
      stratum: 'records',
    }],
    integrity: {
      complete: true,
      statement: 'Every dispatched unit reached a recorded outcome.',
    },
  };
}

function examinedEvidence(eligibleUnits, results) {
  return {
    profile: 'EMILIA-CAP1-EXAMINED-SET-v1',
    strata: [{
      stratum: 'records',
      eligible_units: eligibleUnits,
      eligible_set_digest: canonicalUnitSetDigest(eligibleUnits),
      examined_set_digest: canonicalUnitSetDigest([...new Set(results.map((entry) => entry.unit))]),
      results,
    }],
  };
}

test('the copied upstream vector objects are object-pinned to the observed Certisyn commit', async () => {
  const lock = await json(path.join(HERE, 'source-lock.json'));
  const manifestBytes = await readFile(path.join(UPSTREAM, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(
    createHash('sha256').update(manifestBytes).digest('hex'),
    lock.source.local_observed_vector_manifest_sha256,
  );
  assert.equal(cap1ObjectDigest(manifest), `sha256:${lock.source.observed_vector_manifest_object_sha256}`);
  for (const entry of lock.observed_vectors) {
    const bytes = await readFile(path.join(UPSTREAM, entry.file));
    const document = JSON.parse(bytes);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), entry.local_sha256, entry.file);
    assert.equal(cap1ObjectDigest(document), `sha256:${entry.object_sha256}`, entry.file);
  }
});

test('independent verifier runs all five positive and ten negative upstream vectors', async () => {
  const manifest = await json(path.join(UPSTREAM, 'manifest.json'));
  assert.equal(manifest.length, 15);
  assert.equal(manifest.filter((entry) => entry.kind === 'positive').length, 5);
  assert.equal(manifest.filter((entry) => entry.kind === 'negative').length, 10);

  for (const entry of manifest) {
    const result = verifyCap1(await upstreamVector(entry.id));
    assert.equal(result.verdict, entry.expect === 'conform' ? 'CONFORMS' : 'REFUSES', entry.id);
    if (entry.rule) assert.equal(result.primary_rule, entry.rule, entry.id);
  }
});

test('deleting every schema-required field is refused', async () => {
  const base = await upstreamVector('PV-01');
  const controls = [
    ['profile', (document) => { delete document.profile; }],
    ['subject', (document) => { delete document.subject; }],
    ['strata', (document) => { delete document.strata; }],
    ['integrity', (document) => { delete document.integrity; }],
    ['subject.kind', (document) => { delete document.subject.kind; }],
    ['subject.ref', (document) => { delete document.subject.ref; }],
    ['subject.digest.algorithm', (document) => { delete document.subject.digest.algorithm; }],
    ['subject.digest.value', (document) => { delete document.subject.digest.value; }],
    ['strata[0].id', (document) => { delete document.strata[0].id; }],
    ['strata[0].population', (document) => { delete document.strata[0].population; }],
    ['strata[0].basis', (document) => { delete document.strata[0].basis; }],
    ['strata[0].basis.kind', (document) => { delete document.strata[0].basis.kind; }],
    ['strata[0].eligible', (document) => { delete document.strata[0].eligible; }],
    ['strata[0].examined', (document) => { delete document.strata[0].examined; }],
    ['strata[0].unexamined', (document) => { delete document.strata[0].unexamined; }],
    ['unexamined[0].unit', (document) => { delete document.strata[0].unexamined[0].unit; }],
    ['unexamined[0].disposition', (document) => { delete document.strata[0].unexamined[0].disposition; }],
    ['absence_assertions[0].assertion', (document) => { delete document.absence_assertions[0].assertion; }],
    ['absence_assertions[0].stratum', (document) => { delete document.absence_assertions[0].stratum; }],
    ['integrity.complete', (document) => { delete document.integrity.complete; }],
    ['integrity.statement', (document) => { delete document.integrity.statement; }],
  ];
  for (const [name, mutate] of controls) {
    const document = copy(base);
    mutate(document);
    const result = verifyCap1(document);
    assert.equal(result.verdict, 'REFUSES', name);
  }
});

test('duplicate stratum identifiers fail R0', async () => {
  const document = await upstreamVector('PV-05');
  document.strata[1].id = document.strata[0].id;
  assert.equal(verifyCap1(document).primary_rule, 'R0-shape');
});

test('examining A twice cannot satisfy a two-unit examined-set commitment', () => {
  const document = baseTwoUnitDocument();
  assert.equal(verifyCap1(document).verdict, 'CONFORMS');

  const evidence = {
    profile: 'EMILIA-CAP1-EXAMINED-SET-v1',
    strata: [{
      stratum: 'records',
      eligible_units: ['A', 'B'],
      eligible_set_digest: canonicalUnitSetDigest(['A', 'B']),
      examined_set_digest: canonicalUnitSetDigest(['A']),
      results: [
        { unit: 'A', result_digest: `sha256:${'a'.repeat(64)}` },
        { unit: 'A', result_digest: `sha256:${'b'.repeat(64)}` },
      ],
    }],
  };
  assert.deepEqual(verifyExaminedSetEvidence(document, evidence), {
    verdict: 'REFUSES',
    reason: 'examined_unit_duplicate',
    stratum: 'records',
  });

  const good = examinedEvidence(['A', 'B'], [
    { unit: 'A', result_digest: `sha256:${'a'.repeat(64)}` },
    { unit: 'B', result_digest: `sha256:${'b'.repeat(64)}` },
  ]);
  assert.equal(verifyExaminedSetEvidence(document, good).verdict, 'SATISFIED');
});

test('duplicate unexamined unit identifiers pass CAP-1 arithmetic but fail the EMILIA set control', () => {
  const document = baseTwoUnitDocument();
  document.strata[0].examined = 0;
  document.strata[0].unexamined = [
    { unit: 'A', disposition: 'not_applicable' },
    { unit: 'A', disposition: 'not_applicable' },
  ];
  assert.equal(verifyCap1(document).verdict, 'CONFORMS');

  const evidence = examinedEvidence(['A', 'B'], []);
  assert.deepEqual(verifyExaminedSetEvidence(document, evidence), {
    verdict: 'REFUSES',
    reason: 'unexamined_unit_duplicate',
    stratum: 'records',
  });
});

test('withheld conforms natively but is refused by the examined-set control until its semantics are resolved', async () => {
  const document = await upstreamVector('PV-04');
  assert.equal(verifyCap1(document).verdict, 'CONFORMS');
  const eligible = ['d1', 'd2', 'd3', 'd4', 'pdf.ts', 'audio.ts', 'selector.ts'];
  const results = ['d1', 'd2', 'd3', 'd4'].map((unit, index) => ({
    unit,
    result_digest: `sha256:${String(index + 1).repeat(64)}`,
  }));
  const evidence = {
    profile: 'EMILIA-CAP1-EXAMINED-SET-v1',
    strata: [{
      stratum: 'detectors',
      eligible_units: eligible,
      eligible_set_digest: canonicalUnitSetDigest(eligible),
      examined_set_digest: canonicalUnitSetDigest(results.map((entry) => entry.unit)),
      results,
    }],
  };
  assert.deepEqual(verifyExaminedSetEvidence(document, evidence), {
    verdict: 'REFUSES',
    reason: 'withheld_examined_semantics_ambiguous',
    stratum: 'detectors',
  });
});

test('closed vocabulary cannot express abort, scheduling, or sampling states', async () => {
  const base = await upstreamVector('PV-01');
  for (const disposition of ['aborted_before_dispatch', 'not_reached', 'not_sampled', 'not_yet_due']) {
    const document = copy(base);
    document.strata[0].unexamined[0].disposition = disposition;
    assert.equal(verifyCap1(document).primary_rule, 'R2-closed-disposition', disposition);
  }
});

test('derived basis and technique or depth fields are unrepresentable in native CAP-1', async () => {
  const base = await upstreamVector('PV-01');
  const derived = copy(base);
  derived.strata[0].basis = {
    kind: 'derived',
    source_catalogue_digest: 'b'.repeat(64),
    predicate: 'subject.applicable == true',
  };
  assert.equal(verifyCap1(derived).primary_rule, 'R0-shape');
  assert.ok(verifyCap1(derived).violations.some((entry) => entry.rule === 'R4-denominator-basis'));

  for (const field of ['technique', 'depth']) {
    const document = copy(base);
    document.strata[0][field] = 'full';
    assert.equal(verifyCap1(document).primary_rule, 'R0-shape', field);
  }
});

test('native digest fields cannot state the algorithm required by Section 9', async () => {
  const base = await upstreamVector('PV-01');
  assert.equal(verifyCap1(base).verdict, 'CONFORMS');
  const natural = copy(base);
  natural.strata[0].basis.catalogue_digest = {
    algorithm: 'SHA-256',
    value: 'b'.repeat(64),
  };
  assert.equal(verifyCap1(natural).primary_rule, 'R0-shape');
});

test('a declared denominator selected after results are known still conforms natively', () => {
  const document = baseTwoUnitDocument();
  document.strata[0].population = '460 checks retained after observing 500 results';
  document.strata[0].eligible = 460;
  document.strata[0].examined = 460;
  assert.equal(verifyCap1(document).verdict, 'CONFORMS');
});
