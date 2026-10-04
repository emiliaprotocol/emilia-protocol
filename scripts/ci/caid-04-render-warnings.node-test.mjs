// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { unexpectedXml2rfcWarnings } from '../xml2rfc-render-warnings.mjs';

const historicalDocumentDate = '2026-09-28';
const today = '2026-10-04';
const ageWarning = `Warning: The document date (${historicalDocumentDate}) is more than 3 days away from today's date`;

test('posted CAID date age alone is exempt, including xml2rfc source locations and CRLF', () => {
  assert.deepEqual(unexpectedXml2rfcWarnings(`${ageWarning}\nposted.xml(40): ${ageWarning}\r\n`, {
    historicalDocumentDate, today,
  }), []);
});

test('date warnings remain fatal for a filing, a different date, a future date or an unaged date', () => {
  assert.deepEqual(unexpectedXml2rfcWarnings(ageWarning, { today }), [ageWarning]);
  for (const options of [
    { historicalDocumentDate: '2026-09-27', today },
    { historicalDocumentDate, today: '2026-09-20' },
    { historicalDocumentDate, today: '2026-10-01' },
    { historicalDocumentDate, today: 'not-a-date' },
  ]) assert.deepEqual(unexpectedXml2rfcWarnings(ageWarning, options), [ageWarning]);
});

test('historical date exemption does not swallow other warnings, altered messages or validation errors', () => {
  const diagnostics = [
    'Warning: Invalid reference target',
    `${ageWarning}; an invalid date attribute was also found`,
    ageWarning.replace('Warning:', 'Error:'),
    'Error: Expected a valid submissionType',
    'Error: Setting consensus="true"',
  ];
  assert.deepEqual(unexpectedXml2rfcWarnings([ageWarning, ...diagnostics].join('\n'), {
    historicalDocumentDate, today,
  }), diagnostics);
});

test('the existing individual-draft warnings remain exempt and informational output is ignored', () => {
  assert.deepEqual(unexpectedXml2rfcWarnings([
    'posted.xml(2): Warning: Expected a valid submissionType but found no stream',
    'Warning: Setting consensus="true" for this document',
    'Created output document',
  ].join('\n')), []);
});

test('CAID checker binds the exemption to the posted source date and keeps prefiling strict', () => {
  const checker = readFileSync(new URL('../check-caid-04.mjs', import.meta.url), 'utf8');
  assert.match(checker, /!prefiling && sourceDocumentDate === '2026-09-28'/u);
  assert.match(checker, /unexpectedXml2rfcWarnings\(r\.stderr \|\| '', \{ historicalDocumentDate \}\)/u);
});
