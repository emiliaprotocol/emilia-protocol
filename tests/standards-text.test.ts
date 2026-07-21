// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  normalizeStandardsText,
  stripMarkup,
} from '../scripts/lib/standards-text.mjs';

describe('standards source text extraction', () => {
  it('keeps visible text and drops tags with quoted delimiters', () => {
    expect(stripMarkup('<p data-value=\"1 > 0\">exact <strong>authority</strong></p>'))
      .toBe(' exact  authority  ');
  });

  it('suppresses script and style bodies even when they contain tag-shaped input', () => {
    const source = [
      '<h1>Authority</h1>',
      '<script>const payload = \"</not-script><p>forged quote</p>\";</script>',
      '<style>.forged::after { content: \"<p>not visible</p>\"; }</style>',
      '<p>Evidence</p>',
    ].join('');
    expect(normalizeStandardsText(source)).toBe('Authority Evidence');
  });

  it('treats malformed markup as text and safely handles invalid entities', () => {
    expect(normalizeStandardsText('A < broken &#99999999; B')).toBe('A < broken &#99999999; B');
  });

  it('normalizes entities, punctuation, whitespace, and line-wrapped words', () => {
    expect(normalizeStandardsText('Exact&nbsp;authori-\n ty &mdash; “proved”'))
      .toBe('Exact authori-ty - "proved"');
  });
});
