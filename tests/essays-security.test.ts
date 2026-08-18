// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import {
  ESSAYS,
  essayMdToHtml,
  getEssay,
  loadEssayBody,
} from '../lib/essays.js';

describe('essay markdown security boundary', () => {
  it('escapes raw HTML instead of executing committed prose as markup', () => {
    const html = essayMdToHtml('<img src=x onerror="alert(1)">');

    expect(html).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
    expect(html).not.toContain('<img');
  });

  it('neutralizes executable link schemes and escapes link attributes', () => {
    const html = essayMdToHtml('[click](javascript:alert("x"))');

    expect(html).toContain('<a href="#">click</a>');
    expect(html).not.toContain('javascript:');
  });

  it('does not allow a code-fence language to break out of the class attribute', () => {
    const html = essayMdToHtml('```js\" onmouseover=alert(1)\nconst ok = true;\n```');

    expect(html).toContain('class="lang-text"');
    expect(html).not.toContain('onmouseover');
  });

  it('loads only registered essay sources and strips their structured header', () => {
    for (const entry of ESSAYS) {
      expect(getEssay(entry.slug)).toBe(entry);
      const loaded = loadEssayBody(entry.slug);
      expect(loaded.body.length).toBeGreaterThan(100);
      expect(loaded.body).not.toMatch(/^# /);
      expect(loaded.body).not.toMatch(/^\*\*(Date|Author):\*\*/m);
    }

    expect(getEssay('not-registered')).toBeNull();
    expect(() => loadEssayBody('../../etc/passwd')).toThrow(
      'Unknown essay slug: ../../etc/passwd',
    );
  });

  it('renders the complete supported prose grammar without admitting raw markup', () => {
    const html = essayMdToHtml([
      '# Heading one',
      '## Heading two',
      '### Heading three',
      '',
      'A **strong**, *emphasized*, and `coded` [safe link](https://example.com).',
      '---',
      '```typescript',
      'const comparison = a < b && c > d;',
      '```',
    ].join('\n'));

    expect(html).toContain('<h2>Heading one</h2>');
    expect(html).toContain('<h2>Heading two</h2>');
    expect(html).toContain('<h3>Heading three</h3>');
    expect(html).toContain('<strong>strong</strong>');
    expect(html).toContain('<em>emphasized</em>');
    expect(html).toContain('<code>coded</code>');
    expect(html).toContain('<a href="https://example.com">safe link</a>');
    expect(html).toContain('<hr/>');
    expect(html).toContain('class="lang-typescript"');
    expect(html).toContain('a &lt; b &amp;&amp; c &gt; d');
  });
});
