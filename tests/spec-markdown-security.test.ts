// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  escapeHtml,
  renderInlineMarkdown,
  sanitizeCodeLanguage,
} from '../lib/spec-markdown.js';

describe('/spec markdown HTML boundary', () => {
  it('escapes raw tags and attribute-breaking link content before adding markup', () => {
    const rendered = renderInlineMarkdown(
      '<img src=x onerror=alert(1)> [open](https://example.test/\" onmouseover=\"alert(2))',
    );

    expect(rendered).not.toContain('<img');
    expect(rendered).not.toContain(' onmouseover="');
    expect(rendered).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(rendered).toContain('&quot; onmouseover=&quot;alert(2');
  });

  it('keeps supported inline markdown while refusing executable URL schemes', () => {
    expect(renderInlineMarkdown('**strong** *em* `code` [bad](javascript:alert(1))'))
      .toBe('<strong>strong</strong> <em>em</em> <code>code</code> <a href="#">bad</a>)');
  });

  it('escapes code bytes and constrains a fenced-code language used in a class attribute', () => {
    expect(escapeHtml('<script>"x" & y</script>'))
      .toBe('&lt;script&gt;&quot;x&quot; &amp; y&lt;/script&gt;');
    expect(sanitizeCodeLanguage('typescript')).toBe('typescript');
    expect(sanitizeCodeLanguage('x\" onmouseover=\"alert(1)')).toBe('text');
  });
});
