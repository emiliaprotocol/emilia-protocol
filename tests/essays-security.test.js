// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { essayMdToHtml } from '../lib/essays.js';

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
});
