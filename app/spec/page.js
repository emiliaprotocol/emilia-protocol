import { readFileSync } from 'fs';
import { join } from 'path';

export const metadata = {
  title: 'EP Core RFC v1.1 — EMILIA Protocol Specification',
  description: 'EMILIA Protocol specification — trust profiles, policy evaluation, and appeals for counterparties, software, and machine actors.',
};

/**
 * Minimal markdown-to-HTML converter.
 * Handles: headings, paragraphs, bold, italic, code blocks, inline code,
 * tables, lists, horizontal rules, links.
 */
function mdToHtml(md) {
  let html = md;

  // Code blocks (fenced)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const escaped = code.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `<pre class="code-block"><code class="lang-${lang || 'text'}">${escaped}</code></pre>`;
  });

  // Tables
  html = html.replace(/((?:\|.+\|\n)+)/g, (tableBlock) => {
    const rows = tableBlock.trim().split('\n').filter(r => r.trim());
    if (rows.length < 2) return tableBlock;

    // Check for separator row
    const sepIdx = rows.findIndex(r => /^\|[\s\-:|]+\|$/.test(r.trim()));

    let thead = '';
    let tbody = '';

    rows.forEach((row, i) => {
      if (i === sepIdx) return; // skip separator
      const cells = row.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1).map(c => c.trim());
      const tag = i < sepIdx && sepIdx > 0 ? 'th' : 'td';
      const tr = `<tr>${cells.map(c => `<${tag}>${inlineFormat(c)}</${tag}>`).join('')}</tr>`;
      if (tag === 'th') thead += tr;
      else tbody += tr;
    });

    return `<div class="table-wrap"><table>${thead ? `<thead>${thead}</thead>` : ''}<tbody>${tbody}</tbody></table></div>`;
  });

  // Process line by line for headings, lists, etc.
  const lines = html.split('\n');
  const output = [];
  let inList = false;
  let listType = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      if (inList) { output.push(`</${listType}>`); inList = false; }
      output.push('<hr/>');
      continue;
    }

    // Headings
    const hMatch = line.match(/^(#{1,6})\s+(.+)$/);
    if (hMatch) {
      if (inList) { output.push(`</${listType}>`); inList = false; }
      const level = hMatch[1].length;
      const text = inlineFormat(hMatch[2]);
      const id = hMatch[2].toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '');
      output.push(`<h${level} id="${id}">${text}</h${level}>`);
      continue;
    }

    // Unordered list
    if (/^[-*]\s+/.test(line.trim())) {
      if (!inList || listType !== 'ul') {
        if (inList) output.push(`</${listType}>`);
        output.push('<ul>');
        inList = true;
        listType = 'ul';
      }
      output.push(`<li>${inlineFormat(line.trim().replace(/^[-*]\s+/, ''))}</li>`);
      continue;
    }

    // Ordered list
    if (/^\d+\.\s+/.test(line.trim())) {
      if (!inList || listType !== 'ol') {
        if (inList) output.push(`</${listType}>`);
        output.push('<ol>');
        inList = true;
        listType = 'ol';
      }
      output.push(`<li>${inlineFormat(line.trim().replace(/^\d+\.\s+/, ''))}</li>`);
      continue;
    }

    // Close list if not continuing
    if (inList && line.trim() === '') {
      output.push(`</${listType}>`);
      inList = false;
    }

    // Empty line
    if (line.trim() === '') {
      continue;
    }

    // Skip if already processed (table, code block)
    if (line.startsWith('<')) {
      output.push(line);
      continue;
    }

    // Paragraph
    if (inList) { output.push(`</${listType}>`); inList = false; }
    output.push(`<p>${inlineFormat(line)}</p>`);
  }

  if (inList) output.push(`</${listType}>`);

  return output.join('\n');
}

function inlineFormat(text) {
  // Bold + italic
  text = text.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  // Bold
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Italic
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Inline code
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Links
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return text;
}

export default function SpecPage() {
  const mdPath = join(process.cwd(), 'docs', 'EP-CORE-RFC.md');
  const md = readFileSync(mdPath, 'utf8');
  const html = mdToHtml(md);

  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@700;800;900&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet" />
        <style dangerouslySetInnerHTML={{ __html: `
          :root {
            --bg: #05060a; --bg-card: #0e1120; --brd: rgba(255,255,255,0.06);
            --t1: #e8eaf0; --t2: #7a809a; --t3: #4a4f6a;
            --cyan: #00d4ff; --gold: #ffd700; --green: #00ff88;
            --mono: 'JetBrains Mono', monospace; --disp: 'Outfit', sans-serif; --body: 'Space Grotesk', sans-serif;
          }
          *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: var(--bg); color: var(--t1); font-family: var(--body); -webkit-font-smoothing: antialiased; line-height: 1.8; }
          a { color: var(--cyan); text-decoration: none; }
          a:hover { text-decoration: underline; }

          .spec-nav {
            position: sticky; top: 0; z-index: 100;
            background: rgba(5,6,10,0.9); backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--brd);
            padding: 12px 24px;
            display: flex; justify-content: space-between; align-items: center;
            font-family: var(--mono); font-size: 12px;
          }
          .spec-nav a { color: var(--t2); letter-spacing: 1px; }
          .spec-nav a:hover { color: var(--cyan); text-decoration: none; }

          .spec-content {
            max-width: 800px; margin: 0 auto; padding: 48px 24px 120px;
          }

          h1 { font-family: var(--disp); font-weight: 900; font-size: 36px; letter-spacing: -1px; margin: 48px 0 16px; color: var(--t1); }
          h2 { font-family: var(--disp); font-weight: 800; font-size: 24px; margin: 40px 0 12px; color: var(--t1); border-bottom: 1px solid var(--brd); padding-bottom: 8px; }
          h3 { font-family: var(--disp); font-weight: 700; font-size: 18px; margin: 28px 0 8px; color: var(--t1); }
          h4 { font-family: var(--body); font-weight: 600; font-size: 15px; margin: 20px 0 6px; color: var(--t2); }

          p { color: var(--t2); margin-bottom: 12px; font-size: 15px; }
          strong { color: var(--t1); }
          em { color: var(--t2); font-style: italic; }

          ul, ol { color: var(--t2); padding-left: 24px; margin-bottom: 12px; }
          li { margin-bottom: 4px; font-size: 15px; }
          li::marker { color: var(--cyan); }

          code {
            font-family: var(--mono); font-size: 13px;
            background: rgba(0,212,255,0.06); color: var(--cyan);
            padding: 2px 6px; border-radius: 4px;
          }

          .code-block {
            background: var(--bg-card); border: 1px solid var(--brd);
            border-radius: 8px; padding: 16px 20px; overflow-x: auto;
            margin: 12px 0 16px;
          }
          .code-block code {
            background: none; padding: 0; font-size: 12px;
            color: var(--t2); line-height: 1.6;
          }

          .table-wrap { overflow-x: auto; margin: 12px 0 16px; }
          table {
            width: 100%; border-collapse: collapse;
            font-size: 13px; font-family: var(--mono);
          }
          th {
            text-align: left; padding: 8px 12px;
            background: var(--bg-card); color: var(--t1);
            border: 1px solid var(--brd); font-weight: 600;
            font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
          }
          td {
            padding: 8px 12px; border: 1px solid var(--brd);
            color: var(--t2);
          }

          hr { border: none; border-top: 1px solid var(--brd); margin: 32px 0; }

          .spec-badge {
            display: inline-flex; align-items: center; gap: 8px;
            font-family: var(--mono); font-size: 11px; letter-spacing: 2px;
            color: var(--cyan); background: rgba(0,212,255,0.08);
            border: 1px solid rgba(0,212,255,0.15);
            padding: 8px 16px; border-radius: 100px; margin-bottom: 24px;
          }

          .spec-footer {
            margin-top: 64px; text-align: center;
            font-family: var(--mono); font-size: 10px;
            color: var(--t3); letter-spacing: 1px;
          }
        `}} />
      </head>
      <body>
        <div className="spec-nav">
          <a href="/" style={{ fontWeight: 600, letterSpacing: 2, fontSize: 14, color: '#e8eaf0' }}>EMILIA</a>
          <div style={{ display: 'flex', gap: 24 }}>
            <a href="/">HOME</a>
            <a href="/quickstart.html">QUICKSTART</a>
            <a href="/demo.html">DEMO</a>
            <a href="/spec" style={{ color: '#00d4ff' }}>SPEC</a>
            <a href="/operators.html">OPERATORS</a>
            <a href="/appeal">APPEAL</a>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank">GITHUB</a>
          </div>
        </div>
        <div className="spec-content">
          <div className="spec-badge">EP CORE RFC v1.1 · APACHE 2.0</div>
          <div dangerouslySetInnerHTML={{ __html: html }} />
          <div className="spec-footer">
            EMILIA Protocol — EP Core RFC v1.1 — Apache 2.0 License
          </div>
        </div>
      </body>
    </html>
  );
}
