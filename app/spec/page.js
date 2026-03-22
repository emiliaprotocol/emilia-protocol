import { readFileSync } from 'fs';
import { join } from 'path';
import SiteNav from '@/components/SiteNav';

export const metadata = {
  title: 'EP Core RFC v1.0 — EMILIA Protocol Specification',
  description: 'EMILIA Protocol specification — trust profiles, policy evaluation, and appeals for counterparties, software, and machine actors.',
};

/**
 * Minimal markdown-to-HTML converter.
 */
function mdToHtml(md) {
  const lines = md.split('\n');
  const output = [];
  let inCode = false, codeLang = '', codeLines = [];
  let inTable = false, tableLines = [];

  function processTable(tableBlock) {
    const rows = tableBlock.split('\n').filter(r => r.trim());
    if (rows.length < 2) return tableBlock;
    const sepIdx = rows.findIndex(r => /^\|[\s-:|]+\|$/.test(r.trim()));
    if (sepIdx < 0) return tableBlock;
    let thead = '', tbody = '';
    rows.forEach((row, i) => {
      const cells = row.split('|').slice(1, -1).map(c => c.trim());
      if (i === 0) {
        thead = `<tr>${cells.map(c => `<th>${inlineFormat(c)}</th>`).join('')}</tr>`;
      }
      if (i === sepIdx) return;
      if (i > 0) {
        tbody += `<tr>${cells.map(c => `<td>${inlineFormat(c)}</td>`).join('')}</tr>`;
      }
    });
    return `<div class="table-wrap"><table>${thead ? `<thead>${thead}</thead>` : ''}<tbody>${tbody}</tbody></table></div>`;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('```')) {
      if (!inCode) { inCode = true; codeLang = line.slice(3).trim(); codeLines = []; }
      else {
        const escaped = codeLines.join('\n').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        output.push(`<pre class="code-block"><code class="lang-${codeLang || 'text'}">${escaped}</code></pre>`);
        inCode = false;
      }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }
    if (line.trim().startsWith('|')) {
      if (!inTable) inTable = true;
      tableLines.push(line);
      continue;
    }
    if (inTable) { output.push(processTable(tableLines.join('\n'))); tableLines = []; inTable = false; }
    if (line.startsWith('# '))       { output.push(`<h1>${inlineFormat(line.slice(2))}</h1>`); continue; }
    if (line.startsWith('## '))      { output.push(`<h2>${inlineFormat(line.slice(3))}</h2>`); continue; }
    if (line.startsWith('### '))     { output.push(`<h3>${inlineFormat(line.slice(4))}</h3>`); continue; }
    if (line.startsWith('#### '))    { output.push(`<h4>${inlineFormat(line.slice(5))}</h4>`); continue; }
    if (line.startsWith('---'))      { output.push('<hr/>'); continue; }
    if (line.startsWith('- '))       { output.push(`<ul><li>${inlineFormat(line.slice(2))}</li></ul>`); continue; }
    if (/^\d+\.\s/.test(line))       { output.push(`<ol><li>${inlineFormat(line.replace(/^\d+\.\s/, ''))}</li></ol>`); continue; }
    if (line.trim() === '')          { output.push(''); continue; }
    output.push(`<p>${inlineFormat(line)}</p>`);
  }
  if (inTable) output.push(processTable(tableLines.join('\n')));
  return output.join('\n');
}

function inlineFormat(text) {
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return text;
}

export default function SpecPage() {
  const mdPath = join(process.cwd(), 'docs', 'EP-CORE-RFC.md');
  const md = readFileSync(mdPath, 'utf8');
  const html = mdToHtml(md);

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: `
        body { background: #0a0f1e; color: #e8eaf0; font-family: 'IBM Plex Sans', sans-serif; -webkit-font-smoothing: antialiased; line-height: 1.8; margin: 0; }
        a { color: #4a90d9; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .spec-content { max-width: 800px; margin: 0 auto; padding: 48px 24px 120px; }
        .spec-content h1 { font-family: 'IBM Plex Sans', sans-serif; font-weight: 700; font-size: 36px; letter-spacing: -1px; margin: 48px 0 16px; color: #e8eaf0; }
        .spec-content h2 { font-family: 'IBM Plex Sans', sans-serif; font-weight: 700; font-size: 24px; margin: 40px 0 12px; color: #e8eaf0; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 8px; }
        .spec-content h3 { font-family: 'IBM Plex Sans', sans-serif; font-weight: 700; font-size: 18px; margin: 28px 0 8px; color: #e8eaf0; }
        .spec-content h4 { font-weight: 600; font-size: 15px; margin: 20px 0 6px; color: #7a809a; }
        .spec-content p { color: #7a809a; margin-bottom: 12px; font-size: 15px; }
        .spec-content strong { color: #e8eaf0; }
        .spec-content ul, .spec-content ol { color: #7a809a; padding-left: 24px; margin-bottom: 12px; }
        .spec-content li { margin-bottom: 4px; font-size: 15px; }
        .spec-content li::marker { color: #4a90d9; }
        .spec-content code { font-family: 'IBM Plex Mono', monospace; font-size: 13px; background: rgba(74,144,217,0.06); color: #4a90d9; padding: 2px 6px; border-radius: 4px; }
        .spec-content .code-block { background: #0e1120; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 16px 20px; overflow-x: auto; margin: 12px 0 16px; }
        .spec-content .code-block code { background: none; padding: 0; font-size: 12px; color: #7a809a; line-height: 1.6; }
        .spec-content .table-wrap { overflow-x: auto; margin: 12px 0 16px; }
        .spec-content table { width: 100%; border-collapse: collapse; font-size: 13px; font-family: 'IBM Plex Mono', monospace; }
        .spec-content th { text-align: left; padding: 8px 12px; background: #0e1120; color: #e8eaf0; border: 1px solid rgba(255,255,255,0.06); font-weight: 600; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; }
        .spec-content td { padding: 8px 12px; border: 1px solid rgba(255,255,255,0.06); color: #7a809a; }
        .spec-content hr { border: none; border-top: 1px solid rgba(255,255,255,0.06); margin: 32px 0; }
        .spec-badge { display: inline-flex; align-items: center; gap: 8px; font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 2px; color: #4a90d9; background: rgba(74,144,217,0.08); border: 1px solid rgba(74,144,217,0.15); padding: 8px 16px; border-radius: 100px; margin-bottom: 24px; }
        .spec-footer { margin-top: 64px; text-align: center; font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: #4a4f6a; letter-spacing: 1px; }
      `}} />
      <link rel="preconnect" href="https://fonts.googleapis.com" />
      <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
      <SiteNav activePage="Spec" />
      <div className="spec-content">
        <div className="spec-badge">EP CORE RFC v1.0 · APACHE 2.0</div>
        <div dangerouslySetInnerHTML={{ __html: html }} />
        <div className="spec-footer">
          EMILIA Protocol — EP Core RFC v1.0 — Apache 2.0 License
        </div>
      </div>
    </>
  );
}
