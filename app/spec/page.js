import { readFileSync } from 'fs';
import { join } from 'path';
import { JetBrains_Mono, Outfit, Space_Grotesk } from 'next/font/google';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';

// Self-host the spec page's three custom fonts so the spec renders without
// blocking on Google Fonts CSS and so the @next/next/no-page-custom-font
// lint rule stays clear. The font-family strings (`JetBrains Mono`,
// `Outfit`, `Space Grotesk`) used in the inline <style> tag below match
// next/font's emitted family names verbatim.
const jetBrainsMono = JetBrains_Mono({ subsets: ['latin'], weight: ['400', '500', '600'], display: 'swap' });
const outfit = Outfit({ subsets: ['latin'], weight: ['700', '800', '900'], display: 'swap' });
const spaceGrotesk = Space_Grotesk({ subsets: ['latin'], weight: ['400', '500', '600'], display: 'swap' });
const SPEC_FONT_CLASS = `${jetBrainsMono.className} ${outfit.className} ${spaceGrotesk.className}`;

export const metadata = {
  // This page renders the posted Internet-Draft. "Internet-Draft", not "RFC" —
  // claiming RFC status for an individual I-D overstates IETF standing.
  title: 'draft-schrock-ep-authorization-receipts-03 — EMILIA Protocol Specification',
  description: 'EMILIA Protocol specification (IETF Internet-Draft) — verifiable human-authorization receipts for high-risk agent actions.',
};

/**
 * Minimal markdown-to-HTML converter.
 */
function slugify(text) {
  return text
    .replace(/[*`]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function mdToHtml(md) {
  const lines = md.split('\n');
  const output = [];
  const toc = [];
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
    if (line.startsWith('## '))      { const raw = line.slice(3); const id = slugify(raw); toc.push({ id, text: raw.replace(/[*`]/g, '') }); output.push(`<h2 id="${id}">${inlineFormat(raw)}</h2>`); continue; }
    if (line.startsWith('### '))     { output.push(`<h3>${inlineFormat(line.slice(4))}</h3>`); continue; }
    if (line.startsWith('#### '))    { output.push(`<h4>${inlineFormat(line.slice(5))}</h4>`); continue; }
    if (line.startsWith('---'))      { output.push('<hr/>'); continue; }
    if (line.startsWith('- '))       { output.push(`<ul><li>${inlineFormat(line.slice(2))}</li></ul>`); continue; }
    if (/^\d+\.\s/.test(line))       { output.push(`<ol><li>${inlineFormat(line.replace(/^\d+\.\s/, ''))}</li></ol>`); continue; }
    if (line.trim() === '')          { output.push(''); continue; }
    output.push(`<p>${inlineFormat(line)}</p>`);
  }
  if (inTable) output.push(processTable(tableLines.join('\n')));
  return { html: output.join('\n'), toc };
}

function inlineFormat(text) {
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return text;
}

export default function SpecPage() {
  const mdPath = join(process.cwd(), 'standards', 'draft-schrock-ep-authorization-receipts-03.md');
  const md = readFileSync(mdPath, 'utf8');
  const { html, toc } = mdToHtml(md);

  return (
    <div className={SPEC_FONT_CLASS}>
      <style dangerouslySetInnerHTML={{ __html: `
        html { scroll-behavior: smooth; }
        body { background: #0b0b0d; color: #f4f1ea; font-family: 'Space Grotesk', sans-serif; -webkit-font-smoothing: antialiased; line-height: 1.8; margin: 0; }
        a { color: #E0A82E; text-decoration: none; }
        a:hover { text-decoration: underline; }
        /* Sticky in-page section menu — jumps within the doc, does not navigate away */
        .spec-toc { position: sticky; top: 60px; z-index: 50; display: flex; align-items: center; gap: 8px; overflow-x: auto; padding: 12px 24px; background: rgba(11,11,13,0.9); backdrop-filter: blur(12px); border-bottom: 1px solid rgba(224,168,46,0.18); scrollbar-width: none; }
        .spec-toc::-webkit-scrollbar { display: none; }
        .spec-toc .spec-toc-label { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: #9a968c; flex-shrink: 0; margin-right: 4px; }
        .spec-toc a { flex-shrink: 0; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #cfcabd; border: 1px solid rgba(255,255,255,0.10); border-radius: 100px; padding: 5px 12px; white-space: nowrap; }
        .spec-toc a:hover { color: #0b0b0d; background: #E0A82E; border-color: #E0A82E; text-decoration: none; }
        .spec-content { max-width: 820px; margin: 0 auto; padding: 44px 24px 120px; }
        .spec-content h1 { font-family: 'Outfit', sans-serif; font-weight: 900; font-size: 38px; letter-spacing: -1px; margin: 48px 0 16px; color: #ffffff; scroll-margin-top: 120px; }
        .spec-content h2 { font-family: 'Outfit', sans-serif; font-weight: 800; font-size: 25px; margin: 48px 0 14px; color: #ffffff; border-bottom: 1px solid rgba(224,168,46,0.25); padding-bottom: 10px; scroll-margin-top: 120px; }
        .spec-content h3 { font-family: 'Outfit', sans-serif; font-weight: 700; font-size: 19px; margin: 30px 0 8px; color: #f4f1ea; scroll-margin-top: 120px; }
        .spec-content h4 { font-weight: 600; font-size: 15px; margin: 20px 0 6px; color: #E0A82E; letter-spacing: 0.3px; }
        .spec-content p { color: #cbcfd8; margin-bottom: 14px; font-size: 16px; }
        .spec-content strong { color: #ffffff; font-weight: 600; }
        .spec-content ul, .spec-content ol { color: #cbcfd8; padding-left: 24px; margin-bottom: 14px; }
        .spec-content li { margin-bottom: 6px; font-size: 16px; }
        .spec-content li::marker { color: #E0A82E; }
        .spec-content code { font-family: 'JetBrains Mono', monospace; font-size: 13.5px; background: rgba(224,168,46,0.10); color: #f0c977; padding: 2px 6px; border-radius: 4px; }
        .spec-content .code-block { background: #16161a; border: 1px solid #2a2a30; border-radius: 8px; padding: 16px 20px; overflow-x: auto; margin: 14px 0 18px; }
        .spec-content .code-block code { background: none; padding: 0; font-size: 12.5px; color: #d7dae2; line-height: 1.65; }
        .spec-content .table-wrap { overflow-x: auto; margin: 14px 0 18px; }
        .spec-content table { width: 100%; border-collapse: collapse; font-size: 13.5px; font-family: 'JetBrains Mono', monospace; }
        .spec-content th { text-align: left; padding: 9px 12px; background: #16161a; color: #ffffff; border: 1px solid #2a2a30; font-weight: 600; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; }
        .spec-content td { padding: 9px 12px; border: 1px solid #2a2a30; color: #cbcfd8; }
        .spec-content hr { border: none; border-top: 1px solid rgba(255,255,255,0.08); margin: 34px 0; }
        .spec-figure { margin: 8px 0 8px; padding: 20px; background: #101014; border: 1px solid #2a2a30; border-radius: 14px; }
        .spec-figure img { width: 100%; height: auto; display: block; border-radius: 8px; }
        .spec-figure figcaption { margin-top: 14px; font-size: 13.5px; color: #9a968c; line-height: 1.6; }
        .spec-badge { display: inline-flex; align-items: center; gap: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 2px; color: #E0A82E; background: rgba(224,168,46,0.10); border: 1px solid rgba(224,168,46,0.22); padding: 8px 16px; border-radius: 100px; margin-bottom: 24px; }
        .spec-footer { margin-top: 64px; text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: #6b6f7e; letter-spacing: 1px; }
      `}} />
      <SiteNav activePage="Spec" />
      {toc.length > 0 && (
        <nav className="spec-toc" aria-label="On this page">
          <span className="spec-toc-label">On this page</span>
          {toc.map((t) => (
            <a key={t.id} href={`#${t.id}`}>{t.text}</a>
          ))}
        </nav>
      )}
      <div className="spec-content">
        <div className="spec-badge">DRAFT-SCHROCK-EP-AUTHORIZATION-RECEIPTS-03 · IETF INDIVIDUAL SUBMISSION · APACHE 2.0</div>
        <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#9a968c', marginBottom: 8, lineHeight: 1.7 }}>Canonical copy on the <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/" target="_blank" rel="noopener noreferrer">IETF datatracker</a>. Conformance vectors: <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/CONFORMANCE.md" target="_blank" rel="noopener noreferrer">CONFORMANCE.md</a>. Multi-party companion: <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/" target="_blank" rel="noopener noreferrer">draft-schrock-ep-quorum</a>. Composition companion: <a href="https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/" target="_blank" rel="noopener noreferrer">draft-schrock-ep-authorization-evidence-chain</a>. Preprint: <a href="https://doi.org/10.5281/zenodo.20780638" target="_blank" rel="noopener noreferrer">Zenodo DOI</a>. Composition layer: <a href="/evidence-chain">Authorization Evidence Chains</a>.</p>
        {/* Passport-control model — visual anchor before the formal I-D text */}
        <figure className="spec-figure">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/diagrams/agent-action-stack.svg" alt="Where EMILIA sits: identity is the passport, tool authorization is the visa, and EMILIA is passport control plus the authorization stamp." />
          <figcaption>Where EMILIA sits — identity says which machine is acting (the passport); tool-authorization says which tools it may call (the visa). EMILIA is passport control and the stamp: offline-verifiable proof that a named human authorized <em>this exact action</em>.</figcaption>
        </figure>
        <div dangerouslySetInnerHTML={{ __html: html }} />
        <div className="spec-footer">
          EMILIA Protocol — draft-schrock-ep-authorization-receipts-03 — Apache 2.0 License
        </div>
      </div>
      <SiteFooter />
    </div>
  );
}
