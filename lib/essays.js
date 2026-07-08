/**
 * EP Essays — build-time markdown loader and renderer.
 * @license Apache-2.0
 *
 * Reads an essay's source markdown from docs/essays/ at build time and
 * converts it to HTML for server-component rendering. The prose is rendered
 * verbatim — this module never rewrites essay content, only marks it up.
 *
 * The H1 title and the `**Date:**` / `**Author:**` lines at the top of each
 * source file are parsed out as structured metadata so pages can render a
 * styled header; everything after them is rendered as the essay body.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { safeHref } from './safe-href.js';

// Each essay's source is read through a thunk that joins only string literals
// (matching the /spec page), so no variable — and certainly no caller input —
// ever flows into path.join. Adding an essay means adding a registry entry
// with its own literal read() thunk.
function readCrumpleZone() {
  return readFileSync(join(process.cwd(), 'docs', 'essays', 'the-model-is-the-crumple-zone.md'), 'utf8');
}
function readAuthorizationIsNotProof() {
  return readFileSync(join(process.cwd(), 'docs', 'essays', 'why-authorization-is-not-proof.md'), 'utf8');
}

// Canonical registry of published essays. The order here is the order the
// index page lists them (flagship first). `slug` is the /essays/<slug> route
// segment; `read` returns the raw source markdown for that essay.
export const ESSAYS = [
  {
    slug: 'the-model-is-the-crumple-zone',
    read: readCrumpleZone,
    title: 'The Model Is the Crumple Zone',
    hook: 'When an agent causes harm, blame flows to the most legible target — the model and its maker. The authorization receipt makes the right party provable instead.',
    date: '2026-06-12',
    author: 'Iman Schrock',
  },
  {
    slug: 'why-authorization-is-not-proof',
    read: readAuthorizationIsNotProof,
    title: 'Why Authorization Is Not Proof',
    hook: 'Decision logs are testimony; receipts are evidence. Why the operator’s word stopped being enough once agents could move money and delete data.',
    date: '2026-06-12',
    author: 'Iman Schrock',
  },
];

export function getEssay(slug) {
  return ESSAYS.find((e) => e.slug === slug) || null;
}

/**
 * Read an essay's source markdown and return { body } where `body` is the
 * prose after the title/date/author front matter is stripped. Throws if the
 * slug is not a registered essay (prevents arbitrary path reads).
 */
export function loadEssayBody(slug) {
  const essay = getEssay(slug);
  if (!essay) {
    throw new Error(`Unknown essay slug: ${slug}`);
  }
  const md = essay.read();
  return { body: stripFrontMatter(md) };
}

// Drop the leading `# Title`, `**Date:** ...`, `**Author:** ...` lines and any
// blank lines before the first paragraph. The page renders those from the
// registry metadata instead.
function stripFrontMatter(md) {
  const lines = md.split('\n');
  let i = 0;
  while (i < lines.length) {
    const t = lines[i].trim();
    if (t === '' || t.startsWith('# ') || /^\*\*(Date|Author):\*\*/i.test(t)) {
      i++;
      continue;
    }
    break;
  }
  return lines.slice(i).join('\n');
}

/**
 * Minimal, dependency-free markdown-to-HTML converter scoped to the prose
 * features the essays use: paragraphs, h2/h3, bold/italic/inline-code,
 * links, fenced code blocks, and horizontal rules. Mirrors the converter on
 * the /spec page so the two long-form surfaces stay consistent.
 */
export function essayMdToHtml(md) {
  const lines = md.split('\n');
  const out = [];
  let inCode = false;
  let codeLang = '';
  let codeLines = [];

  for (const line of lines) {
    if (line.startsWith('```')) {
      if (!inCode) {
        inCode = true;
        codeLang = line.slice(3).trim();
        codeLines = [];
      } else {
        const escaped = codeLines
          .join('\n')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;');
        out.push(
          `<pre class="essay-code"><code class="lang-${codeLang || 'text'}">${escaped}</code></pre>`
        );
        inCode = false;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }
    if (line.startsWith('### ')) {
      out.push(`<h3>${inlineFormat(line.slice(4))}</h3>`);
      continue;
    }
    if (line.startsWith('## ')) {
      out.push(`<h2>${inlineFormat(line.slice(3))}</h2>`);
      continue;
    }
    if (line.startsWith('# ')) {
      out.push(`<h2>${inlineFormat(line.slice(2))}</h2>`);
      continue;
    }
    if (line.trim().startsWith('---')) {
      out.push('<hr/>');
      continue;
    }
    if (line.trim() === '') {
      out.push('');
      continue;
    }
    out.push(`<p>${inlineFormat(line)}</p>`);
  }

  return out.join('\n');
}

function inlineFormat(text) {
  // Order matters: escape nothing here (prose is trusted, build-time source),
  // but apply bold before italic so `**x**` is not eaten by the `*` rule.
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_m, label, url) => `<a href="${safeHref(url)}">${label}</a>`);
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  return text;
}
