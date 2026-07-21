#!/usr/bin/env node
/**
 * EMILIA Protocol — SOC 2 Evidence Map PDF builder
 * @license Apache-2.0
 *
 * Reproduces the same method used for the EU AI Act compliance PDFs in
 * public/compliance/ (producer "Skia/PDF", A4, headless-Chrome print-to-pdf):
 * render a styled HTML to PDF with `Google Chrome --headless --print-to-pdf`.
 *
 * Source : docs/compliance/EMILIA-SOC2-EVIDENCE-MAP.md
 * Output : public/compliance/emilia-soc2-evidence-map.pdf
 *
 * Usage  : node scripts/build-soc2-evidence-pdf.mjs
 *
 * No new npm dependency is added: markdown is converted with pandoc (already
 * present in the build environment) and printed with the system Chrome, exactly
 * as the existing sector PDFs were produced.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname: string = dirname(fileURLToPath(import.meta.url));
const ROOT: string = join(__dirname, '..');

const SRC: string = join(ROOT, 'docs/compliance/EMILIA-SOC2-EVIDENCE-MAP.md');
const OUT: string = join(ROOT, 'public/compliance/emilia-soc2-evidence-map.pdf');

const CHROME: string | undefined = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].find((p) => existsSync(p));

if (!CHROME) {
  console.error('No Chrome/Chromium found for headless print. Install Google Chrome.');
  process.exit(1);
}

// --- 1. markdown body -> HTML fragment (pandoc, already in the build env) ---
const bodyHtml: string = execFileSync(
  'pandoc',
  [SRC, '-f', 'gfm', '-t', 'html', '--syntax-highlighting=none'],
  { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
) as string;

// --- 2. wrap in print-tuned shell. The <title> becomes the PDF Title, matching
//        the existing PDFs whose Title is the source HTML filename. ---
const html: string = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>emilia-soc2-evidence-map.html</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body {
    font-family: -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif;
    color: #1a1a1a; font-size: 10pt; line-height: 1.5; margin: 0;
  }
  h1 { font-size: 19pt; line-height: 1.2; margin: 0 0 4pt; letter-spacing: -0.2pt; }
  h2 { font-size: 13pt; margin: 18pt 0 6pt; padding-top: 6pt;
       border-top: 1.5pt solid #B8860B; color: #111; break-after: avoid; }
  h2 + p, h2 + table { break-before: avoid; }
  h3 { font-size: 11pt; margin: 12pt 0 4pt; }
  p { margin: 0 0 7pt; }
  blockquote { margin: 6pt 0; padding: 6pt 12pt; border-left: 2.5pt solid #ccc;
    color: #555; font-style: italic; font-size: 9.5pt; }
  code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 8.6pt;
    background: #f3f3f1; padding: 0.5pt 3pt; border-radius: 2pt; color: #0b4a8a; }
  table { width: 100%; border-collapse: collapse; margin: 6pt 0 12pt;
    font-size: 8.7pt; break-inside: auto; }
  th, td { border: 0.5pt solid #d8d8d4; padding: 4pt 6pt; text-align: left;
    vertical-align: top; }
  th { background: #f6f6f3; font-weight: 600; }
  tr { break-inside: avoid; }
  td code { font-size: 8.2pt; }
  ul, ol { margin: 0 0 8pt; padding-left: 18pt; }
  li { margin-bottom: 3pt; }
  hr { border: none; border-top: 0.5pt solid #ddd; margin: 14pt 0; }
  strong { color: #111; }
  em { color: #333; }
  a { color: #0b4a8a; text-decoration: none; }
  h1, h2, h3 { break-after: avoid; }
</style></head>
<body>${bodyHtml}</body></html>`;

const tmp: string = mkdtempSync(join(tmpdir(), 'ep-soc2-'));
const htmlPath: string = join(tmp, 'emilia-soc2-evidence-map.html');
writeFileSync(htmlPath, html, 'utf8');

// --- 3. headless Chrome print-to-pdf (same producer as the sector PDFs) ---
execFileSync(
  CHROME,
  [
    '--headless=new',
    '--disable-gpu',
    '--no-pdf-header-footer',
    `--print-to-pdf=${OUT}`,
    `file://${htmlPath}`,
  ],
  { stdio: 'ignore' },
);

const bytes: number = readFileSync(OUT).length;
console.log(`OK — wrote ${OUT} (${bytes} bytes)`);
