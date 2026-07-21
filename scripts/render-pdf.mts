#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Render an HTML marketing source to PDF via Playwright/chromium (print media).
//   node scripts/render-pdf.mts <input.html> <output.pdf> [--landscape]
// Used to regenerate one-pagers and decks from their in-repo HTML sources so the
// PDFs are reproducible instead of orphaned design-tool exports.
import { chromium } from '@playwright/test';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [, , inPath, outPath, ...flags]: string[] = process.argv;
if (!inPath || !outPath) {
  console.error('usage: node scripts/render-pdf.mts <input.html> <output.pdf> [--landscape]');
  process.exit(2);
}
const landscape: boolean = flags.includes('--landscape');
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(pathToFileURL(resolve(inPath)).href, { waitUntil: 'networkidle' });
await page.emulateMedia({ media: 'print' });
await page.pdf({
  path: resolve(outPath),
  printBackground: true,
  // Honor any CSS @page size (the deck declares @page { size: 1280px 720px }),
  // so slide pages are exactly the slide size — no cutoff, no trailing black space.
  // One-pagers declare no @page size, so they fall back to A4 portrait.
  preferCSSPageSize: true,
  format: landscape ? undefined : 'A4',
  margin: landscape ? { top: '0', bottom: '0', left: '0', right: '0' } : { top: '0.5in', bottom: '0.5in', left: '0.5in', right: '0.5in' },
});
await browser.close();
console.log('wrote', outPath);
