/**
 * AI Trust Desk — questionnaire extractor.
 *
 * @license Apache-2.0
 *
 * Turns an uploaded questionnaire into a normalized question list:
 *   { id, text, section, requires_freeform, extraction_confidence, locator }
 *
 * Native (zero-dependency) parsers cover the formats security questionnaires
 * actually arrive in for a fast lane: .csv .tsv .md .markdown .txt .json.
 * Binary formats (.xlsx .pdf .docx) are handled via OPTIONAL dynamic imports —
 * if the parsing library isn't installed, extraction throws
 * ExtractionUnsupportedError and the pipeline escalates to a human reviewer
 * with a precise reason instead of silently dropping the file.
 */

import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from '../crypto.js';

export class ExtractionUnsupportedError extends Error {
  constructor(format, detail) {
    super(`extraction unsupported for ${format}: ${detail}`);
    this.name = 'ExtractionUnsupportedError';
    this.format = format;
  }
}

const NATIVE_FORMATS = new Set(['csv', 'tsv', 'md', 'markdown', 'txt', 'text', 'json']);

// Hard extraction cap (defense-in-depth, T7). The HTTP intake route already caps
// uploads at 25 MB, but the binary parsers (pdf-parse, xlsx, mammoth) can be
// reached from any caller of extractQuestions — and a multi-hundred-MB or
// decompression-bomb document is a resource-exhaustion vector regardless of the
// edge limit. Every code path that extracts is bounded here.
const MAX_EXTRACT_BYTES = 20 * 1024 * 1024; // 20 MB

// XLSX parser budget (defense-in-depth against decompression / cell-count
// amplification). MAX_EXTRACT_BYTES only bounds the COMPRESSED input: a ~20 MB
// zip-bomb .xlsx can inflate to a workbook with billions of cells and exhaust
// memory inside xlsx.read + sheet_to_csv. Bound the workbook SHAPE explicitly
// and refuse (fail-closed, escalate to a reviewer) before materializing the
// whole book as CSV. Limits are generous for real security questionnaires
// (hundreds of rows, a handful of columns, a few sheets).
const MAX_XLSX_SHEETS = 64;
const MAX_XLSX_ROWS_PER_SHEET = 100_000;
const MAX_XLSX_COLS_PER_SHEET = 4_096;
const MAX_XLSX_TOTAL_CELLS = 2_000_000;

/**
 * @param {object} opts
 * @param {string} [opts.filePath] path to the questionnaire on disk
 * @param {Buffer|string} [opts.content] raw content (alternative to filePath)
 * @param {string} [opts.filename] original filename (drives format detection)
 * @returns {Promise<{source_format,total_questions,questions:Array,warnings:string[],source_sha256:string}>}
 */
export async function extractQuestions({ filePath, content, filename } = {}) {
  const name = filename || (filePath ? path.basename(filePath) : 'questionnaire.txt');
  const format = detectFormat(name);
  const raw =
    content != null
      ? content
      : filePath
        ? fs.readFileSync(filePath)
        : (() => {
            throw new Error('extractQuestions: filePath or content required');
          })();

  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  if (buf.length > MAX_EXTRACT_BYTES) {
    throw new ExtractionUnsupportedError(
      format,
      `document is ${buf.length} bytes, over the ${MAX_EXTRACT_BYTES}-byte extraction cap — escalate to a human reviewer`,
    );
  }
  const source_sha256 = sha256(buf.toString('utf8'));
  const warnings = [];

  let questions;
  if (NATIVE_FORMATS.has(format)) {
    questions = extractNative(format, buf.toString('utf8'), warnings);
  } else if (format === 'xlsx' || format === 'xls') {
    questions = await extractXlsx(buf, warnings);
  } else if (format === 'pdf') {
    questions = await extractPdf(buf, warnings);
  } else if (format === 'docx') {
    questions = await extractDocx(buf, warnings);
  } else {
    throw new ExtractionUnsupportedError(format, 'unknown file format');
  }

  // Normalize + assign ids.
  const normalized = questions
    .map((q, i) => normalizeQuestion(q, i))
    .filter((q) => q.text.length >= 8); // drop fragments

  return {
    source_format: format,
    total_questions: normalized.length,
    questions: normalized,
    warnings,
    source_sha256,
  };
}

// ── Format detection ──────────────────────────────────────────────────────

function detectFormat(filename) {
  const ext = path.extname(filename).toLowerCase().replace('.', '');
  return ext || 'txt';
}

// ── Native parsers ─────────────────────────────────────────────────────────

function extractNative(format, text, warnings) {
  switch (format) {
    case 'csv':
      return extractDelimited(text, ',', warnings);
    case 'tsv':
      return extractDelimited(text, '\t', warnings);
    case 'json':
      return extractJson(text, warnings);
    case 'md':
    case 'markdown':
    case 'txt':
    case 'text':
    default:
      return extractText(text, warnings);
  }
}

/**
 * Markdown / plain text: a question is a line ending in '?', a numbered/
 * bulleted list item, or a line under a "## Section" heading. Section headings
 * are tracked so each question carries its section.
 */
function extractText(text, warnings) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let section = '';
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const heading = trimmed.match(/^#{1,6}\s+(.*)$/);
    if (heading) {
      section = heading[1].replace(/^[\d.]+\s*/, '').trim();
      continue;
    }

    // Numbered or bulleted list item, or a line that reads as a question.
    const listItem = trimmed.match(/^(?:[-*]|\d+[.)])\s+(.*)$/);
    const candidate = listItem ? listItem[1].trim() : trimmed;

    const looksLikeQuestion =
      candidate.endsWith('?') ||
      /^(describe|explain|do you|does your|how|what|list|provide|are |is |can |has |have |which|where|when)/i.test(
        candidate,
      );

    if (looksLikeQuestion && candidate.length >= 8) {
      out.push({ text: candidate.replace(/\?+$/, '?'), section, locator: `line` });
    }
  }
  if (out.length === 0) warnings.push('no questions detected in text/markdown body');
  return out;
}

/**
 * Delimited (CSV/TSV): find the question column (header matches
 * question|control|requirement|ask, else the column with the longest average
 * cell text). Each data row becomes one question.
 */
function extractDelimited(text, delim, warnings) {
  const rows = parseDelimited(text, delim);
  if (rows.length === 0) {
    warnings.push('empty delimited file');
    return [];
  }
  const header = rows[0].map((h) => h.toLowerCase().trim());
  let qCol = header.findIndex((h) => /question|control|requirement|\bask\b|item|prompt/.test(h));
  let sectionCol = header.findIndex((h) => /section|category|domain|area|topic/.test(h));

  let dataRows = rows.slice(1);
  if (qCol === -1) {
    // No obvious header: treat all rows as data, pick the widest column.
    dataRows = rows;
    qCol = widestColumn(rows);
    warnings.push(`no question-column header found; using column ${qCol} by width`);
  }

  return dataRows
    .filter((r) => (r[qCol] || '').trim().length >= 8)
    .map((r, i) => ({
      text: (r[qCol] || '').trim(),
      section: sectionCol !== -1 ? (r[sectionCol] || '').trim() : '',
      locator: `row ${i + 2}`,
    }));
}

function extractJson(text, warnings) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    warnings.push('invalid JSON');
    return [];
  }
  // Accept: [{question}], [{text}], {questions:[...]}, ["string", ...]
  let arr = [];
  if (Array.isArray(parsed)) arr = parsed;
  else if (Array.isArray(parsed.questions)) arr = parsed.questions;
  else if (Array.isArray(parsed.items)) arr = parsed.items;
  else {
    warnings.push('JSON shape not recognized (expected array or {questions:[]})');
    return [];
  }
  return arr.map((item, i) => {
    if (typeof item === 'string') return { text: item.trim(), section: '', locator: `[${i}]` };
    return {
      text: String(item.question || item.text || item.q || '').trim(),
      section: String(item.section || item.category || '').trim(),
      locator: `[${i}]`,
    };
  });
}

// ── Optional binary parsers (dynamic import, escalate if missing) ───────────

async function extractXlsx(buf, warnings) {
  let xlsx;
  try {
    // Externalized via next.config serverExternalPackages — traced, not bundled.
    xlsx = await import('xlsx');
  } catch {
    throw new ExtractionUnsupportedError(
      'xlsx',
      'the "xlsx" package is not installed — escalate to a human reviewer or `npm i xlsx`',
    );
  }
  // Limited read: `dense` avoids a giant sparse allocation, and `sheetRows`
  // caps the rows materialized per sheet DURING the parse (one past the budget
  // so a sheet that overflows is detected, not silently truncated).
  const wb = xlsx.read(buf, {
    type: 'buffer',
    dense: true,
    sheetRows: MAX_XLSX_ROWS_PER_SHEET + 1,
  });

  const sheetNames = wb.SheetNames || [];
  if (sheetNames.length > MAX_XLSX_SHEETS) {
    throw new ExtractionUnsupportedError(
      'xlsx',
      `workbook has ${sheetNames.length} sheets, over the ${MAX_XLSX_SHEETS}-sheet parser budget — escalate to a human reviewer`,
    );
  }

  // Bound rows*cols per sheet AND the aggregate cell count BEFORE running
  // sheet_to_csv on the whole book (each sheet_to_csv builds an O(cells) string
  // that extractDelimited then walks char-by-char — the amplification step).
  let totalCells = 0;
  for (const sheetName of sheetNames) {
    const sheet = wb.Sheets[sheetName];
    const ref = sheet && sheet['!ref'];
    if (!ref) continue;
    const range = xlsx.utils.decode_range(ref);
    const rows = range.e.r - range.s.r + 1;
    const cols = range.e.c - range.s.c + 1;
    if (rows > MAX_XLSX_ROWS_PER_SHEET || cols > MAX_XLSX_COLS_PER_SHEET) {
      throw new ExtractionUnsupportedError(
        'xlsx',
        `sheet "${sheetName}" is ${rows}x${cols}, over the ${MAX_XLSX_ROWS_PER_SHEET}x${MAX_XLSX_COLS_PER_SHEET} parser budget — escalate to a human reviewer`,
      );
    }
    totalCells += rows * cols;
    if (totalCells > MAX_XLSX_TOTAL_CELLS) {
      throw new ExtractionUnsupportedError(
        'xlsx',
        `workbook exceeds the ${MAX_XLSX_TOTAL_CELLS}-cell parser budget — escalate to a human reviewer`,
      );
    }
  }

  const out = [];
  for (const sheetName of sheetNames) {
    const rows = xlsx.utils.sheet_to_csv(wb.Sheets[sheetName]);
    const qs = extractDelimited(rows, ',', warnings);
    qs.forEach((q) => out.push({ ...q, section: q.section || sheetName }));
  }
  return out;
}

async function extractPdf(buf, warnings) {
  let PDFParse;
  try {
    // pdf-parse v2: named export `PDFParse`, instance API `new PDFParse({data}).getText()`.
    ({ PDFParse } = await import('pdf-parse'));
  } catch {
    throw new ExtractionUnsupportedError(
      'pdf',
      'the "pdf-parse" package is not installed — escalate to a human reviewer or `npm i pdf-parse`',
    );
  }
  const parser = new PDFParse({ data: buf });
  try {
    const result = await parser.getText();
    return extractText(result?.text || '', warnings);
  } finally {
    await parser.destroy?.();
  }
}

async function extractDocx(buf, warnings) {
  let mammoth;
  try {
    mammoth = await import('mammoth');
  } catch {
    throw new ExtractionUnsupportedError(
      'docx',
      'the "mammoth" package is not installed — escalate to a human reviewer or `npm i mammoth`',
    );
  }
  const { value } = await mammoth.extractRawText({ buffer: buf });
  return extractText(value, warnings);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** RFC-4180-ish delimited parser: handles quoted fields + embedded delims. */
function parseDelimited(text, delim) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === delim) {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += c;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((cell) => cell.trim().length > 0));
}

function widestColumn(rows) {
  const widths = {};
  for (const r of rows) {
    r.forEach((cell, i) => {
      widths[i] = (widths[i] || 0) + (cell || '').length;
    });
  }
  let best = 0;
  let bestW = -1;
  for (const [i, w] of Object.entries(widths)) {
    if (w > bestW) {
      bestW = w;
      best = Number(i);
    }
  }
  return best;
}

function normalizeQuestion(q, index) {
  const text = String(q.text || '').replace(/\s+/g, ' ').trim();
  return {
    id: `q_${String(index + 1).padStart(3, '0')}`,
    text,
    section: String(q.section || '').trim(),
    requires_freeform: text.length > 40 || /describe|explain|how|why|detail/i.test(text),
    extraction_confidence: text.length >= 12 ? 0.95 : 0.7,
    locator: q.locator || null,
  };
}
