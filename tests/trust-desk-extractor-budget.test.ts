// SPDX-License-Identifier: Apache-2.0
//
// Regression: the Trust Desk questionnaire extractor is reachable from an
// UNAUTHENTICATED intake route. extractXlsx previously ran xlsx.read + sheet_to_csv
// with only a compressed-byte cap, so a small zip-bomb / oversized .xlsx could
// inflate to a workbook with billions of cells and exhaust memory. The parser
// budget must refuse (fail-closed → ExtractionUnsupportedError) BEFORE the whole
// book is materialized as CSV, while normal small questionnaires still parse.

import { describe, it, expect } from 'vitest';
import * as xlsx from 'xlsx';
import { extractQuestions, ExtractionUnsupportedError } from '../lib/trust-desk/extractor.js';

function toBuffer(wb: xlsx.WorkBook): Buffer {
  return xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

describe('Trust Desk XLSX extractor parser budget', () => {
  it('parses a normal small questionnaire (legit path preserved)', async () => {
    const ws = xlsx.utils.aoa_to_sheet([
      ['Question', 'Section'],
      ['Do you encrypt customer data at rest?', 'Security'],
      ['Describe your incident response process', 'Operations'],
    ]);
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, ws, 'Questionnaire');

    const result = await extractQuestions({ content: toBuffer(wb), filename: 'q.xlsx' });
    expect(result.source_format).toBe('xlsx');
    expect(result.total_questions).toBe(2);
    expect(result.questions.map((q) => q.text)).toContain('Do you encrypt customer data at rest?');
  });

  it('refuses a workbook with too many sheets (fan-out budget)', async () => {
    const wb = xlsx.utils.book_new();
    for (let i = 0; i < 65; i++) {
      // 65 > MAX_XLSX_SHEETS (64)
      xlsx.utils.book_append_sheet(wb, xlsx.utils.aoa_to_sheet([['cell']]), `S${i}`);
    }
    await expect(extractQuestions({ content: toBuffer(wb), filename: 'bomb.xlsx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });

  it('refuses a sheet whose column count blows the per-sheet budget', async () => {
    // One row, 4097 columns > MAX_XLSX_COLS_PER_SHEET (4096). Small on disk, but
    // sheet_to_csv on a book this wide is the amplification we refuse to run.
    const ws = xlsx.utils.aoa_to_sheet([new Array(4097).fill('x')]);
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, ws, 'Wide');
    await expect(extractQuestions({ content: toBuffer(wb), filename: 'wide.xlsx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });
});

describe('Trust Desk DOCX extractor parser budget', () => {
  it('rejects a ZIP entry whose advertised expansion exceeds the budget', async () => {
    // Minimal ZIP central directory with a 4 GiB uncompressed entry. The
    // preflight must reject before mammoth receives the archive.
    const centralOffset = 0;
    const centralSize = 46;
    const eocdOffset = centralSize;
    const buf = Buffer.alloc(centralSize + 22);
    buf.writeUInt32LE(0x02014b50, 0);
    buf.writeUInt32LE(0xffffffff, 24);
    buf.writeUInt32LE(1, 20);
    buf.writeUInt32LE(1, 42);
    buf.writeUInt32LE(0x06054b50, eocdOffset);
    buf.writeUInt16LE(1, eocdOffset + 8);
    buf.writeUInt16LE(1, eocdOffset + 10);
    buf.writeUInt32LE(centralSize, eocdOffset + 12);
    buf.writeUInt32LE(centralOffset, eocdOffset + 16);

    await expect(extractQuestions({ content: buf, filename: 'bomb.docx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });
});
