// SPDX-License-Identifier: Apache-2.0
//
// Regression: the Trust Desk questionnaire extractor is reachable from an
// UNAUTHENTICATED intake route. extractXlsx previously ran xlsx.read + sheet_to_csv
// with only a compressed-byte cap, so a small zip-bomb / oversized .xlsx could
// inflate to a workbook with billions of cells and exhaust memory. The parser
// budget must refuse (fail-closed → ExtractionUnsupportedError) BEFORE the whole
// book is materialized as CSV, while normal small questionnaires still parse.

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import * as xlsx from 'xlsx';
import { extractQuestions, ExtractionUnsupportedError } from '../lib/trust-desk/extractor.js';

function toBuffer(wb: xlsx.WorkBook): Buffer {
  return xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
}

function zipWithDeflatedEntry({
  name,
  content,
  claimedUncompressedBytes,
  flags = 0,
}: {
  name: string;
  content: Buffer;
  claimedUncompressedBytes: number;
  flags?: number;
}): Buffer {
  return zipWithDeflatedEntries([{ name, content, claimedUncompressedBytes, flags }]);
}

function zipWithDeflatedEntries(entries: Array<{
  name: string;
  content: Buffer;
  claimedUncompressedBytes: number;
  flags?: number;
  trailingCompressedBytes?: Buffer;
}>): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, 'utf8');
    const compressed = Buffer.concat([
      deflateRawSync(entry.content),
      entry.trailingCompressedBytes || Buffer.alloc(0),
    ]);
    const flags = entry.flags || 0;

    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(entry.claimedUncompressedBytes, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(entry.claimedUncompressedBytes, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(localOffset, 42);
    nameBytes.copy(central, 46);

    localParts.push(local, compressed);
    centralParts.push(central);
    localOffset += local.length + compressed.length;
  }

  const centralOffset = localOffset;
  const centralSize = centralParts.reduce((total, part) => total + part.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

function signatureOffsets(buf: Buffer, signature: number): number[] {
  const offsets: number[] = [];
  for (let offset = 0; offset <= buf.length - 4; offset++) {
    if (buf.readUInt32LE(offset) === signature) offsets.push(offset);
  }
  return offsets;
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
  const questionDocument = Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>'
      + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
      + '<w:body><w:p><w:r><w:t>Do you encrypt customer data at rest?</w:t></w:r></w:p></w:body>'
      + '</w:document>',
  );

  it('parses a normal small DOCX (legit path preserved)', async () => {
    const buf = zipWithDeflatedEntry({
      name: 'word/document.xml',
      content: questionDocument,
      claimedUncompressedBytes: questionDocument.length,
    });

    const result = await extractQuestions({ content: buf, filename: 'q.docx' });
    expect(result.source_format).toBe('docx');
    expect(result.questions.map((q) => q.text)).toContain('Do you encrypt customer data at rest?');
  });

  it('rejects a deflate stream whose actual expansion exceeds its small size claim', async () => {
    const buf = zipWithDeflatedEntry({
      name: 'word/document.xml',
      content: Buffer.alloc(16 * 1024 * 1024 + 1, 0x41),
      claimedUncompressedBytes: 1,
    });

    await expect(extractQuestions({ content: buf, filename: 'forged-size.docx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });

  it('rejects bounded deflate output whose actual size differs from its claim', async () => {
    const buf = zipWithDeflatedEntry({
      name: 'word/document.xml',
      content: questionDocument,
      claimedUncompressedBytes: 1,
    });

    await expect(extractQuestions({ content: buf, filename: 'size-mismatch.docx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });

  it('rejects data-descriptor entries instead of accepting ambiguous local sizes', async () => {
    const buf = zipWithDeflatedEntry({
      name: 'word/document.xml',
      content: questionDocument,
      claimedUncompressedBytes: questionDocument.length,
      flags: 0x0008,
    });

    await expect(extractQuestions({ content: buf, filename: 'descriptor.docx' })).rejects.toThrow(
      ExtractionUnsupportedError,
    );
  });

  it('rejects local metadata that disagrees with the central directory', async () => {
    const buf = zipWithDeflatedEntry({
      name: 'word/document.xml',
      content: questionDocument,
      claimedUncompressedBytes: questionDocument.length,
    });
    // Change only the local compression method; the central record still says
    // deflate. The verifier must reject before Mammoth chooses which metadata
    // to trust.
    buf.writeUInt16LE(0, 8);

    await expect(extractQuestions({ content: buf, filename: 'metadata-split.docx' }))
      .rejects.toThrow(/ambiguous ZIP entry metadata/);
  });

  it('rejects two central entries that alias the same local byte range', async () => {
    const buf = zipWithDeflatedEntries([
      { name: 'word/a.xml', content: questionDocument, claimedUncompressedBytes: questionDocument.length },
      { name: 'word/b.xml', content: questionDocument, claimedUncompressedBytes: questionDocument.length },
    ]);
    const central = signatureOffsets(buf, 0x02014b50);
    expect(central).toHaveLength(2);
    // Point the second central record at the first local header and make its
    // name agree, so only the explicit overlap/alias check can accept/refuse it.
    buf.writeUInt32LE(buf.readUInt32LE(central[0] + 42), central[1] + 42);
    Buffer.from('word/a.xml').copy(buf, central[1] + 46);

    await expect(extractQuestions({ content: buf, filename: 'aliased-entry.docx' }))
      .rejects.toThrow(/overlapping ZIP entries/);
  });

  it('rejects a valid deflate stream followed by unconsumed trailing bytes', async () => {
    const buf = zipWithDeflatedEntries([{
      name: 'word/document.xml',
      content: questionDocument,
      claimedUncompressedBytes: questionDocument.length,
      trailingCompressedBytes: Buffer.from([0xde, 0xad, 0xbe, 0xef]),
    }]);

    await expect(extractQuestions({ content: buf, filename: 'trailing-stream.docx' }))
      .rejects.toThrow(/deflate stream length does not match/);
  });

  it('rejects aggregate advertised expansion above the whole-document ceiling', async () => {
    // Random input stays close to its compressed size, keeping every entry
    // below the 200x per-entry ratio while five 16 MiB claims exceed 64 MiB in
    // aggregate. Preflight must refuse before any stream is inflated.
    const incompressible = crypto.randomBytes(96 * 1024);
    const buf = zipWithDeflatedEntries(Array.from({ length: 5 }, (_, index) => ({
      name: `word/media/blob${index}.bin`,
      content: incompressible,
      claimedUncompressedBytes: 16 * 1024 * 1024,
    })));

    await expect(extractQuestions({ content: buf, filename: 'aggregate-overflow.docx' }))
      .rejects.toThrow(/ZIP expansion exceeds parser budget/);
  });

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
