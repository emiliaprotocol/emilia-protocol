// SPDX-License-Identifier: Apache-2.0
// Append-only JSONL observation log with a hash chain.
//
// Each line is one JSON object with `seq` (1, 2, 3, ...) and `prev`, the
// SHA-256 of the previous line's bytes (64 zeros for the first line). The
// writer opens the file O_APPEND and fdatasyncs every record. The chain makes
// an edited, reordered, or dropped line in the middle of the log detectable.
// It does not stop whoever controls the file from rewriting all of it or
// cutting off its tail; that is what the policy version chain check is for.

import fs from 'node:fs';
import { strictJsonGate } from '@emilia-protocol/verify/strict-json';
import { sha256Hex } from './canonical.ts';

export const GENESIS = '0'.repeat(64);
export const LOG_FORMAT = 'emilia.openshell.observer-log.v1';

export type LogRecord = { seq: number; prev: string; t: string; kind: string } & Record<string, unknown>;

export class AppendOnlyLog {
  readonly path: string;
  private fd: number;
  private seq: number;
  private prev: string;
  private needsNewline: boolean;

  constructor(filePath: string) {
    this.path = filePath;
    const { lastSeq, lastHash, torn } = recoverTail(filePath);
    this.seq = lastSeq;
    this.prev = lastHash;
    this.needsNewline = torn;
    this.fd = fs.openSync(filePath, 'a', 0o600);
  }

  append(kind: string, fields: Record<string, unknown>): LogRecord {
    const record = { seq: this.seq + 1, prev: this.prev, t: new Date().toISOString(), kind, ...fields } as LogRecord;
    const line = JSON.stringify(record);
    fs.writeSync(this.fd, `${this.needsNewline ? '\n' : ''}${line}\n`);
    this.needsNewline = false;
    fs.fdatasyncSync(this.fd);
    this.seq = record.seq;
    this.prev = sha256Hex(line);
    return record;
  }

  close(): void {
    fs.closeSync(this.fd);
  }
}

function recoverTail(filePath: string): { lastSeq: number; lastHash: string; torn: boolean } {
  let text: string;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { lastSeq: 0, lastHash: GENESIS, torn: false };
    throw error;
  }
  const lines = text.split('\n').filter((line) => line.length > 0);
  if (lines.length === 0) return { lastSeq: 0, lastHash: GENESIS, torn: false };
  const last = lines[lines.length - 1];
  let lastSeq = lines.length;
  try {
    const parsed = JSON.parse(last) as { seq?: unknown };
    if (typeof parsed.seq === 'number' && Number.isSafeInteger(parsed.seq)) lastSeq = parsed.seq;
  } catch {
    // A torn final line (crash mid-write) stays in the file; the next record
    // chains to its bytes and the checker reports the torn line.
  }
  return { lastSeq, lastHash: sha256Hex(last), torn: !text.endsWith('\n') };
}

export interface ParsedLog {
  records: LogRecord[];
  problems: { line: number; code: 'log_malformed_line' | 'log_chain_broken'; reason: string }[];
}

/** Parse and chain-check a log. Never throws; problems are returned. */
export function parseLog(text: string): ParsedLog {
  const records: LogRecord[] = [];
  const problems: ParsedLog['problems'] = [];
  if (typeof text !== 'string') {
    problems.push({ line: 0, code: 'log_malformed_line', reason: 'log is not text' });
    return { records, problems };
  }
  const lines = text.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  let prev = GENESIS;
  let expectedSeq = 1;
  lines.forEach((line, index) => {
    const lineNo = index + 1;
    const hash = sha256Hex(line);
    const gate = strictJsonGate(line);
    if (!gate.ok) {
      problems.push({ line: lineNo, code: 'log_malformed_line', reason: `not strict JSON: ${gate.reason}` });
      prev = hash;
      expectedSeq += 1;
      return;
    }
    const value: unknown = JSON.parse(line);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      problems.push({ line: lineNo, code: 'log_malformed_line', reason: 'line is not a JSON object' });
      prev = hash;
      expectedSeq += 1;
      return;
    }
    const record = value as Record<string, unknown>;
    if (typeof record.seq !== 'number' || !Number.isSafeInteger(record.seq) || typeof record.prev !== 'string'
        || typeof record.kind !== 'string' || typeof record.t !== 'string' || Number.isNaN(Date.parse(record.t))) {
      problems.push({ line: lineNo, code: 'log_malformed_line', reason: 'line lacks seq, prev, kind or t' });
      prev = hash;
      expectedSeq += 1;
      return;
    }
    if (record.prev !== prev) {
      problems.push({ line: lineNo, code: 'log_chain_broken', reason: `prev does not equal SHA-256 of line ${lineNo - 1}` });
    }
    if (record.seq !== expectedSeq) {
      problems.push({ line: lineNo, code: 'log_chain_broken', reason: `seq ${record.seq} where ${expectedSeq} was expected` });
    }
    records.push(record as LogRecord);
    prev = hash;
    expectedSeq = record.seq + 1;
  });
  return { records, problems };
}
