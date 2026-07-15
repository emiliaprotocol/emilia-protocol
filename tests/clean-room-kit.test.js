// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildCleanRoomKit, collectCleanRoomKitFiles } from '../scripts/build-clean-room-kit.mjs';

const repositoryRef = process.env.EP_CLEAN_ROOM_REF || 'HEAD';

describe('external clean-room input kit', () => {
  it('contains only byte-pinned specifications, vectors, schemas, and instructions', () => {
    const { files } = collectCleanRoomKitFiles(repositoryRef);
    const paths = files.map((entry) => entry.path);
    expect(paths).toContain('conformance/clean-room/specification-bundle.v1.json');
    expect(paths).toContain('conformance/vectors/receipts.v1.json');
    expect(paths.some((entry) => /^(app|lib|packages|conformance\/runners)\//.test(entry))).toBe(false);
    const bundle = JSON.parse(fs.readFileSync('conformance/clean-room/bundle.v1.json', 'utf8'));
    const receiptPin = bundle.suites.find((entry) => entry.path === 'conformance/vectors/receipts.v1.json');
    expect(files.find((entry) => entry.path === receiptPin.path)?.sha256).toBe(receiptPin.sha256);
  });

  it('builds a reproducible archive and exact content report', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-clean-room-kit-test-'));
    try {
      const report = buildCleanRoomKit({ ref: repositoryRef, output: path.join(dir, 'kit.tar.gz') });
      expect(report.reference_implementation_included).toBe(false);
      expect(report.archive.reproducible).toBe(true);
      expect(report.archive.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(JSON.parse(fs.readFileSync(report.manifestTarget, 'utf8'))).toEqual({
        '@version': report['@version'],
        source_commit: report.source_commit,
        archive: report.archive,
        reference_implementation_included: false,
        files: report.files,
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
