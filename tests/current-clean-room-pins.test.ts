// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { planCurrentCleanRoomPinRefresh } from '../scripts/sync-current-clean-room-pins.mts';

const files = [
  'conformance/conformance-manifest.json',
  'conformance/clean-room/v2/bundle.v2.json',
  'conformance/clean-room/v3/bundle.v3.json',
  'scripts/verify-clean-room-submission-v2.mts',
  'docs/conformance/CLEAN-ROOM-V2.md',
];
function fixture(run: (root: string) => void) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-current-pins-'));
  try {
    for (const name of files) {
      fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      fs.copyFileSync(name, path.join(root, name));
    }
    run(root);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

describe('current clean-room manifest pin refresh', () => {
  it('plans only current-kit pins, never historical evidence or suite changes', () => fixture(root => {
    const file = path.join(root, files[0]);
    fs.appendFileSync(file, '\n');
    const edits = planCurrentCleanRoomPinRefresh(root);
    expect([...edits.keys()].sort()).toEqual(files.slice(1).sort());
    expect(fs.readFileSync(path.join(root, files[1]), 'utf8')).toBe(fs.readFileSync(files[1], 'utf8'));
  }));
  it.each(['sha256', 'vectors', 'path', 'execution_sha256'])('refuses changed vector contract field %s', field => fixture(root => {
    const file = path.join(root, files[0]);
    const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    manifest.suites[0][field] = field === 'vectors' ? 999 : 'changed';
    fs.writeFileSync(file, JSON.stringify(manifest));
    expect(() => planCurrentCleanRoomPinRefresh(root)).toThrow('corpus revision required');
  }));
  it('refuses changed totals', () => fixture(root => {
    const file = path.join(root, files[0]);
    const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    manifest.totals.vectors += 1;
    fs.writeFileSync(file, JSON.stringify(manifest));
    expect(() => planCurrentCleanRoomPinRefresh(root)).toThrow('corpus revision required');
  }));
});
