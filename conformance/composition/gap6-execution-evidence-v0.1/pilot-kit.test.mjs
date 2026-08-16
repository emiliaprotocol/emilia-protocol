// SPDX-License-Identifier: Apache-2.0
// Generated from pilot-kit.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from 'vitest';
import { exportPilotKit } from './export-pilot-kit.mjs';
import { parseBundleDirectory, verifyPilotKit } from './verify-pilot-kit.mjs';
test('the verifier CLI accepts the documented bundle flag', () => {
    expect(parseBundleDirectory(['--bundle', '/tmp/pilot'])).toBe('/tmp/pilot');
    expect(parseBundleDirectory(['--bundle=/tmp/pilot'])).toBe('/tmp/pilot');
    expect(parseBundleDirectory(['/tmp/pilot'])).toBe('/tmp/pilot');
    expect(() => parseBundleDirectory(['--bundle'])).toThrow(/usage:/);
});
test('one command exports an offline-verifiable M01 pilot bundle and human reports', async () => {
    const root = mkdtempSync(join(tmpdir(), 'emilia-m01-pilot-'));
    const exported = await exportPilotKit(join(root, 'bundle'));
    const verification = await verifyPilotKit(exported.output);
    expect(verification.failures, verification.failures.join(', ')).toEqual([]);
    expect(verification.ok).toBe(true);
    expect(exported.file_count).toBe(19);
    expect(readFileSync(join(exported.output, 'PILOT-REPORT.md'), 'utf8')).toMatch(/refused 5 hostile control-field cases/);
    expect(readFileSync(join(exported.output, 'audit-workpaper.md'), 'utf8')).toMatch(/does not perform the test/i);
    expect(readFileSync(join(exported.output, 'underwriter-attestation.md'), 'utf8')).toMatch(/does not attest/i);
});
