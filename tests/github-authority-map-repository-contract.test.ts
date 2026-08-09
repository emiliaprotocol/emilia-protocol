// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';

import { scanWorkspace } from '../integrations/github-authority-map-action/scan.mjs';

describe('EMILIA repository authority map', () => {
  it('has no obvious privileged sink outside an environment', async () => {
    const report = await scanWorkspace(process.cwd(), {
      generatedAt: '2026-08-08T00:00:00.000Z',
    });
    const criticalSinks = report.findings
      .filter(
        (finding) =>
          finding.code === 'PRIVILEGED_SINK_WITHOUT_ENVIRONMENT' &&
          finding.severity === 'critical',
      )
      .map(({ file, job }) => ({ file, job }));

    expect(criticalSinks).toEqual([]);
  });
});
