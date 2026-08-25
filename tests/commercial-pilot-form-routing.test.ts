// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');

const PILOT_FORM_PAGES = [
  'app/eye/page.tsx',
  'app/product/accountable-signoff/page.tsx',
  'app/product/agent-governance-pack/page.tsx',
  'app/product/cloud/page.tsx',
  'app/product/enterprise/page.tsx',
  'app/product/financial-pack/page.tsx',
  'app/product/government-pack/page.tsx',
  'app/use-cases/ai-agent/page.tsx',
  'app/use-cases/enterprise/page.tsx',
  'app/use-cases/financial/page.tsx',
  'app/use-cases/government/page.tsx',
] as const;

const PILOT_WORKFLOWS = new Set([
  'beneficiary_change',
  'wire_release',
  'payer_adverse_determination',
  'benefit_account_change',
  'caseworker_override',
  'clinical_action',
  'other',
]);

describe('commercial pilot form routing', () => {
  it.each(PILOT_FORM_PAGES)(
    '%s submits the canonical pilot to the dedicated pilot intake',
    (relativePath) => {
      const source = readFileSync(resolve(ROOT, relativePath), 'utf8');

      expect(source).toContain("fetch('/api/pilot/request'");
      expect(source).toContain('PROTECTED_WORKFLOW_PILOT.id');
      const workflow = source.match(/workflow:\s*'([^']+)'/)?.[1];
      expect(workflow).toBeTruthy();
      expect(PILOT_WORKFLOWS.has(workflow ?? '')).toBe(true);
      expect(source).not.toContain("fetch('/api/inquiries'");
      expect(source).not.toMatch(/type:\s*'pilot-/);
      expect(source).toContain('<form');
      expect(source).toContain('onSubmit={handleSubmit}');
      expect(source).toContain('type="submit"');
      expect(source).toContain('!form.org');
      expect(source).not.toContain('onClick={handleSubmit}');
      expect(source).toContain('htmlFor={`pilot-${k}`}');
      expect(source).toContain('name={k}');
      expect(source).toContain("type={k === 'email' ? 'email' : 'text'}");
      expect(source).toContain("required={k === 'name' || k === 'org' || k === 'email'}");
      expect(source).toContain('role="alert"');
    },
  );
});
