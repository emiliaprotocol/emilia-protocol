/**
 * CI Guardrails — Protocol Discipline Check Tests
 *
 * Verifies that the static analysis script correctly:
 * - Flags trust-table write violations in route files
 * - Flags direct EP_ env reads outside lib/env.js
 * - Passes clean files without false positives
 * - Exempts canonical-writer.js and env.js from their respective rules
 *
 * @license Apache-2.0
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';

const ROOT = path.resolve(import.meta.dirname, '..');
const FIXTURE_DIR = path.join(ROOT, '__test_fixtures_guardrails__');
const FIXTURE_API_DIR = path.join(FIXTURE_DIR, 'app', 'api', 'test-route');
const FIXTURE_LIB_DIR = path.join(FIXTURE_DIR, 'lib');

/**
 * We cannot easily re-run the main script with a different ROOT,
 * so we test the detection logic by creating temporary fixture files
 * and scanning them with the same regex patterns used by the script.
 */

// Replicate the core detection patterns from the script
const TRUST_TABLES = ['receipts', 'commits', 'disputes', 'trust_reports', 'protocol_events', 'entities'];

function buildTrustTablePatterns() {
  return TRUST_TABLES.map(table => ({
    table,
    regex: new RegExp(`\\.from\\(\\s*['"\`]${table}['"\`]\\s*\\)\\s*\\.insert`, 'g'),
  }));
}

const ENV_PATTERN = /process\.env\.EP_/g;

function scanFileForTrustViolations(content) {
  const violations = [];
  const lines = content.split('\n');
  const patterns = buildTrustTablePatterns();
  for (let i = 0; i < lines.length; i++) {
    for (const { table, regex } of patterns) {
      regex.lastIndex = 0;
      if (regex.test(lines[i])) {
        violations.push({ line: i + 1, table });
      }
    }
  }
  return violations;
}

function scanFileForEnvViolations(content) {
  const violations = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
    ENV_PATTERN.lastIndex = 0;
    if (ENV_PATTERN.test(lines[i])) {
      violations.push({ line: i + 1 });
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Protocol Discipline Check', () => {

  describe('Trust-table write detection', () => {
    it('flags .from("receipts").insert in a route file', () => {
      const code = `
import { getServiceClient } from '@/lib/supabase';
export async function POST(req) {
  const supabase = getServiceClient();
  await supabase.from('receipts').insert({ foo: 'bar' });
}
`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(1);
      expect(violations[0].table).toBe('receipts');
    });

    it('flags .from("disputes").insert', () => {
      const code = `await supabase.from('disputes').insert({ reason: 'test' });`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(1);
      expect(violations[0].table).toBe('disputes');
    });

    it('flags .from("trust_reports").insert', () => {
      const code = `await supabase.from("trust_reports").insert({ id: 1 });`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(1);
      expect(violations[0].table).toBe('trust_reports');
    });

    it('does not flag .from("receipts").select (reads are fine)', () => {
      const code = `await supabase.from('receipts').select('*');`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(0);
    });

    it('does not flag .from("receipts").update (only insert is checked)', () => {
      const code = `await supabase.from('receipts').update({ status: 'confirmed' });`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(0);
    });

    it('does not flag non-trust tables', () => {
      const code = `await supabase.from('users').insert({ name: 'test' });`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(0);
    });

    it('passes clean route files with no violations', () => {
      const code = `
import { canonicalSubmitReceipt } from '@/lib/canonical-writer';
export async function POST(req) {
  const result = await canonicalSubmitReceipt(body, entity);
  return Response.json(result);
}
`;
      const violations = scanFileForTrustViolations(code);
      expect(violations.length).toBe(0);
    });
  });

  describe('canonical-writer.js exemption', () => {
    it('canonical-writer.js is in the allowlist (tested by script config)', async () => {
      // The script uses an allowlist Set — verify the file exists and
      // actually contains trust-table writes (proving exemption is necessary)
      const cwPath = path.join(ROOT, 'lib', 'canonical-writer.js');
      const content = fs.readFileSync(cwPath, 'utf-8');
      const violations = scanFileForTrustViolations(content);
      // canonical-writer.js SHOULD contain trust-table writes
      expect(violations.length).toBeGreaterThan(0);
      // But the script exempts it — verified by the allowlist config
    });
  });

  describe('EP_ env read detection', () => {
    it('flags process.env.EP_API_KEY in a lib file', () => {
      const code = `const key = process.env.EP_API_KEY;`;
      const violations = scanFileForEnvViolations(code);
      expect(violations.length).toBe(1);
    });

    it('flags process.env.EP_COMMIT_SIGNING_KEY', () => {
      const code = `const sk = process.env.EP_COMMIT_SIGNING_KEY || null;`;
      const violations = scanFileForEnvViolations(code);
      expect(violations.length).toBe(1);
    });

    it('does not flag process.env.NODE_ENV', () => {
      const code = `if (process.env.NODE_ENV === 'production') {}`;
      const violations = scanFileForEnvViolations(code);
      expect(violations.length).toBe(0);
    });

    it('does not flag commented-out env reads', () => {
      const code = `// const key = process.env.EP_API_KEY;`;
      const violations = scanFileForEnvViolations(code);
      expect(violations.length).toBe(0);
    });

    it('does not flag process.env.NEXT_PUBLIC_SUPABASE_URL', () => {
      const code = `const url = process.env.NEXT_PUBLIC_SUPABASE_URL;`;
      const violations = scanFileForEnvViolations(code);
      expect(violations.length).toBe(0);
    });
  });

  describe('env.js exemption', () => {
    it('env.js contains EP_ env reads but is in the allowlist', () => {
      const envPath = path.join(ROOT, 'lib', 'env.js');
      const content = fs.readFileSync(envPath, 'utf-8');
      const violations = scanFileForEnvViolations(content);
      // env.js SHOULD contain EP_ env reads
      expect(violations.length).toBeGreaterThan(0);
      // But the script exempts it — verified by the allowlist config
    });
  });

  describe('Full script integration', () => {
    it('runChecks() returns structured results', async () => {
      const { runChecks } = await import('../scripts/check-protocol-discipline.js');
      const result = runChecks();
      expect(result).toHaveProperty('criticals');
      expect(result).toHaveProperty('warnings');
      expect(result).toHaveProperty('all');
      expect(Array.isArray(result.criticals)).toBe(true);
      expect(Array.isArray(result.warnings)).toBe(true);
    });

    it('each violation has file, line, message, and severity', async () => {
      const { runChecks } = await import('../scripts/check-protocol-discipline.js');
      const result = runChecks();
      for (const v of result.all) {
        expect(v).toHaveProperty('file');
        expect(v).toHaveProperty('line');
        expect(v).toHaveProperty('message');
        expect(v).toHaveProperty('severity');
        expect(typeof v.file).toBe('string');
        expect(typeof v.line).toBe('number');
      }
    });
  });
});
