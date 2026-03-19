/**
 * EMILIA Protocol — Invariant & Cross-Layer Contract Tests
 *
 * These are static-analysis tests that verify protocol-level invariants
 * WITHOUT a running server. They read source files and check that layers
 * (DB schema, API routes, OpenAPI spec, scoring engine, commit engine)
 * agree on enums, scales, vocabularies, and contracts.
 *
 * Why: "passing tests are not enough because they missed a scale bug."
 * These tests catch the class of bugs where individual layers pass their
 * own tests but disagree with each other on fundamental contracts.
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { computeTrustProfile } from '../lib/scoring-v2.js';

const ROOT = path.resolve(import.meta.dirname, '..');

// ============================================================================
// Helpers
// ============================================================================

function makeReceipt(overrides = {}) {
  return {
    delivery_accuracy: 90,
    product_accuracy: 85,
    price_integrity: 95,
    return_processing: 80,
    composite_score: 88,
    submitted_by: overrides.submitted_by || 'submitter-1',
    submitter_score: overrides.submitter_score ?? 85,
    submitter_established: overrides.submitter_established ?? true,
    graph_weight: overrides.graph_weight ?? 1.0,
    agent_behavior: overrides.agent_behavior || 'completed',
    provenance_tier: overrides.provenance_tier || 'bilateral',
    created_at: overrides.created_at || new Date().toISOString(),
    ...overrides,
  };
}

function readSource(relPath) {
  return fs.readFileSync(path.join(ROOT, relPath), 'utf-8');
}

// ============================================================================
// 1. Score Scale Invariants
// ============================================================================

describe('Score Scale Invariants', () => {
  it('computeTrustProfile() returns scores in 0-100 range (empty receipts)', () => {
    const profile = computeTrustProfile([], {});
    expect(profile.score).toBeGreaterThanOrEqual(0);
    expect(profile.score).toBeLessThanOrEqual(100);
  });

  it('computeTrustProfile() returns scores in 0-100 range (good receipts)', () => {
    const receipts = Array.from({ length: 20 }, (_, i) =>
      makeReceipt({ submitted_by: `sub-${i % 5}` })
    );
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeGreaterThanOrEqual(0);
    expect(profile.score).toBeLessThanOrEqual(100);
  });

  it('computeTrustProfile() returns scores in 0-100 range (bad receipts)', () => {
    const receipts = Array.from({ length: 20 }, (_, i) =>
      makeReceipt({
        submitted_by: `sub-${i % 5}`,
        delivery_accuracy: 10,
        product_accuracy: 5,
        price_integrity: 15,
        return_processing: 0,
        composite_score: 8,
        agent_behavior: 'abandoned',
      })
    );
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeGreaterThanOrEqual(0);
    expect(profile.score).toBeLessThanOrEqual(100);
  });

  it('computeTrustProfile() returns scores in 0-100 range (extreme/adversarial inputs)', () => {
    const receipts = Array.from({ length: 10 }, (_, i) =>
      makeReceipt({
        submitted_by: `sub-${i}`,
        delivery_accuracy: 200,    // out of range — should be clamped
        product_accuracy: -50,     // out of range
        composite_score: 999,      // out of range
        agent_behavior: 'disputed',
      })
    );
    const profile = computeTrustProfile(receipts, {});
    expect(profile.score).toBeGreaterThanOrEqual(0);
    expect(profile.score).toBeLessThanOrEqual(100);
  });

  it('no decision path in commit.js treats scores as 0-1 when they are 0-100', () => {
    const commitSource = readSource('lib/commit.js');

    // The commit fallback should NOT compare score against 0-1 thresholds.
    // e.g., "score > 0.7" or "score < 0.5" would be scale bugs.
    // Look for patterns like: score > 0. followed by a single digit (0.1 through 0.9)
    const zeroOneThresholdPattern = /\bscore\s*[<>]=?\s*0\.\d\b/;
    expect(commitSource).not.toMatch(zeroOneThresholdPattern);
  });

  it('commit fallback path (no policy) never uses raw score for decisions', () => {
    const commitSource = readSource('lib/commit.js');

    // The fallback (else branch when no policyResult) should default to 'review',
    // NOT use a numeric score threshold. Verify the code says decision = 'review'.
    // Extract the else block that handles "no policy"
    const fallbackMatch = commitSource.match(
      /}\s*else\s*\{[^}]*?decision\s*=\s*'(\w+)'/s
    );
    expect(fallbackMatch).not.toBeNull();
    expect(fallbackMatch[1]).toBe('review');

    // Verify the comment explains WHY no raw score fallback
    expect(commitSource).toContain('No raw score fallback');
  });
});

// ============================================================================
// 2. Enum Consistency (cross-layer contract tests)
// ============================================================================

describe('Enum Consistency — cross-layer contracts', () => {
  // Extract DB constraint values from migration SQL
  function extractDbReportTypes() {
    const sql = readSource('supabase/migrations/013_disputes.sql');
    // Find the CHECK constraint on report_type in trust_reports table
    const match = sql.match(
      /report_type\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(\s*report_type\s+IN\s*\(([\s\S]*?)\)\s*\)/
    );
    expect(match).not.toBeNull();
    return match[1].match(/'([^']+)'/g).map(s => s.replace(/'/g, ''));
  }

  // Extract API validTypes from route.js
  function extractApiValidTypes() {
    const routeSource = readSource('app/api/disputes/report/route.js');
    const match = routeSource.match(/const\s+validTypes\s*=\s*\[([\s\S]*?)\]/);
    expect(match).not.toBeNull();
    return match[1].match(/'([^']+)'/g).map(s => s.replace(/'/g, ''));
  }

  // Extract OpenAPI enum from openapi.yaml
  function extractOpenApiReportTypes() {
    const yaml = readSource('openapi.yaml');
    // Find report_type enum near the report_type property
    const match = yaml.match(
      /report_type:\s*\n\s+type:\s+string\s*\n\s+enum:\s*\[([^\]]+)\]/
    );
    expect(match).not.toBeNull();
    return match[1].split(',').map(s => s.trim());
  }

  it('API validTypes must be a subset of DB constraint values', () => {
    const dbTypes = new Set(extractDbReportTypes());
    const apiTypes = extractApiValidTypes();

    for (const apiType of apiTypes) {
      expect(dbTypes.has(apiType)).toBe(true);
    }
  });

  it('DB constraint values must be a subset of API validTypes (no orphan DB values)', () => {
    const dbTypes = extractDbReportTypes();
    const apiTypes = new Set(extractApiValidTypes());

    for (const dbType of dbTypes) {
      expect(apiTypes.has(dbType)).toBe(true);
    }
  });

  it('OpenAPI enum must match DB constraint', () => {
    const dbTypes = new Set(extractDbReportTypes());
    const openApiTypes = extractOpenApiReportTypes();

    expect(new Set(openApiTypes)).toEqual(dbTypes);
  });

  it('OpenAPI enum must match API validTypes', () => {
    const apiTypes = extractApiValidTypes();
    const openApiTypes = extractOpenApiReportTypes();

    expect(new Set(openApiTypes)).toEqual(new Set(apiTypes));
  });
});

// ============================================================================
// 3. Decision Vocabulary Invariants
// ============================================================================

describe('Decision Vocabulary Invariants', () => {
  const CANONICAL_DECISIONS = new Set(['allow', 'review', 'deny']);

  it('commit.js VALID_DECISIONS only contains allow, review, deny', () => {
    const source = readSource('lib/commit.js');
    const match = source.match(
      /VALID_DECISIONS\s*=\s*new\s+Set\(\[([^\]]+)\]\)/
    );
    expect(match).not.toBeNull();
    const decisions = match[1].match(/'([^']+)'/g).map(s => s.replace(/'/g, ''));
    expect(new Set(decisions)).toEqual(CANONICAL_DECISIONS);
  });

  it('commit.js VALID_DECISIONS does not contain "block" or "pass"', () => {
    const source = readSource('lib/commit.js');
    const match = source.match(
      /VALID_DECISIONS\s*=\s*new\s+Set\(\[([^\]]+)\]\)/
    );
    const decisions = match[1].match(/'([^']+)'/g).map(s => s.replace(/'/g, ''));
    expect(decisions).not.toContain('block');
    expect(decisions).not.toContain('pass');
  });

  it('trust-decision.js uses the same canonical vocabulary', () => {
    const source = readSource('lib/trust-decision.js');
    // buildTrustDecision documents the decision parameter as 'allow' | 'review' | 'deny'
    expect(source).toContain("'allow'");
    expect(source).toContain("'review'");
    expect(source).toContain("'deny'");
    // passToDecision returns only 'allow' or 'deny' — no 'block' or 'pass'
    expect(source).not.toMatch(/['"]block['"]/);
    expect(source).not.toMatch(/['"]pass['"]/);
  });

  it('trust/gate route returns only canonical decisions', () => {
    const source = readSource('app/api/trust/gate/route.js');

    // Extract all string literals that appear as decision values.
    // Covers: decision = 'x', decision: 'x', ? 'x' : 'y' in decision context
    const allQuotedStrings = source.match(/'(\w+)'/g)?.map(s => s.replace(/'/g, '')) || [];

    // Filter to only those that look like decision values (appear near "decision")
    // Strategy: find lines that assign or set `decision` and extract the string values
    const decisionLines = source.split('\n').filter(line =>
      /\bdecision\b/.test(line) && /'(\w+)'/.test(line)
    );
    const usedDecisions = [];
    for (const line of decisionLines) {
      const matches = line.match(/'(\w+)'/g);
      if (matches) {
        usedDecisions.push(...matches.map(s => s.replace(/'/g, '')));
      }
    }

    // Every decision value used must be in the canonical set
    for (const d of usedDecisions) {
      expect(CANONICAL_DECISIONS.has(d)).toBe(true);
    }
    // Must use at least 'allow' and 'deny'
    expect(usedDecisions).toContain('allow');
    expect(usedDecisions).toContain('deny');
  });
});

// ============================================================================
// 4. Route Comment Integrity
// ============================================================================

describe('Route Comment Integrity', () => {
  it('audit route claims operator-level access and actually checks permissions', () => {
    const source = readSource('app/api/audit/route.js');

    // Verify the comment claims operator-level access
    expect(source.toLowerCase()).toContain('operator-level');

    // Verify it calls authenticateRequest
    expect(source).toContain('authenticateRequest');

    // Verify it ALSO checks permissions beyond just authentication
    // (authenticateRequest alone is not enough — it must check audit.view or role)
    expect(source).toMatch(/audit\.view|permission|OPERATOR_ROLES/);

    // Verify there is a 403 response for insufficient permissions
    expect(source).toContain('403');
    expect(source).toMatch(/insufficient.permission|permission/i);
  });
});

// ============================================================================
// 5. Machine-Readable Discovery
// ============================================================================

describe('Machine-Readable Discovery', () => {
  it('every URL endpoint in ep-trust.json resolves to an actual route file', () => {
    const discovery = JSON.parse(readSource('public/.well-known/ep-trust.json'));

    // Extract all URL values that point to API endpoints
    const urlKeys = Object.keys(discovery).filter(k => k.endsWith('_url'));
    expect(urlKeys.length).toBeGreaterThan(0);

    for (const key of urlKeys) {
      const url = discovery[key];
      // Only check API routes hosted on the same domain (skip GitHub links, etc.)
      if (!url.includes('/api/')) continue;

      // Extract the path portion: /api/trust/profile/{entity_id} -> api/trust/profile
      const pathMatch = url.match(/\/api\/([^\s?#]*)/);
      expect(pathMatch).not.toBeNull();

      let routePath = pathMatch[1];
      // Remove trailing template params like {entity_id}
      routePath = routePath.replace(/\/\{[^}]+\}/g, '');
      // Remove trailing slashes
      routePath = routePath.replace(/\/+$/, '');

      // Check that either a route.js exists in this directory
      // or a dynamic route directory [param]/ exists with route.js
      const directRoute = path.join(ROOT, 'app', 'api', routePath, 'route.js');
      const hasTemplateParam = url.includes('{');

      if (hasTemplateParam) {
        // For parameterized routes, check the parent dir has a [param] subdirectory
        const parentDir = path.join(ROOT, 'app', 'api', routePath);
        let found = false;
        if (fs.existsSync(parentDir)) {
          const entries = fs.readdirSync(parentDir);
          found = entries.some(e =>
            e.startsWith('[') &&
            fs.existsSync(path.join(parentDir, e, 'route.js'))
          );
        }
        expect(found).toBe(true);
      } else {
        expect(fs.existsSync(directRoute)).toBe(true);
      }
    }
  });
});

// ============================================================================
// 6. Event Type Uniqueness
// ============================================================================

describe('Event Type Uniqueness', () => {
  function extractWriteEvents() {
    const source = readSource('lib/canonical-writer.js');
    const match = source.match(
      /export\s+const\s+WRITE_EVENTS\s*=\s*\{([\s\S]*?)\};/
    );
    expect(match).not.toBeNull();
    const entries = {};
    const regex = /(\w+)\s*:\s*'([^']+)'/g;
    let m;
    while ((m = regex.exec(match[1])) !== null) {
      entries[m[1]] = m[2];
    }
    return entries;
  }

  it('no two different semantic actions share the same event type string', () => {
    const events = extractWriteEvents();
    const keys = Object.keys(events);
    const values = Object.values(events);

    // Values must be unique
    expect(new Set(values).size).toBe(values.length);

    // Sanity: we expect a meaningful number of events
    expect(keys.length).toBeGreaterThanOrEqual(8);
  });

  it('appeal filing has its own event type distinct from dispute resolution', () => {
    const events = extractWriteEvents();

    // There must be a DISPUTE_APPEALED event
    expect(events).toHaveProperty('DISPUTE_APPEALED');

    // There must be a DISPUTE_RESOLVED event
    expect(events).toHaveProperty('DISPUTE_RESOLVED');

    // They must have different event type strings
    expect(events.DISPUTE_APPEALED).not.toBe(events.DISPUTE_RESOLVED);
  });

  it('appeal resolution has its own event type distinct from dispute resolution', () => {
    const events = extractWriteEvents();

    // DISPUTE_APPEAL_RESOLVED should exist and differ from DISPUTE_RESOLVED
    expect(events).toHaveProperty('DISPUTE_APPEAL_RESOLVED');
    expect(events.DISPUTE_APPEAL_RESOLVED).not.toBe(events.DISPUTE_RESOLVED);
  });
});
