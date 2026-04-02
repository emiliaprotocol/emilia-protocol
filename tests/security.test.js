/**
 * Security Hardening Tests
 *
 * Verifies that security configurations are correctly set up:
 * - Security headers in next.config.js
 * - CSP directives
 * - TRUST_TABLES completeness
 * - Write-guard enforcement
 * - Rate limit coverage for all route patterns
 *
 * @license Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readFile(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), 'utf-8');
}

// ---------------------------------------------------------------------------
// 1. Security Headers
// ---------------------------------------------------------------------------

describe('Security Headers (next.config.js)', () => {
  const configSrc = readFile('next.config.js');

  const requiredHeaders = [
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
    { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    { key: 'X-DNS-Prefetch-Control', value: 'on' },
    { key: 'X-Frame-Options', value: 'DENY' },
  ];

  for (const { key, value } of requiredHeaders) {
    it(`includes ${key}: ${value}`, () => {
      expect(configSrc).toContain(key);
      expect(configSrc).toContain(value);
    });
  }

  it('applies static security headers to all routes via /:path*', () => {
    expect(configSrc).toContain("'/:path*'");
  });

  it('sets nonce-based CSP dynamically in middleware.js', () => {
    // CSP is set per-request with a nonce in middleware.js (resolves HIGH-09 pentest finding).
    // next.config.js no longer embeds CSP to avoid 'unsafe-inline' on script-src.
    const middlewareSrc = readFile('middleware.js');
    expect(middlewareSrc).toContain('Content-Security-Policy');
  });
});

// ---------------------------------------------------------------------------
// 2. CSP Directives (nonce-based, enforced in middleware.js)
// ---------------------------------------------------------------------------

describe('Content Security Policy directives', () => {
  // CSP moved from next.config.js to middleware.js for per-request nonce support.
  const middlewareSrc = readFile('middleware.js');

  const requiredDirectives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self' https://fonts.gstatic.com",
    "connect-src 'self'",
    "frame-ancestors 'none'",
  ];

  for (const directive of requiredDirectives) {
    it(`includes "${directive}"`, () => {
      expect(middlewareSrc).toContain(directive);
    });
  }

  it('allows Google Fonts in style-src', () => {
    expect(middlewareSrc).toContain('https://fonts.googleapis.com');
  });

  it('allows Google Fonts CDN in font-src', () => {
    expect(middlewareSrc).toContain('https://fonts.gstatic.com');
  });

  it('uses per-request nonce (no unsafe-inline in script-src)', () => {
    // Nonce is injected at request time — 'unsafe-inline' must not appear in script-src.
    // Use [^\n]* to avoid spanning to other directives on separate lines.
    expect(middlewareSrc).toContain("nonce-");
    expect(middlewareSrc).not.toMatch(/script-src[^\n]*'unsafe-inline'/);
  });
});

// ---------------------------------------------------------------------------
// 3. TRUST_TABLES completeness
// ---------------------------------------------------------------------------

describe('TRUST_TABLES list', () => {
  const writeGuardSrc = readFile('lib/write-guard.js');

  // Extract the TRUST_TABLES array from source
  const tableMatch = writeGuardSrc.match(/const TRUST_TABLES\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/);

  it('TRUST_TABLES array is defined and frozen', () => {
    expect(tableMatch).not.toBeNull();
  });

  it('contains the expected number of trust tables (20)', () => {
    const entries = tableMatch[1].match(/'[^']+'/g);
    expect(entries).not.toBeNull();
    expect(entries.length).toBe(20);
  });

  const expectedCoreTables = [
    'receipts',
    'commits',
    'disputes',
    'trust_reports',
    'protocol_events',
    'handshakes',
    'signoff_challenges',
    'signoff_attestations',
  ];

  for (const table of expectedCoreTables) {
    it(`includes core trust table "${table}"`, () => {
      expect(writeGuardSrc).toContain(`'${table}'`);
    });
  }
});

// ---------------------------------------------------------------------------
// 4. Write-guard blocks all trust tables
// ---------------------------------------------------------------------------

describe('Write-guard enforcement', () => {
  const writeGuardSrc = readFile('lib/write-guard.js');

  it('blocks insert operations on trust tables', () => {
    expect(writeGuardSrc).toContain("'insert'");
  });

  it('blocks update operations on trust tables', () => {
    expect(writeGuardSrc).toContain("'update'");
  });

  it('blocks upsert operations on trust tables', () => {
    expect(writeGuardSrc).toContain("'upsert'");
  });

  it('blocks delete operations on trust tables', () => {
    expect(writeGuardSrc).toContain("'delete'");
  });

  it('throws WRITE_DISCIPLINE_VIOLATION on blocked operations', () => {
    expect(writeGuardSrc).toContain('WRITE_DISCIPLINE_VIOLATION');
  });

  it('references protocolWrite() as the required write path', () => {
    expect(writeGuardSrc).toContain('protocolWrite()');
  });
});

// ---------------------------------------------------------------------------
// 5. Rate limit categories cover all route patterns
// ---------------------------------------------------------------------------

describe('Rate limit coverage', () => {
  const middlewareSrc = readFile('middleware.js');
  const rateLimitSrc = readFile('lib/rate-limit.js');

  // Extract all rateCategory values used in middleware
  function extractRateCategories(src) {
    const re = /rateCategory:\s*'([^']+)'/g;
    const categories = new Set();
    let m;
    while ((m = re.exec(src)) !== null) {
      categories.add(m[1]);
    }
    return categories;
  }

  // Extract all RATE_LIMITS keys defined in rate-limit.js
  function extractRateLimitKeys(src) {
    const re = /^\s+(\w+):\s*\{/gm;
    const keys = new Set();
    let m;
    while ((m = re.exec(src)) !== null) {
      keys.add(m[1]);
    }
    return keys;
  }

  const usedCategories = extractRateCategories(middlewareSrc);
  const definedLimits = extractRateLimitKeys(rateLimitSrc);

  it('every rateCategory in middleware has a matching RATE_LIMITS entry', () => {
    const missing = [];
    for (const cat of usedCategories) {
      if (!definedLimits.has(cat)) {
        missing.push(cat);
      }
    }
    expect(missing).toEqual([]);
  });

  it('RATE_LIMITS includes cloud_read category', () => {
    expect(definedLimits.has('cloud_read')).toBe(true);
  });

  it('RATE_LIMITS includes cloud_write category', () => {
    expect(definedLimits.has('cloud_write')).toBe(true);
  });

  it('RATE_LIMITS includes cloud_admin category', () => {
    expect(definedLimits.has('cloud_admin')).toBe(true);
  });

  // Verify cloud routes are classified in middleware
  const expectedCloudPatterns = [
    '/api/cloud/signoff/pending',
    '/api/cloud/signoff/queue',
    '/api/cloud/signoff/dashboard',
    '/api/cloud/signoff/analytics',
    '/api/cloud/signoff/notify',
    '/api/cloud/signoff/escalate',
    '/api/cloud/audit/export',
    '/api/cloud/audit/integrity',
    '/api/cloud/audit/report',
    '/api/cloud/events/search',
    '/api/cloud/events/timeline/',
    '/api/cloud/policies/',
  ];

  for (const pattern of expectedCloudPatterns) {
    it(`middleware covers cloud route pattern: ${pattern}`, () => {
      expect(middlewareSrc).toContain(pattern);
    });
  }

  // Verify cloud rate limit values are correct
  it('cloud_read allows 100 requests per minute', () => {
    expect(rateLimitSrc).toMatch(/cloud_read:\s*\{\s*window:\s*60,\s*max:\s*100\s*\}/);
  });

  it('cloud_write allows 30 requests per minute', () => {
    expect(rateLimitSrc).toMatch(/cloud_write:\s*\{\s*window:\s*60,\s*max:\s*30\s*\}/);
  });

  it('cloud_admin allows 10 requests per minute', () => {
    expect(rateLimitSrc).toMatch(/cloud_admin:\s*\{\s*window:\s*60,\s*max:\s*10\s*\}/);
  });
});
