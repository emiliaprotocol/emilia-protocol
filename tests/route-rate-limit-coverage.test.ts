// SPDX-License-Identifier: Apache-2.0
//
// Continuous rate-limit classification sweep (regression guard).
//
// middleware.ts routes every request through ROUTE_POLICIES to pick a rate-limit
// tier. A mutating route missing from that table used to inherit the READ tier:
// 120/min on an IP-only key, failing OPEN when the limiter was unreachable. So
// forgetting to classify a route made it more permissive than classifying it,
// and the only signal was a console.warn nobody reads in production.
//
// The default is now `unclassified_write` (10/min, fail-closed). That is a
// backstop, not a tier anything should actually run on — this test is what
// keeps it that way: every POST/PUT/PATCH/DELETE handler under app/api must be
// named in ROUTE_POLICIES, or CI fails with the exact line to add.
//
// Two layers, deliberately: the coverage sweep reads ROUTE_POLICIES statically
// (so it can report the exact missing line), while the fallback cases drive the
// real middleware with only the limiter stubbed (so a tier assertion cannot
// pass against source text that no longer matches behaviour).

import { describe, it, expect, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Drive the real middleware and record which tier it picked. Only the limiter
// itself is stubbed, so classifyRoute's fallback and the ROUTE_POLICIES table
// are exercised as shipped rather than re-parsed.
const limiterCalls: Array<{ key: string; category: string }> = [];
vi.mock('../lib/rate-limit.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../lib/rate-limit.js')>();
  return {
    ...actual,
    getClientIP: () => '203.0.113.9',
    checkRateLimit: async (key: string, category: string) => {
      limiterCalls.push({ key, category });
      return { allowed: true, remaining: 5, reset: 60 };
    },
  };
});

async function tierFor(method: string, url: string): Promise<string | undefined> {
  limiterCalls.length = 0;
  const { middleware } = await import('../middleware.js');
  const { NextRequest } = await import('next/server');
  await middleware(new NextRequest(url, { method }) as never);
  return limiterCalls[0]?.category;
}

async function keyFor(method: string, url: string, authorization: string): Promise<string | undefined> {
  limiterCalls.length = 0;
  const { middleware } = await import('../middleware.js');
  const { NextRequest } = await import('next/server');
  await middleware(new NextRequest(url, {
    method,
    headers: { authorization },
  }) as never);
  return limiterCalls[0]?.key;
}

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_DIR = path.join(ROOT, 'app', 'api');
const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'] as const;

interface CompiledPolicy { method: string; regex: RegExp; raw: string }

function loadPolicies(): CompiledPolicy[] {
  const src = fs.readFileSync(path.join(ROOT, 'middleware.ts'), 'utf8');
  const start = src.indexOf('const ROUTE_POLICIES');
  const end = src.indexOf('// Route classifier');
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);

  const block = src.slice(start, end);
  return [...block.matchAll(/^\s*'([A-Z]+) ([^']+)':/gm)].map(([, method, pattern]) => ({
    method,
    // Same compilation middleware performs: '*' stands for one path segment.
    regex: new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]+')}$`),
    raw: `${method} ${pattern}`,
  }));
}

function routeFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) routeFiles(full, out);
    else if (/^route\.(ts|tsx|js)$/.test(entry.name)) out.push(full);
  }
  return out;
}

/** app/api/foo/[id]/route.ts -> /api/foo/* (the shape middleware sees). */
function urlPathFor(file: string): string {
  const rel = path.relative(API_DIR, path.dirname(file));
  const segments = rel.split(path.sep).filter(Boolean)
    .map((segment) => (segment.startsWith('[') ? '*' : segment));
  return `/api/${segments.join('/')}`.replace(/\/$/, '');
}

function exportsMethod(source: string, method: string): boolean {
  return new RegExp(
    `export\\s+(async\\s+)?function\\s+${method}\\b|export\\s+const\\s+${method}\\s*[:=]`,
  ).test(source);
}

describe('rate-limit classification coverage', () => {
  const policies = loadPolicies();

  it('parses the policy table', () => {
    expect(policies.length).toBeGreaterThan(100);
  });

  it('classifies every mutating route under app/api', () => {
    const missing: string[] = [];

    for (const file of routeFiles(API_DIR)) {
      const source = fs.readFileSync(file, 'utf8');
      const urlPath = urlPathFor(file);
      for (const method of MUTATING) {
        if (!exportsMethod(source, method)) continue;
        const matched = policies.some((p) => p.method === method && p.regex.test(urlPath));
        if (!matched) {
          missing.push(`  '${method} ${urlPath}':  ${path.relative(ROOT, file)}`);
        }
      }
    }

    expect(
      missing.sort(),
      `Unclassified mutating route(s). Each falls back to the 'unclassified_write' `
      + `tier (10/min, fail-closed) until it is named in ROUTE_POLICIES in `
      + `middleware.ts. Add an entry for each line below:\n${missing.sort().join('\n')}\n`,
    ).toEqual([]);
  });

  it('sends an unlisted mutating route to the restrictive tier, not the read tier', async () => {
    // The audit's scenario verbatim: someone ships POST /api/v2/trust-receipts/
    // bulk-create and never adds it to the table.
    for (const method of MUTATING) {
      // eslint-disable-next-line no-await-in-loop
      const tier = await tierFor(method, 'https://ep.test/api/v2/trust-receipts/bulk-create');
      expect(tier, `${method} fell through to the wrong tier`).toBe('unclassified_write');
    }
  });

  it('leaves unlisted READ routes on the read tier', async () => {
    // Fail-closed applies to mutation. A GET that nobody classified is not a
    // write amplifier, and demoting every unmatched page fetch would be an
    // availability change dressed up as a security one.
    expect(await tierFor('GET', 'https://ep.test/api/v2/trust-receipts/bulk-create')).toBe('read');
  });

  it('keeps the unclassified-write fallback tighter than read, and fail-closed', async () => {
    const { RATE_LIMITS } = await import('../lib/rate-limit.js');

    expect(RATE_LIMITS.unclassified_write).toBeDefined();
    // Strictly tighter than the read tier it replaced, or the change is cosmetic.
    expect(RATE_LIMITS.unclassified_write.max).toBeLessThan(RATE_LIMITS.read.max);

    const source = fs.readFileSync(path.join(ROOT, 'lib', 'rate-limit.ts'), 'utf8');
    const failClosed = source.slice(
      source.indexOf('FAIL_CLOSED_CATEGORIES'),
      source.indexOf('async function redisCommand'),
    );
    expect(failClosed).toContain("'unclassified_write'");
    expect(failClosed).toContain("'mcp_tool_call'");
  });

  it('does not let attacker-controlled bearer prefixes mint fresh pre-auth buckets', async () => {
    const url = 'https://ep.test/api/v1/trust-receipts';
    const first = await keyFor('POST', url, `Bearer ep_live_${'a'.repeat(48)}`);
    const second = await keyFor('POST', url, `Bearer ep_live_${'b'.repeat(48)}`);

    expect(first).toBe('203.0.113.9');
    expect(second).toBe(first);
  });

  it('gives the hosted MCP tool channel its own tier, not the shared read bucket', async () => {
    const { RATE_LIMITS } = await import('../lib/rate-limit.js');

    // POST is the JSON-RPC channel: every tool call runs Ed25519 / P-256
    // verification in-process on caller-supplied bytes, unauthenticated.
    expect(await tierFor('POST', 'https://ep.test/api/mcp/mcp')).toBe('mcp_tool_call');
    expect(RATE_LIMITS.mcp_tool_call.max).toBeLessThan(RATE_LIMITS.read.max);

    // The SSE stream and session teardown do no crypto; throttling a
    // reconnecting client would break legitimate MCP sessions for no gain.
    expect(await tierFor('GET', 'https://ep.test/api/mcp/mcp')).toBe('read');
    expect(await tierFor('DELETE', 'https://ep.test/api/mcp/mcp')).toBe('read');
  });
});

describe('public evidence surfaces have explicit rate policies', () => {
  // /api/verify/[receiptId] and /api/badge/[entity] take no auth and are the two
  // URLs a public launch points strangers at. Neither was named in
  // ROUTE_POLICIES, so both inherited the read tier by default. The coverage
  // sweep above only guards MUTATING routes (deliberately: demoting every
  // unmatched GET would be an availability change wearing a security label), so
  // nothing would have caught it.

  it('meters receipt verification separately from cheap reads', async () => {
    const { RATE_LIMITS } = await import('../lib/rate-limit.js');
    expect(await tierFor('GET', 'https://ep.test/api/verify/tr_abc123')).toBe('public_verify');
    // Verification re-derives a hash and checks a Merkle proof. It must not
    // share an allowance with a lookup.
    expect(RATE_LIMITS.public_verify.max).toBeLessThan(RATE_LIMITS.read.max);
  });

  it('keeps both public evidence surfaces fail-OPEN on a limiter outage', async () => {
    const source = fs.readFileSync(path.join(ROOT, 'lib', 'rate-limit.ts'), 'utf8');
    const failClosed = source.slice(
      source.indexOf('FAIL_CLOSED_CATEGORIES'),
      source.indexOf('async function redisCommand'),
    );
    // The opposite of the mcp_tool_call decision, and deliberate. mcp_tool_call
    // runs Ed25519 over a caller-supplied 256 KB document under a caller-supplied
    // key, so the attacker chooses the work. These take an id, read a row the
    // server already holds, and check a bounded proof over it.
    //
    // There is also no oracle to protect: the verifier is the published npm
    // package. Failing these closed buys nothing and takes every "verify this
    // yourself" link dark exactly when someone is checking a claim. An earlier
    // revision of this PR did fail public_verify closed and the explorer e2e
    // caught it, because the page renders the 503 body and a reader gets a
    // rate-limiter message instead of an answer about the receipt.
    expect(failClosed).not.toContain("'public_verify'");
    expect(failClosed).not.toContain("'public_badge'");
    // mcp_tool_call stays closed. This asserts the distinction is real and not
    // an accident of someone deleting the whole list.
    expect(failClosed).toContain("'mcp_tool_call'");
  });

  it('gives badges a generous bucket so image proxies do not throttle readers', async () => {
    const { RATE_LIMITS } = await import('../lib/rate-limit.js');
    expect(await tierFor('GET', 'https://ep.test/api/badge/acme-bot')).toBe('public_badge');
    expect(RATE_LIMITS.public_badge.max).toBeGreaterThan(RATE_LIMITS.read.max);
  });
});
