import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { GET as healthGET } from '../app/api/health/route.js';
import { GET as policiesGET } from '../app/api/policies/route.js';
import { GET as entitySearchGET } from '../app/api/entities/search/route.js';
import { GET as trustProfileGET } from '../app/api/trust/profile/[entityId]/route.js';
import { POST as trustEvaluatePOST } from '../app/api/trust/evaluate/route.js';
import { POST as installPreflightPOST } from '../app/api/trust/install-preflight/route.js';
import { GET as trustCompatGET } from '../app/api/trust/route.js';
import { GET as statsGET } from '../app/api/stats/route.js';
import { GET as leaderboardGET } from '../app/api/leaderboard/route.js';
import { GET as feedGET } from '../app/api/feed/route.js';
import { GET as domainScoreGET } from '../app/api/trust/domain-score/[entityId]/route.js';

const ROOT = resolve(__dirname, '..');

function source(path) {
  return readFileSync(resolve(ROOT, path), 'utf8');
}

function nextRequest(url, init) {
  const req = new Request(url, init);
  Object.defineProperty(req, 'nextUrl', { value: new URL(url) });
  return req;
}

describe('anonymous recon hardening', () => {
  it('/api/health exposes only boring liveness', async () => {
    const res = await healthGET();
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ status: 'ok' });
    expect(JSON.stringify(body)).not.toMatch(/surfaces|checks|database|schema|queue|upstash|base_l2|protocol_version/i);
  });

  it('rich trust and entity catalog routes reject anonymous callers before DB-backed lookup', async () => {
    const profile = await trustProfileGET(
      nextRequest('https://example.test/api/trust/profile/ep_entity_target'),
      { params: Promise.resolve({ entityId: 'ep_entity_target' }) },
    );
    expect(profile.status).toBe(401);

    const evaluate = await trustEvaluatePOST(new Request('https://example.test/api/trust/evaluate', {
      method: 'POST',
      body: JSON.stringify({ entity_id: 'ep_entity_target', policy: 'strict' }),
    }));
    expect(evaluate.status).toBe(401);

    const preflight = await installPreflightPOST(new Request('https://example.test/api/trust/install-preflight', {
      method: 'POST',
      body: JSON.stringify({ entity_id: 'ep_entity_target', policy: 'mcp_server_safe_v1' }),
    }));
    expect(preflight.status).toBe(401);

    const search = await entitySearchGET(new Request('https://example.test/api/entities/search?q=redflag'));
    expect(search.status).toBe(401);

    const compat = await trustCompatGET(new Request('https://example.test/api/trust?entity_id=ep_entity_target'));
    expect(compat.status).toBe(401);

    const stats = await statsGET(new Request('https://example.test/api/stats'));
    expect(stats.status).toBe(401);

    const leaderboard = await leaderboardGET(new Request('https://example.test/api/leaderboard'));
    expect(leaderboard.status).toBe(401);

    const feed = await feedGET(new Request('https://example.test/api/feed'));
    expect(feed.status).toBe(401);

    const domainScore = await domainScoreGET(
      new Request('https://example.test/api/trust/domain-score/ep_entity_target'),
      { params: Promise.resolve({ entityId: 'ep_entity_target' }) },
    );
    expect(domainScore.status).toBe(401);
  });

  it('/api/policies anonymous view omits exact decision thresholds', async () => {
    const res = await policiesGET(new Request('https://example.test/api/policies'));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.policies.length).toBeGreaterThan(0);
    for (const policy of body.policies) {
      expect(policy).not.toHaveProperty('min_score');
      expect(policy).not.toHaveProperty('min_confidence');
      expect(policy).not.toHaveProperty('min_receipts');
      expect(policy).not.toHaveProperty('max_dispute_rate');
      expect(policy).not.toHaveProperty('software_requirements');
    }
  });

  it('source guardrail: public key discovery does not publish registration timelines', () => {
    const src = source('app/api/discovery/keys/route.js');
    expect(src).not.toMatch(/select\(['"][^'"]*created_at/i);
    expect(src).not.toMatch(/select\(['"][^'"]*retired_at/i);
    expect(src).not.toMatch(/\bcreated_at:\s*e\.created_at\b/);
    expect(src).not.toMatch(/\bretired_at:\s*r\.retired_at\b/);
  });

  it('source guardrail: trust evaluate does not return full profile internals', () => {
    const src = source('app/api/trust/evaluate/route.js');
    expect(src).not.toContain('profile: result.profile');
    expect(src).not.toContain('score: result.score');
    expect(src).not.toContain('effective_evidence: result.effectiveEvidence');
    expect(src).not.toContain('failures: pr?.failures');
    expect(src).not.toContain('anomaly: result.anomaly');
  });

  it('source guardrail: public UX surfaces do not fetch full trust profiles', () => {
    const publicSources = [
      source('public/embed.js'),
      source('app/explorer/page.js'),
      source('app/appeal/page.js'),
      source('public/demo.html'),
    ].join('\n');

    expect(publicSources).not.toMatch(/fetch\([^)]*\/api\/trust\/profile\/(?![^)]*\?view=capability)/);
    expect(publicSources).not.toMatch(/EP Trust Score|receipt_count\s*\|\|\s*0|unique_submitters|current_confidence|effective_evidence_current/i);
    expect(publicSources).toContain('/api/badge/');
  });

  it('source guardrail: badge/docs do not claim full profiles are public', () => {
    const docs = [
      source('app/api/badge/[entity]/route.js'),
      source('docs/TRUST-BADGE.md'),
      source('docs/api/ROUTES.md'),
      source('openapi.yaml'),
    ].join('\n');

    expect(docs).not.toMatch(/full\s+`?GET \/api\/trust\/profile[^`]*`?\s+(surface\s+)?is\s+public/i);
    expect(docs).not.toMatch(/Auth\*\*:\s*None\s*\(public\)[\s\S]{0,180}\/api\/trust\/profile/i);
    expect(docs).toMatch(/\?view=capability/);
  });

  it('source guardrail: middleware does not mark rich recon surfaces anonymous', () => {
    const src = source('middleware.js');
    const richSurfaces = [
      'GET /api/trust/profile/*',
      'POST /api/trust/evaluate',
      'POST /api/trust/install-preflight',
      'GET /api/entities/search',
      'GET /api/trust',
      'GET /api/trust/domain-score/*',
      'GET /api/stats',
      'GET /api/leaderboard',
      'GET /api/feed',
    ];

    for (const route of richSurfaces) {
      const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      expect(src).toMatch(new RegExp(`['"]${escaped}['"]\\s*:\\s*\\{[^}]*useAuth:\\s*true`));
    }
  });
});
