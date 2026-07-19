import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const read = (relative) => readFileSync(resolve(ROOT, relative), 'utf8');
const json = (relative) => JSON.parse(read(relative));
const exists = (relative) => existsSync(resolve(ROOT, relative));
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

const catalog = json('standards/observatory/catalog.source.v1.json');
const sourceLock = json('standards/observatory/source-lock.v1.json');
const recon = json('standards/observatory/recon-summary.v1.json');
const snapshot = json('lib/standards-observatory.snapshot.json');
const publicSnapshot = json('public/.well-known/standards-observatory.json');

describe('standards observatory evidence contract', () => {
  it('publishes one deterministic snapshot from the source-locked catalog', () => {
    expect(snapshot).toEqual(publicSnapshot);
    const { snapshot_sha256: expected, ...core } = snapshot;
    expect(digest(JSON.stringify(core))).toBe(expected);
    expect(snapshot.metrics.primary_sources_verified).toBe(catalog.sources.length);
    expect(snapshot.dimensions).toHaveLength(7);
  });

  it('requires every matrix cell to carry an allowed value and a rationale', () => {
    const dimensionIds = catalog.dimensions.map((item) => item.id);
    const allowed = new Set(['yes', 'partial', 'no', 'unknown']);
    for (const source of catalog.sources) {
      expect(Object.keys(source.guarantees).sort()).toEqual([...dimensionIds].sort());
      for (const dimensionId of dimensionIds) {
        expect(allowed.has(source.guarantees[dimensionId].value)).toBe(true);
        expect(source.guarantees[dimensionId].rationale.length).toBeGreaterThan(11);
      }
    }
  });

  it('pins every publication-grade quote to the exact source bytes', () => {
    expect(sourceLock.source_count).toBe(catalog.sources.length);
    expect(digest(JSON.stringify(sourceLock.sources))).toBe(sourceLock.lock_sha256);
    const locks = new Map(sourceLock.sources.map((item) => [item.id, item]));
    for (const source of catalog.sources) {
      const lock = locks.get(source.id);
      expect(lock).toBeDefined();
      expect(lock.revision).toBe(source.revision);
      expect(lock.source_url).toBe(source.source_url);
      expect(lock.quote).toEqual(source.quote);
      expect(lock.quote_verified).toBe(true);
      expect(lock.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('distinguishes the operative agentproto charter from historical precedent', () => {
    const operative = catalog.sources.find((item) => item.id === 'agentproto-charter-merge');
    const historical = catalog.sources.find((item) => item.id === 'agentproto-charter-original');
    expect(operative.operative_status).toBe('operative');
    expect(historical.operative_status).toBe('historical_nonoperative');
    expect(catalog.operative_conflicts[0].source_ids).toEqual(expect.arrayContaining([operative.id, historical.id]));
  });

  it('records FIDO as a live neighbor and WIMSE as an explicit composition socket', () => {
    const fido = catalog.sources.find((item) => item.id === 'fido-verifiable-intent');
    const wimse = catalog.sources.find((item) => item.id === 'wimse-condition-bounded');
    expect(fido.quote.text).toContain('portable, verifiable evidence');
    expect(wimse.quote.text).toBe('This profile is an authentication input, not an authorization one');
    expect(wimse.relation).toContain('socket');
  });

  it('keeps the WIMSE agenda request below the acceptance threshold', () => {
    const request = catalog.events.find((item) => item.id === 'wimse-agenda-request-emilia-composition');
    expect(request.status).toBe('pending_public_archive');
    expect(request.title).toMatch(/request submitted/i);
    expect(request.truth_boundary).toMatch(/not agenda acceptance/i);
    expect(request.truth_boundary).toMatch(/not .*working-group adoption/i);
  });

  it('tracks the current SCRAPI state without calling it an RFC', () => {
    const scrapi = catalog.events.find((item) => item.id === 'scitt-scrapi-rfc-editor-queue');
    expect(scrapi.status).toBe('public_verified');
    expect(scrapi.title).toContain('RFC Editor queue');
    expect(scrapi.truth_boundary).toMatch(/not an RFC until publication/i);
  });

  it('keeps broad recon correlated and non-authoritative, as aggregate counts only', () => {
    expect(recon['@version']).toBe('EMILIA-STANDARDS-RECON-SUMMARY-v1');
    expect(recon.metrics.declared_agent_reads).toBe(294);
    expect(recon.metrics.recovered_structured_reports).toBe(291);
    expect(recon.metrics.unrecovered_reports).toBe(3);
    expect(recon.metrics.fetch_failures_in_recovered_reports).toBe(0);
    expect(recon.corpus_sha256).toMatch(/^[0-9a-f]{64}$/);
    // The committed summary must never embed the per-artifact index.
    expect('reports' in recon).toBe(false);
  });

  it('PUBLICATION BOUNDARY: public artifacts expose only the curated matrix, never raw recon', () => {
    // The served JSON and the snapshot carry exactly the curated sources and aggregate recon.
    for (const artifact of [snapshot, publicSnapshot]) {
      expect(artifact.sources).toHaveLength(catalog.sources.length);
      expect('reports' in artifact.recon).toBe(false);
      expect(Object.keys(artifact.recon).sort()).toEqual(
        ['claim_boundary', 'corpus_sha256', 'metrics', 'review_model'],
      );
    }
    // No per-artifact recon record may leak into any served text surface.
    const servedSurfaces = [
      JSON.stringify(publicSnapshot),
      read('public/standards-observatory.llms.txt'),
    ].join('\n');
    expect(servedSurfaces).not.toContain('agent_analyzed_unverified');
    // The raw index must not be tracked under any public path; it is private/local only.
    expect(exists('standards/observatory/recon-index.v1.json')).toBe(false);
  });

  it('defines the CAID mapping frontier as a closed, abstaining decision', () => {
    const caid = catalog.frontiers.find((item) => item.id === 'caid-action-mapping-profile');
    expect(caid.priority).toBe(1);
    expect(caid.verdicts).toEqual([
      'EQUIVALENT_UNDER_PROFILE',
      'NOT_EQUIVALENT',
      'INDETERMINATE',
    ]);
    expect(caid.acceptance_tests.join(' ')).toMatch(/missing required field yields INDETERMINATE/i);
    expect(caid.acceptance_tests.join(' ')).toMatch(/AP2 checkout_hash is recomputed/i);
  });

  it('gives both humans and language models the same discovery surfaces', () => {
    const llms = read('public/standards-observatory.llms.txt');
    const context = json('public/.well-known/emilia-context.json');
    const page = read('app/observatory/ObservatoryClient.js');
    expect(llms).toContain('/.well-known/standards-observatory.json');
    expect(llms).toContain('correlated discovery');
    expect(context.standards_observatory.snapshot_sha256).toBe(snapshot.snapshot_sha256);
    expect(context.standards_observatory.review_model).toBe('correlated_agent_assisted_discovery');
    expect(page).toContain('Know what the standards actually say.');
    expect(page).toContain('Request, not acceptance');
  });

  it('contains none of the superseded blanket claims', () => {
    const publicText = `${JSON.stringify(snapshot)}\n${read('public/standards-observatory.llms.txt')}`.toLowerCase();
    expect(publicText).not.toContain('zero rivals');
    expect(publicText).not.toContain('300 independent');
    expect(publicText).not.toContain('agenda accepted');
  });
});
