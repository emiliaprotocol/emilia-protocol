import { epProblem } from '@/lib/errors';

/**
 * GET /api/score/[entityId] — RETIRED (HTTP 410 Gone).
 *
 * The 0-100 compatibility score endpoint has been retired. EMILIA publishes
 * portable, verifiable authorization EVIDENCE — not a reputation score or
 * ranking. Use the trust profile instead:
 *   - GET  /api/trust/profile/:entityId          (confidence tier + evidence)
 *   - GET  /api/trust/profile/:entityId?view=capability  (leak-free boolean)
 *   - POST /api/trust/evaluate                    (per-action trust decision)
 *
 * Returns 410 (not 404) so callers can distinguish "intentionally removed"
 * from "not found" and migrate.
 */
export async function GET() {
  return epProblem(
    410,
    'endpoint_retired',
    'The compatibility-score endpoint has been retired. EMILIA publishes verifiable evidence, not a score. Use GET /api/trust/profile/:entityId (or ?view=capability) or POST /api/trust/evaluate.',
  );
}
