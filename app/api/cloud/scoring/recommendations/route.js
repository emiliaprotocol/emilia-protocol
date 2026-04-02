import { NextResponse } from 'next/server';
import { authenticateCloudRequest } from '@/lib/cloud/auth';
import { collectCalibrationData, computeWeightRecommendation, VERTICAL_PACKS } from '@/lib/cloud/calibration';
import { epProblem } from '@/lib/errors';
import { logger } from '../../../../../lib/logger.js';

/**
 * GET /api/cloud/scoring/recommendations
 *
 * Returns weight calibration recommendations based on dispute outcomes.
 * Requires Cloud API authentication (tenant-scoped).
 *
 * Query parameters:
 *   ?window=90    — Rolling window in days (default: 90, max: 365)
 *   ?vertical=    — Include vertical pack comparison (government|financial|agent_governance|ecommerce)
 *
 * Response includes:
 *   - recommendation: proposed weights with confidence + sample size (or null if insufficient data)
 *   - analysis: per-dimension overweight/underweight ratios
 *   - vertical_pack: the named vertical's preset weights (if requested)
 *   - current_weights: the protocol defaults for comparison
 *
 * The recommendation does NOT auto-apply. Feed it into:
 *   POST /api/cloud/policies/{policyId}/simulate (backtest)
 *   POST /api/cloud/policies/{policyId}/rollout  (deploy with signoff)
 */
export async function GET(request) {
  try {
    // Authenticate
    const auth = await authenticateCloudRequest(request);
    if (!auth) {
      return epProblem(401, 'unauthorized', 'Valid Cloud API key required');
    }

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams;
    const windowDays = Math.min(365, Math.max(7, parseInt(searchParams.get('window') || '90', 10)));
    const verticalName = searchParams.get('vertical');

    // Validate vertical if provided
    let verticalPack = null;
    if (verticalName) {
      verticalPack = VERTICAL_PACKS[verticalName];
      if (!verticalPack) {
        return epProblem(400, 'invalid_vertical', `Unknown vertical: ${verticalName}. Available: ${Object.keys(VERTICAL_PACKS).join(', ')}`);
      }
    }

    // Collect calibration data
    const { data, stats } = await collectCalibrationData(auth.tenantId, windowDays);

    // Compute recommendation
    const result = computeWeightRecommendation(data, stats);

    return NextResponse.json({
      recommendation: result.recommendation,
      sufficient_data: result.sufficient_data,
      reason: result.reason,
      analysis: result.analysis,

      // Include vertical pack for comparison if requested
      vertical_pack: verticalPack ? {
        name: verticalPack.name,
        description: verticalPack.description,
        weights: verticalPack.weights,
      } : null,

      // Always include current defaults for comparison
      current_weights: {
        version: 'ep-v2-default',
        weights: {
          behavioral: 0.40,
          consistency: 0.25,
          delivery: 0.12,
          product: 0.10,
          price: 0.08,
          returns: 0.05,
        },
      },

      _protocol_version: 'EP/1.1-v2',
    });
  } catch (err) {
    logger.error('Scoring recommendations error:', err);
    return epProblem(500, 'calibration_failed', 'Weight calibration computation failed');
  }
}
