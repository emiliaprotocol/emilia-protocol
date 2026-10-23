/**
 * Embedding provider abstraction for the EMILIA Protocol.
 * @license Apache-2.0
 *
 * Embeddings are an OPTIONAL extension used for semantic search and matching.
 * The protocol works fully without them — routes fall back to text-based
 * matching when no embedding provider is configured.
 *
 * Supported providers, in order:
 *   - OrcaRouter Cyber Inference when a credential is configured
 *     (ORCAROUTER_API_KEY, the settings surface, or a PKCE approval);
 *   - OpenAI (text-embedding-3-small) when OPENAI_API_KEY is set.
 *
 * To add a new provider, extend the logic in generateEmbedding() below.
 * The function must return a numeric array (vector) or null on failure.
 */

import { getOpenAIKey } from '@/lib/env';
import { logger } from '../logger.js';
import { ORCAROUTER_DEFAULT_EMBEDDING_MODEL, resolveOrcaRouterOrigins } from './orcarouter.js';
import {
  getOrcaRouterModelFor,
  resolveOrcaRouterCredential,
} from './orcarouter-credentials.js';

/**
 * Generate an embedding vector for the given text.
 *
 * @param {string} text - The text to embed
 * @returns {Promise<number[] | null>} The embedding vector, or null if unavailable
 */
export async function generateEmbedding(text) {
  if (!text) return null;

  // OrcaRouter provider — one endpoint for every backend, OpenAI wire format.
  const orcarouter = await resolveOrcaRouterCredential();
  if (orcarouter.ok) {
    try {
      const origins = resolveOrcaRouterOrigins();
      // The embedding model comes from the embedding selection saved through
      // the settings surface (or the embedding-specific environment override /
      // default). A chat selection is never reused here.
      const model = (await getOrcaRouterModelFor('embedding')) || ORCAROUTER_DEFAULT_EMBEDDING_MODEL;
      const res = await fetch(`${origins.api}/embeddings`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${orcarouter.key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          input: text,
        }),
        redirect: 'error',
        signal: AbortSignal.timeout(20_000),
      });

      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data?.data?.[0]?.embedding)) return data.data[0].embedding;
        logger.warn('OrcaRouter embedding response had no vector');
        return null;
      }

      logger.warn('OrcaRouter embedding provider returned non-OK status:', res.status);
      return null;
    } catch (e) {
      logger.warn('OrcaRouter embedding generation failed:', e.message);
      return null;
    }
  }

  // OpenAI provider
  const openaiKey = getOpenAIKey();
  if (openaiKey) {
    try {
      const res = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${openaiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'text-embedding-3-small',
          input: text,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        return data.data[0].embedding;
      }

      logger.warn('Embedding provider returned non-OK status:', res.status);
      return null;
    } catch (e) {
      logger.warn('Embedding generation failed:', e.message);
      return null;
    }
  }

  // No provider configured — embeddings are optional
  return null;
}
