/**
 * Embedding provider abstraction for the EMILIA Protocol.
 * @license Apache-2.0
 *
 * Embeddings are an OPTIONAL extension used for semantic search and matching.
 * The protocol works fully without them — routes fall back to text-based
 * matching when no embedding provider is configured.
 *
 * Currently supported providers:
 *   - OpenAI (text-embedding-3-small) when OPENAI_API_KEY is set
 *
 * To add a new provider, extend the logic in generateEmbedding() below.
 * The function must return a numeric array (vector) or null on failure.
 */

import { getOpenAIKey } from '@/lib/env';
import { logger } from '../logger.js';

/**
 * Generate an embedding vector for the given text.
 *
 * @param {string} text - The text to embed
 * @returns {Promise<number[] | null>} The embedding vector, or null if unavailable
 */
export async function generateEmbedding(text) {
  if (!text) return null;

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
