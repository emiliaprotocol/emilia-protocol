import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/feed
 * 
 * Server-Sent Events stream of open needs.
 * Agents connect to this to discover work opportunities in real time.
 * 
 * Query params:
 *   capability     - filter by capability type
 *   category       - filter by context category (e.g. "electronics", "furniture")
 *   trust_policy   - only show needs requiring this policy (strict, standard, permissive, discovery)
 *   min_confidence - only show needs you could claim at this confidence level
 *   min_score      - legacy: only show needs requiring at most this score (default 0)
 *   limit          - max results per poll (default 20)
 * 
 * No auth required for reading the feed.
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const capability = searchParams.get('capability');
  const category = searchParams.get('category');
  const trustPolicy = searchParams.get('trust_policy');
  const minConfidence = searchParams.get('min_confidence');
  const minScore = parseFloat(searchParams.get('min_score')) || 0;
  const limit = Math.min(parseInt(searchParams.get('limit')) || 20, 50);

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const supabase = getServiceClient();

      const sendNeeds = async () => {
        try {
          let query = supabase
            .from('needs')
            .select(`
              need_id, capability_needed, context,
              budget_cents, deadline_ms, min_emilia_score,
              trust_policy, status, created_at, expires_at,
              from_entity:entities!needs_from_entity_id_fkey(entity_id, display_name, emilia_score)
            `)
            .eq('status', 'open')
            .gt('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(limit);

          if (capability) {
            query = query.ilike('capability_needed', `%${capability}%`);
          }

          // Context-aware filtering: filter by category in need context
          if (category) {
            query = query.contains('context', { category });
          }

          // Policy-aware filtering: show only needs with specific trust policy
          if (trustPolicy) {
            query = query.eq('trust_policy', JSON.stringify(trustPolicy));
          }

          // Legacy score filter
          if (minScore > 0) {
            query = query.lte('min_emilia_score', minScore);
          }

          const { data: needs, error } = await query;

          if (error) {
            controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: error.message })}\n\n`));
            return;
          }

          for (const need of (needs || [])) {
            controller.enqueue(
              encoder.encode(`event: need\ndata: ${JSON.stringify(need)}\n\n`)
            );
          }
        } catch (e) {
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: e.message })}\n\n`));
        }
      };

      await sendNeeds();

      const interval = setInterval(async () => {
        try {
          await sendNeeds();
          controller.enqueue(encoder.encode(`:heartbeat\n\n`));
        } catch {
          clearInterval(interval);
          controller.close();
        }
      }, 5000);

      request.signal.addEventListener('abort', () => {
        clearInterval(interval);
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
}
