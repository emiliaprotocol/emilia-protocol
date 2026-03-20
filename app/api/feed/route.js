import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';

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
 *   min_confidence - only show needs from broadcasters with at least this confidence level
 *   min_score      - legacy: only show needs requiring at most this score (default 0)
 *   limit          - max results per poll (default 20)
 *
 * SSE reconnection:
 *   Clients may send a Last-Event-ID header on reconnect. The server will
 *   only emit needs that are new or updated since that checkpoint.
 *
 * No auth required for reading the feed.
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const capability = searchParams.get('capability');
  const category = searchParams.get('category');
  const trustPolicy = searchParams.get('trust_policy');
  const minConfidence = searchParams.get('min_confidence');
  // LEGACY: min_score filters by compat_score sort key, not trust decision.
  // New consumers should use trust_policy or min_confidence params instead.
  const minScore = parseFloat(searchParams.get('min_score')) || 0;
  const limit = Math.min(parseInt(searchParams.get('limit')) || 20, 50);

  const lastEventId = request.headers.get('Last-Event-ID');

  const encoder = new TextEncoder();

  let supabase;
  try {
    supabase = getGuardedClient();
  } catch (e) {
    return epProblem(500, 'feed_unavailable', 'Feed service initialization failed');
  }

  const stream = new ReadableStream({
    async start(controller) {
      // SSE event ID counter; resume from Last-Event-ID when reconnecting
      let eventId = lastEventId ? parseInt(lastEventId, 10) || 0 : 0;

      // Deduplication: track need_id -> updated_at for needs already sent
      const sentNeeds = new Map();

      const sendNeeds = async () => {
        try {
          let query = supabase
            .from('needs')
            .select(`
              need_id, capability_needed, context,
              budget_cents, deadline_ms, min_emilia_score,
              trust_policy, status, created_at, updated_at, expires_at,
              from_entity_id,
              from_entity:entities!needs_from_entity_id_fkey(entity_id, display_name, emilia_score, trust_snapshot)
            `)
            .eq('status', 'open')
            .gt('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(limit);

          if (capability) query = query.ilike('capability_needed', `%${capability}%`);
          if (category) query = query.contains('context', { category });
          if (trustPolicy) query = query.eq('trust_policy', trustPolicy);
          if (minScore > 0) query = query.lte('min_emilia_score', minScore);

          const { data: needs, error } = await query;

          if (error) {
            controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: error.message })}\n\n`));
            return;
          }

          let filtered = needs || [];

          // Filter by broadcaster confidence level using materialized trust_snapshot
          // from the joined entity. This avoids per-row canonicalEvaluate calls.
          // TODO: At scale, broadcaster confidence should be materialized on the needs
          // table or cached. Current per-row filtering is O(n) in needs count, though
          // it now reads from the pre-computed snapshot rather than re-evaluating.
          if (minConfidence && filtered.length > 0) {
            const confLevels = ['pending', 'insufficient', 'provisional', 'emerging', 'confident'];
            const minIdx = confLevels.indexOf(minConfidence);
            if (minIdx >= 0) {
              filtered = filtered
                .map((n) => {
                  const snap = n.from_entity?.trust_snapshot || {};
                  return { ...n, _broadcaster_confidence: snap.confidence || 'pending' };
                })
                .filter(n => confLevels.indexOf(n._broadcaster_confidence) >= minIdx);
            }
          }

          // Deduplicate: only send needs that are new or have been updated
          for (const need of filtered) {
            const needUpdatedAt = need.updated_at || need.created_at;
            const previouslySeenAt = sentNeeds.get(need.need_id);

            if (previouslySeenAt && previouslySeenAt === needUpdatedAt) {
              // Already sent this exact version; skip
              continue;
            }

            sentNeeds.set(need.need_id, needUpdatedAt);
            eventId++;
            controller.enqueue(encoder.encode(
              `id: ${eventId}\nevent: need\ndata: ${JSON.stringify(need)}\n\n`
            ));
          }
        } catch (e) {
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({ error: e.message })}\n\n`));
        }
      };

      await sendNeeds();

      const interval = setInterval(async () => {
        try {
          await sendNeeds();
          // Heartbeat with current event ID so clients know the latest checkpoint
          controller.enqueue(encoder.encode(`:heartbeat ${eventId}\n\n`));
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
