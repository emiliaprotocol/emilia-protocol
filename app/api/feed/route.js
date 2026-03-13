import { getServiceClient } from '@/lib/supabase';

/**
 * GET /api/feed
 * 
 * Server-Sent Events stream of open needs.
 * Agents connect to this to discover work opportunities in real time.
 * 
 * Query params:
 *   capability - filter by capability type
 *   min_score  - only show needs requiring at least this score
 *   limit      - max results per poll (default 20)
 * 
 * No auth required for reading the feed. Anyone can see open needs.
 */
export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const capability = searchParams.get('capability');
  const minScore = parseFloat(searchParams.get('min_score')) || 0;
  const limit = Math.min(parseInt(searchParams.get('limit')) || 20, 50);

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const supabase = getServiceClient();

      // Send initial batch
      const sendNeeds = async () => {
        try {
          let query = supabase
            .from('needs')
            .select(`
              need_id, capability_needed, context,
              budget_cents, deadline_ms, min_emilia_score,
              status, created_at, expires_at,
              from_entity:entities!needs_from_entity_id_fkey(entity_id, display_name, emilia_score)
            `)
            .eq('status', 'open')
            .gt('expires_at', new Date().toISOString())
            .order('created_at', { ascending: false })
            .limit(limit);

          if (capability) {
            query = query.ilike('capability_needed', `%${capability}%`);
          }

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

      // Send initial batch immediately
      await sendNeeds();

      // Poll every 5 seconds for new needs
      const interval = setInterval(async () => {
        try {
          await sendNeeds();
          controller.enqueue(encoder.encode(`:heartbeat\n\n`));
        } catch {
          clearInterval(interval);
          controller.close();
        }
      }, 5000);

      // Clean up on disconnect
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
