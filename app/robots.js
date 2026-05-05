// Auto-generated /robots.txt via Next.js's app/robots.js convention.
//
// Strategy:
//   • Allow everything by default — EP is open-source and the marketing
//     surface is intentionally indexable.
//   • Block dynamic per-receipt and per-entity URLs (/r/* and /entity/*)
//     from search indexes — they are not search-targets and exist in the
//     thousands; indexing them would dilute crawl budget away from the
//     canonical marketing pages.
//   • Block authenticated cloud control-plane routes (/cloud/*) since
//     those require auth and produce noisy redirects to /login for crawlers.
//   • Sitemap pointer for engine discovery.

export default function robots() {
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        disallow: [
          '/api/',
          '/r/',          // /r/[receiptId] — public receipt detail; not a search target
          '/entity/',     // /entity/[entityId] — public entity detail; not a search target
          '/cloud/',      // authenticated control-plane
          '/_next/',
          '/static/',
        ],
      },
      // Allow specific search engine bots full access (they read this above
      // already; explicit rules can prioritize crawl behavior on some engines).
      { userAgent: 'Googlebot',          allow: '/' },
      { userAgent: 'Bingbot',            allow: '/' },
      { userAgent: 'DuckDuckBot',        allow: '/' },
      // AI search crawlers — Google AI Overviews, ChatGPT browsing, Claude,
      // Perplexity. Allow them; EP wants citation surface in AI search.
      { userAgent: 'Google-Extended',    allow: '/' },
      { userAgent: 'GPTBot',             allow: '/' },
      { userAgent: 'ChatGPT-User',       allow: '/' },
      { userAgent: 'OAI-SearchBot',      allow: '/' },
      { userAgent: 'ClaudeBot',          allow: '/' },
      { userAgent: 'anthropic-ai',       allow: '/' },
      { userAgent: 'PerplexityBot',      allow: '/' },
    ],
    sitemap: 'https://www.emiliaprotocol.ai/sitemap.xml',
    host: 'https://www.emiliaprotocol.ai',
  };
}
