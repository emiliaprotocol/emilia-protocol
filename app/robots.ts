import type { MetadataRoute } from 'next';

// Auto-generated /robots.txt via Next.js's app/robots.ts convention.
//
// One wildcard policy applies the same crawl boundary to search and AI user
// agents. Static assets stay crawlable so engines can render the pages. A
// robots rule is crawl control, not access control; private data remains behind
// authentication and route-level noindex headers.

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: '*',
      allow: '/',
      disallow: [
        '/api/',
        '/r/',          // per-receipt detail; not a search target
        '/entity/',     // per-entity detail; not a search target
        '/cloud/',      // authenticated control plane
        '/adopt/r/',    // capability-addressed public share pages
        '/agent-record/r/',
        '/arena/r/',
        '/trust-desk/c/',
      ],
    },
    sitemap: 'https://www.emiliaprotocol.ai/sitemap.xml',
    host: 'https://www.emiliaprotocol.ai',
  };
}
