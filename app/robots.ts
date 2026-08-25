import type { MetadataRoute } from 'next';

// Auto-generated /robots.txt via Next.js's app/robots.ts convention.
//
// Search and answer-engine crawlers share one crawl boundary. Static assets
// stay crawlable so engines can render public pages. A robots rule is crawl
// control, not access control; private data remains behind authentication and
// route-level noindex headers.

const PRIVATE_CRAWL_PATHS = [
  '/api/',
  '/r/',          // per-receipt detail; not a search target
  '/entity/',     // per-entity detail; not a search target
  '/cloud',       // authenticated control plane
  '/adopt/r/',    // capability-addressed public share pages
  '/agent-record/r/',
  '/arena/r/',
  '/trust-desk/c/',
  '/internal/',
  '/approvers/',
  '/mobile/',
  '/release-lock/',
  '/signoff/',
  '/evidence-readiness',
  '/trust-desk/upload',
];

const AI_ANSWER_CRAWLERS = [
  'OAI-SearchBot',
  'ChatGPT-User',
  'PerplexityBot',
  'Claude-SearchBot',
  'Claude-User',
  'Google-Extended',
];

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        disallow: PRIVATE_CRAWL_PATHS,
      },
      {
        userAgent: AI_ANSWER_CRAWLERS,
        allow: '/',
        disallow: PRIVATE_CRAWL_PATHS,
      },
    ],
    sitemap: 'https://www.emiliaprotocol.ai/sitemap.xml',
    host: 'https://www.emiliaprotocol.ai',
  };
}
