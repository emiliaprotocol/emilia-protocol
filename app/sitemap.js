// Auto-generated XML sitemap. Next.js's app/sitemap.js convention serves
// this file at /sitemap.xml automatically. Regenerated on each request
// (cheap — no I/O), so adding a new page only requires updating this list.
//
// Priority and changeFrequency are hints to crawlers; Google largely
// ignores them but other engines (Bing, Yandex, DuckDuckBot) still use them.

const BASE = 'https://www.emiliaprotocol.ai';

// Last-modified for the whole site set to the build time. For pages with
// content that changes more frequently (e.g. /explorer, dashboards),
// override per-route below.
const NOW = new Date();

export default function sitemap() {
  // Top-level marketing surfaces — highest crawl priority.
  const marketing = [
    { path: '/',                      priority: 1.0, changeFrequency: 'weekly' },
    { path: '/protocol',              priority: 0.95, changeFrequency: 'monthly' },
    { path: '/spec',                  priority: 0.9, changeFrequency: 'monthly' },
    { path: '/govguard',              priority: 0.95, changeFrequency: 'monthly' },
    { path: '/finguard',              priority: 0.95, changeFrequency: 'monthly' },
    { path: '/use-cases',             priority: 0.9, changeFrequency: 'monthly' },
    { path: '/use-cases/government',  priority: 0.85, changeFrequency: 'monthly' },
    { path: '/use-cases/financial',   priority: 0.85, changeFrequency: 'monthly' },
    { path: '/use-cases/enterprise',  priority: 0.85, changeFrequency: 'monthly' },
    { path: '/use-cases/ai-agent',    priority: 0.9,  changeFrequency: 'monthly' },
  ];

  // Product detail pages — packaged offerings.
  const product = [
    { path: '/product/government-pack',       priority: 0.8, changeFrequency: 'monthly' },
    { path: '/product/financial-pack',        priority: 0.8, changeFrequency: 'monthly' },
    { path: '/product/agent-governance-pack', priority: 0.8, changeFrequency: 'monthly' },
    { path: '/product/enterprise',            priority: 0.75, changeFrequency: 'monthly' },
    { path: '/product/cloud',                 priority: 0.75, changeFrequency: 'monthly' },
    { path: '/product/accountable-signoff',   priority: 0.75, changeFrequency: 'monthly' },
  ];

  // Functional / dynamic surfaces — present but lower SEO priority.
  const functional = [
    { path: '/playground',  priority: 0.6, changeFrequency: 'weekly' },
    { path: '/explorer',    priority: 0.6, changeFrequency: 'daily' },
    { path: '/score',       priority: 0.5, changeFrequency: 'weekly' },
    { path: '/eye',         priority: 0.7, changeFrequency: 'monthly' },
    { path: '/trust-desk',  priority: 0.6, changeFrequency: 'weekly' },
    { path: '/governance',  priority: 0.7, changeFrequency: 'monthly' },
    { path: '/adopt',       priority: 0.7, changeFrequency: 'monthly' },
  ];

  // Static legal / org pages.
  const corporate = [
    { path: '/contact',    priority: 0.4, changeFrequency: 'yearly' },
    { path: '/partners',   priority: 0.5, changeFrequency: 'monthly' },
    { path: '/investors',  priority: 0.4, changeFrequency: 'yearly' },
    { path: '/enterprise', priority: 0.7, changeFrequency: 'monthly' },
    { path: '/cloud',      priority: 0.6, changeFrequency: 'monthly' },
    { path: '/docs',       priority: 0.7, changeFrequency: 'weekly' },
    { path: '/appeal',     priority: 0.3, changeFrequency: 'yearly' },
  ];

  return [...marketing, ...product, ...functional, ...corporate].map((entry) => ({
    url: `${BASE}${entry.path}`,
    lastModified: NOW,
    changeFrequency: entry.changeFrequency,
    priority: entry.priority,
  }));
}
