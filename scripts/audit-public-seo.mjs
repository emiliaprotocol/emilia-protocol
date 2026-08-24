#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

const CANONICAL_ORIGIN = new URL('https://www.emiliaprotocol.ai');
const BASE = new URL(process.argv[2] || process.env.SEO_BASE_URL || CANONICAL_ORIGIN);
const CONCURRENCY = Math.max(1, Math.min(24, Number(process.env.SEO_AUDIT_CONCURRENCY || 12)));
const errors = [];
const warnings = [];

function decodeHtml(value = '') {
  return value
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .trim();
}

function tags(html, name) {
  return [...html.matchAll(new RegExp(`<${name}\\b[^>]*>`, 'gi'))].map((match) => match[0]);
}

function attribute(tag, name) {
  const quoted = tag.match(new RegExp(`\\s${name}\\s*=\\s*(["'])([\\s\\S]*?)\\1`, 'i'));
  if (quoted) return decodeHtml(quoted[2]);
  const bare = tag.match(new RegExp(`\\s${name}\\s*=\\s*([^\\s>]+)`, 'i'));
  return decodeHtml(bare?.[1] || '');
}

function meta(html, key, selector = 'name') {
  const found = tags(html, 'meta').find((tag) => attribute(tag, selector).toLowerCase() === key.toLowerCase());
  return found ? attribute(found, 'content') : '';
}

function links(html, rel) {
  return tags(html, 'link').filter((tag) => attribute(tag, 'rel').toLowerCase().split(/\s+/).includes(rel));
}

function canonicalUrl(value) {
  const url = new URL(value, CANONICAL_ORIGIN);
  url.hash = '';
  url.search = '';
  if (url.pathname !== '/') url.pathname = url.pathname.replace(/\/$/, '');
  return url.toString();
}

function requestUrl(value) {
  const canonical = new URL(value, CANONICAL_ORIGIN);
  return new URL(`${canonical.pathname}${canonical.search}`, BASE).toString();
}

function titleText(html) {
  return decodeHtml(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '');
}

function jsonLd(html) {
  return [...html.matchAll(/<script\b[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]
    .map((match) => match[1].trim());
}

async function pool(items, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index], index);
    }
  }));
  return results;
}

async function fetchText(url) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'user-agent': 'EMILIA-SEO-Audit/1.0' },
  });
  return {
    response,
    text: await response.text(),
  };
}

function isCrawlableLink(url) {
  if (url.origin !== CANONICAL_ORIGIN.origin) return false;
  if (/\.(?:avif|css|csv|gif|ico|jpe?g|json|map|md|mjs|mp3|mp4|pdf|png|svg|txt|webm|webp|xml|zip)$/i.test(url.pathname)) return false;
  return ![
    '/_next/', '/api/', '/r/', '/entity/', '/cloud/', '/adopt/r/',
    '/agent-record/r/', '/arena/r/', '/trust-desk/c/',
  ].some((prefix) => url.pathname.startsWith(prefix));
}

const sitemapUrl = new URL('/sitemap.xml', BASE);
const { response: sitemapResponse, text: sitemapXml } = await fetchText(sitemapUrl);
if (!sitemapResponse.ok) errors.push(`/sitemap.xml returned ${sitemapResponse.status}`);
if (/<lastmod>/i.test(sitemapXml)) warnings.push('sitemap emits <lastmod>; verify every date comes from source data');

const sitemapUrls = [...sitemapXml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => decodeHtml(match[1]));
if (!sitemapUrls.length) errors.push('sitemap contains no URLs');
if (new Set(sitemapUrls).size !== sitemapUrls.length) errors.push('sitemap contains duplicate URLs');
for (const url of sitemapUrls) {
  if (new URL(url).origin !== CANONICAL_ORIGIN.origin) errors.push(`sitemap URL is on a different origin: ${url}`);
}

const pageRows = await pool(sitemapUrls, async (url) => {
  try {
    const { response, text: html } = await fetchText(requestUrl(url));
    return { url, response, html };
  } catch (error) {
    errors.push(`${new URL(url).pathname}: fetch failed (${error.message})`);
    return null;
  }
});

const internalTargets = new Map();
const imageTargets = new Set();
const titles = new Map();

for (const row of pageRows.filter(Boolean)) {
  const { url, response, html } = row;
  const path = new URL(url).pathname;
  if (!response.ok) {
    errors.push(`${path}: returned ${response.status}`);
    continue;
  }

  const title = titleText(html);
  const description = meta(html, 'description');
  const robots = `${meta(html, 'robots')} ${meta(html, 'googlebot')} ${response.headers.get('x-robots-tag') || ''}`;
  const canonicalTags = links(html, 'canonical');
  const canonical = canonicalTags.length === 1 ? attribute(canonicalTags[0], 'href') : '';

  if (!title) errors.push(`${path}: missing <title>`);
  if (!description) errors.push(`${path}: missing meta description`);
  if (!/<h1\b/i.test(html)) errors.push(`${path}: missing rendered <h1>`);
  if (!/<html\b[^>]*\blang=["']en["']/i.test(html)) errors.push(`${path}: missing html lang="en"`);
  if (/\bnoindex\b/i.test(robots)) errors.push(`${path}: sitemap page is noindex`);
  if (canonicalTags.length !== 1) errors.push(`${path}: expected one canonical, found ${canonicalTags.length}`);
  if (canonical && canonicalUrl(canonical) !== canonicalUrl(url)) {
    errors.push(`${path}: canonical ${canonical} does not match sitemap URL`);
  }

  const ogTitle = meta(html, 'og:title', 'property');
  const ogDescription = meta(html, 'og:description', 'property');
  const ogImage = meta(html, 'og:image', 'property');
  const twitterCard = meta(html, 'twitter:card');
  const twitterImage = meta(html, 'twitter:image');
  if (!ogTitle) errors.push(`${path}: missing og:title`);
  if (!ogDescription) errors.push(`${path}: missing og:description`);
  if (!ogImage) errors.push(`${path}: missing og:image`);
  if (!twitterCard) errors.push(`${path}: missing twitter:card`);
  if (!twitterImage) errors.push(`${path}: missing twitter:image`);
  for (const image of [ogImage, twitterImage].filter(Boolean)) {
    imageTargets.add(new URL(image, CANONICAL_ORIGIN).toString());
  }

  const llmAlternate = links(html, 'alternate').some((tag) => attribute(tag, 'href') === '/llms.txt');
  const machineAlternate = links(html, 'alternate').some((tag) => attribute(tag, 'href') === '/.well-known/emilia-context.json');
  if (!llmAlternate) errors.push(`${path}: missing llms.txt discovery link`);
  if (!machineAlternate) errors.push(`${path}: missing machine-context discovery link`);

  const schemas = jsonLd(html);
  if (!schemas.length) errors.push(`${path}: missing JSON-LD`);
  schemas.forEach((schema, index) => {
    try { JSON.parse(schema); } catch (error) {
      errors.push(`${path}: invalid JSON-LD block ${index + 1} (${error.message})`);
    }
  });

  const normalizedTitle = title.toLowerCase();
  if (titles.has(normalizedTitle)) {
    errors.push(`${path}: duplicate title with ${titles.get(normalizedTitle)} (${title})`);
  } else if (title) {
    titles.set(normalizedTitle, path);
  }

  for (const tag of tags(html, 'a')) {
    const href = attribute(tag, 'href');
    if (!href || /^(?:mailto:|tel:|javascript:|data:|blob:)/i.test(href)) continue;
    try {
      const target = new URL(href, url);
      target.hash = '';
      target.search = '';
      if (!isCrawlableLink(target)) continue;
      const key = canonicalUrl(target.toString());
      if (!internalTargets.has(key)) internalTargets.set(key, path);
    } catch {
      errors.push(`${path}: malformed internal link ${href}`);
    }
  }
}

await pool([...internalTargets], async ([url, source]) => {
  try {
    const response = await fetch(requestUrl(url), {
      redirect: 'follow',
      headers: { 'user-agent': 'EMILIA-SEO-Audit/1.0' },
    });
    await response.body?.cancel();
    if (!response.ok) errors.push(`${source}: internal link ${new URL(url).pathname} returned ${response.status}`);
  } catch (error) {
    errors.push(`${source}: internal link ${new URL(url).pathname} failed (${error.message})`);
  }
});

await pool([...imageTargets], async (url) => {
  try {
    const response = await fetch(requestUrl(url), {
      redirect: 'follow',
      headers: { 'user-agent': 'EMILIA-SEO-Audit/1.0' },
    });
    await response.body?.cancel();
    if (!response.ok) errors.push(`social image ${url} returned ${response.status}`);
    if (!/^image\//i.test(response.headers.get('content-type') || '')) {
      errors.push(`social image ${url} has non-image content type ${response.headers.get('content-type') || '(missing)'}`);
    }
  } catch (error) {
    errors.push(`social image ${url} failed (${error.message})`);
  }
});

const requiredMachineSurfaces = ['/robots.txt', '/llms.txt', '/llms-full.txt', '/.well-known/emilia-context.json'];
for (const path of requiredMachineSurfaces) {
  try {
    const { response, text } = await fetchText(new URL(path, BASE));
    if (!response.ok) errors.push(`${path}: returned ${response.status}`);
    if (!text.trim()) errors.push(`${path}: empty response`);
    if (path.endsWith('.json')) {
      try { JSON.parse(text); } catch (error) { errors.push(`${path}: invalid JSON (${error.message})`); }
    }
    if (path === '/robots.txt') {
      if (/Disallow:\s*\/(?:_next|static)\//i.test(text)) errors.push('/robots.txt blocks render-critical static assets');
      if (!/Sitemap:\s*https:\/\/www\.emiliaprotocol\.ai\/sitemap\.xml/i.test(text)) errors.push('/robots.txt is missing the canonical sitemap URL');
    }
  } catch (error) {
    errors.push(`${path}: fetch failed (${error.message})`);
  }
}

if (warnings.length) {
  console.log(`Warnings (${warnings.length})`);
  warnings.forEach((warning) => console.log(`- ${warning}`));
}

if (errors.length) {
  console.error(`SEO audit failed with ${errors.length} error(s):`);
  errors.forEach((error) => console.error(`- ${error}`));
  process.exitCode = 1;
} else {
  console.log(`SEO audit passed: ${sitemapUrls.length} sitemap pages, ${internalTargets.size} internal targets, ${imageTargets.size} social images.`);
}
