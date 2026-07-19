// SPDX-License-Identifier: Apache-2.0
// EP EssayArticle — renders a docs/essays markdown essay in the site's
// long-form typography. Server component: the markdown is read and converted
// at build time, so the adversarially-reviewed prose renders verbatim.
// @license Apache-2.0

import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { color } from '@/lib/tokens';
import { getEssay, loadEssayBody, essayMdToHtml } from '@/lib/essays';

/** @type {Intl.DateTimeFormatOptions} */
const DATE_FMT = { year: 'numeric', month: 'long', day: 'numeric' };

function formatDate(iso) {
  // iso is a YYYY-MM-DD literal from the registry; parse as UTC so the
  // displayed day does not shift under the server's local timezone.
  const d = new Date(`${iso}T00:00:00Z`);
  return d.toLocaleDateString('en-US', { ...DATE_FMT, timeZone: 'UTC' });
}

export default function EssayArticle({ slug }) {
  const essay = getEssay(slug);
  if (!essay) {
    throw new Error(`EssayArticle: unknown essay slug "${slug}"`);
  }
  const { body } = loadEssayBody(slug);
  const html = essayMdToHtml(body);

  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1 }}>
      <style>{`
        .essay-shell { max-width: 720px; margin: 0 auto; padding: 88px 24px 112px; font-family: 'IBM Plex Sans', -apple-system, sans-serif; }
        .essay-eyebrow { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: ${color.t3}; margin-bottom: 16px; }
        .essay-title { font-family: 'IBM Plex Sans', sans-serif; font-size: clamp(30px, 5vw, 44px); font-weight: 700; letter-spacing: -1px; line-height: 1.1; color: ${color.t1}; margin: 0 0 20px; }
        .essay-byline { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: ${color.t3}; letter-spacing: 0.3px; margin-bottom: 40px; padding-bottom: 28px; border-bottom: 1px solid ${color.border}; }
        .essay-byline strong { color: ${color.t1}; font-weight: 600; }
        .essay-body { font-size: 17px; line-height: 1.78; color: ${color.t2}; }
        .essay-body p { margin: 0 0 22px; }
        .essay-body h2 { font-family: 'IBM Plex Sans', sans-serif; font-size: 24px; font-weight: 700; letter-spacing: -0.5px; color: ${color.t1}; margin: 44px 0 16px; }
        .essay-body h3 { font-family: 'IBM Plex Sans', sans-serif; font-size: 19px; font-weight: 700; letter-spacing: -0.3px; color: ${color.t1}; margin: 32px 0 12px; }
        .essay-body strong { color: ${color.t1}; font-weight: 600; }
        .essay-body em { font-style: italic; }
        .essay-body a { color: ${color.blue}; text-decoration: none; }
        .essay-body a:hover { text-decoration: underline; }
        .essay-body code { font-family: 'IBM Plex Mono', monospace; font-size: 14px; background: #F5F5F4; color: ${color.t1}; padding: 2px 6px; border-radius: 4px; }
        .essay-body .essay-code { background: #0C0A09; border: 1px solid ${color.border}; border-radius: 8px; padding: 16px 20px; overflow-x: auto; margin: 22px 0; }
        .essay-body .essay-code code { background: none; color: #E7E5E4; padding: 0; font-size: 13.5px; line-height: 1.6; }
        .essay-body hr { border: none; border-top: 1px solid ${color.border}; margin: 36px 0; }
        .essay-foot { margin-top: 56px; padding-top: 28px; border-top: 1px solid ${color.border}; }
        .essay-foot a { font-family: 'IBM Plex Sans', sans-serif; font-size: 14px; font-weight: 500; color: ${color.gold}; text-decoration: none; }
        .essay-foot a:hover { text-decoration: underline; }
      `}</style>
      <SiteNav activePage="Essays" />
      <article className="essay-shell">
        <div className="essay-eyebrow">Essay</div>
        <h1 className="essay-title">{essay.title}</h1>
        <div className="essay-byline">
          By <strong>{essay.author}</strong> · {formatDate(essay.date)}
        </div>
        {/* essayMdToHtml escapes raw HTML and only emits its fixed markup set. */}
        <div className="essay-body" dangerouslySetInnerHTML={{ __html: html }} /> {/* nosemgrep: typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml */}
        <div className="essay-foot">
          <a href="/essays">← All essays</a>
        </div>
      </article>
      <SiteFooter />
    </div>
  );
}
