// SPDX-License-Identifier: Apache-2.0

import { safeHref } from './safe-href.js';

/** Escape text before it crosses a dangerouslySetInnerHTML boundary. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Keep a fenced-code language from becoming attacker-controlled class text. */
export function sanitizeCodeLanguage(value: unknown): string {
  const language = String(value ?? '').trim();
  return /^[A-Za-z0-9_-]{1,32}$/.test(language) ? language : 'text';
}

/**
 * Render the deliberately tiny inline-markdown subset used by the spec page.
 * Source bytes are escaped before any supported markup is introduced.
 */
export function renderInlineMarkdown(value: unknown): string {
  let text = escapeHtml(value);
  text = text.replace(
    /\[([^\]]+)\]\(([^)]+)\)/g,
    (_match, label, url) => `<a href="${safeHref(url)}">${label}</a>`,
  );
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');
  text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
  return text;
}
