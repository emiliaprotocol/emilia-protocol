// SPDX-License-Identifier: Apache-2.0
/**
 * safeHref — neutralize dangerous URL schemes in markdown links that are rendered
 * via dangerouslySetInnerHTML. Closes the `javascript:` / `data:` / `vbscript:`
 * href-injection class (pen-test LOW-05): a captured link target from markdown
 * must never become an executable-scheme anchor, even though today's source
 * markdown is committed and reviewed.
 *
 * Policy: allow http(s) and mailto explicitly; allow schemeless URLs (relative,
 * absolute-path, anchor); drop ANY other scheme (javascript, data, vbscript,
 * file, …) to '#'. Control characters are stripped first so an obfuscated scheme
 * ("java\tscript:") cannot slip past the check.
 *
 * @param {string} url  the raw href captured from markdown
 * @returns {string} a safe href ('#' if the scheme is not allowed)
 */
const CONTROL_CHARS = /[\x00-\x1F\x7F-\x9F]/g;

export function safeHref(url) {
  const s = String(url ?? '').replace(CONTROL_CHARS, '').trim();
  if (/^(https?:|mailto:)/i.test(s)) return s;    // explicitly allowed schemes
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return '#'; // any other scheme -> drop
  return s;                                         // schemeless: relative/anchor/path
}
