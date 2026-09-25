// SPDX-License-Identifier: Apache-2.0
/**
 * Issuer comparison form for native-authorization source pins.
 *
 * Internal to @emilia-protocol/verify: no package export names this module.
 * The handoff verifier uses it only to detect pins that spell one issuer two
 * ways; the replay identity never hashes this form.
 *
 * Every step is linear in the input. The input is bounded first by the pin
 * identifier grammar's maximum length, and trailing characters are trimmed
 * with a single backward scan instead of an end-anchored regular expression,
 * so no input can make the comparison backtrack polynomially.
 */

/** Longest issuer the pin identifier grammar admits (IDENTIFIER_RE and its byte bound). */
export const AEB_ISSUER_COMPARISON_MAX_LENGTH = 512;

const DEFAULT_PORTS: Readonly<Record<string, string>> = Object.freeze({
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
  'ftp:': '21',
});

/** `value` without any run of `char` at its end. One backward scan. */
function trimTrailing(value: string, char: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === char.charCodeAt(0)) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}

function isAsciiLetter(code: number): boolean {
  return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
}

function isAsciiDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

/**
 * Length of a leading run whose characters satisfy `accept`, ending at a
 * `:`; -1 when the run is empty, longer than `maximum`, or not followed by
 * `:`. Equivalent to an anchored `^([first][rest]{0,maximum-1}):` match.
 */
function leadingLabel(
  value: string,
  first: (code: number) => boolean,
  rest: (code: number) => boolean,
  maximum: number,
): number {
  if (value.length === 0 || !first(value.charCodeAt(0))) return -1;
  let index = 1;
  while (index < value.length && index < maximum && rest(value.charCodeAt(index))) index += 1;
  return index < value.length && value.charCodeAt(index) === 0x3a ? index : -1;
}

const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;

/**
 * Comparison form of an issuer, used only to detect aliased pins. The scheme
 * compares case-insensitively. For the special URL schemes (http, https, ws,
 * wss, ftp) the issuer is parsed as a WHATWG URL, which also accepts a
 * missing `//` and resolves dot segments; the host compares lower-case without
 * trailing dots, a default port is dropped, and trailing slashes on the path
 * are dropped. For `urn:` the namespace identifier compares case-insensitively
 * (RFC 8141). For `did:` the method name compares lower-case, and for
 * `did:web` the host compares lower-case without trailing dots. For
 * `spiffe://` the trust domain compares lower-case without trailing dots and
 * trailing slashes on the path are dropped. Any other identifier, and every
 * path, compares as written. An input longer than the pin grammar admits is
 * returned unchanged. This finds common aliases, not every alias.
 */
export function aebIssuerComparisonForm(issuer: string): string {
  if (typeof issuer !== 'string' || issuer.length > AEB_ISSUER_COMPARISON_MAX_LENGTH) return issuer;
  // ^([A-Za-z][A-Za-z0-9+.-]*):
  const schemeLength = leadingLabel(
    issuer,
    isAsciiLetter,
    (code) => isAsciiLetter(code) || isAsciiDigit(code)
      || code === 0x2b || code === 0x2e || code === 0x2d,
    Number.MAX_SAFE_INTEGER,
  );
  if (schemeLength < 0) return issuer;
  const protocol = `${issuer.slice(0, schemeLength).toLowerCase()}:`;
  const rest = issuer.slice(schemeLength + 1);
  if (protocol === 'urn:') {
    // ^([A-Za-z0-9][A-Za-z0-9-]{0,31}):
    const nid = leadingLabel(
      rest,
      (code) => isAsciiLetter(code) || isAsciiDigit(code),
      (code) => isAsciiLetter(code) || isAsciiDigit(code) || code === 0x2d,
      32,
    );
    return nid >= 0
      ? `urn:${rest.slice(0, nid).toLowerCase()}:${rest.slice(nid + 1)}`
      : `urn:${rest}`;
  }
  if (protocol === 'did:') {
    // ^([A-Za-z0-9]+):
    const alphanumeric = (code: number) => isAsciiLetter(code) || isAsciiDigit(code);
    const method = leadingLabel(rest, alphanumeric, alphanumeric, Number.MAX_SAFE_INTEGER);
    if (method < 0) return `did:${rest}`;
    const methodName = rest.slice(0, method).toLowerCase();
    const id = rest.slice(method + 1);
    if (methodName !== 'web') return `did:${methodName}:${id}`;
    // The pin identifier grammar has no `%`, so a did:web issuer here never
    // carries an encoded port: the host is the first colon-separated part.
    const colon = id.indexOf(':');
    const host = colon < 0 ? id : id.slice(0, colon);
    const path = colon < 0 ? '' : id.slice(colon);
    return `did:web:${trimTrailing(host.toLowerCase(), '.')}${path}`;
  }
  if (protocol === 'spiffe:') {
    // ^\/\/([^/?#]*)(.*)$ : the remainder may not hold a line terminator.
    if (!rest.startsWith('//')) return `spiffe:${rest}`;
    const afterSlashes = rest.slice(2);
    let end = 0;
    while (end < afterSlashes.length) {
      const code = afterSlashes.charCodeAt(end);
      if (code === 0x2f || code === 0x3f || code === 0x23) break;
      end += 1;
    }
    const remainder = afterSlashes.slice(end);
    if (LINE_TERMINATOR.test(remainder)) return `spiffe:${rest}`;
    const trustDomain = trimTrailing(afterSlashes.slice(0, end).toLowerCase(), '.');
    return `spiffe://${trustDomain}${trimTrailing(remainder, '/')}`;
  }
  if (!Object.hasOwn(DEFAULT_PORTS, protocol)) return `${protocol}${rest}`;
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return `${protocol}${rest}`;
  }
  const port = url.port !== '' && url.port !== DEFAULT_PORTS[url.protocol] ? `:${url.port}` : '';
  const userinfo = url.username !== '' || url.password !== ''
    ? `${url.username}${url.password !== '' ? `:${url.password}` : ''}@`
    : '';
  const host = trimTrailing(url.hostname.toLowerCase(), '.');
  const path = trimTrailing(url.pathname, '/');
  return `${url.protocol}//${userinfo}${host}${port}${path}${url.search}${url.hash}`;
}
