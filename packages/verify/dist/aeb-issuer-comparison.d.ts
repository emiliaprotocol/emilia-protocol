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
export declare const AEB_ISSUER_COMPARISON_MAX_LENGTH = 512;
/**
 * Comparison form of an issuer, used only to detect aliased pins. The scheme
 * compares case-insensitively. For the special URL schemes (http, https, ws,
 * wss, ftp) the issuer is parsed as a WHATWG URL, which also accepts a
 * missing `//` and resolves dot segments; the host compares lower-case without
 * trailing dots (an IPv4 host in any spelling the URL parser accepts, such as
 * `127.1` or `0x7f.0.0.1`, compares in dotted-decimal form), a default or
 * empty port is dropped, and trailing slashes on the path are dropped. For `urn:` the namespace identifier compares case-insensitively
 * (RFC 8141). For `did:` the method name compares lower-case, and for
 * `did:web` the host compares lower-case without trailing dots. For
 * `spiffe://` the trust domain compares lower-case without trailing dots and
 * trailing slashes on the path are dropped. Any other identifier, and every
 * path, compares as written. An input longer than the pin grammar admits is
 * returned unchanged. This finds common aliases, not every alias.
 */
export declare function aebIssuerComparisonForm(issuer: string): string;
//# sourceMappingURL=aeb-issuer-comparison.d.ts.map