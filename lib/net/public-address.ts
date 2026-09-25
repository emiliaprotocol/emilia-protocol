// SPDX-License-Identifier: Apache-2.0
//
// Public-address policy for server-side outbound requests (webhooks, SSO/OIDC
// fetches, adapter metadata fetches, operator notifiers).
//
// An SSRF guard that lists the private ranges it knows about fails OPEN on
// every range it forgot. IPv6 has several families that carry an IPv4 target
// or route to the local host without looking private to a deny-list:
//
//   ::                 unspecified; connect() lands on the local host
//   ::a.b.c.d          IPv4-compatible (deprecated)
//   64:ff9b::/96       NAT64 well-known prefix (RFC 6052)
//   64:ff9b:1::/48     NAT64 local-use prefix (RFC 8215)
//   2002::/16          6to4 (RFC 3056)
//   2001::/32          Teredo (RFC 4380)
//
// So IPv6 is judged by ALLOWLIST: only global unicast (2000::/3) is public,
// minus the special-purpose blocks inside it. IPv4-mapped addresses
// (::ffff:a.b.c.d, in dotted or hex form) are unwrapped and judged as IPv4.
// This is the same classification @emilia-protocol/verify (federation.ts) and
// @emilia-protocol/gate (discovery-permit-resolver.ts) already ship.
//
// Residual: a deployment whose NAT64 gateway uses a network-specific prefix
// inside 2000::/3 cannot be distinguished from ordinary public IPv6 here.

import net from 'node:net';
import type { LookupFunction } from 'node:net';

function stripHost(value: unknown): string {
  return String(value ?? '')
    .trim()
    .replace(/^\[(.*)\]$/, '$1') // URL.hostname keeps IPv6 brackets
    .replace(/%.*$/, '')         // zone id (fe80::1%eth0)
    .replace(/\.$/, '')          // FQDN root dot
    .toLowerCase();
}

/**
 * Canonicalize an IP literal (dotted IPv4, or IPv6 in the WHATWG URL
 * serializer's compressed form). Returns null when `value` is not an IP.
 */
export function normalizeIpAddress(value: unknown): string | null {
  const raw = stripHost(value);
  const version = net.isIP(raw);
  if (version === 4) return raw.split('.').map((part) => String(Number(part))).join('.');
  if (version !== 6) return null;
  try {
    return stripHost(new URL(`https://[${raw}]/`).hostname);
  } catch {
    return null;
  }
}

function isPublicIPv4(address: string): boolean {
  const [a, b, c] = address.split('.').map(Number);
  return !(
    a === 0 ||                               // "this" network
    a === 10 ||                              // private
    a === 127 ||                             // loopback
    (a === 169 && b === 254) ||              // link-local, incl. 169.254.169.254 metadata
    (a === 172 && b >= 16 && b <= 31) ||     // private
    (a === 192 && b === 168) ||              // private
    (a === 100 && b >= 64 && b <= 127) ||    // carrier-grade NAT
    (a === 192 && b === 0) ||                // IETF protocol assignments + documentation
    (a === 192 && b === 88 && c === 99) ||   // deprecated 6to4 relay anycast
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    (a === 198 && b === 51 && c === 100) ||  // documentation
    (a === 203 && b === 0 && c === 113) ||   // documentation
    a >= 224                                 // multicast, reserved, broadcast
  );
}

function isPublicIPv6(address: string): boolean {
  const mappedDotted = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedDotted) return net.isIPv4(mappedDotted[1]) && isPublicIPv4(mappedDotted[1]);
  const mappedHex = address.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = Number.parseInt(mappedHex[1], 16);
    const lo = Number.parseInt(mappedHex[2], 16);
    return isPublicIPv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
  }
  const first = Number.parseInt(address.split(':', 1)[0] || '0', 16);
  if ((first & 0xe000) !== 0x2000) return false; // not global unicast 2000::/3
  return !(
    address.startsWith('2001::') ||    // Teredo 2001::/32 (compressed zero hextet)
    address.startsWith('2001:0:') ||   // Teredo
    address.startsWith('2001:2:') ||   // benchmarking
    address.startsWith('2001:10:') ||  // ORCHID
    address.startsWith('2001:20:') ||  // ORCHIDv2
    address.startsWith('2001:db8:') || // documentation
    address === '2001:db8::' ||
    address.startsWith('2002:') ||     // 6to4
    address === '2002::' ||
    address.startsWith('3fff:')        // documentation
  );
}

/**
 * True only for a publicly routable unicast IP address. Anything else,
 * including a value that is not an IP literal at all, is NOT public: callers
 * use this on resolver output, where a non-IP answer must fail closed.
 */
export function isPublicAddress(value: unknown): boolean {
  const address = normalizeIpAddress(value);
  if (!address) return false;
  return address.includes(':') ? isPublicIPv6(address) : isPublicIPv4(address);
}

/**
 * For a URL hostname: true when it is an IP literal that is not public.
 * DNS names return false here; they must be resolved and each answer checked
 * with isPublicAddress.
 */
export function isNonPublicIpLiteral(hostname: unknown): boolean {
  return normalizeIpAddress(hostname) !== null && !isPublicAddress(hostname);
}

/**
 * A `lookup` for node:net / node:https that always answers with one
 * pre-validated address, so the connection cannot re-resolve (DNS rebinding).
 *
 * It must honor `options.all`: since Node 20 the socket layer defaults to
 * autoSelectFamily and calls lookup with `{ all: true }`, expecting an array.
 * Answering with the (address, family) form there fails every connection
 * with "Invalid IP address: undefined".
 */
export function pinnedLookup(address: string): LookupFunction {
  const pinnedFamily = net.isIPv6(address) ? 6 : 4;
  return (_hostname, options, callback) => {
    if (options && (options as { all?: boolean }).all) {
      (callback as unknown as (err: null, addresses: { address: string; family: number }[]) => void)(
        null,
        [{ address, family: pinnedFamily }],
      );
      return;
    }
    callback(null, address, pinnedFamily);
  };
}
