// SPDX-License-Identifier: Apache-2.0
//
// Public-address policy shared by every server-side outbound guard (webhooks,
// SSO/OIDC fetches, adapter fetches, the Eye notifier).
//
// The guards it replaced were deny-lists. They refused ::ffff:127.0.0.1 but
// accepted the IPv6 families that also carry an IPv4 target, and the
// unspecified address `::`, which connect() delivers to the local host. A DNS
// name answering AAAA with any of these passed the webhook guard.

import { describe, it, expect } from 'vitest';
import {
  isNonPublicIpLiteral,
  isPublicAddress,
  normalizeIpAddress,
  pinnedLookup,
} from '../lib/net/public-address.js';

describe('isPublicAddress', () => {
  it.each([
    ['::', 'unspecified (connects to the local host)'],
    ['::1', 'loopback'],
    ['::127.0.0.1', 'IPv4-compatible loopback, as getaddrinfo prints it'],
    ['::a00:1', 'IPv4-compatible 10.0.0.1, compressed'],
    ['64:ff9b::a00:1', 'NAT64 -> 10.0.0.1'],
    ['64:ff9b::7f00:1', 'NAT64 -> 127.0.0.1'],
    ['64:ff9b::a9fe:a9fe', 'NAT64 -> 169.254.169.254'],
    ['64:ff9b::10.0.0.1', 'NAT64, dotted tail'],
    ['64:ff9b:1::a00:1', 'NAT64 local-use prefix'],
    ['2002:7f00:1::', '6to4 -> 127.0.0.1'],
    ['2002:a9fe:a9fe::', '6to4 -> 169.254.169.254'],
    ['2001:0:4136:e378:8000:63bf:3fff:fdd2', 'Teredo'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback, dotted'],
    ['::ffff:7f00:1', 'IPv4-mapped loopback, hex (URL serializer form)'],
    ['::ffff:a9fe:a9fe', 'IPv4-mapped metadata, hex'],
    ['0:0:0:0:0:ffff:7f00:1', 'IPv4-mapped, expanded'],
    ['::ffff:0:7f00:1', 'IPv4-translated'],
    ['fc00::1', 'ULA'],
    ['fd00::1', 'ULA'],
    ['fe80::1', 'link-local'],
    ['fe80::1%eth0', 'link-local with zone id'],
    ['ff02::1', 'multicast'],
    ['2001:db8::1', 'documentation'],
    ['127.0.0.1', 'loopback'],
    ['10.0.0.1', 'private'],
    ['172.16.0.1', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'metadata'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['0.0.0.0', 'this network'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'broadcast'],
  ])('refuses %s (%s)', (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it.each([
    '93.184.216.34',
    '8.8.8.8',
    '2606:4700:4700::1111',
    '2a00:1450:4001:80b::200e',
    '::ffff:5db8:d822', // IPv4-mapped 93.184.216.34
  ])('accepts public unicast %s', (address) => {
    expect(isPublicAddress(address)).toBe(true);
  });

  it('fails closed on anything that is not an IP literal', () => {
    for (const value of ['example.com', '', null, undefined, 'not an ip', '1.2.3', '::g']) {
      expect(isPublicAddress(value)).toBe(false);
    }
  });
});

describe('isNonPublicIpLiteral', () => {
  it('judges bracketed URL hostnames as IPs', () => {
    expect(isNonPublicIpLiteral('[::]')).toBe(true);
    expect(isNonPublicIpLiteral('[64:ff9b::a00:1]')).toBe(true);
    expect(isNonPublicIpLiteral(new URL('https://[::10.0.0.1]/').hostname)).toBe(true);
    expect(isNonPublicIpLiteral('[2606:4700:4700::1111]')).toBe(false);
  });

  it('leaves DNS names to the resolver check', () => {
    expect(isNonPublicIpLiteral('hooks.example.com')).toBe(false);
  });
});

describe('normalizeIpAddress', () => {
  it('canonicalizes IPv6 to the URL serializer form', () => {
    expect(normalizeIpAddress('64:ff9b::10.0.0.1')).toBe('64:ff9b::a00:1');
    expect(normalizeIpAddress('[0:0:0:0:0:0:0:1]')).toBe('::1');
    expect(normalizeIpAddress('hooks.example.com')).toBeNull();
  });
});

describe('pinnedLookup', () => {
  it('answers the array form when the socket layer asks for all addresses', () => {
    // Node >= 20 defaults to autoSelectFamily, which calls lookup with
    // { all: true } and expects an array; the single-address form fails every
    // connection with "Invalid IP address: undefined".
    const lookup = pinnedLookup('2606:4700:4700::1111');
    let answer: unknown;
    lookup('hooks.example.com', { all: true }, ((_err: unknown, addresses: unknown) => { answer = addresses; }) as never);
    expect(answer).toEqual([{ address: '2606:4700:4700::1111', family: 6 }]);
  });

  it('answers the single-address form otherwise', () => {
    const lookup = pinnedLookup('93.184.216.34');
    const answer: unknown[] = [];
    lookup('hooks.example.com', {}, ((_err: unknown, address: unknown, family: unknown) => { answer.push(address, family); }) as never);
    expect(answer).toEqual(['93.184.216.34', 4]);
  });
});
