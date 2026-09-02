// SPDX-License-Identifier: Apache-2.0
//
// Reference resolvers for the resolve-before-approve profile.
//
// A resolver answers exactly one question: what identity does this
// reference name RIGHT NOW. It returns {ok:true, identity, evidence} or
// {ok:false, reason}. It never throws for an expected failure, and the
// core module treats a thrown resolver as a refusal anyway.
//
// The identity string is the whole security surface: two resolutions agree
// if and only if their identity strings are byte-equal. Each resolver
// below states its identity form explicitly. A deployment that needs a
// different notion of sameness supplies its own resolver; the core does
// not care where the string came from, only that it is stable.
//
// None of these resolvers establishes authority, ownership, or safety of
// the target. They answer "the same thing as before?" and nothing else.

import fsDefault from 'node:fs';
import pathDefault from 'node:path';

const MAX_REDIRECT_HOPS = 5;

/**
 * filesystem-path.
 *
 * Identity form: "<fully resolved real path>#<device>:<inode>".
 *
 * Both halves are load-bearing. The real path catches a symlink re-pointed
 * at a different location. The device and inode catch the case where the
 * path string is unchanged AND resolves to the same location, but the file
 * at that location was replaced (unlink plus create, or a rename over the
 * top) - the classic swap that leaves every visible name identical.
 *
 * Options:
 *   fs          node:fs-compatible object (injectable for tests)
 *   path        node:path-compatible object
 *   root        when set, the resolved real path MUST sit inside the
 *               resolved real root, or resolution fails. This is the
 *               containment guard for a symlink pointing out of an
 *               approved directory. Absent, no containment is claimed.
 */
export function filesystemPathResolver({ fs = fsDefault, path = pathDefault, root = null } = {}) {
  let realRoot = null;
  return (reference) => {
    if (typeof reference !== 'string' || reference.length === 0) {
      return { ok: false, reason: 'invalid_reference' };
    }
    if (!path.isAbsolute(reference)) {
      // A relative path resolves against a working directory that is not
      // part of the approved action. Refuse rather than guess.
      return { ok: false, reason: 'reference_not_absolute' };
    }
    let realPath;
    let stat;
    try {
      realPath = fs.realpathSync(reference);
      stat = fs.statSync(realPath);
    } catch {
      return { ok: false, reason: 'unresolvable_path' };
    }
    if (root !== null) {
      if (realRoot === null) {
        try {
          realRoot = fs.realpathSync(root);
        } catch {
          return { ok: false, reason: 'unresolvable_root' };
        }
      }
      const relative = path.relative(realRoot, realPath);
      if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
        return { ok: false, reason: 'outside_approved_root' };
      }
    }
    return {
      ok: true,
      identity: `${realPath}#${stat.dev}:${stat.ino}`,
      evidence: {
        real_path: realPath,
        device: stat.dev,
        inode: stat.ino,
        indirect: realPath !== reference,
      },
    };
  };
}

function normalizeOrigin(url) {
  // URL.origin is "null" for non-special schemes; build it explicitly so a
  // scheme this profile does not allow can never collapse into the string
  // "null" and compare equal to another one.
  const port = url.port === '' ? '' : `:${url.port}`;
  return `${url.protocol}//${url.hostname.toLowerCase()}${port}`;
}

/**
 * url-origin.
 *
 * Identity form: the origin of the FINAL URL after following the redirect
 * chain, as "<scheme>//<lowercased host>[:<port>]".
 *
 * The approved argument is a URL string. What matters for an irreversible
 * action is which origin ends up receiving or serving the bytes, and that
 * is decided by a redirect chain the approver never saw. The identity is
 * the final origin; the full chain is returned as evidence for the
 * presentation layer.
 *
 * The transport is injected and MUST NOT follow redirects itself: this
 * resolver needs to see each hop. Pass a fetch-like function called as
 * transport(url, {redirect: 'manual'}) returning {status, headers} where
 * headers.get('location') yields the Location header.
 *
 * Options:
 *   transport       required; see above
 *   maxHops         redirect hops before refusing (default 5)
 *   allowedSchemes  schemes accepted anywhere in the chain (default https:)
 *
 * @param {object} [options]
 * @param {((url: string, init: object) => any) | null} [options.transport]
 * @param {number} [options.maxHops]
 * @param {string[]} [options.allowedSchemes]
 */
export function urlOriginResolver({ transport = null, maxHops = MAX_REDIRECT_HOPS, allowedSchemes = ['https:'] } = {}) {
  const schemes = new Set(allowedSchemes);
  return async (reference) => {
    if (typeof transport !== 'function') return { ok: false, reason: 'no_transport' };
    if (typeof reference !== 'string' || reference.length === 0) {
      return { ok: false, reason: 'invalid_reference' };
    }
    let current;
    try {
      current = new URL(reference);
    } catch {
      return { ok: false, reason: 'invalid_url' };
    }
    if (!schemes.has(current.protocol)) return { ok: false, reason: 'scheme_not_allowed' };

    const chain = [current.toString()];
    for (let hop = 0; hop <= maxHops; hop += 1) {
      let response;
      try {
        response = await transport(current.toString(), { redirect: 'manual' });
      } catch {
        return { ok: false, reason: 'transport_failed' };
      }
      const status = response && typeof response.status === 'number' ? response.status : null;
      if (status === null) return { ok: false, reason: 'transport_failed' };
      const isRedirect = status >= 300 && status <= 399;
      if (!isRedirect) {
        return {
          ok: true,
          identity: normalizeOrigin(current),
          evidence: { final_url: current.toString(), redirect_chain: chain, final_status: status },
        };
      }
      if (hop === maxHops) return { ok: false, reason: 'too_many_redirects' };
      const location = response.headers && typeof response.headers.get === 'function'
        ? response.headers.get('location')
        : null;
      if (typeof location !== 'string' || location.length === 0) {
        return { ok: false, reason: 'redirect_without_location' };
      }
      let next;
      try {
        next = new URL(location, current);
      } catch {
        return { ok: false, reason: 'invalid_redirect_target' };
      }
      if (!schemes.has(next.protocol)) return { ok: false, reason: 'scheme_not_allowed' };
      current = next;
      chain.push(current.toString());
    }
    return { ok: false, reason: 'too_many_redirects' };
  };
}

/**
 * beneficiary-label.
 *
 * Identity form: the account identifier the directory returns, normalized
 * by uppercasing and removing ASCII space and hyphen. The normalization is
 * stated here because CAID requires the normalization rule to be stated by
 * whoever issues the digest (registry note on beneficiary_account).
 *
 * The human approves a LABEL ("Acme Supplies"). The money moves to whatever
 * account identifier the directory maps that label to at dispatch time.
 * Those are two different facts and this resolver keeps them apart.
 *
 * Options:
 *   directory  required; called as directory(label), returning either a
 *              string account identifier, or {ok, account_id, record},
 *              or a nullish value for "no such label". A directory that
 *              throws is a resolution failure, never a match.
 *
 * @param {object} [options]
 * @param {((label: string) => any) | null} [options.directory]
 */
export function beneficiaryLabelResolver({ directory = null } = {}) {
  return async (reference) => {
    if (typeof directory !== 'function') return { ok: false, reason: 'no_directory' };
    if (typeof reference !== 'string' || reference.length === 0) {
      return { ok: false, reason: 'invalid_reference' };
    }
    let answer;
    try {
      answer = await directory(reference);
    } catch {
      return { ok: false, reason: 'directory_failed' };
    }
    let accountId = null;
    let record = null;
    if (typeof answer === 'string') {
      accountId = answer;
    } else if (answer && typeof answer === 'object' && answer.ok !== false) {
      accountId = typeof answer.account_id === 'string' ? answer.account_id : null;
      record = answer.record ?? null;
    }
    if (typeof accountId !== 'string' || accountId.length === 0) {
      return { ok: false, reason: 'label_not_mapped' };
    }
    const normalized = accountId.toUpperCase().replace(/[ -]/gu, '');
    if (normalized.length === 0) return { ok: false, reason: 'label_not_mapped' };
    return {
      ok: true,
      identity: normalized,
      evidence: { account_id: accountId, normalized_account_id: normalized, record },
    };
  };
}
