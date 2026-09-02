#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Runner for the frozen resolve-before-approve vector corpus.
//
// Every vector is hermetic: resolvers are table lookups over the vector's
// declared world, so nothing here touches the filesystem or the network.
// The real filesystem, URL and directory resolvers are exercised by the
// node:test suite instead.
//
//   node caid/resolution/run-vectors.mjs          human-readable
//   node caid/resolution/run-vectors.mjs --json   machine-readable outcomes

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  checkResolvedReferencesAtDispatch,
  freezeResolvedReferences,
  REFERENCE_KINDS,
  referenceIdentityDigest,
} from './resolve-before-approve.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CORPUS_PATH = path.join(HERE, 'vectors.json');

const PLACEHOLDER_RE = /^PLACEHOLDER:([a-z-]+):(.+)$/u;

/** Build table-driven resolvers over a vector's declared world. */
export function worldResolvers(world, omit = []) {
  const resolvers = {};
  for (const kind of REFERENCE_KINDS) {
    if (omit.includes(kind)) continue;
    const table = (world && world[kind]) || {};
    let call = 0;
    resolvers[kind] = (reference) => {
      if (!Object.prototype.hasOwnProperty.call(table, reference)) {
        return { ok: false, reason: 'not_in_world' };
      }
      const entry = table[reference];
      if (entry === '__throw__') throw new Error('resolver blew up');
      if (Array.isArray(entry)) {
        const identity = entry[Math.min(call, entry.length - 1)];
        call += 1;
        return { ok: true, identity, evidence: { unstable: true } };
      }
      return { ok: true, identity: entry, evidence: { world: kind } };
    };
  }
  return resolvers;
}

/**
 * Vectors written before the digest values existed carry
 * "PLACEHOLDER:<kind>:<identity>" so the corpus stays readable. They are
 * expanded here through the same domain-separated digest the profile uses.
 * Expansion applies ONLY to the inputs of dispatch-shaped vectors; every
 * expected digest in the corpus is a frozen literal.
 */
function expandPlaceholders(value) {
  if (typeof value === 'string') {
    const match = PLACEHOLDER_RE.exec(value);
    if (!match) return value;
    const digest = referenceIdentityDigest(match[1], match[2]);
    if (digest === null) throw new Error(`unexpandable placeholder: ${value}`);
    return digest;
  }
  if (Array.isArray(value)) return value.map(expandPlaceholders);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expandPlaceholders(v)]));
  }
  return value;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function fail(id, message) {
  return { id, ok: false, message };
}

export async function runVector(vector, observedById) {
  const { id, spec, expect } = vector;
  const resolvers = worldResolvers(vector.world, vector.omit_resolvers || []);

  if (vector.kind === 'capture' || vector.kind === 'capture-then-dispatch') {
    const args = expandPlaceholders(vector.input.arguments);
    const captured = await freezeResolvedReferences(args, spec, resolvers);
    const captureShouldPass = vector.kind === 'capture-then-dispatch'
      ? expect.capture_ok === true
      : expect.ok === true;

    if (!captureShouldPass) {
      if (captured.ok) return fail(id, 'capture accepted a vector that must refuse');
      const got = canonicalJson(captured.refusals);
      const want = canonicalJson(expect.refusals);
      if (got !== want) return fail(id, `capture refusals ${got} != expected ${want}`);
      return { id, ok: true };
    }

    if (!captured.ok) return fail(id, `capture refused: ${JSON.stringify(captured.refusals)}`);

    if (expect.observed) {
      const got = canonicalJson(captured.observed);
      const want = canonicalJson(expect.observed);
      if (got !== want) return fail(id, `observed action ${got} != expected ${want}`);
    }
    if (vector.same_observed_as) {
      const reference = observedById.get(vector.same_observed_as);
      if (!reference) return fail(id, `no observed action recorded for ${vector.same_observed_as}`);
      if (canonicalJson(captured.observed) !== reference) {
        return fail(id, `observed action differs from ${vector.same_observed_as}`);
      }
    }
    if (Array.isArray(expect.distinct_identity_digests)) {
      const digests = expect.distinct_identity_digests
        .map((field) => captured.observed.resolved_references[field].identity_digest);
      if (new Set(digests).size !== digests.length) {
        return fail(id, 'identity digests collided across reference kinds');
      }
    }
    observedById.set(id, canonicalJson(captured.observed));

    if (vector.kind === 'capture') return { id, ok: true };

    const dispatchResolvers = worldResolvers(vector.world_at_dispatch, vector.omit_resolvers || []);
    const dispatched = await checkResolvedReferencesAtDispatch(captured.observed, spec, dispatchResolvers);
    return compareDispatch(id, dispatched, expect.dispatch);
  }

  if (vector.kind === 'dispatch') {
    const observed = expandPlaceholders(vector.input.observed);
    const dispatched = await checkResolvedReferencesAtDispatch(observed, spec, resolvers);
    return compareDispatch(id, dispatched, expect);
  }

  return fail(id, `unknown vector kind: ${vector.kind}`);
}

function compareDispatch(id, dispatched, expected) {
  if (expected.ok === true) {
    if (!dispatched.ok) return fail(id, `dispatch refused: ${JSON.stringify(dispatched.refusals)}`);
    return { id, ok: true };
  }
  if (dispatched.ok) return fail(id, 'dispatch accepted a vector that must refuse');
  const got = canonicalJson(dispatched.refusals);
  const want = canonicalJson(expected.refusals);
  if (got !== want) return fail(id, `dispatch refusals ${got} != expected ${want}`);
  return { id, ok: true };
}

export async function runCorpus(corpusPath = CORPUS_PATH) {
  const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));
  const observedById = new Map();
  const results = [];
  for (const vector of corpus.vectors) {
    try {
      results.push(await runVector(vector, observedById));
    } catch (error) {
      // A vector runner exception is itself a finding: the profile promises
      // refusals, not throws.
      results.push(fail(vector.id, `threw: ${error && error.message}`));
    }
  }
  return results;
}

const invokedDirectly = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  const results = await runCorpus();
  if (process.argv.includes('--json')) {
    process.stdout.write(`${JSON.stringify(results, null, 1)}\n`);
  } else {
    for (const result of results) {
      process.stdout.write(`${result.ok ? 'PASS' : 'FAIL'} ${result.id}${result.ok ? '' : ` - ${result.message}`}\n`);
    }
  }
  const failed = results.filter((result) => !result.ok);
  if (failed.length > 0) {
    process.stderr.write(`${failed.length} of ${results.length} resolve-before-approve vectors failed\n`);
    process.exit(1);
  }
  process.stdout.write(`resolve-before-approve: ${results.length} vectors green\n`);
}
