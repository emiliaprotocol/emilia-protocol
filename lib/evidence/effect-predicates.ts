// SPDX-License-Identifier: Apache-2.0
// The published offline verifier is the single source of truth for the
// EP-OUTCOME-BINDING-v1 predicate contract. The evidence-graph layer composes
// that exact implementation so package and server behavior cannot drift.
export * from '../../packages/verify/effect-predicates.js';
