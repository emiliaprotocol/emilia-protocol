// SPDX-License-Identifier: Apache-2.0
// Generated from no-symmetric.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP security invariant: NO symmetric-key primitive may appear on the offline
// verification trust path. EP receipts and quorum signoffs are verified with
// ASYMMETRIC signatures (Ed25519 receipts, ES256/P-256 device signoffs) so a
// relying party verifies them WITHOUT trusting — or sharing any key with — the
// operator that issued them. A symmetric primitive (HMAC, a shared secret, a
// symmetric cipher) anywhere in the verifier would mean the operator holds a key
// that can forge the very evidence the verifier is meant to check independently.
//
// This is the property that distinguishes an EP receipt from an HMAC-chained
// audit log: the log's keeper can rewrite its own history; an EP receipt's
// issuer cannot. We enforce it mechanically here so a future change cannot
// quietly reintroduce operator-forgeable evidence.
import { test } from 'node:test';
import assert from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
// Actual symmetric-crypto API surface (Node `crypto`). We match calls, not the
// substring "symmetric" (which appears legitimately inside "asymmetric").
const FORBIDDEN = /createHmac|createCipheriv|createCipher\b|crypto\.Hmac|secretbox/i;
test('verify trust path uses no symmetric-key primitive', () => {
    const files = readdirSync(here)
        .filter((f) => f.endsWith('.js') && !f.endsWith('.test.js'));
    assert.ok(files.length > 0, 'expected verifier source files to scan');
    for (const f of files) {
        const src = readFileSync(join(here, f), 'utf8');
        const m = src.match(FORBIDDEN);
        assert.strictEqual(m, null, `${f} introduces a symmetric primitive (${m?.[0]}) on the verification trust path — `
            + 'EP receipts MUST be verifiable with asymmetric signatures alone.');
    }
});
