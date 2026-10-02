// SPDX-License-Identifier: Apache-2.0
// Narrow, dependency-free checks for the IANA scheme-name revision.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const old = readFileSync('standards/posted/draft-schrock-canonical-action-identifier-04.xml', 'utf8');
const next = readFileSync('standards/staged/NEXT-CAID-05/UPLOAD-THIS/draft-schrock-canonical-action-identifier-05.xml', 'utf8');
assert.equal(createHash('sha256').update(old).digest('hex'), '2327aa36bba57c368140d7573184113df38e6c4f75a97fe09625d76a91162b93');

assert.match(next, /docName="draft-schrock-canonical-action-identifier-05"/);
assert.match(next, /<name>The "canactid" URI Scheme<\/name>/);
assert.match(next, /<dt>Scheme name:<\/dt>\s*<dd>canactid<\/dd>/);
assert.match(next, /caid\s+= %s"canactid"/);
assert.doesNotMatch(next, /caid:1:/);
assert.match(next, /<section anchor="legacy-scheme">[\s\S]*?<bcp14>MUST NOT<\/bcp14>\s+accept a "caid:" string/);
assert.match(next, /Rewriting an existing signed artifact's identifier does not\s+migrate its authorization or preserve its signature/);

// RFC 8792 folds long examples. Unfold before comparing their identifier
// payloads; a renamed scheme must leave all example suffixes unchanged.
const unfold = text => text.replace(/\\\n\s*/g, '');
const identifiers = text => [...unfold(text).matchAll(/(?:canactid|caid):1:[a-z0-9.<>_-]+:[a-z0-9<>_-]+:[A-Za-z0-9<>_-]+/g)]
  .map(match => match[0]);
const before = identifiers(old);
const after = identifiers(next);
assert.equal(before.length, 8);
assert.deepEqual(after, before.map(id => id.replace(/^caid:/, 'canactid:')));
console.log('CAID -05 scheme transition: posted -04 unchanged; eight identifier examples and legacy boundary PASS');
