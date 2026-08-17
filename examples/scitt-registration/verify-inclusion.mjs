// SPDX-License-Identifier: Apache-2.0
//
// Re-verify the CHECKED-IN Markovian transparency-log return package, offline.
//
//   node examples/scitt-registration/verify-inclusion.mjs
//
// No network. Reads only interop/markovian-emilia/MARKOVIAN-CROSS-RUN-20260729-001.json.
//
// WHY THIS FILE EXISTS. The registration client next door can build a Signed
// Statement but cannot prove that our proof-checking machinery works, because
// nothing of ours has been registered anywhere. This runs the proof path we
// already have against the one real transparency-log return the repo holds, so
// the machinery is demonstrated rather than asserted.
//
// TWO INDEPENDENT PATHS, REQUIRED TO AGREE:
//
//   A. The verifier Markovian returned with the package,
//      interop/markovian-emilia/verify_cross_run.py, run as a subprocess.
//      Skipped (not failed) when python3 or its `cryptography` dependency is
//      absent; the skip is reported, never hidden.
//   B. A Node re-implementation in this file of the same checks: RFC 6962
//      inclusion and consistency, the c2sp.org/tlog-checkpoint signed note, and
//      c2sp.org/tlog-cosignature v1 witness cosignatures.
//
// NOT THE SAME MERKLE TREE AS EP-MERKLE-v2. `packages/verify/src/consistency.ts`
// implements EP-MERKLE-v2, whose branch hash is SHA-256(0x01 || leftHexString ||
// rightHexString) over ASCII hex. Markovian's log is RFC 6962: leaf hash
// SHA-256(0x00 || leafBytes), branch hash SHA-256(0x01 || leftDigest ||
// rightDigest) over raw 32-byte digests. The two are deliberately not
// interchangeable and this file does not pretend otherwise: it implements RFC
// 6962 to match the artifact, exactly as the returned Python verifier does.
//
// WHAT A GREEN RUN PROVES. The exact canonical leaf bytes were included in the
// witnessed log at tree size 4881, and the later witnessed head at 4912 is an
// append-only extension of it, under the pinned log and witness keys. It does
// NOT make the receipt's claims true, and it says nothing about the
// EP-SCITT-STATEMENT-v1 statements built by register.mjs, none of which have
// been submitted anywhere.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PACKAGE_FILE = path.join(ROOT, 'interop/markovian-emilia/MARKOVIAN-CROSS-RUN-20260729-001.json');
const PYTHON_VERIFIER = path.join(ROOT, 'interop/markovian-emilia/verify_cross_run.py');

// --- RFC 6962 primitives -----------------------------------------------------

const H = (buf) => crypto.createHash('sha256').update(buf).digest();
const leafHash = (leafBytes) => H(Buffer.concat([Buffer.from([0x00]), leafBytes]));
const nodeHash = (left, right) => H(Buffer.concat([Buffer.from([0x01]), left, right]));

/** RFC 6962 Section 2.1.1 inclusion-proof verification. */
export function verifyInclusion(index, size, leaf, root, proof) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const sibling of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(sibling, r);
      while (!(fn === 0 || (fn & 1) === 1)) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHash(r, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

/** RFC 6962 Section 2.1.2 consistency-proof verification. */
export function verifyConsistency(first, second, firstHash, secondHash, proof) {
  if (first < 1 || first >= second) return false;
  let p = [...proof];
  if ((first & (first - 1)) === 0) p = [firstHash, ...p];
  let fn = first - 1;
  let sn = second - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  if (p.length === 0) return false;
  let fr = p[0];
  let sr = p[0];
  for (const sibling of p.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(sibling, fr);
      sr = nodeHash(sibling, sr);
      while (!(fn === 0 || (fn & 1) === 1)) { fn >>= 1; sn >>= 1; }
    } else {
      sr = nodeHash(sr, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return fr.equals(firstHash) && sr.equals(secondHash) && sn === 0;
}

// --- c2sp signed notes and cosignatures --------------------------------------

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function ed25519Verify(rawPublicKey32, message, signature) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, rawPublicKey32]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}

/** Parse a c2sp.org/signed-note verification key: `<name>+<keyhash hex>+<b64>`. */
export function parseVkey(vkey) {
  const match = /^(.+)\+([0-9a-f]{8})\+(.+)$/.exec(vkey);
  if (!match) throw new Error(`malformed vkey: ${vkey}`);
  const [, name, keyHashHex, keyB64] = match;
  const keyBlob = Buffer.from(keyB64, 'base64');
  const alg = keyBlob[0];
  const key = keyBlob.subarray(1);
  const keyHash = H(Buffer.concat([Buffer.from(name, 'utf8'), Buffer.from([0x0a]), keyBlob])).subarray(0, 4);
  if (keyHash.toString('hex') !== keyHashHex) throw new Error(`vkey self-check failed for ${name}`);
  return { name, alg, key, keyHash };
}

function splitNote(note) {
  const bodyEnd = note.indexOf('\n\n') + 1;
  if (bodyEnd <= 0) throw new Error('malformed signed note');
  const body = note.slice(0, bodyEnd);
  const signatures = [];
  for (const rawLine of note.slice(bodyEnd).split('\n')) {
    const line = rawLine.trim();
    // c2sp.org/signed-note: every signature line begins U+2014 EM DASH then a
    // space. Written as an escape so the file stays pure ASCII on disk; the
    // character itself is a format constant, not prose.
    if (!line.startsWith('\u2014 ')) continue;
    const parts = line.split(' ');
    signatures.push({ name: parts[1], blob: Buffer.from(parts.slice(2).join(' '), 'base64') });
  }
  return { body, signatures };
}

/**
 * Verify a signed note's log signature and count distinct witness cosignatures.
 * Only signatures from PINNED keys are counted; anything else is ignored, and an
 * invalid signature from a pinned key is a hard failure.
 */
export function verifyNote(note, logVkey, witnessVkeys) {
  const { body, signatures } = splitNote(note);
  const log = parseVkey(logVkey);
  const bodyBytes = Buffer.from(body, 'utf8');
  let logOk = false;
  const witnessesSeen = new Set();

  for (const { name, blob } of signatures) {
    const keyHash = blob.subarray(0, 4);
    const rest = blob.subarray(4);
    if (name === log.name && keyHash.equals(log.keyHash) && log.alg === 0x01 && rest.length === 64) {
      if (!ed25519Verify(log.key, bodyBytes, rest)) {
        return { logOk: false, quorum: 0, message: 'log signature INVALID' };
      }
      logOk = true;
      continue;
    }
    for (const witness of witnessVkeys) {
      if (name !== witness.name || !keyHash.equals(witness.keyHash)) continue;
      // c2sp.org/tlog-cosignature v1: alg 0x04, 8-byte big-endian unix time
      // followed by a 64-byte Ed25519 signature over the domain-separated
      // message below. This is a DIFFERENT construction from the log signature.
      if (witness.alg !== 0x04 || rest.length !== 72) continue;
      const timestamp = rest.readBigUInt64BE(0);
      const message = Buffer.from(`cosignature/v1\ntime ${timestamp}\n${body}`, 'utf8');
      if (!ed25519Verify(witness.key, message, rest.subarray(8))) {
        return { logOk, quorum: witnessesSeen.size, message: `cosignature INVALID for ${witness.name}` };
      }
      witnessesSeen.add(witness.name);
    }
  }
  return { logOk, quorum: witnessesSeen.size, message: 'ok' };
}

// --- path B: the Node re-verification ----------------------------------------

export function verifyPackageInNode(pkg) {
  const results = [];
  const check = (label, ok) => { results.push({ label, ok: Boolean(ok) }); };
  const b64 = (s) => Buffer.from(s, 'base64');

  const witnesses = pkg.witnesses.map(parseVkey);
  const source = b64(pkg.source_receipt.b64);
  const leaf = b64(pkg.typed_leaf.b64);

  check('source receipt sha256 matches',
    crypto.createHash('sha256').update(source).digest('hex') === pkg.source_receipt.sha256);
  check('canonical leaf sha256 matches',
    crypto.createHash('sha256').update(leaf).digest('hex') === pkg.typed_leaf.sha256);
  // The source receipt bytes and the canonical leaf bytes are deliberately
  // distinct artifacts with distinct digests. Conflating them would let a leaf
  // digest be presented as a receipt digest.
  check('source and canonical leaf are distinct byte strings (as declared)',
    !source.equals(leaf) && pkg.source_equals_canonical !== true);

  const head1 = pkg.inclusion_head;
  const head2 = pkg.next_witnessed_head;
  const root1 = b64(head1.root_hash_b64);
  const root2 = b64(head2.root_hash_b64);

  check(`RFC 6962 inclusion: leaf ${pkg.typed_leaf.leaf_index} in root@${head1.tree_size}`,
    verifyInclusion(
      pkg.typed_leaf.leaf_index,
      head1.tree_size,
      leafHash(leaf),
      root1,
      pkg.inclusion.nodes_b64.map(b64),
    ));

  const note1 = verifyNote(head1.signed_note, pkg.log.vkey, witnesses);
  check(`inclusion head note: log signature valid (${note1.message})`, note1.logOk);
  check(`inclusion head note: witness quorum ${note1.quorum}/${witnesses.length}`,
    note1.quorum === witnesses.length);

  check(`RFC 6962 consistency ${head1.tree_size} -> ${head2.tree_size}`,
    verifyConsistency(
      head1.tree_size,
      head2.tree_size,
      root1,
      root2,
      pkg.consistency_proof.nodes_b64.map(b64),
    ));

  const note2 = verifyNote(head2.signed_note, pkg.log.vkey, witnesses);
  check(`next head note: log signature valid (${note2.message})`, note2.logOk);
  check(`next head note: witness quorum ${note2.quorum}/${witnesses.length}`,
    note2.quorum === witnesses.length);

  // A negative control. If a corrupted proof also "verified", every PASS above
  // would be meaningless.
  const corrupted = pkg.inclusion.nodes_b64.map(b64);
  corrupted[0] = Buffer.from(corrupted[0]);
  corrupted[0][0] ^= 0x01;
  check('negative control: a corrupted inclusion proof is REJECTED',
    !verifyInclusion(pkg.typed_leaf.leaf_index, head1.tree_size, leafHash(leaf), root1, corrupted));

  return results;
}

// --- path A: the verifier Markovian returned ---------------------------------

export function runReturnedPythonVerifier() {
  try {
    execFileSync('python3', ['-c', 'import cryptography'], { stdio: 'ignore' });
  } catch {
    return { status: 'skipped', reason: 'python3 with the cryptography package is not available' };
  }
  try {
    const output = execFileSync('python3', [PYTHON_VERIFIER, PACKAGE_FILE], { encoding: 'utf8' });
    return { status: 'pass', output };
  } catch (error) {
    return { status: 'fail', output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

// --- main --------------------------------------------------------------------

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_FILE, 'utf8'));
  console.log(`package: ${pkg.package}`);
  console.log(`log origin: ${pkg.log.origin}`);
  console.log(`leaf index ${pkg.typed_leaf.leaf_index}, inclusion head ${pkg.inclusion_head.tree_size}, next head ${pkg.next_witnessed_head.tree_size}, ${pkg.witnesses.length} pinned witnesses`);
  console.log('');

  console.log('PATH B: Node re-verification (this file)');
  const results = verifyPackageInNode(pkg);
  for (const { label, ok } of results) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  const nodeFailures = results.filter((r) => !r.ok);
  console.log('');

  console.log('PATH A: the verifier Markovian returned with the package');
  const python = runReturnedPythonVerifier();
  if (python.status === 'skipped') {
    console.log(`  SKIPPED  ${python.reason}`);
  } else {
    for (const line of (python.output ?? '').trim().split('\n')) console.log(`  ${line}`);
  }
  console.log('');

  if (nodeFailures.length) {
    console.error(`RESULT: FAIL - ${nodeFailures.length} Node check(s) failed`);
    process.exit(1);
  }
  if (python.status === 'fail') {
    console.error('RESULT: FAIL - the returned Python verifier did not pass');
    process.exit(1);
  }
  if (python.status === 'skipped') {
    console.log('RESULT: PASS (Node path only; the returned Python verifier was skipped)');
  } else {
    console.log('RESULT: PASS - both paths green and in agreement');
  }
  console.log('');
  console.log('SCOPE. This proves inclusion and append-only extension for the 2026-07-29');
  console.log('cross-run leaf under the pinned keys. It does not make that receipt\'s claims');
  console.log('true, and no EP-SCITT-STATEMENT-v1 statement has been submitted to any log.');
}
