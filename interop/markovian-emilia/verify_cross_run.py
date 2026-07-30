#!/usr/bin/env python3
"""Offline verifier for MARKOVIAN-CROSS-RUN-20260729-001.

Usage: verify_cross_run.py MARKOVIAN-CROSS-RUN-20260729-001.json

Verifies, with no network access:
  1. the canonical typed leaf's digest, and the preserved source receipt's
     digest (reported separately; the two are NOT interchangeable);
  2. RFC 6962 inclusion: the leaf at index 4869 folds to the inclusion head's
     root at its tree size;
  3. the inclusion head's signed note: log Ed25519 signature + witness
     cosignatures (c2sp.org/tlog-cosignature v1), quorum over pinned keys only;
  4. RFC 6962 consistency: inclusion head is a prefix of the next witnessed
     head (append-only, nothing rewritten);
  5. the next head's signed note, same rule as 3.

Exit 0 = all green. Needs: python3, cryptography.
"""
import sys, json, base64, hashlib, re, struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def H(b): return hashlib.sha256(b).digest()
def hc(l, r): return H(b"\x01" + l + r)

def verify_inclusion(index, size, leaf_hash, root, proof):
    if index >= size: return False
    fn, sn = index, size - 1
    r = leaf_hash
    for c in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            r = hc(c, r)
            while not (fn == 0 or fn & 1):
                fn >>= 1; sn >>= 1
        else:
            r = hc(r, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root

def verify_consistency(first, second, first_hash, second_hash, proof):
    if first < 1 or first >= second: return False
    p = list(proof)
    if first & (first - 1) == 0:
        p = [first_hash] + p
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    if not p: return False
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = hc(c, fr); sr = hc(c, sr)
            while not (fn == 0 or fn & 1):
                fn >>= 1; sn >>= 1
        else:
            sr = hc(sr, c)
        fn >>= 1; sn >>= 1
    return fr == first_hash and sr == second_hash and sn == 0

def parse_vkey(vk):
    m = re.match(r"^(.+)\+([0-9a-f]{8})\+(.+)$", vk)
    name, khex, kb = m.group(1), m.group(2), base64.b64decode(m.group(3))
    alg, key = kb[0], kb[1:]
    keyhash = H(name.encode() + b"\n" + kb)[:4]
    assert keyhash.hex() == khex, f"vkey self-check failed for {name}"
    return name, alg, key, keyhash

def split_note(note):
    body_end = note.index("\n\n") + 1
    body = note[:body_end]
    sigs = []
    for line in note[body_end:].splitlines():
        line = line.strip()
        if not line.startswith("— "): continue
        _, name, blob = line.split(" ", 2)
        sigs.append((name, base64.b64decode(blob)))
    return body, sigs

def verify_note(note, log_vkey, witness_vkeys):
    if isinstance(log_vkey, dict):
        log_vkey = log_vkey["vkey"]
    body, sigs = split_note(note)
    lname, lalg, lkey, lhash = parse_vkey(log_vkey)
    log_ok, seen = False, set()
    for name, blob in sigs:
        kh, rest = blob[:4], blob[4:]
        if name == lname and kh == lhash and lalg == 0x01 and len(rest) == 64:
            try:
                Ed25519PublicKey.from_public_bytes(lkey).verify(rest, body.encode())
                log_ok = True
            except InvalidSignature:
                return False, 0, "log signature INVALID"
            continue
        for wname, walg, wkey, whash in witness_vkeys:
            if name == wname and kh == whash and walg == 0x04 and len(rest) == 72:
                ts = struct.unpack(">Q", rest[:8])[0]
                msg = f"cosignature/v1\ntime {ts}\n{body}".encode()
                try:
                    Ed25519PublicKey.from_public_bytes(wkey).verify(rest[8:], msg)
                    seen.add(wname)
                except InvalidSignature:
                    return False, len(seen), f"cosignature INVALID for {wname}"
    return log_ok, len(seen), "ok"

def main():
    V = json.load(open(sys.argv[1]))
    wit = [parse_vkey(w) for w in V["witnesses"]]
    n_wit = len(wit)
    failures = []
    def check(label, ok):
        print(("PASS  " if ok else "FAIL  ") + label)
        if not ok: failures.append(label)

    src = base64.b64decode(V["source_receipt"]["b64"])
    leaf = base64.b64decode(V["typed_leaf"]["b64"])
    check("source receipt sha256 matches",
          hashlib.sha256(src).hexdigest() == V["source_receipt"]["sha256"])
    check("canonical leaf sha256 matches",
          hashlib.sha256(leaf).hexdigest() == V["typed_leaf"]["sha256"])
    check("source and canonical leaf are distinct byte strings (as declared)",
          (src != leaf) and not V.get("source_equals_canonical", False))

    h1 = V["inclusion_head"]; h2 = V["next_witnessed_head"]
    h1_root = base64.b64decode(h1["root_hash_b64"])
    h2_root = base64.b64decode(h2["root_hash_b64"])
    incl = [base64.b64decode(x) for x in V["inclusion"]["nodes_b64"]]
    cons = [base64.b64decode(x) for x in V["consistency_proof"]["nodes_b64"]]

    leaf_hash = H(b"\x00" + leaf)
    check(f"RFC6962 inclusion: leaf {V['typed_leaf']['leaf_index']} in root@{h1['tree_size']}",
          verify_inclusion(V["typed_leaf"]["leaf_index"], h1["tree_size"],
                           leaf_hash, h1_root, incl))

    ok, quorum, msg = verify_note(h1["signed_note"], V["log"], wit)
    check(f"inclusion head note: log signature valid ({msg})", ok)
    check(f"inclusion head note: witness quorum {quorum}/{n_wit}", quorum == n_wit)

    check(f"RFC6962 consistency {h1['tree_size']} -> {h2['tree_size']}",
          verify_consistency(h1["tree_size"], h2["tree_size"], h1_root, h2_root, cons))

    ok2, quorum2, msg2 = verify_note(h2["signed_note"], V["log"], wit)
    check(f"next head note: log signature valid ({msg2})", ok2)
    check(f"next head note: witness quorum {quorum2}/{n_wit}", quorum2 == n_wit)

    print()
    if failures:
        print("RESULT: FAIL —", len(failures), "check(s) failed")
        sys.exit(1)
    print("RESULT: PASS — all checks green")
    sys.exit(0)

if __name__ == "__main__":
    main()
