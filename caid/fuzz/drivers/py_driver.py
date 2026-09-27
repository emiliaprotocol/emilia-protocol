# SPDX-License-Identifier: Apache-2.0
# CAID differential fuzz driver: Python lane.
#
# Reads JSON-lines cases on stdin, writes one JSON line per case on stdout:
#   {"id": ..., "r": {"py": <outcome>}}
#
# Objects under test ("obj", base64 octets) go to the JSON text entry
# points (compute_caid_json, verify_caid_json). When the octets decode
# (decode_caid_json), the native entry point also runs on the decoded value
# and a different result is reported as "parity". "native" cases go to
# compute_caid and verify_caid. Mapping sources in "src" are decoded with
# decode_caid_json; a refusal is {"json_error": true}.
# Standard library only.
#
# Usage: python3 py_driver.py --root <tree root> --tables <tables.json>

import argparse
import base64
import json
import os
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--root", required=True)
ap.add_argument("--tables", required=True)
ns = ap.parse_args()

sys.path.insert(0, os.path.join(os.path.abspath(ns.root), "caid", "impl", "python"))
import caid as core  # noqa: E402
import mapping as cmap  # noqa: E402

with open(ns.tables, "r", encoding="utf-8") as fh:
    TABLES = json.load(fh)

decode = core.decode_caid_json
compute_json = core.compute_caid_json
verify_json = core.verify_caid_json


# ---------------------------------------------------------------- native lane
# The builder the conformance runner uses, from this harness checkout.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "conformance", "runners"))
from native_lane import build_native  # noqa: E402


def resolve(c, inline_key, ref_key, table):
    if ref_key in c:
        return TABLES[table][c[ref_key]]
    return c.get(inline_key)


def stable(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=True, default=repr)


def norm_map(r):
    if not isinstance(r, dict):
        return {"bad_result": True}
    if r.get("ok") is True:
        return {"ok": True, "caid": r.get("caid"), "digest": r.get("digest")}
    return {"ok": False, "reasons": r.get("reasons")}


def run_case(c):
    defs = resolve(c, "defs", "defs_ref", "defs")
    if c.get("defs_native"):
        defs = build_native(defs)
    snaps = resolve(c, "snaps", "snaps_ref", "snaps")
    op = c["op"]
    try:
        copts = {"definitions": defs, "enum_snapshots": snaps}
        if "suite" in c:
            copts["suite"] = c["suite"]
        vopts = {"definitions": defs, "enum_snapshots": snaps}
        if "expected" in c:
            vopts["expected_definition_sha256"] = c["expected"]
        if op in ("compute", "verify"):
            def run(native, value):
                if op == "compute":
                    return core.compute_caid(value, copts) if native else compute_json(value, copts)
                return core.verify_caid(value, c.get("caid"), vopts) if native else verify_json(value, c.get("caid"), vopts)
            if "native" in c:
                return run(True, build_native(c["native"]))
            data = base64.b64decode(c["obj"])
            out = run(False, data)
            d = decode(data)
            if isinstance(d, dict) and d.get("ok") is True:
                n = run(True, d["value"])
                if stable(n) != stable(out):
                    out = dict(out) if isinstance(out, dict) else {"result": out}
                    out["parity"] = n
            return out
        if op == "parse":
            return core.parse_caid(c.get("caid"))
        if op == "definition":
            d = c.get("definition")
            return core.definition_sha256(build_native(d) if c.get("definition_native") else d)
        if op == "canon":
            return core.canonicalize(build_native(c.get("native")))
        if op == "map":
            source = c.get("source")
            if "src" in c:
                d = decode(base64.b64decode(c["src"]))
                if not (isinstance(d, dict) and d.get("ok") is True):
                    return {"json_error": True}
                source = d["value"]
            kwargs = dict(
                profile=c.get("profile"),
                source_descriptor=c.get("desc"),
                expected_profile_hash=c.get("pin"),
                native_verified=c.get("nv", False),
                definitions=defs,
                enum_snapshots=snaps,
            )
            if "suite" in c:
                kwargs["suite"] = c["suite"]
            return norm_map(cmap.map_action(source, **kwargs))
        if op == "compare":
            kwargs = dict(definitions=defs, enum_snapshots=snaps)
            if "suite" in c:
                kwargs["suite"] = c["suite"]
            r = cmap.compare_mapped_actions(c.get("left"), c.get("right"), **kwargs)
            return {"verdict": r["verdict"], "reasons": r["reasons"], "left": norm_map(r["left"]), "right": norm_map(r["right"])}
        return {"driver_error": "unknown op " + str(op)}
    except BaseException as e:  # a conforming port never raises
        return {"crash": type(e).__name__}


def main():
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 1000))
    out = sys.stdout
    buf = []
    for raw_line in sys.stdin.buffer:  # binary: split on b"\n" only
        raw_line = raw_line.rstrip(b"\n")
        if not raw_line:
            continue
        c = json.loads(raw_line.decode("utf-8"))
        buf.append(json.dumps({"id": c["id"], "r": {"py": run_case(c)}}, ensure_ascii=True, default=repr) + "\n")
        if len(buf) >= 256:
            out.write("".join(buf))
            buf.clear()
    out.write("".join(buf))
    out.flush()


main()
