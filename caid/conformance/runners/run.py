# SPDX-License-Identifier: Apache-2.0
#
# Python conformance runner for the CAID core corpus (vectors.json,
# version 5) and the grammar boundary corpus (grammar-vectors.json). It
# drives an implementation only through its public entry points.
#
#   python3 caid/conformance/runners/run.py [--impl DIR] [--corpus core|grammar|all]
#                                           [--json]
#
# --impl is the directory holding the caid module (default
# caid/impl/python). The entry points used are named in API below; all of
# them are required. Standard library only.

import argparse
import base64
import importlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CONFORMANCE = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(CONFORMANCE))

ap = argparse.ArgumentParser()
ap.add_argument("--impl", default=os.path.join(ROOT, "caid", "impl", "python"))
ap.add_argument("--corpus", default="all", choices=["core", "grammar", "all"])
ap.add_argument("--json", action="store_true")
ns = ap.parse_args()

sys.path.insert(0, os.path.abspath(ns.impl))
port = importlib.import_module("caid")

# ---------------------------------------------------------------- API
missing = []


def need(name, *candidates):
    for c in candidates:
        fn = getattr(port, c, None)
        if callable(fn):
            return fn
    missing.append(name)
    return None


API = {
    "decode": need("decode_caid_json", "decode_caid_json"),
    "compute_json": need("compute_caid_json", "compute_caid_json"),
    "verify_json": need("verify_caid_json", "verify_caid_json"),
    "compute": need("compute_caid", "compute_caid"),
    "verify": need("verify_caid", "verify_caid"),
    "parse": need("parse_caid", "parse_caid"),
    "definition_sha256": need("definition_sha256", "definition_sha256"),
}
# ---------------------------------------------------------------- native lane
sys.path.insert(0, HERE)
from native_lane import build_native, units_to_str  # noqa: E402


def input_bytes(inp):
    if "json" in inp:
        return inp["json"].encode("utf-8")
    if "json_b64" in inp:
        return base64.b64decode(inp["json_b64"])
    if "json_repeat" in inp:
        r = inp["json_repeat"]
        return r["prefix"].encode("utf-8") + r["unit"].encode("utf-8") * int(r["count"]) + r["suffix"].encode("utf-8")
    return None


# ---------------------------------------------------------------- helpers
def norm(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=repr)


def guard(fn):
    try:
        return fn()
    except BaseException as e:  # a conforming port never raises
        return {"thrown": type(e).__name__ + ": " + str(e)[:200]}


def read_corpus(name):
    with open(os.path.join(CONFORMANCE, name), "rb") as fh:
        data = fh.read()
    if API["decode"] is not None:
        d = API["decode"](data)
        if isinstance(d, dict) and d.get("ok") is True:
            return d["value"]
    return json.loads(data.decode("utf-8"))


results = []
counts = {"pass": 0, "fail": 0}
per_corpus = {}


def report(corpus, vid, ok, detail=None):
    pc = per_corpus.setdefault(corpus, {"pass": 0, "fail": 0})
    if ok:
        counts["pass"] += 1
        pc["pass"] += 1
    else:
        counts["fail"] += 1
        pc["fail"] += 1
        results.append({"corpus": corpus, "id": vid, "detail": detail})


# ---------------------------------------------------------------- core corpus
def run_core():
    corpus = read_corpus("vectors.json")
    if corpus.get("version") != 5:
        report("core", "(corpus)", False, "expected corpus version 5")
        return
    snapshots = corpus["enum_snapshots"]
    caids = {}
    for v in corpus["vectors"]:
        inp = v["input"]
        kind = v["kind"]
        opts = {"definitions": v.get("definitions"), "enum_snapshots": snapshots}
        if kind == "compute" and "suite" in inp:
            opts["suite"] = inp["suite"]
        if kind == "verify" and "expected_definition_sha256" in inp:
            opts["expected_definition_sha256"] = inp["expected_definition_sha256"]
        parity = None
        elapsed = 0.0
        if kind == "decode":
            r = guard(lambda: API["decode"](input_bytes(inp)))
            if isinstance(r, dict) and r.get("ok") is True:
                actual = {"ok": True}
            elif isinstance(r, dict) and r.get("ok") is False:
                actual = {"ok": False, "refusals": r.get("refusals")}
            else:
                actual = r
        elif kind == "parse":
            actual = guard(lambda: API["parse"](inp["caid"]))
        elif kind == "definition":
            actual = guard(lambda: API["definition_sha256"](inp["definition"]))
        elif "native" in inp:
            host = build_native(inp["native"])
            opts["definitions"] = build_native(v.get("definitions"))
            if kind == "compute":
                actual = guard(lambda: API["compute"](host, opts))
            else:
                actual = guard(lambda: API["verify"](host, inp["caid"], opts))
        else:
            data = input_bytes(inp)
            t0 = time.perf_counter()
            if kind == "compute":
                actual = guard(lambda: API["compute_json"](data, opts))
            else:
                actual = guard(lambda: API["verify_json"](data, inp["caid"], opts))
            elapsed = (time.perf_counter() - t0) * 1000
            d = guard(lambda: API["decode"](data))
            if isinstance(d, dict) and d.get("ok") is True:
                if kind == "compute":
                    n = guard(lambda: API["compute"](d["value"], opts))
                else:
                    n = guard(lambda: API["verify"](d["value"], inp["caid"], opts))
                if norm(n) != norm(actual):
                    parity = "native entry point on the decoded value gave " + norm(n)[:300]
        if kind == "compute" and isinstance(actual, dict) and isinstance(actual.get("caid"), str):
            caids[v["id"]] = actual["caid"]
        ok = norm(actual) == norm(v["expect"])
        detail = None if ok else "expected " + norm(v["expect"])[:400] + " got " + norm(actual)[:400]
        report("core", v["id"], ok and not parity, detail or parity)
        budget = v.get("time_budget_ms")
        if budget and elapsed > budget:
            report("core", v["id"] + " (time)", False, "%d ms exceeds the %d ms budget" % (elapsed, budget))
    for v in corpus["vectors"]:
        rel = v.get("relation")
        if not rel:
            continue
        other = rel.get("same_caid_as") or rel.get("different_caid_from")
        a, b = caids.get(v["id"]), caids.get(other)
        ok = a is not None and b is not None and ((a == b) if "same_caid_as" in rel else (a != b))
        report("core", v["id"] + " (relation " + other + ")", ok, None if ok else "%s vs %s" % (a, b))


# ---------------------------------------------------------------- grammar corpus
def substitute(template, value):
    if template == "$CASE":
        return value
    if isinstance(template, list):
        return [substitute(x, value) for x in template]
    if isinstance(template, dict):
        return {(value if k == "$CASE" else k): substitute(x, value) for k, x in template.items()}
    return template


def case_string(c):
    if isinstance(c, str):
        return c
    if "$units" in c:
        return units_to_str(c["$units"])
    if "repeat" in c:
        r = c["repeat"]
        return r["prefix"] + r["unit"] * int(r["count"]) + r["suffix"]
    return None


def to_json_bytes(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def run_grammar():
    corpus = read_corpus("grammar-vectors.json")
    placeholder = corpus["placeholder"]
    for index, c in enumerate(corpus["cases"]):
        d = corpus["drivers"][c["driver"]]
        vid = "grammar[%d] %s %s" % (index, c["driver"], c["lane"])
        if d["operation"] == "parse":
            actual = guard(lambda: API["parse"](d["caid"]["prefix"] + case_string(c["case"]) + d["caid"]["suffix"]))
        else:
            s = placeholder if c["lane"] == "bytes" else case_string(c["case"])
            definition = substitute(d["definition"], s)
            obj = substitute(d["object"], s)
            opts = {"definitions": [definition], "enum_snapshots": [], "suite": s if d.get("suite") == "$CASE" else "jcs-sha256"}
            if c["lane"] == "native":
                actual = guard(lambda: API["compute"](obj, opts))
            else:
                if c["lane"] == "bytes":
                    raw = base64.b64decode(c["case"]["b64"])
                    data = raw.join(to_json_bytes(obj).split(placeholder.encode("ascii")))
                else:
                    data = to_json_bytes(obj)
                actual = guard(lambda: API["compute_json"](data, opts))
                if c["lane"] == "text":
                    dec = guard(lambda: API["decode"](data))
                    if isinstance(dec, dict) and dec.get("ok") is True:
                        n = guard(lambda: API["compute"](dec["value"], opts))
                        if norm(n) != norm(actual):
                            report("grammar", vid, False, "native parity: %s vs %s" % (norm(n)[:200], norm(actual)[:200]))
                            continue
            if isinstance(actual, dict) and isinstance(actual.get("caid"), str) and "caid" in c["expect"]:
                actual = {"caid": actual["caid"]}
        ok = norm(actual) == norm(c["expect"])
        report("grammar", vid, ok, None if ok else "case %s: expected %s got %s" % (norm(c["case"])[:80], norm(c["expect"])[:200], norm(actual)[:200]))


# ---------------------------------------------------------------- main
if missing:
    print("FAIL %s lacks the entry points %s (see caid/conformance/README.md)" % (ns.impl, ", ".join(missing)), file=sys.stderr)
    sys.exit(1)
if ns.corpus in ("core", "all"):
    run_core()
if ns.corpus in ("grammar", "all"):
    run_grammar()
summary = {
    "runner": "python",
    "impl": os.path.relpath(os.path.abspath(ns.impl), ROOT),
    "corpus": ns.corpus,
    "pass": counts["pass"],
    "fail": counts["fail"],
    "per_corpus": per_corpus,
    "failures": results[:500],
}
if ns.json:
    sys.stdout.write(json.dumps(summary, ensure_ascii=True) + "\n")
else:
    for r in results[:60]:
        print("FAIL %s %s\n     %s" % (r["corpus"], r["id"], r["detail"]))
    if len(results) > 60:
        print("... %d more failures" % (len(results) - 60))
    print("%s %s (%s): %d passed, %d failed %s" % (
        summary["runner"], summary["impl"], ns.corpus, counts["pass"], counts["fail"], json.dumps(per_corpus)))
sys.exit(1 if counts["fail"] else 0)
