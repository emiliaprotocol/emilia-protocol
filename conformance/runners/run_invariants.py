# SPDX-License-Identifier: Apache-2.0
#
# TLA+-invariant cross-language conformance runner — Python lane (SCAFFOLD).
#
# STATUS: SCAFFOLDED, NOT WIRED. This lane parses the shared invariant corpus
# (conformance/invariants.json) and dispatches every case by domain, exactly as
# the JavaScript lane (conformance/runners/run-invariants.mjs) does, so that when
# the state machines gain Python ports this file drives them with zero corpus
# changes and any cross-port divergence surfaces immediately.
#
# WIRING BLOCKER (precise): the invariants are STATE-MACHINE properties, not
# receipt-verification properties. Driving them in Python requires a Python port
# of the two production state machines the JS lane drives:
#   * capability domain -> createMemoryCapabilityStore (register/reserveSpend/
#                          commitSpend) in packages/gate/capability-receipt.js
#   * handshake domain  -> checkNoDuplicateResult / checkResultImmutability /
#                          checkNotExpired / checkBindingValid in
#                          lib/handshake/invariants.js
# packages/python-verify/emilia_verify today verifies RECEIPT vectors only; it
# has NO capability store and NO handshake invariant module. Until such a port
# exists, wiring this lane would mean re-implementing the state machines here,
# which is a NEW implementation the author writes — it cannot honestly detect a
# divergence from itself. So this lane is intentionally left unwired and reports
# each case as SKIPPED(unwired) rather than fabricating a pass.
#
# When a Python port lands (proposed: packages/python-verify/emilia_verify/
# capability_store.py and .../handshake_invariants.py), replace the dispatch
# bodies below and flip UNWIRED = False.
#
#   python3 conformance/runners/run_invariants.py [path/to/invariants.json]
#
# Exit codes: 0 = every case executed and held; 2 = lane is unwired (default
# today) so it can never be mistaken for a passing conformance lane.

import json
import os
import sys

UNWIRED = True  # flip to False once the Python state-machine ports exist.

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(HERE, "..", "invariants.json")


def run_capability_case(case):
    # TODO(python-port): drive a Python createMemoryCapabilityStore equivalent.
    raise NotImplementedError("capability store has no Python port")


def run_handshake_case(case):
    # TODO(python-port): drive Python ports of the handshake invariant guards.
    raise NotImplementedError("handshake invariants have no Python port")


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    corpus_path = argv[0] if argv else DEFAULT_CORPUS
    with open(corpus_path, "r", encoding="utf-8") as fh:
        corpus = json.load(fh)

    total = sum(len(inv["cases"]) for inv in corpus["invariants"])
    if UNWIRED:
        print("EP invariant conformance — Python lane: SCAFFOLD (UNWIRED)")
        print(f"  parsed {total} cases across {len(corpus['invariants'])} invariants from {corpus_path}")
        print("  no Python port of the capability store / handshake invariants exists yet;")
        print("  see the wiring blocker at the top of this file. Reporting SKIPPED(unwired).")
        sys.exit(2)

    failures = 0
    for inv in corpus["invariants"]:
        for case in inv["cases"]:
            cid = f"{inv['invariant']}/{case['name']}"
            try:
                if inv["domain"] == "capability":
                    run_capability_case(case)
                elif inv["domain"] == "handshake":
                    run_handshake_case(case)
                else:
                    raise ValueError(f"unknown domain: {inv['domain']}")
                print(f"  ok   {cid}  {inv['spec']}")
            except Exception as err:  # noqa: BLE001 — report every divergence
                failures += 1
                print(f" FAIL  {cid}  {inv['spec']}\n        -> {err}")
    print(f"\n{total - failures}/{total} invariant cases hold.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
