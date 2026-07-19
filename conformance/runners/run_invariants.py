# SPDX-License-Identifier: Apache-2.0
#
# TLA+-invariant cross-language conformance runner — Python lane.
#
# This lane replays the shared, language-agnostic invariant corpus
# (conformance/invariants.json) against a faithful Python port of the two
# production state machines that the JavaScript lane
# (conformance/runners/run-invariants.mjs) drives:
#
#   * capability domain -> the reserve/commit accounting of
#       createMemoryCapabilityStore in packages/gate/capability-receipt.js
#       (registerCapability / reserveSpend / commitSpend / getState /
#        getOperation, source lines 431-490). Ported below as _CapabilityStore.
#   * handshake domain  -> the pure guard functions in
#       lib/handshake/invariants.js (checkNoDuplicateResult /
#       checkResultImmutability / checkNotExpired / checkBindingValid,
#       source lines 96-309). Ported below as the check_* functions.
#
# WHAT IS AND IS NOT PORTED (honesty note). The invariants under test are
# ACCOUNTING and PREDICATE properties: a budget identity, single-commit,
# commit-requires-reserve, monotonic consumption, and the four handshake
# guards. None of them is a property of the Ed25519 capability envelope or of
# the durable Postgres store. So this port reimplements ONLY that ~30-line
# accounting logic and those pure predicates. It does NOT reimplement the
# receipt crypto or the durable store: capabilities are registered directly by
# (budget, expiry, fingerprint), exactly the shape createMemoryCapabilityStore
# holds internally after it verifies and unwraps the signed envelope. The JS
# lane's Ed25519 minting is only harness setup to obtain a registered
# capability; it does not change any accounting outcome asserted by the corpus.
#
# WHY THIS IS REAL CROSS-PORT CONFORMANCE. This is a third independent
# implementation (JS, Python, Go) of the same state machine, each checked
# against the same TLA+-derived corpus of expected outcomes. If this port's
# logic diverged from the specification the corpus would flag it (a FAIL); its
# agreement is genuine tri-lingual agreement, not a self-check. Every reason /
# code the corpus asserts (budget_exceeded, capability_expired,
# capability_operation_already_finalized, operation_already_committed,
# capability_operation_not_found, capability_reservation_owner_mismatch, and
# the handshake codes) is produced here by faithfully-ported branch logic.
#
#   python3 conformance/runners/run_invariants.py [path/to/invariants.json]
#   python3 conformance/runners/run_invariants.py --json
#
# Exit 0 iff every case holds; exit 1 on any divergence.

import datetime
import json
import os
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CORPUS = os.path.join(HERE, "..", "invariants.json")


class DivergenceError(Exception):
    pass


# ── Capability domain: faithful port of createMemoryCapabilityStore ──────────
# Mirrors packages/gate/capability-receipt.js reserveSpend (lines 450-467) and
# commitSpend (lines 468-480), including the exact refusal-reason ordering.


class _CapabilityStore:
    def __init__(self):
        self._states = {}      # capability_id -> state dict
        self._operations = {}  # operation_id  -> operation dict

    def register(self, capability_id, budget_amount, currency, expires_at, fingerprint):
        # Direct registration of the unwrapped capability state (see honesty
        # note at the top of the file). Mirrors capabilityStateFromEnvelope +
        # registerCapability once the envelope has been verified/unwrapped.
        existing = self._states.get(capability_id)
        if existing is not None:
            return (
                existing["capability_fingerprint"] == fingerprint
                and existing["budget_amount"] == budget_amount
                and existing["currency"] == currency
                and existing["expires_at"] == expires_at
            )
        self._states[capability_id] = {
            "capability_id": capability_id,
            "capability_fingerprint": fingerprint,
            "budget_amount": budget_amount,
            "currency": currency,
            "expires_at": expires_at,
            "consumed_amount": 0,
            "reserved_amount": 0,
        }
        return True

    def reserve_spend(self, capability_id, capability_fingerprint, operation_id, amount, currency, now):
        state = self._states.get(capability_id)
        if state is None:
            return {"ok": False, "reason": "capability_not_registered"}
        if state["capability_fingerprint"] != capability_fingerprint:
            return {"ok": False, "reason": "capability_envelope_mismatch"}
        existing = self._operations.get(operation_id)
        if existing is not None:
            reason = "operation_in_flight" if existing["status"] == "reserved" else "operation_already_committed"
            return {"ok": False, "reason": reason}
        if now >= state["expires_at"]:
            return {"ok": False, "reason": "capability_expired"}
        if currency != state["currency"]:
            return {"ok": False, "reason": "currency_mismatch"}
        if state["consumed_amount"] + state["reserved_amount"] + amount > state["budget_amount"]:
            return {"ok": False, "reason": "budget_exceeded"}
        token = str(uuid.uuid4())
        self._operations[operation_id] = {
            "capability_id": capability_id,
            "amount": amount,
            "currency": currency,
            "status": "reserved",
            "reservation_token": token,
        }
        state["reserved_amount"] += amount
        return {
            "ok": True,
            "operation_id": operation_id,
            "reservation_token": token,
            "remaining": state["budget_amount"] - state["consumed_amount"] - state["reserved_amount"],
        }

    def commit_spend(self, capability_id, operation_id, reservation_token, now):
        operation = self._operations.get(operation_id)
        state = self._states.get(capability_id)
        if operation is None or state is None or operation["capability_id"] != capability_id:
            return {"ok": False, "reason": "capability_operation_not_found"}
        if operation["status"] != "reserved":
            return {"ok": False, "reason": "capability_operation_already_finalized"}
        if operation["reservation_token"] != reservation_token:
            return {"ok": False, "reason": "capability_reservation_owner_mismatch"}
        operation["status"] = "committed"
        state["reserved_amount"] -= operation["amount"]
        state["consumed_amount"] += operation["amount"]
        return {
            "ok": True,
            "consumed": state["consumed_amount"],
            "remaining": state["budget_amount"] - state["consumed_amount"] - state["reserved_amount"],
        }

    def get_state(self, capability_id):
        return self._states.get(capability_id)

    def get_operation(self, operation_id):
        return self._operations.get(operation_id)


# ── Handshake domain: faithful port of lib/handshake/invariants.js ───────────


def _pass(code):
    return {"ok": True, "code": code, "message": "ok"}


def _fail(code, message):
    return {"ok": False, "code": code, "message": message}


def check_not_expired(handshake):
    code = "BINDING_EXPIRED"
    binding = (handshake or {}).get("binding") if handshake else None
    if not handshake or not binding or not binding.get("expires_at"):
        return _fail(code, "Handshake binding or expiry is missing")
    expires_at = _parse_iso(binding["expires_at"])
    if _now_utc() >= expires_at:
        return _fail(code, "Handshake binding has expired")
    return _pass(code)


def check_binding_valid(binding, verification_payload_hash):
    code = "BINDING_INVALID"
    if not binding:
        return _fail(code, "Binding is missing")
    if not binding.get("nonce"):
        return _fail(code, "Binding nonce is missing")
    if binding.get("payload_hash"):
        if not verification_payload_hash:
            return _fail(code, "Binding has payload_hash but verificationPayloadHash was not provided")
        if binding["payload_hash"] != verification_payload_hash:
            return _fail(code, "Payload hash mismatch")
    return _pass(code)


def check_no_duplicate_result(existing_results, binding_hash):
    code = "DUPLICATE_RESULT"
    if not existing_results:
        return _pass(code)
    for r in existing_results:
        if r.get("outcome") == "accepted" and r.get("binding_hash") == binding_hash:
            return _fail(code, "An accepted result with the same binding hash already exists")
    return _pass(code)


def check_result_immutability(existing_result):
    code = "RESULT_IMMUTABLE"
    if not existing_result:
        return _pass(code)
    if existing_result.get("outcome") in ("accepted", "rejected"):
        return _fail(code, "Result is finalized and cannot be modified")
    return _pass(code)


def _parse_iso(value):
    # invariants.json expiries are RFC3339 with a trailing 'Z'.
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


# ── Shared assertion (mirrors assertExpect in the JS lane) ───────────────────


def assert_expect(idx, observed, expect):
    if not expect:
        return
    if isinstance(expect.get("ok"), bool) and bool(observed.get("ok")) != expect["ok"]:
        got = observed.get("reason") or observed.get("code") or "none"
        raise DivergenceError(
            f"action[{idx}]: expected ok={expect['ok']}, got ok={bool(observed.get('ok'))} (reason={got})"
        )
    if expect.get("reason") and observed.get("reason") != expect["reason"]:
        raise DivergenceError(
            f"action[{idx}]: expected reason={expect['reason']}, got reason={observed.get('reason') or 'none'}"
        )
    if expect.get("code") and observed.get("code") != expect["code"]:
        raise DivergenceError(
            f"action[{idx}]: expected code={expect['code']}, got code={observed.get('code') or 'none'}"
        )


# ── Case harnesses (mirror runCapabilityCase / runHandshakeCase) ─────────────


def run_capability_case(case, now_base):
    store = _CapabilityStore()
    caps = {}            # logical name -> {capability_id, fingerprint}
    tokens = {}          # operation id -> reservation token
    committed_amt = {}   # capability_id -> oracle sum of committed op amounts
    consumed_seen = {}   # capability_id -> last observed consumed (monotonicity)
    reg_counter = [0]

    def observe_monotonic(capability_id):
        s = store.get_state(capability_id)
        if s is None:
            return
        prev = consumed_seen.get(capability_id, 0)
        if s["consumed_amount"] < prev:
            raise DivergenceError(
                f"consumed decreased {prev} -> {s['consumed_amount']} (ConsumptionMonotonic violated)"
            )
        consumed_seen[capability_id] = s["consumed_amount"]

    def find_cap_id(name):
        if name and name in caps:
            return caps[name]["capability_id"]
        if len(caps) == 1:
            return next(iter(caps.values()))["capability_id"]
        raise DivergenceError("commit action could not resolve its capability")

    for i, a in enumerate(case["actions"]):
        at = now_base + a.get("atMs", 0)
        do = a["do"]
        if do == "register":
            reg_counter[0] += 1
            cap_id = f"{a['capability']}#{reg_counter[0]}"
            fingerprint = f"sha256:{'0' * 64}"
            store.register(cap_id, a["budget"], a.get("currency", "USD"),
                           now_base + a["expiryMs"], fingerprint)
            caps[a["capability"]] = {"capability_id": cap_id, "fingerprint": fingerprint}
            committed_amt[cap_id] = 0
            observe_monotonic(cap_id)
        elif do == "reserve":
            cap = caps[a["capability"]]
            res = store.reserve_spend(cap["capability_id"], cap["fingerprint"], a["operation"],
                                      a["amount"], a.get("currency", "USD"), at)
            assert_expect(i, res, a.get("expect"))
            if res["ok"]:
                tokens[a["operation"]] = res["reservation_token"]
            observe_monotonic(cap["capability_id"])
        elif do == "commit":
            op = store.get_operation(a["operation"])
            capability_id = op["capability_id"] if op else find_cap_id(a.get("capability"))
            res = store.commit_spend(capability_id, a["operation"], tokens.get(a["operation"]), at)
            assert_expect(i, res, a.get("expect"))
            if res["ok"]:
                committed_amt[capability_id] = committed_amt.get(capability_id, 0) + op["amount"]
            observe_monotonic(capability_id)
        elif do == "commitRaw":
            cap = caps[a["capability"]]
            res = store.commit_spend(cap["capability_id"], a["operation"], a.get("token"), at)
            assert_expect(i, res, a.get("expect"))
            observe_monotonic(cap["capability_id"])
        else:
            raise DivergenceError(f"unknown capability action: {do}")

    structural = case.get("structural")
    if structural:
        cap = caps[structural["capability"]]
        state = store.get_state(cap["capability_id"])
        pred = structural["predicate"]
        if pred == "reserve_within_budget":
            if state["consumed_amount"] + state["reserved_amount"] > state["budget_amount"]:
                raise DivergenceError(
                    f"consumed({state['consumed_amount']}) + reserved({state['reserved_amount']}) "
                    f"> budget({state['budget_amount']})"
                )
        elif pred == "consumed_is_committed_sum":
            expected = committed_amt.get(cap["capability_id"], 0)
            if state["consumed_amount"] != expected:
                raise DivergenceError(
                    f"consumed({state['consumed_amount']}) != sum of committed ops({expected})"
                )
        elif pred == "consumption_monotonic":
            pass  # enforced step-by-step via observe_monotonic
        else:
            raise DivergenceError(f"unknown structural predicate: {pred}")


def run_handshake_case(case):
    for i, a in enumerate(case["actions"]):
        do = a["do"]
        if do == "check_no_duplicate_result":
            res = check_no_duplicate_result(a["existingResults"], a["bindingHash"])
        elif do == "check_result_immutability":
            res = check_result_immutability(a["existingResult"])
        elif do == "check_not_expired":
            res = check_not_expired(a["handshake"])
        elif do == "check_binding_valid":
            res = check_binding_valid(a["binding"], a.get("verificationPayloadHash"))
        else:
            raise DivergenceError(f"unknown handshake action: {do}")
        assert_expect(i, res, a.get("expect"))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv[1:]
    corpus_path = args[0] if args else DEFAULT_CORPUS
    with open(corpus_path, "r", encoding="utf-8") as fh:
        corpus = json.load(fh)

    now_base = int(_parse_iso(corpus.get("baselineNowIso", "2026-07-18T22:00:00.000Z")).timestamp() * 1000)

    results = []
    failures = 0
    skipped = 0
    for inv in corpus["invariants"]:
        for case in inv["cases"]:
            cid = f"{inv['invariant']}/{case['name']}"
            try:
                if inv["domain"] == "capability":
                    run_capability_case(case, now_base)
                elif inv["domain"] == "handshake":
                    run_handshake_case(case)
                else:
                    raise DivergenceError(f"unknown domain: {inv['domain']}")
                results.append({"id": cid, "spec": inv["spec"], "status": "hold"})
            except DivergenceError as err:
                failures += 1
                results.append({"id": cid, "spec": inv["spec"], "status": "DIVERGED", "detail": str(err)})

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print(f"EP invariant conformance — Python lane ({len(results)} cases from {corpus_path})\n")
        for r in results:
            mark = "  ok " if r["status"] == "hold" else " FAIL"
            line = f"{mark}  {r['id']:<52} {r['spec']}"
            if r.get("detail"):
                line += f"\n        -> {r['detail']}"
            print(line)
        held = len(results) - failures
        print(f"\n{held}/{len(results)} invariant cases hold. ({skipped} skipped)")
        if failures:
            print(f"{failures} CROSS-PORT/CONFORMANCE DIVERGENCE(S) — investigate before merge.")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
