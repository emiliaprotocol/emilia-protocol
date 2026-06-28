#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Laptop-on-fire — agent context-handoff as a verifiable receipt chain.

ONE primitive, TWO trust boundaries. A signed, offline-verifiable receipt is the
same object whether it spans the operator<->auditor boundary (GRACE / distributed
-trace audit) or the agent<->agent context-handoff boundary (this demo). The
receiver never trusts the runtime's memory; it verifies the chain.

The story:
  An agent runs a multi-step task, writing a receipt to disk BEFORE and AFTER each
  action (intent -> act -> result). Mid-task the context window dies ("laptop on
  fire" / token wall). A FRESH agent boots from the on-disk chain (as if
  git-pulled + JSON memory injected), VERIFIES every receipt offline with the
  published verifier, learns exactly what is done vs unfinished from the RECEIPTS
  (not from a summary it can't trust), and resumes -- fail-closed if the chain
  was tampered.

This is the same fail-closed-handoff argument as the IETF trust-boundary case:
the next agent and the prior agent do not share state, so a mutable local memory
cannot answer "what was authorized / what actually ran" across the cut. A signed
receipt chain can.

Run:  python3 examples/handoff/laptop_on_fire.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Use the published verifier; fall back to the in-repo copy so a fresh clone runs.
try:
    from emilia_verify import verify_receipt, canonicalize
except ModuleNotFoundError:  # pragma: no cover - convenience for repo clones
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "python-verify"))
    from emilia_verify import verify_receipt, canonicalize


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def spki_b64u(sk: Ed25519PrivateKey) -> str:
    return b64u(sk.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def issue(payload: dict, sk: Ed25519PrivateKey) -> dict:
    """Mint an EP-RECEIPT-v1: Ed25519 signature over the RFC-8785/JCS canonical payload."""
    sig = sk.sign(canonicalize(payload).encode("utf-8"))
    return {
        "@version": "EP-RECEIPT-v1",
        "payload": payload,
        "signature": {"algorithm": "Ed25519", "value": b64u(sig)},
    }


def receipt_id(receipt: dict) -> str:
    """Stable id = sha256 of the canonical payload. Used as the prev-link in the chain."""
    return hashlib.sha256(canonicalize(receipt["payload"]).encode("utf-8")).hexdigest()


def line(s: str = "") -> None:
    print(s)


# --- the disk-backed handoff chain (the "git-pulled JSON memory") -------------

def append(chain_path: str, receipt: dict) -> None:
    with open(chain_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(receipt) + "\n")


def load_chain(chain_path: str) -> list[dict]:
    if not os.path.exists(chain_path):
        return []
    with open(chain_path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def intent(chain_path: str, sk: Ed25519PrivateKey, task_id: str, step: int, action: str, success: str) -> None:
    chain = load_chain(chain_path)
    prev = receipt_id(chain[-1]) if chain else "root"
    append(chain_path, issue({
        "kind": "intent",
        "task_id": task_id,
        "step": step,
        "action": action,
        "success_condition": success,
        "prev": prev,
    }, sk))


def result(chain_path: str, sk: Ed25519PrivateKey, task_id: str, step: int, action: str, work: str) -> None:
    chain = load_chain(chain_path)
    prev = receipt_id(chain[-1]) if chain else "root"
    append(chain_path, issue({
        "kind": "result",
        "task_id": task_id,
        "step": step,
        "action": action,
        "status": "done",
        "work_digest": hashlib.sha256(work.encode("utf-8")).hexdigest(),
        "prev": prev,
    }, sk))


# --- boot-verify: reconstruct trustworthy state from the chain ----------------

def boot_verify(chain: list[dict], pub: str) -> dict:
    """
    Verify the chain offline: every receipt's Ed25519 signature AND the prev-hash
    linkage. Returns the trustworthy reconstructed state. Fail-closed: a single
    bad signature or broken link makes the whole handoff unacceptable.
    """
    prev_expected = "root"
    completed: set[int] = set()
    started: set[int] = set()
    for idx, receipt in enumerate(chain):
        res = verify_receipt(receipt, pub)
        if not res.valid:
            return {"ok": False, "reason": f"receipt #{idx} signature invalid ({res.error})"}
        if receipt["payload"].get("prev") != prev_expected:
            return {"ok": False, "reason": f"receipt #{idx} prev-link broken (chain reordered or spliced)"}
        p = receipt["payload"]
        if p["kind"] == "intent":
            started.add(p["step"])
        elif p["kind"] == "result":
            completed.add(p["step"])
        prev_expected = receipt_id(receipt)
    unfinished = sorted(started - completed)
    return {"ok": True, "completed": sorted(completed), "unfinished": unfinished}


# --- the task ----------------------------------------------------------------

TASK = "normalize-and-publish-orders"
STEPS = [
    ("fetch", "GET /orders (12 records)", "12 records in buffer"),
    ("transform", "normalize address + currency fields", "12 normalized records"),
    ("write", "PUT /orders/normalized", "server acks 200"),
]


def do_work(step: int) -> str:
    return f"step-{step} output for {STEPS[step][0]}"


def run() -> int:
    AGENT_SK = Ed25519PrivateKey.generate()
    PUB = spki_b64u(AGENT_SK)
    workdir = tempfile.mkdtemp(prefix="continuum_handoff_")
    chain_path = os.path.join(workdir, "handoff_chain.jsonl")

    line("=" * 72)
    line("LAPTOP-ON-FIRE — verifiable agent context-handoff (EP-RECEIPT-v1)")
    line("=" * 72)
    line(f"workspace: {chain_path}")
    line(f"agent key (pub, pinned by the next agent): {PUB[:24]}...")
    line()

    # ---- PHASE 1: work until the context window dies -------------------------
    line("PHASE 1  agent A works the task, writing intent->act->result to disk")
    DIE_AFTER_INTENT_OF = 2  # crash mid-step-2: intent written, result not
    for step, (name, action, success) in enumerate(STEPS):
        intent(chain_path, AGENT_SK, TASK, step, action, success)
        line(f"  step {step}  intent   -> {action}")
        if step == DIE_AFTER_INTENT_OF:
            line(f"  step {step}  ... 💥 context window died (token wall / laptop on fire)")
            line("            result NOT written. agent A is gone. memory is gone.")
            break
        result(chain_path, AGENT_SK, TASK, step, action, do_work(step))
        line(f"  step {step}  result   -> done")
    line()

    # ---- PHASE 2: a fresh agent boots from the chain and resumes -------------
    line("PHASE 2  agent B cold-boots: git pull -> inject JSON memory -> verify -> resume")
    chain = load_chain(chain_path)
    line(f"  loaded {len(chain)} receipts from disk (zero trust in agent A's runtime)")
    state = boot_verify(chain, PUB)
    if not state["ok"]:
        line(f"  ✗ chain did not verify: {state['reason']}")
        return 1
    line(f"  ✓ chain verified offline — every receipt signature + prev-link checks out")
    line(f"    completed steps : {state['completed']}")
    line(f"    unfinished steps: {state['unfinished']}  (intent on disk, no result)")
    for step in state["unfinished"]:
        name, action, success = STEPS[step]
        line(f"  resuming step {step}: {action}")
        result(chain_path, AGENT_SK, TASK, step, action, do_work(step))
        line(f"  step {step}  result   -> done")
    final = boot_verify(load_chain(chain_path), PUB)
    if not (final["ok"] and not final["unfinished"]):
        line("  ✗ task did not reach a complete, verified state")
        return 1
    line(f"  ✓ RESUMED — task complete, chain valid end-to-end {final['completed']}")
    line()

    # ---- PHASE 3: adversarial — a tampered handoff must be refused -----------
    line("PHASE 3  adversarial: someone edits a receipt in the handoff chain")
    tampered = load_chain(chain_path)
    tampered[1]["payload"]["action"] = "PUT /orders/attacker-controlled"  # mutate, do NOT re-sign
    bad = boot_verify(tampered, PUB)
    if bad["ok"]:
        line("  ✗ SECURITY FAILURE: tampered chain was accepted")
        return 1
    line(f"  ✓ REFUSED: {bad['reason']}")
    line("    fail-closed — agent B will not resume on an unverifiable handoff.")
    line()

    line("=" * 72)
    line("RESULT: handoff survived a mid-task cut. State was reconstructed from")
    line("signed receipts, not memory. Tampering is detected and refused.")
    line("Same primitive as GRACE — pointed at the context-window boundary.")
    line("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(run())
