# emilia-crewai

Guard [CrewAI](https://crewai.com) tools with the **EMILIA Protocol** — require an
**offline-verifiable authorization receipt** (EP-RECEIPT-v1) before an irreversible
tool runs.

```
missing receipt  -> refused
valid receipt    -> runs
replayed receipt -> refused   (one-time consumption)
forged receipt   -> refused
```

Verification is offline Ed25519 over canonical JSON via
[`emilia-verify`](https://pypi.org/project/emilia-verify/) — **zero network, no
vendor in the loop.** The approval becomes portable evidence an auditor can check
without trusting the operator. It is *necessary, not sufficient*: it composes with —
never replaces — your tool's own checks.

> The base gate proves a pinned issuer signed an action-bound authorization claim.
> For a human-presence claim, require `assurance_class="class_a"` and supply an
> independent assurance verifier pinned to the relying party's keys, RP, and origins.

## Install

```bash
pip install emilia-crewai          # brings in emilia-verify
pip install "emilia-crewai[crewai]" # also install CrewAI (optional peer)
```

## Quick start

Gate a CrewAI `BaseTool` instance — its `_run` now requires a receipt:

```python
from emilia_crewai import guard_crewai_tool, using_receipt

guard_crewai_tool(
    my_wire_tool,
    action="payment.release",
    trusted_keys=[ISSUER_SPKI_B64URL],     # pin the issuer keys you trust
    target_for=lambda to, amount: f"payment.release:{to}",  # optional per-call binding
    assurance_class="class_a",
    verify_assurance=verify_pinned_class_a_evidence,
)

# Bind the human-approved receipt for the agent step, then run as normal:
with using_receipt(receipt):
    crew.kickoff()        # my_wire_tool runs only with a valid, action-bound receipt
```

Or decorate a plain tool function:

```python
from emilia_crewai import require_receipt, using_receipt

@require_receipt("payment.release", trusted_keys=[ISSUER_SPKI_B64URL])
def send_payment(to: str, amount: int) -> str:
    return do_transfer(to, amount)
```

Lower-level gate (verify -> reserve -> execute -> commit yourself):

```python
from emilia_crewai import ReceiptGate
gate = ReceiptGate("payment.release", trusted_keys=[ISSUER_SPKI_B64URL])
result = gate.run(receipt, lambda: do_transfer(to, amount), target=to)
```

`run()` consumes the receipt after any execution attempt, including an exception:
the external effect may have happened before its response was lost. Production
fleets must pass an atomic, ownership-fenced `{reserve, commit, release}` store;
the default is process-local. Call `release()` only when you can prove execution
never began.

## Multi-agent / quorum

For collective decisions (M-of-N agents or humans approving one action), EMILIA's
quorum produces a single composite, offline-verifiable receipt. See the
`emilia_verify.verify_quorum` primitive and `draft-schrock-ep-quorum`.

## What it is / isn't

- **Is:** an offline gate for an action-bound issuer receipt, with an explicit
  Class-A/quorum verifier hook for independently established human ceremony.
- **Isn't:** authentication ("who is the agent"), access control, or a hosted runtime.
  It composes on top of whatever runtime you use.

Apache-2.0. Reference implementation, experimental. Part of the
[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol) — an open
IETF-track authorization-receipt standard (`draft-schrock-ep-authorization-receipts`).
