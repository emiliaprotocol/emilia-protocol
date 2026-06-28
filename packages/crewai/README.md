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

> EMILIA proves **who authorized** a specific action. It is not a truth oracle and
> not an access-control runtime; it is the portable authorization receipt any
> runtime can emit.

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

Lower-level gate (verify -> reserve -> commit/release yourself):

```python
from emilia_crewai import ReceiptGate
gate = ReceiptGate("payment.release", trusted_keys=[ISSUER_SPKI_B64URL])
result = gate.run(receipt, lambda: do_transfer(to, amount), target=to)
```

## Multi-agent / quorum

For collective decisions (M-of-N agents or humans approving one action), EMILIA's
quorum produces a single composite, offline-verifiable receipt. See the
`emilia_verify.verify_quorum` primitive and `draft-schrock-ep-quorum`.

## What it is / isn't

- **Is:** an offline gate that enforces *a named human authorized this exact action*
  and yields portable, third-party-verifiable evidence.
- **Isn't:** authentication ("who is the agent"), access control, or a hosted runtime.
  It composes on top of whatever runtime you use.

Apache-2.0. Reference implementation, experimental. Part of the
[EMILIA Protocol](https://github.com/emiliaprotocol/emilia-protocol) — an open
IETF-track authorization-receipt standard (`draft-schrock-ep-authorization-receipts`).
