# EMILIA for smolagents

**Let your agent prepare the action. Decide what it may execute.**

Give a Hugging Face agent access to a consequential tool without letting the
model supply its own authorization. This adapter wraps a native `smolagents.Tool`
and checks an offline-verifiable EMILIA receipt before calling the tool.

The receipt must cover the exact tool name and complete arguments, including
defaults. Missing, invalid, expired, mismatched, and already consumed receipts
refuse the call. If the provider throws after entry, the receipt stays consumed:
a lost response is not permission to try the action again.

Freshness is checked again after waiting for setup and immediately before the
protected `forward` call. Expiry during setup refuses that call and consumes the
reserved attempt; it does not make the receipt reusable. The adapter reports
`ToolExecutionIndeterminate` with `receipt_expired_after_admission`, because setup
code may already have contacted the provider.

This is an in-process adapter for covered calls. It does not prevent generated
code or a process owner from using another credential or calling an unwrapped
tool. For a non-bypassable boundary, put enforcement beside the credential-owning
provider and mediate every protected path.

## Try the downloadable demo

The community release includes a self-contained refund demo and the three required
EMILIA wheels. Download `EMILIA-Hugging-Face-Space.zip` from the
[release page](https://github.com/emiliaprotocol/emilia-protocol/releases/tag/smolagents-v0.1.1),
unzip it, and open a terminal in the extracted folder:

```bash
shasum -a 256 -c SHA256SUMS
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

The demo uses synthetic refunds. No model token, payment account, or money is
involved. The adapter and demo are free and open source under Apache-2.0.

## Install the adapter

Use an isolated Python 3.10+ environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install emilia-smolagents==0.1.1
```

### Install from this checkout

To work from source instead, run these commands from the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ./packages/python-verify ./packages/crewai ./packages/smolagents
```

The dependency named `emilia-crewai` contains EMILIA's shared Python receipt gate.
It does not install CrewAI. This adapter reuses its verifier and consumption
ordering rather than maintaining another authorization implementation. Version
floors are intentional; older Python gate releases lack relevant fixes.

## Wrap a tool

```python
from emilia_smolagents import guard_smolagents_tool
from smolagents import ToolCallingAgent

# refund_tool is your existing synchronous smolagents.Tool.
# approval_store and APPROVER_PUBLIC_KEY are configured by the host, not the model.
guarded = guard_smolagents_tool(
    refund_tool,
    action="refund.issue",
    trusted_keys=[APPROVER_PUBLIC_KEY],
    get_receipt=lambda arguments: approval_store.lookup(arguments),
)

# Use this exact, default-expanded target in the separate approval flow.
action = guarded.bound_action_for(order_id="order-42", amount_cents=2500)

agent = ToolCallingAgent(tools=[guarded], model=model)
```

`get_receipt` receives one detached dictionary of complete arguments. Retrieve
authority already granted by the host's approval flow. Do not sign whatever the
agent requests inside this callback. The receipt never becomes a model-visible
tool input. Provider outputs still go to the model; return only appropriate data.

For a local script, `using_receipt(receipt)` supplies the receipt through a context
variable. smolagents 1.26.0 copies that context into its parallel tool workers;
plain host-created threads and other execution boundaries may not. A host-owned,
thread-safe resolver is useful when integrating an approval store. Resolve within
the correct tenant and user session; do not keep one global current receipt for
unrelated users.

## What the adapter supports

- Native synchronous `Tool` instances, including `@tool` functions with explicit
  signatures and JSON-valued inputs. Numbers must be finite safe integers (up to
  `2**53 - 1` in magnitude); use integer minor units or strings for decimal
  quantities. This keeps bindings within the shared verifier's cross-language
  canonical profile. Tested against smolagents 1.26.0.
- Normal calls, native single-dictionary calls, and direct `forward()` calls.
- Frozen tool name, schema, callable, and default values at wrapper construction.
  The provider still owns its implementation and any internal mutable state.
- Host-pinned keys, receipt age and signed expiry checks, accepted allow outcomes,
  and optional independently configured Class-A or quorum verification.
- A default process-local atomic replay store, or a host-supplied store with
  `reserve`, `commit`, and `release` methods understood by `ReceiptGate`.

The default store survives neither process restarts nor another wrapper instance.
Share one atomic consumption domain across replicas and wrappers that accept the
same receipts. The adapter does not provide that durable backend. One-time
consumption is by receipt identifier, not global deduplication of every logically
equivalent action; issuing a fresh receipt grants a separate attempt.

Software-key receipts prove a signature under a pinned key, not a human ceremony,
civil identity, or successful provider effect. Class-A or quorum requirements
need a separate verifier that actually verifies the required evidence. This
adapter does not add mandate budgets, provider reconciliation, or signed execution
records from the full EMILIA Gate runtime.

Async tools, generator tools, variadic input signatures, and non-JSON inputs are
unsupported. Lazy coroutine/iterator results are never advanced; the admitted
receipt remains consumed. `ToolExecutionIndeterminate.reason` reports an unusable
provider result or unknown consumption state without exposing raw provider errors.
Reconcile with the provider before separately authorizing any further attempt.

Do not use this wrapper as a sandbox for `CodeAgent`. Code execution, alternative
tools, imports, and credentials need their own isolation and enforcement. The
wrapper deliberately refuses `save`, `to_dict`, `push_to_hub`, and pickling, so a
configured host's authority is not accidentally serialized into a shared tool.
Share reviewed source and an unconfigured demo instead.

## Tests

```bash
python -m pip install './packages/smolagents[test]'
python -m pytest packages/smolagents/tests packages/crewai/tests
```

The tests use real Ed25519 signatures and a local fake provider. They make no
network calls and do not move money. The shared tool-call binding vectors pin
agreement with EMILIA's other adapters; they are same-team consistency evidence,
not independent interoperability or adoption evidence.

## Protect one tool you already use

Start with a tool whose effect matters: issuing a refund, changing a record, or
releasing a deployment. Keep the approval lookup under the host's control, bind
the full arguments, and test a changed argument and repeated receipt before
connecting any real credentials. The synthetic demo is a starting point, not a
production deployment checklist.

If you try an integration, [tell us what you protected and what got in the way](https://github.com/emiliaprotocol/emilia-protocol/issues/new).
Do not post credentials, receipts containing private data, or customer details.
