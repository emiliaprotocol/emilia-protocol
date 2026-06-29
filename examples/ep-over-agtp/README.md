# EP-receipt-over-AGTP — composition demo

A self-contained, runnable demo showing **EMILIA Protocol (EP)** as the
**external-IdP / human-authorization profile** in
**draft-hood-agtp-composition-01** (AGTP v09 × EP receipts).

```bash
node demo.mjs
```

## What it shows

| Layer | Proves | Signed by |
|---|---|---|
| **AGTP** (`draft-hood-independent-agtp-09`) | which **agent/Owner-ID** sent the message | agent's AGTP-CERT key (Agent CA–issued) |
| **EMILIA Protocol** (`EP-RECEIPT-v1`) | which **human** authorized the exact action | approver's device key (external-IdP credential) |

`agtp-composition-01` defines three profile families; the **external-IdP**
family is the human-authorization layer. EP is one concrete realization:
the EP receipt is placed in the AGTP `authorization.credential` slot and
is opaque to the transport layer.

The receiver verifies **both halves independently** plus the **join** (the
action about to execute equals the authorized claim), then accepts. Two
tamper checks confirm each layer fails closed on its own:

- inflate the amount inside the EP receipt → **EP signature fails**
- reroute the AGTP envelope → **AGTP signature fails**

## Why it composes

Both specs share **Ed25519 + RFC 8785 (JCS)** — the canonical bytes are
interoperable with no glue. AGTP answers *"which agent/Owner-ID sent
this?"*; EP answers *"which human authorized this exact action?"*:
**accountable identity + accountable authorization**, end to end.

- AGTP: <https://datatracker.ietf.org/doc/draft-hood-independent-agtp/>
- EP receipts: `draft-schrock-ep-authorization-receipts`
- Composition: `draft-hood-agtp-composition`

> Demo only — illustrative keys/values, no network. The external-IdP
> credential slot is defined in `agtp-composition-01`; EP occupies that
> slot as the `ep-receipt-v1` profile.
