# EP-receipt-over-ATP — composition demo

A self-contained, runnable demo for the **IETF 126 hackathon**: an EMILIA
Protocol human-authorization receipt carried as an **ATP** (`draft-li-atp`)
payload. Two layers, two independent Ed25519 signatures over RFC 8785 (JCS)
canonical JSON, no single point of trust.

```bash
node demo.mjs
```

## What it shows

| Layer | Proves | Signed by |
|---|---|---|
| **ATP** (`draft-li-atp`) | which **agent/domain** sent the message | the domain's ATK key (DNS-published) |
| **EMILIA Protocol** (`EP-RECEIPT-v1`) | which **human** authorized the exact action | the approver's device key |

ATP's payload is opaque by design, so the EP receipt rides inside the ATP
message untouched. The receiver verifies **both halves independently** plus the
**join** (the action about to execute equals the authorized claim), then accepts.
Two tamper checks confirm each layer fails closed on its own:

- inflate the amount inside the EP receipt → **EP signature fails** (the human didn't sign that amount);
- reroute the ATP envelope → **ATP signature fails** (the domain didn't sign that route).

## Why it composes

Both specs already standardize on **Ed25519 + RFC 8785 (JCS)**, so the canonical
bytes are interoperable with no glue. ATP answers *"which agent/domain sent
this?"*; EP answers *"which human authorized this exact action?"*. Together:
**accountable identity + accountable authorization**, end to end.

- ATP: https://datatracker.ietf.org/doc/draft-li-atp/
- EP receipts: `draft-schrock-ep-authorization-receipts`

> Demo only — illustrative keys/values, no network or DNS. The real hackathon
> build wires the EP receipt through an actual ATP relay with DNS-published ATK.
