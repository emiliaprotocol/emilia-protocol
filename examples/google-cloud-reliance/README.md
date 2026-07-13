# External Reliance Lab for Google Cloud-shaped mutations

IAM answers **who may call**. Content controls inspect **what the call contains**.
This lab exercises the separate question a regulated customer, auditor, or
insurer asks before relying on the consequence:

> Did this exact high-blast-radius action clear the evidence bar we pinned,
> and can the evidence drive the mutation only once?

The demonstration wraps the existing EMILIA MCP tool boundary and Google Cloud
action pack around an illustrative `setIamPolicy` mutation granting `roles/owner`.
The local IAM and Model Armor outcomes are deliberately modeled as `allow`.
EMILIA still refuses four bad presentations, runs one exact quorum-authorized
mutation, and refuses replay.

```bash
node examples/google-cloud-reliance/demo.mjs
node examples/google-cloud-reliance/demo.mjs --json
npx vitest run tests/google-cloud-reliance.test.js
```

## The six exercised outcomes

| Case | Result | Executor called? |
|---|---|---:|
| IAM/content controls allow, no customer evidence | Refuse | No |
| One human signs a two-person-rule action | Refuse | No |
| Receipt binds `roles/viewer`, call requests `roles/owner` | Refuse | No |
| Signed receipt is altered after issuance | Refuse | No |
| Genuine two-person evidence binds the exact mutation | Rely | Yes, once |
| Accepted evidence is presented again | Refuse | No second call |

The valid case uses real Ed25519 receipt signing plus WebAuthn-shaped P-256
per-signer evidence through the repository's EG-1 harness. The enforcement path
is the published Gate, MCP wrapper, and GCP action pack, not a demo-only
allow/deny stub.

## Composition boundary

This does not replace Google Cloud IAM, Google Cloud remote MCP governance, or
Model Armor. Those controls remain valuable. The lab adds a customer-pinned,
portable reliance record at the mutation boundary:

```text
Gemini / agent
    -> Google-side authentication, IAM, content inspection
    -> customer-controlled EMILIA reliance boundary
    -> exact GCP mutation
    -> execution record + portable reliance packet
```

The injected handler is the seam where a production MCP server supplies its
Google Cloud SDK, API proxy, or remote-MCP forwarding client. If EMILIA refuses,
that handler is never invoked.

## Honest limits

- This is an independent open-source compatibility demonstration. It is not
  affiliated with, endorsed by, or deployed at Google.
- No Google service is called. The IAM and Model Armor outcomes are illustrative
  inputs so the lab can isolate the external-reliance question.
- A `rely` verdict proves the configured evidence and execution-binding checks
  passed. It does not prove granting `roles/owner` was wise.
- Complete mediation remains a deployment requirement: every protected write
  path must traverse the gate.

Google Cloud MCP documentation:
<https://docs.cloud.google.com/mcp/overview>

Apache-2.0. Run it, inspect it, and try to make a refused mutation execute.
