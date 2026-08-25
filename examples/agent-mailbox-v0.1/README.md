# Signed agent mailbox v0.1

This reference turns a Nomadic-style inbox into a signed, recipient-bound
store-and-forward channel between two agents. It demonstrates the narrow
interoperability boundary:

1. Agent Smith signs a GRACE curtailment proposal for one recipient.
2. The mailbox verifies the pinned sender key, expiry, recipient, payload
   digest, closed envelope shape, and thread sequence before storing it.
3. The mailbox emits a metadata-only chime and a signed delivery receipt.
4. A restart reads the same durable record. An identical delivery is
   reported as `DUPLICATE` without another store write or chime. An envelope-ID
   or thread-sequence equivocation is refused.
5. The proposal remains non-authorizing. The adapter reports executor readiness
   only after a separate caller-supplied EMILIA Gate authorization result binds
   the exact action digest and explicitly distinguishes authorization from
   verification and acceptance.

Run the complete round trip from the repository root:

```bash
npm run demo:agent-mailbox
```

Run the executable and hostile contracts:

```bash
npm run test:agent-mailbox
```

The demo uses a deterministic stand-in for that Gate adapter contract. It does
not execute a provider action or prove a deployed Gate integration.

## What this demonstrates

The executable reference demonstrates deterministic envelope signing and verification,
recipient and expiry binding, payload tamper refusal, metadata-only
notification, body-bound idempotency, same-sequence equivocation refusal,
signed delivery receipts, local filesystem persistence across a process
restart, and exact-action composition through a separate authorization adapter.

## What it does not prove

The mailbox is a transport and storage surface, not an authority source. A
delivery receipt proves what this mailbox accepted under its pinned keys. It
does not prove that the message is true, that the outside world changed, or
that an action was authorized or executed.

Accepted store records bind the exact sender key verified at delivery and are
authenticated by the mailbox service key that wrote the record. When rotating
that service key, pass retired public keys through `mailboxVerificationKeys`,
keyed by their original key IDs, so historical records remain verifiable. The
current private key is pinned automatically, and a contradictory current-key
pin is refused. Keys carried only by the store are never trusted. Every stored
binding remains explicitly non-authorizing.

Read state is never a bare mutable timestamp. A first-write-wins
`read_acknowledgement` binds the recipient, envelope identity and digest, exact
delivery-binding digest, mailbox, read time, and service key under a distinct
mailbox signature domain with `authorizes: false`. New acknowledgements use
only the current service key; historical service-key pins verify an existing
acknowledgement after rotation. The service verifies the returned record and
rereads the persisted state before returning the authenticated acknowledgement.
`read_acknowledgement: null` means only **no authenticated read evidence**; it
is never proof that the message was unread, so deleting or rolling back the
signed acknowledgement cannot create an authenticated contrary state.

This stored-record shape intentionally does not accept the earlier experimental
bare `read_at` field. The mailbox profile was not merged or published with that
shape, and treating an unsigned timestamp as historical evidence would preserve
the defect this binding closes.

`action_digest` is a strict-canonical-JSON content digest used to bind the
mailbox proposal to one action value. It is not a Canonical Action Identifier
(CAID), does not establish profile validity or cross-format equivalence, and
does not grant authority. A Gate adapter must independently validate the action
profile, apply any relying-party-pinned CAID or mapping rules, and authorize the
covered executor path under the normal Gate contract.

Envelope verification and delivery-receipt verification return different
verification-profile discriminators. Action extraction accepts only the
in-process result of the envelope verifier, so a delivery receipt cannot be
substituted for sender-envelope verification. A `DUPLICATE` receipt is valid
replay evidence but is not reported as a fresh accepted delivery.

The reference uses a single-process filesystem store. Its tests cover process
restart persistence, not power-loss durability, and it does not claim
linearizable delivery across multiple mailbox processes. A production service
needs a shared durable store with an atomic uniqueness constraint over both
the envelope ID and `(recipient, sender, thread, sequence)`, service-held keys,
recipient key lifecycle, authenticated client sessions, encryption in transit
and at rest, and an explicit payload-confidentiality profile. The notification
contains metadata, so even without the payload it can reveal communication
patterns.
