# Signed agent mailbox v0.1

This reference turns a Nomadic-style inbox into a signed, recipient-bound
store-and-forward channel between two agents. It demonstrates the narrow
interoperability boundary:

1. Agent Smith signs a GRACE curtailment proposal for one recipient.
2. The mailbox verifies the pinned sender key, expiry, recipient, payload
   digest, closed envelope shape, and thread sequence before storing it.
3. The mailbox emits a metadata-only chime and a signed delivery receipt.
4. A restart reads the same durable record. An identical delivery is
   idempotent. An envelope-ID or thread-sequence equivocation is refused.
5. The proposal remains non-authorizing. It becomes executor-ready only after
   a separately verified EMILIA admission binds the exact GRACE action digest.

Run the complete round trip from the repository root:

```bash
npm run demo:agent-mailbox
```

Run the executable and hostile contracts:

```bash
npm run test:agent-mailbox
```

## What this proves

The reference proves deterministic envelope signing and verification,
recipient and expiry binding, payload tamper refusal, metadata-only
notification, body-bound idempotency, same-sequence equivocation refusal,
signed delivery receipts, local filesystem persistence across a restart, and
exact-action composition with a separately verified admission.

## What it does not prove

The mailbox is a transport and storage surface, not an authority source. A
delivery receipt proves what this mailbox accepted under its pinned keys. It
does not prove that the message is true, that the outside world changed, or
that an action was authorized or executed.

The reference uses a single-process filesystem store. It does not claim
linearizable delivery across multiple mailbox processes. A production service
needs a shared durable store with an atomic uniqueness constraint over both
the envelope ID and `(recipient, sender, thread, sequence)`, service-held keys,
recipient key lifecycle, authenticated client sessions, encryption in transit
and at rest, and an explicit payload-confidentiality profile. The notification
contains metadata, so even without the payload it can reveal communication
patterns.
