# Authorization Receipts -12 candidate packet

This packet contains an unposted candidate for
`draft-schrock-ep-authorization-receipts-12`. It has not been filed with the
IETF Datatracker.

Revision -12 adds three narrowly separated security properties:

- acceptance-prefix integrity: a later key reveal does not rewrite the signed
  contexts that preceded an already recorded acceptance;
- the anti-backdating limit: ordinary signatures and signer-asserted time do
  not let an offline verifier distinguish a pre-compromise signature from a
  backdated post-compromise signature; and
- historical acceptance remains separate from current policy and status
  acceptance and cannot authorize a new effect.

The formal model proves only the first property under its stated trace and
acceptance assumptions. It does not claim trusted time, forward security,
offline anti-backdating, current authorization, or current policy acceptance.
