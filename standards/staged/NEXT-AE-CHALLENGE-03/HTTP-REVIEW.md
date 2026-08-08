Subject: Narrow HTTP review request: 403 + RFC 9457 evidence-challenge binding

Mark,

Would you be willing to sanity-check the HTTP binding in
`draft-schrock-ae-challenge-03`?

https://datatracker.ietf.org/doc/draft-schrock-ae-challenge/

I removed the -02 use of 428 and the dedicated media type. The revised binding
uses 403 Forbidden with `application/problem+json`, carries the transport-neutral
challenge in an `evidence_challenge` extension, requires `Cache-Control:
no-store`, and requests an HTTP Problem Types registry entry under Specification
Required.

The narrow questions are whether 403 is the right refusal status, whether the
extension shape follows RFC 9457 cleanly, whether `no-store` is sufficient for
the nonce-bearing response, and whether the requested common problem type is
appropriately scoped for that registry.

No endorsement or commitment is implied; even a short "this belongs elsewhere"
would be useful.

Best,
Iman

