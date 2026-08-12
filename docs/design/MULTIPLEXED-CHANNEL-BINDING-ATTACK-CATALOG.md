# Multiplexed channel-binding pre-implementation attack catalog

Status: design-time test requirements. These are not executed vectors, proof,
or conformance results because the multiplexed construction is not implemented.
The purpose of this catalog is to prevent a future implementation from choosing
only favorable tests and to separate executable cases from cryptographic
assumptions and deployment assertions.

The candidate under review is defined in
`MULTIPLEXED-CHANNEL-BINDING-CANDIDATE.md`.

## Executable cases required before experimental implementation can pass

| ID | Hostile case | Required result |
|---|---|---|
| MCB-01 | Replay the same nonce and signed presentation concurrently on one connection | At most one atomic nonce transition succeeds; every other attempt is refused as replay |
| MCB-02 | Replay a valid presentation on a different TLS connection while keeping the nonce, audience, CAID, and evidence unchanged | HMAC comparison fails and the original nonce is not consumed by the wrong-connection attempt |
| MCB-03 | Reuse a tag with a fresh nonce on the same connection | The reconstructed frame differs and HMAC comparison fails while nonce-in-message remains in the candidate |
| MCB-04 | Swap the closed presenter-to-relying-party message type | The reconstructed frame differs and HMAC comparison fails |
| MCB-05 | Substitute another relying-party audience on a coalesced connection | The audience digest differs and HMAC comparison fails |
| MCB-06 | Use a byte-distinct audience that a URI library might normalize to the same display form | Exact configured bytes produce a different digest; no normalization is applied |
| MCB-07 | Substitute the CAID action type or CAID version while retaining the embedded action hash | The full-CAID digest differs and HMAC comparison fails |
| MCB-08 | Change one material action field and recompute the request without a fresh tag | CAID and HMAC verification fail |
| MCB-09 | Replace, remove, or add an optional native evidence artifact | The typed evidence transcript digest differs and HMAC comparison fails |
| MCB-10 | Move a channel-binding field, HTTP Signature field, or tag into the evidence transcript | The implementation refuses the unsupported transcript rather than creating a circular digest |
| MCB-11 | Present a correct HMAC tag that is omitted from the workload HTTP Message Signature coverage | Presentation is rejected |
| MCB-12 | Present a valid workload signature with an incorrect HMAC tag | Presentation is rejected |
| MCB-13 | Present a valid HMAC tag with an invalid workload signature | Presentation is rejected |
| MCB-14 | Use padded base64url, non-canonical base64url, the wrong nonce length, or the wrong tag length | Presentation is rejected before comparison |
| MCB-15 | Use the TLS early exporter or 0-RTT path | Construction is unavailable and cannot return an accepted binding |
| MCB-16 | Resume into a new TLS connection and replay a tag from the prior connection | HMAC comparison fails under the new regular exporter key |
| MCB-17 | Perform TLS 1.3 KeyUpdate without ending the connection | The target TLS implementations retain the candidate's documented exporter behavior and valid in-flight instances remain verifiable |
| MCB-18 | Reuse or alias a proxy/local connection handle for a different TLS connection | Binding is `INDETERMINATE` or rejected; no substitute handle is accepted as the exporter source |
| MCB-19 | Reach the AEB enforcer while bypassing the trusted TLS terminator | Required binding is `INDETERMINATE`; presenter-controlled forwarding metadata never creates a pass |
| MCB-20 | Inject or replay a terminator-to-enforcer exporter assertion on another request | Authenticated handoff request binding fails and no channel-binding claim is accepted |
| MCB-21 | Flood unauthenticated stateful nonce issuance beyond capacity | Authenticated presenters' live records are not evicted; issuance is rate-limited or refused |
| MCB-22 | Submit two valid presentations for one stateless issuance token, if that alternative is implemented | Atomic insert-if-absent permits one success and refuses the other |
| MCB-23 | Use the experimental label with a verifier configured for a future registered label, or change the exporter context | HMAC comparison fails; the two versions cannot silently interoperate |
| MCB-24 | Close the TLS connection with outstanding nonces and try to use them later | Key and outstanding instance state are destroyed; later use cannot pass |

## Differential cases that decide the construction

These cases compare candidates rather than assuming the current candidate is
best:

1. Remove the nonce from `M` while retaining signature coverage and the atomic
   replay store. Demonstrate whether any splice or reflection case newly passes.
2. Derive one exporter value per instance using the nonce as context and omit
   the connection-wide HMAC key. Compare the security transcript and API
   surface to nonce-in-message.
3. Compare stateful `OPEN` issuance with a MAC-protected stateless issuance
   token plus an atomic consumed-token set under the same flood and replay
   workloads.
4. Compare the multiplexed candidate with the RFC 9266 baseline of one
   authentication mechanism instance per TLS connection. If the baseline is
   operationally adequate, the custom construction has not earned its cost.

## Benchmark requirements

No claim that TLS exporter derivation dominates HMAC is accepted without
measurement. Benchmark at least OpenSSL and one additional target TLS stack
using identical hardware and connection reuse. Report exporter calls, HMACs,
replay-store operations, CPU time, allocations, lock contention, and p50/p95/
p99 latency for 1, 10, 100, and 1,000 concurrent authentication instances.

The nonce-in-exporter-context comparison must specify whether the exporter
output is used directly as the channel-binding authenticator or is followed by
an additional HMAC. Comparing one construction with an unnecessary extra HMAC
would not be a valid benchmark.

## Cryptographic assumptions, not runnable collision tests

The following are assumptions or review questions and must not be reported as
passing hostile vectors:

- finding two distinct SHA-256 inputs with the same digest;
- forging HMAC-SHA-256 without the exporter-derived key;
- preserving security after `K_bind` is disclosed; and
- proving the composition free of unknown-key-share or transcript-splicing
  attacks.

If `K_bind` is disclosed, an attacker can compute valid HMAC tags for that TLS
connection. A test expecting forgery to fail with a leaked key would be wrong.
The remaining asymmetric signature still matters, but the channel-binding key
compromise must be reported as a lost channel-binding guarantee.

## Deployment assertions, not cryptographic vectors

Whether a proxy is local, a service mesh shares the intended trust boundary,
or a given data-center deployment exposes a trustworthy exporter API cannot be
proved by a JSON vector. Those properties require deployment configuration,
attestation or authenticated handoff evidence, and an end-to-end integration
test at the actual enforcement point.

`INDETERMINATE` records that a required relationship could not be established.
It does not itself shift liability, prove legal defensibility, or authorize the
operation on other evidence. The relying party's explicit policy decides what
an indeterminate channel-binding leg permits, and a policy requiring that leg
cannot silently downgrade it to success.
