# AE Challenge revision 04 candidate

This isolated candidate is derived from the immutable posted
`draft-schrock-ae-challenge-03` source. Revision -03 remains unchanged. The
upload source for the next revision is:

`UPLOAD-THIS/draft-schrock-ae-challenge-04.xml`

Revision -04 is a substantive protocol update based on public Agent2Agent and
AgentProto review from Sumit P. Ahuja, Guigui Wang, and Henri Sirkkavaara.

The transport-neutral core adds optional `retry_timing` with an absolute
`not_before` lower bound and an optional `jitter_sec` interval. A presenter
that processes the member cannot answer before the lower bound and should add
an independently selected delay. Issuers expecting correlated refusals should
use recipient- or challenge-specific schedules. Pure overload remains a
carrier-level failure, not a fabricated authorization-evidence challenge.

The HTTP binding maps the lower bound to RFC 9110 `Retry-After`. The core body
retains the jitter value; neither the header nor the body authorizes the action,
extends challenge expiry, or makes an uncertain action safe to repeat.

The revision also recommends a structured refusal or error carrier without
making the core transport-specific. It requires each receiving delegation or
rewriting hop to re-evaluate its own local action and, when challenging, issue
its own action binding. Prior-hop bindings can be evidence or context but do
not survive as the binding for a rewritten action. Capability discovery stays
separate from authority, and local authenticated policy alone decides whether
presented evidence is sufficient.

The DMSC boundary from -03 is preserved: AE-CHALLENGE communicates evidence
requirements but does not transfer admission ownership or prevent
cross-gateway double admission. The separate handoff requirement is stated as
conservation of committed capacity under every admission and release
interleaving, not as an ordering contest between gateways.

Identifier governance and replay ordering are now closed rather than left as
open questions. Evidence-type, action-profile, and presentation-profile
identifiers are absolute URIs. Action agreement is checked before expiry and
atomic nonce consumption. A concurrent duplicate arriving after consumption
starts is refused as replay even while the first evidence evaluation remains
in flight; it cannot trigger a second evaluation or admission.
