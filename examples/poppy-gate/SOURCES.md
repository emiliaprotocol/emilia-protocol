<!-- SPDX-License-Identifier: Apache-2.0 -->
# Source and requirement map

Primary sources read October 12, 2026:

- [Personal Agent Protocol](https://personalagentprotocol.org/docs/spec), Draft 0.1,
  updated October 9, 2026.
- [Operations](https://personalagentprotocol.org/docs/extensions/operations), version 1.
- [Extensions](https://personalagentprotocol.org/docs/extensions).
- [Open topics](https://personalagentprotocol.org/docs/open-topics).

These documents can change. This candidate targets the identified draft, not an
unversioned promise of compatibility with later revisions.

| Native requirement | Reference implementation responsibility |
| --- | --- |
| Core 3.3; Operations 2: extension negotiation | Use authenticated client metadata; refuse unsupported required extensions. |
| Core 4.3: native Session Token and DPoP checks | Host-supplied authentication adapter; do not accept MCP bearer tokens at the Operations endpoint. |
| Operations 3, 3.1: immutable material revisions | Snapshot terms, increment revisions only before confirmation, atomically claim the current revision. |
| Operations 3.2: owner and account/session scope | Authenticate reads, confirmation and cancellation; preserve same-agent/user/account renewal. |
| Operations 5.1: revision-specific approval mode | Preserve user versus standing permission; stronger optional profile verifies native EP evidence separately. |
| Operations 5.2: confirmation checks | Enforce scope, latest revision, approval mode, expiry and state before Gate/provider entry. |
| Operations 6: repeat confirmation and unknown effect | At most one covered provider attempt; uncertain outcomes stay in progress without blind replay. |
| Operations 7: cancellation | Refuse pre-confirmation cancellation races; do not claim that cancellation undoes a possible effect. |
| Operations 8: assertion versus approval evidence | Keep agent statement, credential-ceremony evidence, Gate authority and reported outcome distinct. |

The core token issuer, personal-agent UI and a real remote provider are outside
this example. Local tests are implementation evidence, not third-party Poppy
interoperability, customer acceptance, certification or a production guarantee.
