<!-- SPDX-License-Identifier: Apache-2.0 -->
# SCITT interoperability ask

Use this when asking the SCITT list which implementation should be the external target for the
EP-RECEIPT-SCITT-PROFILE demo.

## Short ask

Hi all,

I am building a small EP-SCITT profile demo: an EMILIA authorization receipt is carried as a
`COSE_Sign1` Signed Statement, registered through SCRAPI, and then verified as two separate checks:

- EMILIA authorization check: Ed25519 over the canonical EP receipt payload, offline.
- SCITT transparency check: returned inclusion / transparency receipt verified against the service's
  parameters.

The in-repo harness now emits the RFC 9943 protected CWT claims, handles both synchronous and
asynchronous SCRAPI registration, and dispatches an RFC 9942 Receipt by protected `vds` only to a
relying-party-pinned native verifier. The mock path remains reproducible CI plumbing; I do **not**
want to claim official SCITT conformance against our own mock or injected test adapters.

Which public SCRAPI-compatible service and native Receipt-profile implementation should I use as the
external interoperability target today? I found `scitt-community/scitt-api-emulator`, but it appears
archived, so I do not want to overstate its current status. If the WG has a preferred service or
verifier for RFC9162_SHA256, CCF, or MMR, I would rather pin that exact implementation and report the
result narrowly.

Thanks,
Iman
