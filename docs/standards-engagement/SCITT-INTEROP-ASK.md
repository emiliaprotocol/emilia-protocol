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

The in-repo harness already proves the EP/COSE profile and a reproducible mock
register-to-receipt-to-verify path in CI. I do **not** want to claim official SCITT conformance
against our own mock.

Which public SCRAPI-compatible implementation should I use as the external interoperability target
for this profile demo today? I found `scitt-community/scitt-api-emulator`, but it appears archived,
so I do not want to overstate its current status. If the WG has a preferred emulator, test service,
or implementation target, I would rather point the EP demo there and document the verifier behavior
precisely.

Thanks,
Iman
