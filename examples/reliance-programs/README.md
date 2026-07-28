<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reliance Program source fixtures

These three `EP-RELIANCE-PROGRAM-SOURCE-v1` files are synthetic, PHI-free
reference inputs for the Reliance Program compiler. Each source is owned by the
named synthetic relying party. EMILIA compiles the source; it does not author
the customer's evidence bar.

| Fixture | Protected reference action | Customer-owned policy boundary |
| --- | --- | --- |
| `payer-davinci-pas-adverse-determination.v1.json` | Emit one synthetic Da Vinci PAS adverse-determination result | A synthetic payer pins PAS mapping, licensed-review, and current-authority profiles. |
| `auditor-proof-of-human-authorization.v1.json` | Issue one synthetic proof-of-human-authorization export | A synthetic audit firm pins native verification, human binding, and re-performance profiles. |
| `platform-mcp-clearance.v1.json` | Clear one synthetic privileged MCP tool call | A synthetic platform pins request binding, delegated authority, human clearance, and platform-posture profiles. |

The fixtures contain no FHIR resources, patient or member identifiers,
diagnoses, procedures, dates of birth, names, addresses, NPIs, or clinical
free text. Their digests, CAIDs, organization names, and policy pins are
synthetic test values.

Compiling or verifying a fixture does not establish payer deployment, Da Vinci
PAS conformance, licensed clinical review, an audit opinion, MCP server safety,
production durability, complete mediation, or occurrence of an external
effect. See
[`RELIANCE-PROGRAMS.md`](../../docs/architecture/RELIANCE-PROGRAMS.md) and
[`RELIANCE-PROGRAM-CANNOT-EXPRESS.md`](../../docs/architecture/RELIANCE-PROGRAM-CANNOT-EXPRESS.md).
