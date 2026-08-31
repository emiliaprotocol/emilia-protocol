<!-- SPDX-License-Identifier: Apache-2.0 -->
# Bulk-Power Action Assurance v0.1

> Supply-chain authorities decide whether equipment or a transaction is eligible.
> EMILIA Gate decides whether one exact operational action may cross now.

This experimental profile shows how a bulk-power operator can consume a governed
equipment status as an external input, then bind that input to one exact action at a
customer-controlled Gate. Vendor, transaction, license, and mitigation-status adapters
are possible extension points, but this v0.1 runner does not implement them. It is designed
to support implementation evidence and audit procedures arising from the August 26,
2026 order, **“Declaring a National Emergency to Secure the United States Bulk-Power
System.”** It is not an interpretation of that order and is not a compliance profile.

## Run the evidence

```sh
npm --prefix packages/gate run build
npm run build:standalone-runtimes
npm run test:bulk-power-action-assurance
npm run demo:bulk-power-action-assurance
```

The executable profile constructs and decodes a synthetic Modbus TCP function-code
`0x06` write; it does not transmit the frame to live equipment. The reference conduit
derives the protocol, operation, and material parameters from those decoded bytes plus
conduit-owned asset facts. Gate binds and evaluates that action, checks a pinned
equipment-status source in the final guard immediately before provider entry,
and passes that status evidence into the provider call context. Gate then appends a
copy to the in-process execution detail after provider entry and effect handling;
the runner does not prove atomic durable evidence persistence. The reference run
covers exact admission, asset and parameter
substitution, an expired exact-action interval, stale/future-dated/revoked/unavailable
status, a cached `ACTIVE` value racing a committed freeze, same-process replay, and a
lost controller response. The action, Gate, organization-status, and equipment-status
checks all use the same live clock domain; the JSON example dates are illustrative
input, not the runner's clock.

The hostile-case catalog below is the profile's required test surface, not a claim
that this reference runner exercises every row. In particular, the runner does not
verify signed outcome statements, simulate a process restart against a durable shared
store, or establish complete mediation around a real controller.

## Source pin

- Primary citation: **Executive Order 14421; 91 FR 55995; Federal Register
  Document 2026-17843**, published August 31, 2026:
  <https://www.govinfo.gov/content/pkg/FR-2026-08-31/pdf/2026-17843.pdf>
- White House publication, August 26, 2026:
  <https://www.whitehouse.gov/presidential-actions/2026/08/declaring-a-national-emergency-to-secure-the-united-states-bulk-power-system/>

`source-lock.json` records the retrieved final Federal Register PDF's byte length and
SHA-256 digest.

The final Federal Register publication identifies the order as **Executive Order
14421**. The White House page labeled it “Executive Order 14420” when the final source
was pinned; this profile uses the final Federal Register identifier. Rules,
directives, licenses, lists, and FAR text that follow the order remain separate future
inputs and require their own pinned profile updates.

## The boundary

The order addresses supply-chain eligibility and conditions on acquisition, use,
maintenance, updates, remote access, isolation, disconnection, replacement, and
removal. Those determinations belong to the Government or another authority selected
by the relying party. Gate does not make them.

Gate consumes the authoritative result and asks a different question:

> Given this current external status, this operating mandate, this policy version,
> this asset, and this relying-party admission domain, may this exact command with
> these exact parameters enter the provider once?

The status input and the operational decision remain separate. A valid signature on an
old list entry is not current authorization. A secure tunnel authenticates a channel;
it does not authorize the command inside it. Software provenance describes supplied
software; it does not authorize its installation or execution.

## Minimum input contract

### Governed external status

The selected status authority supplies, at minimum:

- `subject_type` and `subject_id` for the equipment, vendor, transaction, license, or
  mitigation measure;
- an explicit `status` such as `ACTIVE`, `PREQUALIFIED`, `RESTRICTED`, or `REVOKED`;
- `source_id`, `source_version`, `source_artifact_digest`, and `issuer_key_id`;
- `effective_at`, `observed_at`, and `expires_at`;
- the asset and operation scope to which the status applies;
- the configuration and firmware digests plus an authenticated-source result; and
- a source-authored claim boundary.

The relying party pins the accepted source and status vocabulary. Missing, stale,
revoked, unavailable, out-of-scope, or untrusted status refuses before provider entry.
That read alone is not atomic with a source-side revocation. A deployment that needs
race-free revocation must project the source's freeze or revision into the same durable
Gate control domain that serializes provider entry.

### Exact operational action

The action binds, at minimum:

- `rp_id`, `admission_domain_id`, and a stable `operation_id`;
- `site_id`, `asset_id`, equipment class, model, serial number, configuration digest,
  and firmware digest;
- the native operation and every material parameter;
- the authority artifact and current external-status digests;
- the profile-pinned local policy identifier, version, and digest;
- the policy/control epoch and the action validity interval; and
- the profile-pinned provider route and outcome-evidence profile. The runner does
  not cryptographically authenticate a live provider endpoint.

The final provider-entry guard resamples its clock after the asynchronous status read
and evaluates the action interval again before Gate asks the store to serialize provider
entry. Admission requires
`valid_from <= checked_at < expires_at`; malformed or expired intervals refuse before
the provider is called, and an expired action burns the reserved authority.

For an isolation, disconnection, replacement, or removal action, the relying party may
also require current, separately governed safety, reliability, replacement-availability,
and continuity evidence. Gate can require and bind those artifacts; it does not decide
whether their underlying assertions are true or legally sufficient.

### Decision and outcome record

The target decision-record contract includes the exact action digest, status observation
and digest, policy digest and epoch, admission domain, reservation, and refusal or
admission result. This runner supplies the status evidence to the effect and later
copies it into the execution detail; it does not atomically persist that evidence with
provider entry. If provider entry occurs, the operation becomes terminal as either
`EXECUTED` or `INDETERMINATE`. Post-entry uncertainty consumes the authority and refuses
blind replay. An authenticated outcome statement remains a statement by the configured
source, not proof of physical truth.

## Clause-to-control map

This map describes a possible implementation aid. It does not state that the order
requires EMILIA or any particular artifact format.

| Order basis | Authoritative decision outside EMILIA | Profile control at Gate | Evidence produced, with boundary |
| --- | --- | --- | --- |
| Sec. 2(a)(i)-(ii): covered foreign interest and unacceptable-risk determinations | Government determines covered status and risk | Require a current, pinned status record for the exact equipment/vendor/transaction; bind its digest and observation time to the action | Shows which governed status Gate used; does not determine origin, ownership, control, or risk |
| Sec. 2(b): conditions on continued use, operation, maintenance, servicing, or updating | Government or operator defines the applicable condition | Bind the condition identifier and digest to one asset, operation, parameter set, admission domain, and validity interval | Shows whether one covered action matched the configured condition |
| Sec. 2(b): identify, isolate, monitor, secure, disconnect, replace, or remove | Authorized operator selects a bounded response | Use distinct action types and authority scopes for observation, isolation, disconnection, replacement, and removal | Prevents a monitoring authorization from being reused for a destructive action on a covered path |
| Sec. 2(b): reliability, safety, secure replacements, continuity, and phased compliance | Designated sources assess these factors | Require current evidence references for disruptive actions and bind the selected phase/policy epoch | Shows which assertions were required and accepted; does not establish their truth or adequacy |
| Sec. 2(c): negotiated mitigation measures as preconditions | Government issues or accepts the mitigation measure | Bind mitigation id, version, digest, status, scope, and expiry to the exact action | Shows that Gate evaluated the configured precondition, not that the measure satisfies the order |
| Sec. 2(d): statutes, regulations, orders, directives, or licenses may provide exceptions | Competent authority supplies the exception or license | Pin issuer, scope, status, observation time, and expiry; refuse absent or stale authority | Does not interpret law or establish that an exception applies |
| Sec. 2(e): pre-qualified equipment and vendor lists | Government establishes and maintains the list | Consume a current signed or otherwise authenticated list entry immediately before provider entry; project source freeze/revision state into Gate's serialized control domain when race-free revocation is required | The runner proves a committed Gate-domain freeze wins, not atomicity with an arbitrary external list |
| Sec. 2(f): evasion and avoidance | Competent authority determines evasion or violation | Bind all material action fields; refuse asset, parameter, domain, operation, and fleet-scope substitution | Detects profile-defined substitution; does not make an intent or legal-violation finding |
| Sec. 3(b): future rules may identify entities, equipment, scrutiny, and licensing procedures | Government publishes controlling rules and status sources | Pin policy source, version, digest, status vocabulary, and effective interval | Makes the applied rule set reproducible; does not predict or replace final rules |
| Sec. 3(c): identify, inventory, isolate, monitor, or replace affected items | Asset owner and designated authorities maintain inventory and decisions | Bind site, asset, model, serial, configuration, firmware, and exact lifecycle action | Shows the asset identity presented to Gate; does not prove inventory completeness |
| Sec. 4(a)-(b): federal procurement recommendations and possible FAR amendments | DOE, FAR Council, and contracting authorities define procurement requirements | Export an offline decision packet joining exact action, current status, policy, admission, and outcome references | Supports procurement review; it is not a FAR representation or contract-compliance finding |
| Sec. 5(a)-(b): bulk-power scope, exclusions, equipment, software, firmware, remote access, and lifecycle mechanisms | Competent authority determines whether the item is in scope | Require an external scope assertion and bind it to the exact asset and action | Does not determine legal scope; local distribution remains excluded by the order's definition |
| Sec. 6: recurring and final reports to Congress | Government defines reporting content and completeness | Preserve exportable, action-bound decision and outcome records | Does not establish population completeness or satisfy a reporting obligation by itself |

## Hostile cases the profile must refuse or preserve safely

The executable runner covers selected rows and several narrower substitutions. Rows
that require a production key/status service, durable restart, or a live deployment
remain conformance requirements for an integrating system.

| Case | Required behavior |
| --- | --- |
| Asset substitution | Changing site, asset id, model, serial, configuration, or equipment class refuses before provider entry |
| Parameter substitution | Changing an operation, register, value, limit, firmware digest, or target set produces a different exact action and refuses |
| Admission-domain substitution | Authority issued for one relying party or control domain cannot cross another |
| Single asset widened to a fleet | A one-device authority cannot be expanded by a wildcard, group id, or altered target list |
| Read-only authority reused for mutation | Monitoring authority cannot admit isolate, disconnect, update, replace, or remove |
| Stale, revoked, unavailable, or untrusted external status | Refuse before provider entry, even if an older artifact still verifies cryptographically |
| Cached `ACTIVE` races a Gate-domain freeze | Recheck immediately before entry; a freeze already committed in Gate's serialized control domain wins. External-source race freedom requires source-to-domain integration |
| Firmware or configuration drift | A digest change after authorization refuses until new authority covers the new bytes |
| Expired exact action | Recheck `valid_from` and `expires_at` at provider entry; an expired action burns its reservation and never reaches the provider |
| Secure transport offered as authority | An authenticated tunnel without the required action-bound authority artifact refuses |
| Replay, including after restart | Durable consumption state permits at most one admitted provider attempt for the operation |
| Response loss after provider entry | Record `INDETERMINATE`, consume authority, and refuse blind retry |
| Negative reconciliation after provider entry | A later `not_entered` assertion cannot release authority already consumed at provider entry |
| Untrusted or revoked outcome signer | Preserve admission state but refuse the outcome statement as evidence |
| Clock skew or expired evidence | Apply the relying party's pinned clock policy and refuse outside the accepted interval |

## Claim boundary

In the exercised paths, this profile can show which material normalized command fields,
authenticated configured equipment-status record, profile-pinned local policy values,
and admission domain the configured Gate evaluated; whether it refused or admitted that action; whether authority was consumed
once in the in-process store; and which terminal outcome Gate recorded for the provider
attempt. Signed outcome-statement verification is outside this runner.

It does **not** establish:

- compliance with the order, future DOE rules, the FAR, a contract, or any law;
- whether equipment or a vendor is foreign-produced, owned, controlled, directed,
  pre-qualified, licensed, safe, or legally in scope;
- device, firmware, supply-chain, or operator integrity;
- the absence of a backdoor, bypass path, malicious logic, or compromise;
- physical actuation, physical meter truth, grid reliability, safety, or continuity;
- complete inventory, complete mediation outside the deployed Gate, or population
  completeness;
- certification, accreditation, Government approval, adoption, or endorsement.

This is a synthetic, source-pinned implementation profile. A real deployment requires
authoritative status feeds, trusted clocks and keys, durable shared admission state,
source-to-domain freeze or revision integration, atomic durable entry-evidence persistence,
complete mediation of every protected path, independently governed outcome evidence,
and site-specific engineering and safety review.
