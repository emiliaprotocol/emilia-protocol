<!-- SPDX-License-Identifier: Apache-2.0 -->
# Optional Poppy operation-approval evidence profile

Status: implementation candidate, authored by EMILIA. This profile is not adopted
by Poppy's maintainers. It composes existing EP verification with Operations v1;
it does not change Poppy's approval, session, transport or outcome definitions.

## Discovery

Poppy core section 3.3 permits domain-named optional extensions. A company and a
personal agent must advertise this profile before using it:

```json
{
  "extensions": {
    "operations": { "version": "1" },
    "emiliaprotocol.ai/approval-evidence": { "version": "1" }
  }
}
```

The company also advertises its normal Operations endpoint. An operation subject
to the stronger profile cannot silently fall back to an agent assertion when the
extension is unsupported or its evidence is missing. It returns `extension_required`
or the profile's bounded refusal; it does not execute.

## Confirmation

The confirmation keeps Poppy's operation ID in the URL and its numeric revision
and approval mode in the body. The optional extension carries a native EP-AEC-v1
chain containing a Class-A Trust Receipt:

```json
{
  "revision": 1,
  "approved_by": "user",
  "extensions": {
    "emiliaprotocol.ai/approval-evidence": {
      "version": "1",
      "evidence": { "@version": "EP-AEC-v1" }
    }
  }
}
```

The abbreviated evidence object above is not valid evidence. The executable demo
constructs a complete native artifact. Do not infer trust from an artifact's
embedded keys, role labels or approval strings.

## Exact binding

`buildPoppyAction` constructs the verifier's expected action from the immutable,
company-owned operation and authenticated owner context. It binds company issuer,
authenticated personal-agent identity and pairwise user identity, account or the
original signed-out session, operation ID, revision, complete summary, complete
structured terms when present, expiry and the operation's approval requirement.
Optional material is not silently discarded. Missing terms and empty terms remain
different. A new revision needs evidence for that revision.

A signed-in operation remains accessible from a new session of the same personal
agent, user and account, as Poppy permits. A signed-out operation remains scoped
to its original session. This does not create authority for another account or
another agent.

The company pins the EP receipt profile, enrolled keys, allowed origins, audience,
policy, freshness and log trust outside the transaction. The native AEC verifier
must verify the Class-A leg against this exact expected action. A machine's signed
statement cannot replace the required credential ceremony.

The pinned `ownerScope` associates that profile with one authenticated
client/user/account, or the original signed-out session. It does not infer a
customer's civil identity or legal authority from an enrolled key. The hosting
company must establish and maintain that association. The verifier checks the
same immutable evidence again after asynchronous authority resolution, immediately
before confirmation is atomically accepted. This is freshness at confirmation;
later provider-entry requirements remain the configured Gate's responsibility.

## Execution remains separate

Evidence satisfaction is not execution authority. The company's configured Gate
independently verifies its native authority record against the resolved action.
The Poppy adapter then uses Gate's existing reserve-before-provider-entry path.
It must not reinterpret a Trust Receipt as an EP-RECEIPT-v1 Gate record.

Operation state and Gate consumption must remain fail-closed across failures.
After provider entry, lost responses or uncertain storage/evidence completion
leave the operation `in_progress`. A retry reads or reconfirms the same operation;
it does not request another effect. A final result requires the hosting company's
configured, authenticated outcome procedure.

## Non-claims

This profile proves only the accepted artifact's specified cryptographic and
binding properties under company-pinned inputs. It does not prove civil identity,
human understanding, current legal authority, correctness of terms, provider
honesty, an external physical effect, complete mediation outside the installed
boundary, universal replay prevention or Poppy endorsement.

Poppy section 8 already allows the company to obtain approval on its own site.
This candidate supplies one portable evidence implementation, not the only way
to meet a business's stronger assurance requirement.
