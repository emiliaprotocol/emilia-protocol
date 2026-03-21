# EP Handshake State Machine

Formal description of the allowed state transitions in the EP handshake lifecycle.

---

## State Diagram

```
                          +-----------+
                          |   none    |
                          +-----+-----+
                                |
                           Initiate()
                                |
                          +-----v-----+
                     +--->| initiated |<---+
                     |    +-----+-----+    |
                     |          |          |
                     |     Present()       |
                     |          |          |
                     |  +-------v--------+ |
                     +--| pending_       |-+
                        | verification   |
                        +--+----+----+---+
                           |    |    |
             VerifyAccept()|    |    |VerifyReject()
             (policy OK,   |    |    |(policy fail,
              not revoked) |    |    | revoked issuer,
                           |    |    | missing party)
                      +----v-+  |  +-v-------+
                      |verified| |  |rejected |
                      +--+--+-+  |  +---------+
                         |  |    |   TERMINAL
                Consume()|  |    |
                         |  |  Expire()
                +--------v+ |  (binding past
                |consumed | |   expires_at)
                +---------+ |
                 TERMINAL   |  +--------+
                            +->|expired |
                               +--------+
                                TERMINAL

       Revoke() can be applied from:
         initiated, pending_verification, verified
       (but NOT from consumed, expired, rejected, revoked)

                        +--------+
                   ---->|revoked |
                        +--------+
                         TERMINAL
```

---

## States

| State                  | Terminal | Description |
|------------------------|----------|-------------|
| `none`                 | --       | Pre-existence; handshake not yet created |
| `initiated`            | No       | Handshake created, awaiting presentations |
| `pending_verification` | No       | At least one presentation added, awaiting verification |
| `verified`             | No       | All invariants passed; handshake accepted and ready for consumption |
| `rejected`             | Yes      | Verification failed (policy, trust, binding, or party violation) |
| `expired`              | Yes      | Binding TTL exceeded before verification completed |
| `revoked`              | Yes      | Explicitly revoked by an authorized party or system |
| `consumed`             | Yes      | One-time consumption completed; handshake fulfilled its purpose |

---

## Allowed Transitions

| From                   | To                     | Action           | Code Reference |
|------------------------|------------------------|------------------|----------------|
| `none`                 | `initiated`            | `Initiate()`     | `lib/handshake/initiate.js` |
| `initiated`            | `pending_verification` | `Present()`      | `lib/handshake/present.js` |
| `pending_verification` | `verified`             | `VerifyAccept()`  | `lib/handshake/verify.js` (outcome=accepted) |
| `pending_verification` | `rejected`             | `VerifyReject()`  | `lib/handshake/verify.js` (outcome=rejected) |
| `pending_verification` | `expired`              | `Expire()`        | `lib/handshake/verify.js` (outcome=expired) |
| `verified`             | `consumed`             | `Consume()`       | `lib/handshake/consume.js` |
| `initiated`            | `revoked`              | `Revoke()`        | `lib/handshake/finalize.js` |
| `pending_verification` | `revoked`              | `Revoke()`        | `lib/handshake/finalize.js` |
| `verified`             | `revoked`              | `Revoke()`        | `lib/handshake/finalize.js` |
| `initiated`            | `expired`              | `Expire()`        | `lib/handshake/verify.js` (binding TTL) |
| `verified`             | `expired`              | `Expire()`        | `lib/handshake/verify.js` (binding TTL) |

---

## Forbidden Transitions

These transitions are explicitly prevented by code guards. The formal model (TLA+) proves they cannot occur.

| From        | To                     | Why Forbidden |
|-------------|------------------------|---------------|
| `consumed`  | any state              | Terminal. Unique constraint prevents re-consumption. DB row is immutable after consumption. |
| `revoked`   | any state              | Terminal. `finalize.js` line 78: rejects revoke on already-revoked. `verify.js` line 83: rejects verify on non-initiated/non-pending. |
| `expired`   | any state              | Terminal. Same status guard in `verify.js` line 83. `finalize.js` line 78: rejects revoke on expired. |
| `rejected`  | any state              | Terminal. Same status guard in `verify.js` line 83. |
| `verified`  | `initiated`            | No backward transitions exist in the protocol. |
| `verified`  | `pending_verification` | No backward transitions exist in the protocol. |
| `none`      | `verified`             | Must pass through `initiated` and `pending_verification` first. |
| `none`      | `consumed`             | Must pass through full lifecycle. |
| `initiated` | `verified`             | Must have presentations (`pending_verification`) before verification. |
| `initiated` | `consumed`             | Must pass through `verified` first. |

---

## Transition Preconditions

### Initiate
- Handshake does not yet exist
- Valid mode (basic, mutual, selective, delegated)
- Actor identity bound to initiator party

### Present
- Status is `initiated`
- Actor matches party entity_ref (no role spoofing -- invariant 9)
- Issuer resolved from authority registry (invariant 3)

### VerifyAccept
- Status is `initiated` or `pending_verification`
- Binding not expired (invariant 1)
- All required parties have presentations (invariant 2)
- Binding payload hash matches (invariant 3)
- All issuers trusted and not revoked (invariants 4, 5)
- Assurance level meets minimum (invariant 6)
- No duplicate accepted result (invariant 7)
- Interaction reference present (invariant 8)
- Policy hash matches initiation snapshot (tamper detection)

### VerifyReject
- Status is `initiated` or `pending_verification`
- One or more verification invariants failed

### Consume
- Status is `verified`
- Not already consumed (unique constraint)
- Binding hash integrity check passes

### Revoke
- Status is `initiated`, `pending_verification`, or `verified`
- Not `revoked` or `expired` (finalize.js line 78)
- Actor is a party to the handshake or `system`

### Expire
- Binding `expires_at` timestamp has passed
- Status is not already terminal

---

## Event Ordering Guarantee

Every state transition records a durable event BEFORE the state change:

1. `requireHandshakeEvent()` writes the event record
2. If event write succeeds, state is updated
3. If event write fails, state remains unchanged (safe)
4. If state update fails after event write, the event exists as an uncommitted-transition log (safe for retry)

This ordering is enforced in:
- `lib/handshake/verify.js` lines 278-285
- `lib/handshake/finalize.js` lines 88-94

---

---

## Accountable Signoff State Machine

The signoff lifecycle is a sub-state-machine that activates after a handshake reaches `verified`. It models an accountable challenge-response flow where a human actor must explicitly approve or deny a signoff before it can be consumed.

### Signoff State Diagram

```
                        +-----------+
                        |   none    |
                        +-----+-----+
                              |
                    IssueChallenge(h, actor)
                   (requires state[h] = "verified")
                              |
                    +---------v----------+
                    | challenge_issued   |
                    +--+-----+-----+----+
                       |     |     |
            ViewChallenge()  |     |
                       |     |     |
               +-------v---+|     |
               | challenge_ ||     |
               | viewed     ||     |
               +--+----+---+|     |
                  |    |     |     |
    ApproveSignoff()   |     |     |
    (binding match)    |     |     |
                  |    |     |     |
             +----v-+  |     |     |
             |approved| |     |     |
             +--+--+-+  |     |     |
                |  |    |     |     |
   ConsumeSignoff()|    |     |     |
   (binding match) |    |     |     |
                |  |    |     |     |
     +----------v+ |    |     |     |
     |consumed_  | |    |     |     |
     |signoff    | |    |     |     |
     +-----------+ |    |     |     |
      TERMINAL     |    |     |     |
                   |  DenySignoff()  |
                   |    |     |     |
                   | +--v---+ |     |
                   | |denied| |     |
                   | +------+ |     |
                   |  TERMINAL|     |
                   |          |     |
                   |   ExpireSignoff()
                   |          |     |
                   |  +-------v---+ |
                   |  |expired_   | |
                   |  |signoff    | |
                   |  +-----------+ |
                   |   TERMINAL     |
                   |                |
                   |     RevokeSignoff()
                   |                |
                   |        +-------v---+
                   |        |revoked_   |
                   |        |signoff    |
                   |        +-----------+
                   |         TERMINAL
                   |
        ExpireSignoff() / RevokeSignoff()
        can also be applied from approved
```

### Signoff States

| State              | Terminal | Description |
|--------------------|----------|-------------|
| `none`             | --       | No signoff in progress for this handshake |
| `challenge_issued` | No       | Signoff challenge issued, awaiting actor response |
| `challenge_viewed` | No       | Actor has viewed the challenge but not yet responded |
| `approved`         | No       | Actor approved the signoff; ready for consumption |
| `denied`           | Yes      | Actor explicitly denied the signoff |
| `expired_signoff`  | Yes      | Signoff TTL exceeded before approval or consumption |
| `revoked_signoff`  | Yes      | Signoff explicitly revoked by authorized party |
| `consumed_signoff` | Yes      | Signoff consumed; one-time use fulfilled |

### Signoff Transitions

| From               | To                 | Action              | Code Reference |
|--------------------|--------------------|----------------------|----------------|
| `none`             | `challenge_issued` | `IssueChallenge()`   | `lib/signoff/challenge.js` |
| `challenge_issued` | `challenge_viewed` | `ViewChallenge()`    | `lib/signoff/challenge.js` |
| `challenge_issued` | `approved`         | `ApproveSignoff()`   | `lib/signoff/approve.js` |
| `challenge_viewed` | `approved`         | `ApproveSignoff()`   | `lib/signoff/approve.js` |
| `challenge_issued` | `denied`           | `DenySignoff()`      | `lib/signoff/approve.js` |
| `challenge_viewed` | `denied`           | `DenySignoff()`      | `lib/signoff/approve.js` |
| `approved`         | `consumed_signoff` | `ConsumeSignoff()`   | `lib/signoff/approve.js` |
| `challenge_issued` | `expired_signoff`  | `ExpireSignoff()`    | `lib/signoff/revoke.js` |
| `challenge_viewed` | `expired_signoff`  | `ExpireSignoff()`    | `lib/signoff/revoke.js` |
| `approved`         | `expired_signoff`  | `ExpireSignoff()`    | `lib/signoff/revoke.js` |
| `challenge_issued` | `revoked_signoff`  | `RevokeSignoff()`    | `lib/signoff/revoke.js` |
| `challenge_viewed` | `revoked_signoff`  | `RevokeSignoff()`    | `lib/signoff/revoke.js` |
| `approved`         | `revoked_signoff`  | `RevokeSignoff()`    | `lib/signoff/revoke.js` |

### Signoff Preconditions

#### IssueChallenge
- Handshake status is `verified`
- No signoff currently in progress (`signoffState = "none"`)
- Actor has authority class matching policy requirement

#### ApproveSignoff
- Signoff state is `challenge_issued` or `challenge_viewed`
- Signoff binding hash matches handshake binding hash (tamper detection)

#### ConsumeSignoff
- Signoff state is `approved`
- Signoff binding hash matches handshake binding hash at consumption time

#### DenySignoff
- Signoff state is `challenge_issued` or `challenge_viewed`

#### ExpireSignoff / RevokeSignoff
- Signoff state is `challenge_issued`, `challenge_viewed`, or `approved`

### Signoff Forbidden Transitions

| From               | To                 | Why Forbidden |
|--------------------|--------------------|---------------|
| `denied`           | any state          | Terminal. Denied signoffs cannot be approved or consumed. |
| `consumed_signoff` | any state          | Terminal. Consumed signoffs are immutable. |
| `expired_signoff`  | any state          | Terminal. Expired signoffs cannot be reactivated. |
| `revoked_signoff`  | any state          | Terminal. Revoked signoffs cannot be reinstated. |
| `denied`           | `approved`         | Explicitly prevented (S18). |

---

## Formal Model References

- **TLA+ state machine**: `formal/ep_handshake.tla` (19 safety theorems, 23 actions)
- **Alloy relational model**: `formal/ep_relations.als` (32 facts, 15 assertions)
