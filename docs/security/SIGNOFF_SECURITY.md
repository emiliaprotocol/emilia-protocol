# EMILIA Protocol -- Signoff Security

## Scope

This document covers security considerations specific to Accountable Signoff -- the mechanism by which a human (or authorized system) explicitly approves a trust-bearing action. Signoff is the final human-in-the-loop gate before a handshake outcome is consumed.

---

## 1. Approval Laundering

**Threat**: An actor obtains signoff for a low-risk action and reuses or redirects it to authorize a high-risk action.

**Mitigation**:

- **Authority class matching**: The signoff actor must hold an authority class that matches the action's risk classification. A signoff from a `standard` authority cannot authorize a `critical` action. Policy rules define which authority classes are required for each risk tier.
- **Policy-enforced ownership**: The signoff is bound to a specific handshake via `handshake_id`. The binding hash includes `action_type`, `resource_ref`, `policy_id`, `payload_hash`, and `party_set_hash`. Redirecting a signoff to a different action produces a binding hash mismatch, which is rejected at verification.
- **Consumption model**: Signoff attestations are consumed once (see Section 8). A consumed signoff cannot be replayed against a different action.

---

## 2. Signoff Fatigue

**Threat**: If every action requires signoff, approvers develop reflexive approval habits and stop evaluating risk.

**Mitigation**:

- **Adaptive signoff**: Signoff is required only for policy-defined high-risk action classes. Low-risk and medium-risk actions proceed through standard handshake verification without human signoff.
- **Risk classification**: Policy rules assign risk classes to action types. Only actions classified at or above the signoff threshold trigger the signoff flow.
- **Concise risk UI**: The signoff interface must present a focused summary: action type, target resource, risk class, and material changes. Verbose or irrelevant context degrades attention. The interface should not exceed one screen of content.
- **Batching prohibition**: Each signoff approves exactly one action. Batch approval of multiple unrelated actions is not supported by the protocol.

---

## 3. Signoff Social Engineering

**Threat**: An attacker manipulates the signoff approver into approving a harmful action by obscuring, misrepresenting, or omitting critical details.

**Mitigation -- mandatory disclosure**: Before signoff, the human must see:

1. **Exact action**: The `action_type` and any qualifying parameters.
2. **Target**: The `resource_ref` identifying what is being acted upon.
3. **Before/after diff**: For state-changing actions, the material difference between current state and proposed state.
4. **Risk class**: The policy-assigned risk classification of this action.
5. **Consequences**: A plain-language summary of what happens if the action proceeds, including irreversibility.

**Enforcement**: The signoff UI layer must render all five elements. The protocol does not accept signoff attestations from channels that cannot present structured content (e.g., a plain "yes/no" prompt without context is insufficient for `critical` risk class actions).

**Anti-spoofing**: The signoff interface must source action details from the handshake binding record, not from the requesting application. This prevents a malicious application from showing a benign description while the actual binding references a destructive action.

---

## 4. Channel Security

### 4.1 Allowed Signoff Methods

Signoff attestation must be collected through a channel that provides:
- **Authentication**: The approver's identity is verified.
- **Integrity**: The attestation cannot be modified in transit.
- **Non-repudiation**: The approver cannot deny having given signoff.

**Approved channels**:
- **Passkey / WebAuthn**: Preferred. Hardware-bound credential with user presence verification.
- **Platform authenticator**: OS-level biometric or PIN (Touch ID, Windows Hello). Acceptable for all risk classes.
- **Secure application**: A dedicated signoff application that renders the full action context and collects explicit confirmation. Must use TLS and authenticate the approver.
- **Out-of-band confirmation**: A separate communication channel (e.g., push notification to a registered device) where the approver reviews and confirms. Must include action details, not just a code.

### 4.2 SMS as Transitional

SMS-based signoff is permitted only for `low` and `medium` risk classes as a transitional mechanism. SMS does not provide adequate protection against SIM-swapping, interception, or spoofing for high-risk actions.

Deployments should establish a migration timeline to move all signoff to passkey/WebAuthn or platform authenticator.

### 4.3 Biometric Handling

EP never stores raw biometric data. Biometric verification is delegated to the platform authenticator (which stores templates in a secure enclave). The signoff attestation contains a cryptographic proof of user presence, not biometric samples.

---

## 5. Dual Signoff Requirements

**When required**: Policy rules may specify dual signoff for actions at `critical` risk class or above a configurable threshold (e.g., financial transactions above a value limit, permission changes affecting multiple entities).

**Model**:
- Two distinct entities must each provide independent signoff attestations.
- The two signers must have different `entity_ref` values. Self-dual-signoff is rejected.
- Both attestations must reference the same `handshake_id` and binding hash.
- Both must be collected within the binding's TTL window.

**Threshold configuration**: Dual signoff thresholds are defined in policy rules, not hardcoded. A policy may require dual signoff for:
- Any action with `risk_class: 'critical'`.
- Financial mutations above a specified amount.
- Permission changes affecting more than N entities.

---

## 6. Signoff Expiry and Revocation

### 6.1 Expiry

Signoff attestations inherit the binding TTL. A signoff collected at time T is valid until the binding's `expires_at`. If the binding expires before the downstream action consumes it, both the binding and the signoff are void.

There is no mechanism to extend signoff validity. If the window closes, a new handshake must be initiated and new signoff collected.

### 6.2 Revocation

A signoff can be revoked before consumption by transitioning the handshake to `revoked` status. Once the handshake is revoked, the binding cannot be consumed, and the signoff attestation is effectively void.

After consumption, revocation of the signoff is not possible -- the action has already been authorized. Post-consumption remediation must go through the protocol's reversal or appeal mechanisms.

---

## 7. Signoff Replay Prevention

**Mechanism**: Signoff attestations are consumed once through the same one-time consumption mechanism used for all handshake bindings.

**Enforcement**:
- The binding's `consumed_at` field transitions from `null` to a timestamp on first consumption.
- The update uses `.is('consumed_at', null)` as a conditional filter (compare-and-swap).
- A unique constraint on `handshake_consumptions` prevents duplicate consumption records.
- The hard gate at the top of `_handleVerifyHandshake()` rejects already-consumed bindings before any processing.

**Result**: A signoff attestation authorizes exactly one action. Capturing and replaying the attestation produces `binding_already_consumed` and the action is rejected.

---

## 8. Signoff Audit Trail

Every signoff produces protocol events:
- `signoff_requested`: Logged when the signoff flow is initiated.
- `signoff_provided`: Logged when the attestation is received, including the channel used and the approver's entity reference.
- `signoff_consumed`: Logged when the downstream action consumes the binding.

Events are written before state changes (event-first ordering). If event persistence fails, the signoff state change does not proceed.

The event trail enables forensic reconstruction of who approved what, when, through which channel, and what action consumed the approval.
