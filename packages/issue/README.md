# @emilia-protocol/issue

**Issue locally, verify anywhere.**

The signing-side companion to [`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify). It lets any external developer **mint** an EP authorization receipt (EP-RECEIPT-v1; I-D [draft-schrock-ep-authorization-receipts](https://www.emiliaprotocol.ai/spec/trust-receipt) §6.2) on their own machine, signed with their own keys — then anyone can verify it offline with `@emilia-protocol/verify`. No EMILIA backend. No account. No API key. Just `node:crypto`.

Zero runtime dependencies. The whole issuer is one small file you can read in an afternoon.

## Install

```bash
npm install @emilia-protocol/issue @emilia-protocol/verify
```

Or run the CLI straight from npx — no install needed.

## 60-second quickstart

```bash
# 1. Generate a local issuer bundle (one approver key + one log key)
npx @emilia-protocol/issue keygen --out issuer-keys.json --log-name acme

# 2. Describe the irreversible action you're authorizing
cat > action.json <<'JSON'
{
  "ep_version": "1.0",
  "action_type": "vendor_bank_account_change",
  "target": { "system": "erp.example", "resource": "vendor/acme" },
  "parameters": { "new_bank_hash": "sha256:9f2c..." },
  "initiator": "ep:entity:ap-agent",
  "policy_id": "ep:policy:vendor-bank-change@v1",
  "requested_at": "2026-06-12T16:00:00Z"
}
JSON

# 3. Issue a signed receipt (+ the public verification material)
npx @emilia-protocol/issue issue \
  --keys issuer-keys.json \
  --action action.json \
  --out receipt.json \
  --verification verification.json

# 4. Verify it offline — anyone, anywhere, with the public material only
node --input-type=module -e '
import { verifyTrustReceipt } from "@emilia-protocol/verify";
import { readFileSync } from "node:fs";
const receipt = JSON.parse(readFileSync("receipt.json", "utf8"));
const v = JSON.parse(readFileSync("verification.json", "utf8"));
const r = verifyTrustReceipt(receipt, { approverKeys: v.approver_keys, logPublicKey: v.log_public_key });
console.log(r.checks, r.valid ? "VERIFIED" : "NOT VERIFIED");
'
```

Want it in one shot? `npx @emilia-protocol/issue demo` generates throwaway keys, issues a sample receipt for a sample irreversible action, and verifies it — printing all 7 checks.

### Optional: attach an initiator escalation attestation (PIP-007)

One optional extra step. The initiator can attach its own **stated reason** for asking a human — a structured `escalation_trigger`, an optional `policy_basis` rule id, and an optional ≤280-char `statement`. Because the context is canonicalized whole, the approver's signature automatically covers it: the receipt then proves the stated reason was part of what the approver signed.

```bash
# Describe why the initiator escalated (one of: irreversibility, magnitude,
# uncertainty, novelty, authority_gap, policy_rule). policy_basis is required
# whenever a deterministic rule fired (always for policy_rule).
cat > attestation.json <<'JSON'
{
  "escalation_trigger": "irreversibility",
  "policy_basis": "ep:policy:vendor-bank-change@v1",
  "statement": "Vendor bank-account change is irreversible; policy requires a named human approval."
}
JSON

# Pass it to the same issue command — the attestation is copied verbatim into
# every context (identical across all of them for m-of-n approvals).
npx @emilia-protocol/issue issue \
  --keys issuer-keys.json --action action.json --out receipt.json \
  --verification verification.json \
  --attestation attestation.json
```

The attestation is **a claim by the initiator** — identified but never trusted. It does not relax any check or raise any trust score; `@emilia-protocol/verify`'s `verifyTrustReceipt()` surfaces it as an advisory (`result.attestation`) and flags malformed or cross-context-inconsistent attestations, but never changes signature validity. See [PIP-007](https://github.com/emiliaprotocol/emilia-protocol/blob/main/PIPs/PIP-007-initiator-attestation.md).

> The receipt is an I-D §6.2 authorization receipt, so it's verified with `@emilia-protocol/verify`'s `verifyTrustReceipt(receipt, { approverKeys, logPublicKey })` — the full §6.3 algorithm. (The `npx @emilia-protocol/verify <file>` CLI is for the single-signature EP-RECEIPT-v1 wire format.) `verification.json` supplies both the approver keys and the log public key, all public.

`receipt.json` is the portable evidence artifact. `verification.json` carries the public approver key entry and the log public key a verifier needs. **Keep `issuer-keys.json` secret** — it holds private keys.

## Library quickstart

```js
import { generateIssuerKeyBundle, issueFromKeyBundle } from '@emilia-protocol/issue';
import { verifyTrustReceipt } from '@emilia-protocol/verify';

const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });

const action = {
  ep_version: '1.0',
  action_type: 'payment.release',
  target: { system: 'treasury.example', resource: 'wire/8841' },
  parameters: { amount: '25000.00', currency: 'USD' },
  initiator: 'ep:entity:agent-recon-7',
  policy_id: 'ep:policy:wires-over-10k@v1',
  requested_at: new Date().toISOString(),
};

const { receipt, verification } = await issueFromKeyBundle({ keys, action });

const result = verifyTrustReceipt(receipt, {
  approverKeys: verification.approver_keys,
  logPublicKey: verification.log_public_key,
});

console.log(result.valid); // true
```

For multi-approver receipts, separation of duties, or chaining to a prior receipt, drop down to `buildContexts` → `collectSignoffs` → `assembleAuthorizationReceipt` (or the one-call `issueAuthorizationReceipt`). See `index.d.ts` for the full surface.

## What a locally-issued receipt proves — and what it does not

Be precise about the claim. A receipt this package issues proves, with offline cryptography and no trust in your logs or in EMILIA:

- a **named key** signed off on **this exact action** (the action hash binds every parameter — change one byte and verification fails);
- the signoff was made **under the stated policy** (the context commits to the policy hash);
- the signoff happened **before execution**, inside the stated validity window;
- the receipt is **included in a log checkpoint** signed by the named log key, so it can't be silently backdated or altered after the fact.

The receipt proves those things. It does **not** prove that **the human is who the key claims to be**. Binding a key to a real, identity-proofed person is a separate layer — the **Approver Directory** plus **Class-A device-bound (WebAuthn) signoffs**. A Class-B/C software-key signoff (what this CLI issues) proves a key authorized the action; it does not prove a specific enrolled human held that key.

**Class-A signoffs are not produced by this CLI.** A device-bound WebAuthn assertion (the strongest "a verified human was present" signal) requires EP's **hosted ceremony** — the issuer never holds the device key. This package issues Class-B/C software-key signoffs and assembles the full receipt around them. If you later add Class-A device signoffs through the ceremony, the same `@emilia-protocol/verify` checks them too.

In short: **issue locally to get the cryptographic crank turning — mint a receipt first, then layer the Approver Directory and Class-A device binding around it for human-identity assurance.**

## CLI reference

```
ep-issue keygen --out issuer-keys.json [--approver-id …] [--approver-key-id …] [--log-name acme | --log-key-id ep:log:acme#1]
ep-issue issue  --keys issuer-keys.json --action action.json --out receipt.json [--verification …] [--policy …] [--policy-hash sha256:…] [--receipt-id …] [--expires-in 3600] [--attestation attestation.json]
ep-issue demo
```

`keygen` prints the log key id in the canonical `ep:log:<name>#1` form. `issue` writes a complete signed receipt including the Merkle `log_proof`. `--attestation` attaches the optional PIP-007 initiator escalation attestation (see above); it is validated against PIP-007 §1 (enum, ≤280-char `statement`, only the three defined members) and copied verbatim into every context.

## Design principles

- **Zero dependencies** — only `node:crypto`. No supply chain risk.
- **Byte-compatible with the verifier** — canonicalization, hashing, and the Merkle/checkpoint shapes are identical to `@emilia-protocol/verify`'s reference profile (§6.3), so issued receipts verify 7/7. This is enforced in CI on every push.
- **Delegated signing** — the issuer never holds approver keys in its core path; each approver supplies a callback.

## License

Apache-2.0
