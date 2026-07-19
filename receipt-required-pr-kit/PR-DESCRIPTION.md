# Add "Receipt Required" to one dangerous action

This PR puts a **Receipt Required** rail in front of a single irreversible action (`delete_all_records`). It's small, has no backend dependency, and is fully offline.

**What it does** — the action refuses to run unless it arrives with a verifiable authorization receipt (proof a named human approved *this exact action*):

| Check | Behavior |
|---|---|
| Missing receipt | `428 Receipt Required` (refused) |
| Valid receipt | action runs (`200`) |
| Replayed receipt | refused (one-time consumption) |
| Forged receipt | refused (signature / action-binding fails) |

**How it's verified** — `receipt-required.test.js` runs the four checks on every push via the published conformance harness and asserts level **RR-1**. It also proves that presenter-written “human” or “quorum” labels cannot satisfy Class-A, and that missing relying-party assurance configuration fails closed. The self-contained test uses a generated P-256 WebAuthn-shaped fixture; it demonstrates verifier behavior, not a real person's ceremony.

**What it is / isn't** — this is *not* auth ("who are you") or permissions ("are you allowed"). It's portable accountability evidence the service keeps for its own liability: it proves a named human authorized the action — a *necessary, not sufficient*, condition. It does not prove the decision was wise or lawful.

**Dependency** — one package, `@emilia-protocol/require-receipt` (Apache-2.0), which uses the open `@emilia-protocol/verify` reference verifier. No API key, no account, no EMILIA server trusted. Spec: IETF Internet-Drafts `draft-schrock-ep-authorization-receipts` and `draft-schrock-ep-enforcement-point` (individual I-Ds, not RFCs).

**Production note** — the demo verifies the outer receipt with `allowInlineKey: true` for self-containment. In production, pin the issuer keys, the enrolled approver-key directory, WebAuthn RP ID and origins; drop `allowInlineKey`; and use an ownership-fenced durable `{ reserve, commit, release }` store. Issuer trust, human assurance, and one-time consumption are separate requirements.

Happy to adjust which action this guards, or the assurance class, before merge.
