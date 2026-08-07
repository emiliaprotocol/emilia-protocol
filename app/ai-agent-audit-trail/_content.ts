/**
 * Shared copy for /ai-agent-audit-trail.
 *
 * The FAQ lives here so the visible section (page.tsx, a client component) and
 * the FAQPage JSON-LD (layout.tsx, a server component that needs the CSP nonce)
 * are rendered from one array and can never drift apart.
 *
 * @license Apache-2.0
 */

export const PAGE_URL = 'https://www.emiliaprotocol.ai/ai-agent-audit-trail';

export const FAQ = [
  {
    q: 'What is an AI agent audit trail?',
    a: 'A per-action record of what an autonomous agent did and what authorized it. To be useful in a review it has to '
      + 'carry the exact action parameters, the named human who approved that action, the assurance tier actually proven, '
      + 'the policy pinned at request time, a one-time consumption key, and the outcome, including the case where the '
      + 'outcome is unknown.',
  },
  {
    q: 'Are application logs enough for an AI agent audit trail?',
    a: 'Logs answer what your system says happened. They are written by the system whose conduct is under review, stored '
      + 'where that system controls, and read back through an interface it provides. That is sound engineering telemetry '
      + 'and a weak evidentiary position, because every step of the verification path runs through the party being '
      + 'questioned.',
  },
  {
    q: 'What does offline-verifiable mean here?',
    a: 'An EMILIA authorization receipt is an Ed25519 signature over the canonical JSON of a claim, optionally anchored in '
      + 'a sorted-pair Merkle tree. Checking it needs the receipt, the canonicalization rule, and the issuer public key the '
      + 'checker pinned. It does not need the issuing system to be reachable, cooperative, or still in business.',
  },
  {
    q: 'What happens when the provider never responds?',
    a: 'The record says indeterminate. Once the executor has been entered, a thrown error is an indeterminate effect, not '
      + 'proof that nothing happened. The authorization is burned rather than reopened, a blind retry on the same operation '
      + 'is refused, and the entry stays unresolved until authenticated provider evidence bound to the same operation and '
      + 'the same canonical action digest resolves it.',
  },
] as const;
