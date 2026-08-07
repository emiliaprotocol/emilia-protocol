/**
 * Shared copy for /ai-agent-approvals.
 *
 * The FAQ lives here so the visible section (page.tsx, a client component) and
 * the FAQPage JSON-LD (layout.tsx, a server component that needs the CSP nonce)
 * are rendered from one array and can never drift apart.
 *
 * @license Apache-2.0
 */

export const PAGE_URL = 'https://www.emiliaprotocol.ai/ai-agent-approvals';

export const FAQ = [
  {
    q: 'What is an AI agent approval workflow?',
    a: 'A single decision point in front of every consequential action an agent attempts, with three outcomes: run it '
      + 'because it is inside policy, escalate it to a named human because it is outside policy, or refuse it because no '
      + 'approver could make it acceptable. The design work is in the second outcome and in what that escalation produces.',
  },
  {
    q: 'How do you stop an agent from approving its own actions?',
    a: 'By making authority flow only downward and fail closed. A principal that itself holds delegated authority cannot '
      + 'grant more than it holds, and a request for a scope outside that is refused as a scope escalation. If the '
      + 'delegation record cannot be read at all, the request refuses rather than falling back to permissive. The assurance '
      + 'tier is also not self-declared: a receipt that merely claims a higher tier is graded down and refused.',
  },
  {
    q: 'What is the difference between an approval and an authorization receipt?',
    a: 'An approval is an event in your system. A receipt is a portable artifact: a signature over the exact action, the '
      + 'named approver, the pinned policy, and a one-time consumption key, verifiable by someone who does not trust your '
      + 'systems and cannot query them.',
  },
  {
    q: 'Can an approval be reused?',
    a: 'Not on a mediated path. Consumption is keyed to a stable issuer-generated receipt identifier, and a second '
      + 'presentation is refused as a replay rather than executing a second time. The key is deliberately not a hash of '
      + 'the content, because canonicalization differences between language implementations would silently break replay '
      + 'detection when services share a consumption store.',
  },
] as const;
