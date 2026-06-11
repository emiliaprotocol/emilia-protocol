// SPDX-License-Identifier: Apache-2.0
// Metadata for /try — the self-serve Class-A signoff demo. Built as a layout so
// the page itself can stay a client component.

export const metadata = {
  title: 'Try it: approve an AI agent action with Face ID — EMILIA Protocol',
  description:
    'An AI agent tries to wire $82,000. Approve it on your own device with Face ID / Touch ID, then watch the approval verify — every check — in your browser, and watch a forged amount collapse. No account, nothing uploaded.',
  alternates: { canonical: '/try' },
  openGraph: {
    title: 'Be the human in the loop — approve an agent action with Face ID',
    description:
      'A real WebAuthn signoff, verified live in your browser with the open-source @emilia-protocol/verify. Then tamper one digit and watch the signature collapse.',
    url: 'https://www.emiliaprotocol.ai/try',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Be the human in the loop — approve an agent action with Face ID',
    description:
      'A real WebAuthn signoff, verified live in your browser. Tamper one digit and watch it collapse.',
  },
};

export default function TryLayout({ children }) {
  return children;
}
