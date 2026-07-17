// SPDX-License-Identifier: Apache-2.0

export const metadata = {
  title: 'Declaration to Proof — Human Consent for One Exact AI Use | EMILIA',
  description:
    'An independent compatibility reference showing how a standing media-use declaration '
    + 'can lead to a pinned, exact-use authorization receipt that an executor consumes once.',
  alternates: { canonical: '/eu/declaration-to-proof' },
  openGraph: {
    title: 'A declaration states the rule. A receipt proves one exact use.',
    description:
      'RSL-MEDIA declaration discovery composed with EMILIA exact-use authorization and '
      + 'one-time executor enforcement. Independent reference; no endorsement implied.',
    url: 'https://www.emiliaprotocol.ai/eu/declaration-to-proof',
    type: 'website',
    images: [{ url: '/hero-human-machine-shoreline-v1.webp' }],
  },
};

export default function DeclarationToProofLayout({ children }) {
  return children;
}
