export const metadata = {
  title: 'Eye — Graduated Risk Observation Without Production Risk',
  description:
    'EP\'s Eye layer observes risk patterns in three modes: OBSERVE (log ' +
    'only), SHADOW (evaluate without acting), ENFORCE (gate the action). ' +
    'Roll out enforcement without breaking production traffic.',
  alternates: { canonical: '/eye' },
  openGraph: {
    title: 'Eye — Observe → Shadow → Enforce',
    description:
      'Graduated AI-action risk observation. Roll out enforcement safely.',
    url: 'https://www.emiliaprotocol.ai/eye',
    type: 'article',
  },
};

export default function EyeLayout({ children }) {
  return children;
}
