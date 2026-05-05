export const metadata = {
  title: 'AI Voice Cloning Fraud — Defense by Action Binding',
  description:
    'Voice authentication breaks when 3 seconds of audio reproduces any ' +
    'caller. Pre-action authorization sidesteps the channel: bind the ' +
    'action to a named human signoff, not the actor channel. Field guide ' +
    'for community banks, credit unions, and fintech treasury teams.',
  alternates: { canonical: '/blog/ai-voice-cloning-fraud-defense' },
  openGraph: {
    title: 'AI Voice Cloning Fraud — Defense by Action Binding',
    description:
      'Voice authentication is broken. Action binding is the next layer. ' +
      'Field guide for treasury, wire desks, and fraud operations.',
    url: 'https://www.emiliaprotocol.ai/blog/ai-voice-cloning-fraud-defense',
    type: 'article',
    publishedTime: '2026-04-22T00:00:00.000Z',
  },
  keywords: [
    'AI voice cloning fraud',
    'voice deepfake fraud defense',
    'wire fraud AI voice',
    'community bank fraud',
    'credit union fraud',
    'BEC voice fraud',
    'treasury fraud prevention',
    'callback fraud AI',
  ],
};

export default function BlogVoiceFraudLayout({ children }) {
  return children;
}
