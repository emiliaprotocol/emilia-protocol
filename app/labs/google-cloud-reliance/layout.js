export const metadata = {
  title: 'External Reliance Lab for Google Cloud MCP',
  description:
    'A runnable compatibility lab showing why IAM and content controls are necessary but not sufficient for external reliance on consequential Google Cloud agent actions.',
  alternates: { canonical: '/labs/google-cloud-reliance' },
  openGraph: {
    title: 'IAM says the agent may act. Can the customer prove why it did?',
    description:
      'Google Cloud-shaped IAM mutation: four attacks refused, an exact two-person authorization runs once, and replay is refused.',
    url: 'https://www.emiliaprotocol.ai/labs/google-cloud-reliance',
    type: 'article',
  },
  keywords: [
    'Google Cloud MCP security',
    'Gemini agent governance',
    'Google Cloud IAM agent authorization',
    'Model Armor external reliance',
    'proof carrying MCP',
    'AI agent two person rule',
  ],
};

export default function GoogleCloudRelianceLayout({ children }) {
  return children;
}
