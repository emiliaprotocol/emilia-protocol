export const metadata = {
  title: 'Sub-processors — EMILIA Protocol',
  description:
    'Third-party vendors that process data on behalf of EMILIA Protocol ' +
    'customers. Updated whenever a data flow changes. Customers may ' +
    'subscribe to change notifications.',
  alternates: { canonical: '/legal/sub-processors' },
  openGraph: {
    title: 'EMILIA Protocol Sub-processors',
    description: 'Third-party data processors and their roles.',
    url: 'https://www.emiliaprotocol.ai/legal/sub-processors',
    type: 'article',
  },
};

export default function SubProcessorsLayout({ children }) {
  return children;
}
