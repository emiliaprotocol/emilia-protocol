export const metadata = {
  title: 'EMILIA Protocol',
  description: 'A vendor-neutral trust attestation standard for agentic commerce. Receipts, not reviews.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
