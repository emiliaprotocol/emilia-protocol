export const metadata = {
  title: 'EMILIA Protocol — Portable Trust for Machine Counterparties and Software',
  description: 'An open protocol for trust profiles, policy evaluation, and appeals across commerce, software, marketplaces, and AI systems.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
