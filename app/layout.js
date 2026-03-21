export const metadata = {
  title: 'EMILIA Protocol — Trust Before High-Risk Action',
  description: 'Protocol-grade trust infrastructure for high-risk action enforcement. Bind actor identity, authority, policy, exact action context, replay resistance, one-time consumption, and accountable signoff before execution.',
  icons: {
    icon: [
      { url: '/favicon.svg', type: 'image/svg+xml' },
    ],
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#0a0f1e', overflowX: 'hidden' }}>{children}</body>
    </html>
  );
}
