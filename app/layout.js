export const metadata = {
  title: 'EMILIA Protocol — Trust Before High-Risk Action',
  description: 'Protocol-grade trust infrastructure for high-risk action enforcement. Bind actor identity, authority, policy, and exact action context before execution.',
  icons: {
    icon: [
      { url: "data:image/svg+xml,%3Csvg width='32' height='32' viewBox='0 0 34 34' xmlns='http://www.w3.org/2000/svg'%3E%3Crect x='7' y='5' width='2.5' height='24' rx='1.25' fill='%234a90d9'/%3E%3Crect x='9.5' y='5' width='16' height='2.5' rx='1.25' fill='%234a90d9'/%3E%3Crect x='9.5' y='15.5' width='12' height='2.5' rx='1.25' fill='%23d4af55'/%3E%3Crect x='9.5' y='26.5' width='14' height='2.5' rx='1.25' fill='%234a90d9'/%3E%3C/svg%3E", type: 'image/svg+xml' },
    ],
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#0a0f1e', overflowX: 'hidden' }}>{children}</body>
    </html>
  );
}
