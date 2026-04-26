import { headers } from 'next/headers';
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import './ep.css';

// Self-host IBM Plex via next/font so the browser does not block on the
// Google Fonts CSS request and so we eliminate the @next/next/no-page-custom-font
// lint warning. The font name strings used by ep.css (`IBM Plex Sans`,
// `IBM Plex Mono`) are matched verbatim by next/font's font-family output,
// so existing `font-family: 'IBM Plex Sans'` rules continue to work.
const ibmPlexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['300', '400', '500', '600', '700'],
  display: 'swap',
});
const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  display: 'swap',
});

export const metadata = {
  title: 'EMILIA Protocol — Trust Before High-Risk Action',
  description: 'Protocol-grade trust infrastructure for high-risk action enforcement. Bind actor identity, authority, policy, exact action context, replay resistance, one-time consumption, and accountable signoff before execution.',
  icons: {
    icon: [
      { url: '/favicon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico', sizes: '32x32' },
    ],
  },
};

// Reading headers() forces dynamic rendering per request.
// Next.js detects the x-nonce header and automatically applies it
// as the nonce attribute on every inline <script> it generates
// (flight data chunks, bootstrap scripts, etc.) — satisfying the
// nonce-based CSP set by middleware.js without unsafe-inline.
export default async function RootLayout({ children }) {
  const nonce = (await headers()).get('x-nonce') ?? '';

  // ibmPlexSans/ibmPlexMono are referenced for their side-effect of
  // injecting the @font-face CSS via next/font; the className string is
  // applied to <html> so font-family lookups in ep.css resolve.
  const fontClass = `${ibmPlexSans.className} ${ibmPlexMono.className}`;
  // Reference nonce so the lint pass keeps the headers() call (its true
  // purpose is forcing dynamic rendering for CSP nonce injection).
  void nonce;

  return (
    <html lang="en" className={fontClass}>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.ico" sizes="32x32" />
      </head>
      <body style={{ margin: 0, padding: 0, background: '#FAFAF9', overflowX: 'hidden' }}>{children}</body>
    </html>
  );
}
