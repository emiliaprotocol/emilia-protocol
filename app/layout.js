export const metadata = {
  title: 'EMILIA Protocol',
  description: 'The open-source credit score for the agent economy.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
