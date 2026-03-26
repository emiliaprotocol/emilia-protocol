export const metadata = {
  title: '404 — EMILIA Protocol',
};

export default function NotFound() {
  return (
    <html lang="en">
      <head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=IBM+Plex+Sans:wght@400;700&display=swap" rel="stylesheet" />
        <style>{`
          *{margin:0;padding:0;box-sizing:border-box}
          body{background:#0a0f1e;color:#f0f4ff;font-family:'IBM Plex Sans',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:40px 24px}
          .logo{font-family:'IBM Plex Mono',monospace;font-size:12px;letter-spacing:3px;color:#475569;text-transform:uppercase;margin-bottom:48px}
          .code{font-family:'IBM Plex Mono',monospace;font-size:80px;font-weight:700;color:rgba(74,144,217,0.15);line-height:1;margin-bottom:16px}
          h1{font-size:clamp(22px,4vw,32px);font-weight:700;margin-bottom:12px}
          p{font-size:15px;color:#64748b;max-width:420px;line-height:1.7;margin-bottom:36px}
          .links{display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
          a{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;text-decoration:none;padding:10px 20px;border-radius:8px;transition:all .2s}
          .btn-p{background:rgba(96,165,250,0.1);border:1px solid rgba(96,165,250,0.25);color:#60a5fa}
          .btn-p:hover{background:rgba(96,165,250,0.18)}
          .btn-s{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);color:#64748b}
          .btn-s:hover{color:#f0f4ff;border-color:rgba(255,255,255,0.15)}
        `}</style>
      </head>
      <body>
        <div className="logo">EMILIA Protocol</div>
        <div className="code">404</div>
        <h1>Page not found</h1>
        <p>This route doesn&rsquo;t exist in the protocol. The entity you&rsquo;re looking for may have moved or never existed.</p>
        <div className="links">
          <a href="/" className="btn-p">Back to Home</a>
          <a href="/appeal" className="btn-s">File an Appeal</a>
          <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" className="btn-s">GitHub</a>
        </div>
      </body>
    </html>
  );
}
