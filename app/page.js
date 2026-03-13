export default function Home() {
  return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 640, margin: '80px auto', padding: '0 20px' }}>
      <h1 style={{ fontSize: 48, fontWeight: 700, letterSpacing: 2 }}>EMILIA</h1>
      <p style={{ fontSize: 14, color: '#888', marginTop: -8 }}>
        Entity Measurement Infrastructure for Ledgered Interaction Accountability
      </p>
      <p style={{ fontSize: 20, marginTop: 24 }}>
        The open-source credit score for the agent economy.
      </p>
      <p style={{ color: '#666' }}>
        Reputation earned through receipts, not reviews.
      </p>
      <div style={{ marginTop: 40, fontSize: 14, color: '#888' }}>
        <p><strong>API Endpoints:</strong></p>
        <code style={{ display: 'block', margin: '8px 0' }}>POST /api/entities/register</code>
        <code style={{ display: 'block', margin: '8px 0' }}>POST /api/receipts/submit</code>
        <code style={{ display: 'block', margin: '8px 0' }}>GET  /api/score/:entityId</code>
      </div>
      <p style={{ marginTop: 40, fontSize: 13, color: '#aaa' }}>
        <a href="https://github.com/emiliaprotocol/emilia-protocol" style={{ color: '#666' }}>GitHub</a>
        {' · '}
        emiliaprotocol.ai
      </p>
    </div>
  );
}
