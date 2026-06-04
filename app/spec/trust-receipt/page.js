import { headers } from 'next/headers';
import Link from 'next/link';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { cta, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Trust Receipt Format (EP-RECEIPT-v1) — EMILIA Protocol',
  description:
    'The EP-RECEIPT-v1 specification: recursive canonical JSON, Ed25519 signatures, and '
    + 'sorted-pair Merkle anchors. Implementable in any language; verifiable offline in JS and Python.',
  alternates: { canonical: '/spec/trust-receipt' },
  openGraph: {
    title: 'Trust Receipt Format — EP-RECEIPT-v1',
    description: 'A signed, offline-verifiable record that an action was authorized. Implementable in any language.',
    url: 'https://www.emiliaprotocol.ai/spec/trust-receipt',
    type: 'article',
  },
  keywords: ['trust receipt', 'EP-RECEIPT-v1', 'Ed25519', 'Merkle proof', 'canonical JSON', 'AI agent authorization receipt', 'offline verification'],
};

const ARTICLE_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'TechArticle',
  headline: 'Trust Receipt Format (EP-RECEIPT-v1)',
  description:
    'Specification for EMILIA Protocol Trust Receipts: recursive canonical JSON, Ed25519 signatures over the '
    + 'canonical payload, and sorted-pair Merkle anchors. Two interoperating reference implementations (JS, Python).',
  about: 'Cryptographic authorization receipts for AI agent actions',
  url: 'https://www.emiliaprotocol.ai/spec/trust-receipt',
  author: { '@type': 'Organization', name: 'EMILIA Protocol' },
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
};

const C = ({ children, style }) => (
  <div style={{ maxWidth: 880, margin: '0 auto', padding: '0 32px', ...style }}>{children}</div>
);
const Pre = ({ children }) => (
  <pre style={{ fontFamily: font.mono, fontSize: 12.5, lineHeight: 1.65, color: '#D6D3D1', background: '#1C1917', border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '20px 22px', margin: '0 0 20px', overflowX: 'auto', whiteSpace: 'pre' }}>{children}</pre>
);
const H2 = ({ children }) => (
  <h2 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(20px, 2.4vw, 27px)', letterSpacing: -0.6, color: color.t1, margin: '52px 0 16px' }}>{children}</h2>
);
const P = ({ children }) => (
  <p style={{ fontSize: 15.5, color: color.t2, lineHeight: 1.75, margin: '0 0 16px' }}>{children}</p>
);
const mono = { fontFamily: font.mono, fontSize: 13, color: color.t1 };

const DOC = `{
  "@version": "EP-RECEIPT-v1",
  "payload":   { ... the signed claim ... },
  "signature": { "algorithm": "ed25519", "value": "<base64url>" },
  "anchor": {                                  // OPTIONAL
    "leaf_hash":    "<hex sha-256>",
    "merkle_proof": [ { "hash": "<hex>", "position": "left|right" } ],
    "merkle_root":  "<hex>"
  }
}`;

const PAYLOAD = `{
  "receipt_id": "ep_...",
  "issued_at":  "2026-06-04T00:00:00Z",
  "claim": {
    "action":   "payment.release",
    "outcome":  "allow | allow_with_signoff | deny",
    "approver": "operator:<named human>",
    "context":  { "amount": 50000, "destination": "acct_9f12", "currency": "USD" }
  }
}`;

const CANON = `object  -> "{" + keys.sort().map(k => json(k) ":" canon(v[k])).join(",") + "}"
array   -> "[" + elements.map(canon).join(",") + "]"
scalar  -> JSON encoding (UTF-8; non-ASCII NOT escaped)`;

export default async function TrustReceiptSpecPage() {
  const nonce = (await headers()).get('x-nonce') ?? '';
  return (
    <div style={{ minHeight: '100vh', background: color.bg, color: color.t1, fontFamily: font.sans }}>
      <script type="application/ld+json" nonce={nonce} dangerouslySetInnerHTML={{ __html: JSON.stringify(ARTICLE_JSONLD) }} />
      <SiteNav activePage="" />

      <section style={{ paddingTop: 120, paddingBottom: 8 }}>
        <C>
          <div style={{ fontFamily: font.mono, fontSize: 11, letterSpacing: 2.5, textTransform: 'uppercase', color: color.gold, marginBottom: 20 }}>Specification · EP-RECEIPT-v1</div>
          <h1 style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 'clamp(34px, 4.6vw, 52px)', letterSpacing: -2, lineHeight: 1.05, color: color.t1, margin: '0 0 20px', maxWidth: 760 }}>
            The Trust Receipt format
          </h1>
          <p style={{ fontSize: 18, color: color.t2, maxWidth: 640, lineHeight: 1.7, margin: 0 }}>
            A <strong>Trust Receipt</strong> is a signed, offline-verifiable record that a specific action
            was authorized — by whom, under what policy, with what outcome. Anyone with the signer&rsquo;s
            public key can verify one with no account, no API, no network. This page specifies it precisely
            enough to implement a verifier in any language.
          </p>
        </C>
      </section>

      <section style={{ padding: '24px 0 80px' }}>
        <C>
          <H2>1. Document</H2>
          <P><code style={mono}>anchor</code> is optional; <code style={mono}>@version</code>, <code style={mono}>payload</code>, and <code style={mono}>signature</code> are required.</P>
          <Pre>{DOC}</Pre>

          <H2>2. Payload</H2>
          <P>The payload is application-defined; the signature covers it whole. EP&rsquo;s convention:</P>
          <Pre>{PAYLOAD}</Pre>

          <H2>3. Canonicalization</H2>
          <P>The exact bytes that get signed. Recursive, depth-first key sort at every level — byte-identical on signer and verifier for any nesting depth. A shallow sort is <em>not</em> sufficient; nested keys must be ordered too.</P>
          <Pre>{CANON}</Pre>

          <H2>4. Signature</H2>
          <P>
            Algorithm <strong>Ed25519</strong>, over <code style={mono}>canonicalize(payload)</code> as UTF-8 bytes.
            The public key is the <strong>base64url</strong> of its <strong>SPKI DER</strong> encoding;
            <code style={mono}> signature.value</code> is the base64url of the 64-byte signature.
          </P>

          <H2>5. Merkle anchor (optional)</H2>
          <P>
            <code style={mono}>leaf_hash</code> is a hex SHA-256. Each proof step folds the running hash with a
            sibling: <code style={mono}>sorted([a, b])</code> then <code style={mono}>SHA-256(lo ‖ hi)</code> (hex);
            <code style={mono}> position: &quot;left&quot;</code> means the sibling is on the left. The reconstructed
            value must equal <code style={mono}>merkle_root</code>. Proof length is bounded (≤ 20).
          </P>

          <H2>6. Verification algorithm</H2>
          <ol style={{ fontSize: 15.5, color: color.t2, lineHeight: 1.8, paddingLeft: 22, margin: '0 0 16px' }}>
            <li><code style={mono}>@version</code> ∈ {'{'}<code style={mono}>EP-RECEIPT-v1</code>{'}'}, else invalid.</li>
            <li>Ed25519-verify <code style={mono}>signature.value</code> over <code style={mono}>canonicalize(payload)</code> with the signer&rsquo;s key.</li>
            <li>If <code style={mono}>anchor</code> is present, reconstruct the root from <code style={mono}>leaf_hash</code> + <code style={mono}>merkle_proof</code>; it must equal <code style={mono}>merkle_root</code>.</li>
            <li><strong>Valid</strong> iff version holds, signature verifies, and (anchor absent OR anchor reconstructs). A malformed receipt verifies as invalid — never raises.</li>
          </ol>

          <H2>7. Reference implementations</H2>
          <P>Interop is tested: a receipt signed on the JS side verifies under the Python implementation, and vice versa.</P>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginBottom: 28 }}>
            <a href="https://www.npmjs.com/package/@emilia-protocol/verify" target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none', background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px' }}>
              <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, color: color.t1 }}>JavaScript / Node</div>
              <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.gold }}>@emilia-protocol/verify</code>
            </a>
            <a href="https://pypi.org/project/emilia-verify/" target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none', background: color.card, border: `1px solid ${color.border}`, borderRadius: radius.base, padding: '18px 20px' }}>
              <div style={{ fontFamily: font.sans, fontWeight: 600, fontSize: 14, color: color.t1 }}>Python</div>
              <code style={{ fontFamily: font.mono, fontSize: 12.5, color: color.gold }}>pip install emilia-verify</code>
            </a>
          </div>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link href="/mcp" className="ep-cta" style={cta.primary}>Get the MCP server &rarr;</Link>
            <Link href="/spec" className="ep-cta-secondary" style={cta.secondary}>Full protocol spec</Link>
          </div>
        </C>
      </section>

      <SiteFooter />
    </div>
  );
}
