import { color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

type FooterLink = [string, string];

const COL_SYSTEM: FooterLink[] = [
  ['/products', 'Product Story'],
  ['/authority-brain', 'Authority Brain'],
  ['/gate', 'EMILIA Gate'],
  ['/host', 'EMILIA Host'],
  ['/product/accountable-signoff', 'EMILIA Approver'],
  ['/assurance', 'Assurance Plane'],
  ['/protocol', 'EMILIA Protocol'],
];

const COL_SOLUTIONS: FooterLink[] = [
  ['/use-cases', 'All Solutions'],
  ['/private-equity', 'Private Equity'],
  ['/financial', 'Finance Operations'],
  ['/use-cases/enterprise', 'Code and Cloud'],
  ['/government', 'Government'],
  ['/health/program-integrity', 'Health Program Integrity'],
  ['/grace', 'Energy and GRACE'],
];

const COL_DEVELOPERS: FooterLink[] = [
  ['/docs', 'Docs'],
  ['/scan', 'Local Scanner'],
  ['/quickstart', 'Gate Quickstart'],
  ['/verify', 'Open Verifier'],
  ['/mcp', 'MCP Integration'],
  ['/llms.txt', 'LLM Context'],
  ['/.well-known/emilia-context.json', 'Machine Context'],
  ['https://github.com/emiliaprotocol/emilia-protocol', 'GitHub'],
];

const COL_PROTOCOL: FooterLink[] = [
  ['/spec', 'Specifications'],
  ['/proof', 'Engineering Evidence'],
  ['/diligence', 'Public Diligence'],
  ['/observatory', 'Standards Observatory'],
  ['/standards', 'Standards Map'],
  ['/governance', 'Governance'],
];

const COL_COMPANY: FooterLink[] = [
  ['/about', 'About'],
  ['/partners', 'Partners'],
  ['/security', 'Security'],
  ['/auditors', 'For Auditors'],
  ['/trust-desk', 'Trust Desk'],
  [`mailto:${ENTITY.email}`, 'Contact'],
  ['/legal/privacy', 'Privacy Policy'],
  ['/legal/terms', 'Terms of Service'],
];

type Column = { title: string; links: FooterLink[] };

const COLUMNS: Column[] = [
  { title: 'System',   links: COL_SYSTEM },
  { title: 'Solutions', links: COL_SOLUTIONS },
  { title: 'Developers', links: COL_DEVELOPERS },
  { title: 'Protocol', links: COL_PROTOCOL },
  { title: 'Company',   links: COL_COMPANY },
];

type SiteFooterProps = Record<string, never>;

export default function SiteFooter({}: SiteFooterProps) {
  const year = new Date().getFullYear();

  return (
    <footer style={{
      borderTop: `1px solid ${color.border}`,
      padding: '64px 32px 32px',
      background: color.bg,
    }}>
      <div style={{ maxWidth: 1120, margin: '0 auto' }}>
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          gap: 32,
          alignItems: 'flex-end',
          flexWrap: 'wrap',
          paddingBottom: 34,
          marginBottom: 40,
          borderBottom: `1px solid ${color.border}`,
        }}>
          <div>
            <div style={{ fontFamily: font.sans, fontWeight: 700, fontSize: 19, color: color.t1 }}>
              Protocol proves. Gate prevents.
            </div>
            <div style={{ fontSize: 13, color: color.t2, marginTop: 8, lineHeight: 1.6, maxWidth: 560 }}>
              Authority Brain maps supported declared actions and blind spots. Gate controls configured
              crossings. Approver captures an exact-action decision when required. The Protocol keeps the record
              portable. Assurance re-performs it.
            </div>
          </div>
          <a href="/products" className="ep-footer-link" style={{ fontFamily: font.mono, fontSize: 12, color: '#765A13' }}>
            Follow the product story &rarr;
          </a>
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 32,
          marginBottom: 48,
        }}>
          {COLUMNS.map(col => (
            <div key={col.title}>
              <div style={{
                fontFamily: font.mono,
                fontSize: 10,
                fontWeight: 600,
                letterSpacing: 1.5,
                textTransform: 'uppercase',
                color: color.t1,
                marginBottom: 16,
              }}>{col.title}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {col.links.map(([href, label]) => (
                  <a
                    key={label}
                    href={href}
                    target={href.startsWith('http') ? '_blank' : undefined}
                    rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
                    className="ep-footer-link"
                    style={{ fontSize: 13 }}
                  >{label}</a>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div style={{
          paddingTop: 24,
          borderTop: `1px solid ${color.border}`,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: 24,
          fontFamily: font.mono,
          fontSize: 11,
          color: color.t3,
          letterSpacing: 0.5,
          lineHeight: 1.6,
        }}>
          <div style={{ maxWidth: 520 }}>
            <div style={{ fontWeight: 600, color: color.t1, letterSpacing: 1, textTransform: 'uppercase', marginBottom: 6 }}>
              {ENTITY.legalName}
            </div>
            <div>{ENTITY.entityType} · {ENTITY.jurisdiction}</div>
            <div>{ENTITY.address}</div>
            {ENTITY.registrationNumber && <div>Reg. {ENTITY.registrationNumber}</div>}
          </div>
          <div style={{ textAlign: 'right' }}>
            <div>&copy; {year} {ENTITY.legalName}. Protocol artifacts are Apache 2.0.</div>
            <div style={{ marginTop: 4 }}>
              <a href={`mailto:${ENTITY.privacyEmail}`} className="ep-footer-link">{ENTITY.privacyEmail}</a>
              {' · '}
              <a href={`mailto:${ENTITY.securityEmail}`} className="ep-footer-link">{ENTITY.securityEmail}</a>
              {' · '}
              <a href={`mailto:${ENTITY.legalEmail}`} className="ep-footer-link">{ENTITY.legalEmail}</a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
