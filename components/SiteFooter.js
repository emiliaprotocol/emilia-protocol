import { color, font } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const COL_PRODUCT = [
  ['/protocol', 'Protocol'],
  ['/spec', 'Specification'],
  ['/govguard', 'GovGuard'],
  ['/finguard', 'FinGuard'],
  ['/playground', 'Playground'],
  ['/explorer', 'Explorer'],
  ['/adopt', 'Adopt'],
];

const COL_RESOURCES = [
  ['/docs', 'Docs'],
  ['/blog', 'Blog'],
  ['/compare', 'Comparisons'],
  ['/governance', 'Governance'],
  ['https://github.com/emiliaprotocol/emilia-protocol', 'GitHub'],
];

const COL_TRUST = [
  ['/security', 'Trust & Security'],
  ['/about', 'About'],
  ['/.well-known/security.txt', 'Responsible Disclosure'],
  ['/governance', 'Governance Framework'],
];

const COL_LEGAL = [
  ['/legal/privacy', 'Privacy Policy'],
  ['/legal/terms', 'Terms of Service'],
  ['/legal/acceptable-use', 'Acceptable Use'],
  ['/legal/sub-processors', 'Sub-processors'],
];

const COL_COMPANY = [
  ['/partners', 'Partners'],
  [`mailto:${ENTITY.email}`, 'Contact'],
  [`mailto:${ENTITY.securityEmail}`, 'Security'],
  ['/investors', 'Investor Inquiries'],
];

const COLUMNS = [
  { title: 'Product',   links: COL_PRODUCT },
  { title: 'Resources', links: COL_RESOURCES },
  { title: 'Trust',     links: COL_TRUST },
  { title: 'Legal',     links: COL_LEGAL },
  { title: 'Company',   links: COL_COMPANY },
];

export default function SiteFooter() {
  const year = new Date().getFullYear();

  return (
    <footer style={{
      borderTop: `1px solid ${color.border}`,
      padding: '64px 32px 32px',
      background: color.bg,
    }}>
      <div style={{ maxWidth: 1120, margin: '0 auto' }}>
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
            <div>&copy; {year} {ENTITY.legalName}. Apache 2.0 reference runtime.</div>
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
