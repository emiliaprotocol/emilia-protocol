import { color, font } from '@/lib/tokens';

const DEFAULT_LINKS = [
  ['/governance', 'Governance'],
  ['/partners', 'Partners'],
  ['mailto:team@emiliaprotocol.ai', 'Contact'],
  ['/investors', 'Investor Inquiries'],
];

export default function SiteFooter({ links = DEFAULT_LINKS }) {
  return (
    <footer style={{
      borderTop: `1px solid ${color.border}`,
      padding: '40px 40px 32px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: 16,
    }}>
      <div style={{
        fontFamily: font.mono,
        fontSize: 11,
        color: color.t3,
        letterSpacing: 1,
      }}>EMILIA PROTOCOL &middot; APACHE 2.0</div>
      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        {links.map(([href, label]) => (
          <a key={label} href={href} className="ep-footer-link">{label}</a>
        ))}
      </div>
    </footer>
  );
}
