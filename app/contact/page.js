import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, font, radius } from '@/lib/tokens';

export const metadata = {
  title: 'Contact | EMILIA Protocol',
  description: 'Get in touch with the EMILIA Protocol team.',
};

export default function ContactPage() {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Contact" />
      <div style={{ ...styles.section, paddingTop: 100, paddingBottom: 80 }}>
        <div style={styles.eyebrow}>Contact</div>
        <h1 style={styles.h1}>Get in touch</h1>
        <p style={styles.body}>We are available to discuss protocol integrations, pilot programs, and partnership opportunities.</p>

        <div className="ep-card-hover" style={{ ...styles.card, marginBottom: 16 }}>
          <div style={styles.cardTitle}>General Inquiries</div>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 8 }}>For questions about EMILIA Protocol, integrations, or collaboration.</div>
          <a href="mailto:team@emiliaprotocol.ai" style={{ fontSize: 14, color: color.blue, textDecoration: 'none' }}>team@emiliaprotocol.ai</a>
        </div>

        <div className="ep-card-hover" style={{ ...styles.card, marginBottom: 16 }}>
          <div style={styles.cardTitle}>Pilot Program</div>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 8 }}>Interested in running a pilot? Submit a request through our partner portal.</div>
          <a href="/partners" style={{ fontSize: 14, color: color.blue, textDecoration: 'none' }}>Request a Pilot &#8594;</a>
        </div>

        <div className="ep-card-hover" style={{ ...styles.card, marginBottom: 16 }}>
          <div style={styles.cardTitle}>Investor Relations</div>
          <div style={{ fontSize: 14, color: color.t2, lineHeight: 1.65, marginBottom: 8 }}>For investment inquiries and funding discussions.</div>
          <a href="/investors" style={{ fontSize: 14, color: color.blue, textDecoration: 'none' }}>Investor Information &#8594;</a>
        </div>
      </div>

      <SiteFooter />
    </div>
  );
}
