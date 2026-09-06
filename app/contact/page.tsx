import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, color, cta } from '@/lib/tokens';
import { ENTITY } from '@/lib/site-config';

const workforceEmail = `mailto:${ENTITY.email}?subject=${encodeURIComponent('EMILIA workforce evaluation')}`;

export default function ContactPage(): React.JSX.Element {
  return (
    <div style={styles.page}>
      <SiteNav activePage="Contact" />
      <main style={{ ...styles.section, paddingTop: 100, paddingBottom: 80 }}>
        <div style={styles.eyebrow}>Contact</div>
        <h1 style={styles.h1}>What job do you want your agent to do?</h1>
        <p style={styles.body}>
          Tell us about one workflow, the person responsible for it, and the action
          the agent needs permission to take. We can assess where EMILIA could fit.
        </p>

        <section id="workforce" style={{ ...styles.card, marginTop: 32, marginBottom: 24, scrollMarginTop: 100 }}>
          <h2 style={styles.h2}>Discuss your workflow</h2>
          <p style={{ ...styles.body, marginBottom: 20 }}>
            Our first evaluation is a finance team&rsquo;s refunds workflow: one job,
            one owner, agreed limits and a review of the results. The team and provider
            are not yet selected. If that matches your work, tell us what you need
            an agent to handle and what must stay under your control.
          </p>
          <a href={workforceEmail} className="ep-cta" style={cta.primary}>Email us about your workflow</a>
          <p style={{ fontSize: 16, color: color.t2, lineHeight: 1.65, marginTop: 20, marginBottom: 0 }}>
            The workforce product is a private local alpha, not a hosted signup or a
            customer deployment. Scope, integrations, pricing and production readiness
            need to be agreed separately. Please do not send credentials, customer
            records or sensitive financial data in your first email.
          </p>
        </section>

        <section style={{ paddingTop: 24, borderTop: `1px solid ${color.border}` }}>
          <h2 style={styles.h2}>Other conversations</h2>
          <p style={styles.body}>
            For protocol integrations, partnerships, press or general questions,
            contact <a href={`mailto:${ENTITY.email}`} style={{ color: color.blue }}>{ENTITY.email}</a>.
          </p>
          <p style={styles.body}>
            Investors can <a href="/investors" style={{ color: color.blue }}>request investor information</a>.
            {' '}For a vulnerability, use our <a href="/security" style={{ color: color.blue }}>security disclosure process</a>.
          </p>
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
