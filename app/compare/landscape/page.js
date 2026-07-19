'use client';

import { useEffect } from 'react';
import SiteNav from '@/components/SiteNav';
import SiteFooter from '@/components/SiteFooter';
import { styles, cta, color, font, radius } from '@/lib/tokens';

export default function CompareLandscapePage() {
  useEffect(() => {
    const els = document.querySelectorAll('.ep-reveal');
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); } }),
      { threshold: 0.12 }
    );
    els.forEach(el => obs.observe(el));
    return () => obs.disconnect();
  }, []);

  // Columns: Dimension · EMILIA · HumanLayer · Tenet · DRP (IETF). CIBA + DIY covered in prose.
  const ROWS = [
    { dim: 'Category', ep: 'Enforcement + evidence layer', hl: 'Approval-routing middleware', tenet: 'Governance layer — gates + audit', drp: 'Authorization protocol (individual I-D)' },
    { dim: 'Gates irreversible actions', ep: 'Yes — policy engine + signoff', hl: 'Yes — routes to Slack/email', tenet: 'Yes — auto-pause', drp: 'Yes — pre-action checks (per draft -09, May 2026)' },
    { dim: 'Tamper-evident evidence', ep: 'Ed25519 + Merkle receipt', hl: 'A log line in your own app', tenet: 'SHA-256 hash chain', drp: 'Append-only log + RFC 3161 timestamps (per draft -09)' },
    { dim: 'Offline-verifiable receipt', ep: 'Yes — @emilia-protocol/verify, no network', hl: 'No', tenet: 'Verify the chain yourself; no offline receipt lib', drp: 'No — verification requires the log' },
    { dim: 'Formal verification', ep: 'Yes — 26 TLA+ theorems + 35 Alloy facts in CI, plus a symbolic Dolev-Yao model (Tamarin) of the core receipt lemma', hl: 'No', tenet: 'No', drp: 'No — spec with 14 checks' },
    { dim: 'Separation of duties', ep: 'Enforced — approver ≠ initiator', hl: 'Whoever clicks the button', tenet: 'Not addressed', drp: 'Implicit, not formalized' },
    { dim: 'Approver key custody', ep: 'Device-bound WebAuthn keys (Class A) — shipped; server-side legacy fallback', hl: '—', tenet: '—', drp: 'User holds the key (client-signed)' },
    { dim: 'Standard / licensing', ep: 'Apache-2.0 + open spec & conformance', hl: 'Open core', tenet: 'Commercial SaaS ($29/mo)', drp: 'Individual Internet-Draft (no IETF standing); Authproof hosted' },
    { dim: 'Best for', ep: 'Provable authorization for auditors, regulators, fraud/treasury', hl: 'Fast approval UX, dev velocity', tenet: 'Turnkey gates + audit, multi-framework', drp: 'A future interop standard, if adopted' },
  ];

  const cols = [
    { key: 'ep', label: 'EMILIA', accent: color.gold },
    { key: 'hl', label: 'HumanLayer', accent: color.t2 },
    { key: 'tenet', label: 'Tenet', accent: color.t2 },
    { key: 'drp', label: 'DRP (Authproof)', accent: color.t2 },
  ];

  return (
    <div style={styles.page}>
      <SiteNav activePage="" />

      <section style={{ ...styles.section, paddingTop: 100, paddingBottom: 56 }}>
        <div className="ep-tag ep-hero-badge" style={{ color: color.gold }}>Comparison / The landscape</div>
        <h1 className="ep-hero-text" style={styles.h1}>The AI agent action-governance landscape</h1>
        <p className="ep-hero-text" style={{ ...styles.body, maxWidth: 680 }}>
          &ldquo;Stop my agent before it does something irreversible&rdquo; is a real category now, with real, good products in it. Here is the honest map — what each does well, and the few things that are genuinely EMILIA&rsquo;s. We concede the rest, because a comparison you can&rsquo;t trust isn&rsquo;t worth citing.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 64 }}>
        <h2 style={styles.h2}>Side by side</h2>
        <div style={{ overflowX: 'auto', border: `1px solid ${color.border}`, borderRadius: radius.base }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontFamily: font.sans, minWidth: 760 }}>
            <thead>
              <tr>
                <th style={/** @type {import('react').CSSProperties} */ (styles.tableHead)}>Dimension</th>
                {cols.map(c => (
                  <th key={c.key} style={/** @type {import('react').CSSProperties} */ ({ ...styles.tableHead, color: c.accent })}>{c.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ROWS.map(r => (
                <tr key={r.dim}>
                  <td style={{ ...styles.tableCell, color: color.t1, fontWeight: 600 }}>{r.dim}</td>
                  {cols.map(c => (
                    <td key={c.key} style={{ ...styles.tableCell, ...(c.key === 'ep' ? { color: color.t1, background: '#FAFAF9' } : null) }}>{r[c.key]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="ep-reveal" style={{ ...styles.body, fontSize: 13, color: color.t3, marginTop: 12 }}>
          Based on each project&rsquo;s public docs and, for DRP, the Internet-Draft <code style={{ fontFamily: font.mono, fontSize: 12 }}>draft-nelson-agent-delegation-receipts</code> (an individual submission with no IETF standing — read directly). If we&rsquo;ve mischaracterized anything, tell us and we&rsquo;ll correct it.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>Where each is the right call</h2>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>HumanLayer</strong> — the cleanest <em>approval UX</em>. If you want a human in the loop via Slack/email in an afternoon and &ldquo;a human clicked approve&rdquo; is the whole question, it wins on developer velocity. <a href="/compare/humanlayer" style={{ color: color.blue, textDecoration: 'none' }}>Full comparison →</a></li>
          <li><strong style={{ color: color.t1 }}>Tenet</strong> — turnkey gates plus a SHA-256 hash-chained audit across <em>every</em> tool call, with LangChain/LangGraph, raw OpenAI/Anthropic, and n8n/Mastra adapters and simple pricing. If you want a polished product today, it&rsquo;s a strong choice.</li>
          <li><strong style={{ color: color.t1 }}>CIBA / WorkOS</strong> — frames approval as an <em>authentication</em> problem using CIBA (an OIDC standard). Right when approval should live in your identity stack; it authenticates a person, but does not bind a cryptographic, offline-verifiable receipt to the exact action.</li>
          <li><strong style={{ color: color.t1 }}>DIY framework interrupts</strong> — LangGraph/Agents-SDK interrupts give you full control if you&rsquo;re willing to build and maintain the binding, replay protection, and evidence yourself. <a href="/compare/human-in-the-loop" style={{ color: color.blue, textDecoration: 'none' }}>Why that gets expensive →</a></li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>What is genuinely EMILIA&rsquo;s</h2>
        <p className="ep-reveal" style={styles.body}>
          Cryptographic receipts are no longer rare — a fast-growing cluster of projects (below) already signs agent actions with Ed25519 and hash-chains them. So we don&rsquo;t lead with the receipt. We lead with what almost no one else has:
        </p>
        <ul className="ep-reveal" style={styles.list}>
          <li><strong style={{ color: color.t1 }}>A named human signs the exact action on their own device.</strong> Touch ID / passkey, <em>before</em> the irreversible action runs. The signing key belongs to the approver — not the agent, not us — so neither a compromised agent nor a compromised operator can fabricate the approval. This is the line almost every other project doesn&rsquo;t cross.</li>
          <li><strong style={{ color: color.t1 }}>Formal verification.</strong> The protocol core is machine-checked — 26 TLA+ theorems + 35 Alloy facts, run in CI on every change to the formal models — plus a first symbolic Dolev-Yao model (Tamarin) of the core receipt lemma: the prover verified core authenticity, and when the one-time-consumption check is deliberately removed it finds the replay attack itself. The receipt cluster proves tamper-evidence; none claim machine-checked proofs of the protocol itself.</li>
          <li><strong style={{ color: color.t1 }}>Cross-language and external verification, proven in CI.</strong> JavaScript, Python, and Go same-team reference ports agree across 21 suites and 329 vectors. Separately, an externally authored Rust implementation is rebuilt from a pinned public commit and tree, then run against the pinned 16-suite/164-vector clean-room bundle and a 359-case hostility campaign in its own CI lane. This proves external interoperability and parser robustness, not strict clean-room construction independence; the aggregate case records zero strict independent acceptances pending a current attestation. The vectors are public (<a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/CONFORMANCE.md" style={{ color: color.blue, textDecoration: 'none' }}>CONFORMANCE.md</a>) — any project here, including the ones above, is welcome to conform against them.</li>
          <li><strong style={{ color: color.t1 }}>Enforced separation of duties + one-time consumption.</strong> The approver cannot be the initiator, checked in protocol, and a signoff is consumed once.</li>
          <li><strong style={{ color: color.t1 }}>An offline-verifiable receipt</strong> — now table stakes in the receipt cluster, but still ahead of the approval tools (HumanLayer, Tenet): <code style={{ fontFamily: font.mono, fontSize: 13 }}>@emilia-protocol/verify</code> checks it with pure Ed25519 + Merkle math — no log, no network, no account.</li>
        </ul>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>The cryptographic-receipt cluster (and the line we draw)</h2>
        <p className="ep-reveal" style={styles.body}>
          A fast-growing set of open-source projects ships cryptographic accountability for agent actions — among them <strong style={{ color: color.t1 }}>nobulex</strong> (Ed25519 + hash-chains, pre-action enforcement, &ldquo;trust capital for machines&rdquo;), <strong style={{ color: color.t1 }}>Agent Receipts</strong> (a signing daemon that mints a W3C Verifiable Credential per tool call), and <strong style={{ color: color.t1 }}>signet</strong>. They are real and genuinely well-built, and we share their conviction: every irreversible agent action should leave tamper-evident, independently verifiable proof. On that, EMILIA is not unique — offline receipts are becoming table stakes, and we&rsquo;d rather say so than pretend otherwise.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The line we draw is <em>who signs</em>. In that cluster the agent signs its own receipts, or an operator-run daemon auto-signs every call — which proves what the software did and that no one edited it afterward, but <em>not</em> that an accountable human authorized that specific action. EMILIA&rsquo;s signature is produced by a named human on their own device, before the action runs — the one thing neither a compromised agent nor an operator can manufacture — backed by separation of duties and a machine-checked protocol the cluster doesn&rsquo;t claim. Receipts are table stakes; a provably accountable human is the wedge.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>On the Delegation Receipt Protocol (and where it leads us)</h2>
        <p className="ep-reveal" style={styles.body}>
          DRP is the serious one to watch — an individual Internet-Draft for user-signed delegation receipts (Authproof&rsquo;s spec; no IETF working-group standing yet, the same early status any new proposal in this space has, ours included). We are not here to rebut it. Its core choice is right: the signing key belongs on the human&rsquo;s own device, removing the operator from the trust path. EMILIA now does the same — approver-held WebAuthn keys (Class A), shipped and verified on real hardware, with a server-side legacy fallback (documented in our <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/THREAT_MODEL.md" style={{ color: color.blue, textDecoration: 'none' }}>threat model</a>). The remaining distinction is <em>whose</em> key signs: DRP binds the delegating user; EMILIA binds the accountable approver, under enforced separation of duties.
        </p>
        <p className="ep-reveal" style={styles.body}>
          Where EMILIA adds beyond DRP: a <strong style={{ color: color.t1 }}>formally-verified</strong> policy engine, an <strong style={{ color: color.t1 }}>offline</strong>-verifiable receipt (DRP&rsquo;s draft states verification requires the append-only log), enforced separation of duties, and one-time global consumption. The honest aim is to be a rigorous, offline-verifiable realization of the delegation-receipt idea — not a competing silo.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>On PSEA — the closest convergence</h2>
        <p className="ep-reveal" style={styles.body}>
          The nearest peer to EMILIA is <strong style={{ color: color.t1 }}>PSEA</strong> (<a href="https://datatracker.ietf.org/doc/draft-yossif-psea/" style={{ color: color.blue, textDecoration: 'none' }}>draft-yossif-psea</a>, Yuthent) — an EAT token profile for action-bound, user-verification-gated transaction confirmation. It reached the IETF datatracker before our draft, and we&rsquo;ll say that plainly. It is also the strongest evidence we have that this is a real problem and not one vendor&rsquo;s framing: two efforts arrived at the same core construction — a canonical hash of the exact action, a user-verification-gated signature, and fail-closed verifier rules — without contact. We treat it as convergent, not competing.
        </p>
        <p className="ep-reveal" style={styles.body}>
          The lanes are genuinely different. PSEA explicitly scopes <em>out</em> FIDO2/WebAuthn — its model needs a conforming authenticator and a mobile SDK; EMILIA profiles exactly that excluded path, so the approver signs with a <strong style={{ color: color.t1 }}>commodity passkey</strong> already in their pocket (Face ID / a browser), nothing to install. And where Yuthent&rsquo;s implementation is proprietary and patent-pending, EMILIA is <strong style={{ color: color.t1 }}>Apache-2.0, with public dated history and a verifier anyone can run</strong> — including in their own browser at <a href="/verify" style={{ color: color.blue, textDecoration: 'none' }}>/verify</a>, with nothing uploaded. Different authenticator model, different openness posture, same verifier philosophy. We&rsquo;ve offered, on the public list, to align claim names so the two profiles don&rsquo;t gratuitously diverge for implementers.
        </p>
      </section>

      <section style={{ ...styles.section, paddingTop: 0, paddingBottom: 56 }}>
        <h2 className="ep-reveal" style={styles.h2}>The caveat we hold for everyone, including us</h2>
        <p className="ep-reveal" style={styles.body}>
          Any in-process guard is skippable by the operator who controls the process — true of every product here. The differentiator is the evidence that survives outside the runtime, and end-to-end enforcement only when the system of record verifies the receipt before executing. We say this plainly on our <a href="/security" style={{ color: color.blue, textDecoration: 'none' }}>security page</a>.
        </p>
      </section>

      <section className="ep-reveal" style={{ ...styles.section, paddingTop: 0, paddingBottom: 96 }}>
        <h2 style={styles.h2}>See it for yourself</h2>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a href="/quickstart" className="ep-cta" style={cta.primary}>Add it to your agent</a>
          <a href="/playground" className="ep-cta-secondary" style={cta.secondary}>Try the live demo</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
