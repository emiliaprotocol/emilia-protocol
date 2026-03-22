import { getServiceClient } from '@/lib/supabase';
import { canonicalEvaluate } from '@/lib/canonical-evaluator';
import { notFound } from 'next/navigation';

export async function generateMetadata({ params }) {
  const { entityId } = await params;
  return {
    title: `${entityId} — EMILIA Protocol`,
    description: `Trust profile, policy posture, and receipt history for ${entityId}`,
  };
}

async function getEntity(entityId) {
  const supabase = getServiceClient();
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityId);

  const { data: entity } = await supabase
    .from('entities')
    .select('*')
    .eq(isUuid ? 'id' : 'entity_id', entityId)
    .single();

  if (!entity || entity.status !== 'active') return null;

  // Get recent receipts for display
  const { data: receipts } = await supabase
    .from('receipts')
    .select('receipt_id, transaction_type, composite_score, agent_behavior, anchor_batch_id, created_at')
    .eq('entity_id', entity.id)
    .order('created_at', { ascending: false })
    .limit(50);

  // Canonical trust evaluation for current profile + historical establishment
  const canonical = await canonicalEvaluate(entity.id, {
    includeDisputes: false,
    includeEstablishment: true,
  });

  const estResult = canonical.establishment || { established: false, unique_submitters: 0, effective_evidence: 0 };
  const trustProfile = {
    profile: canonical.profile,
    score: canonical.score,
    confidence: canonical.confidence,
    effectiveEvidence: canonical.effectiveEvidence,
    qualityGatedEvidence: canonical.qualityGatedEvidence,
    uniqueSubmitters: canonical.uniqueSubmitters,
    anomaly: canonical.anomaly,
  };

  return { entity, receipts: receipts || [], establishment: estResult, trustProfile };
}

function ScoreBar({ label, value, color }) {
  if (value == null) return null;
  const rounded = Math.round(value * 10) / 10;
  return `
    <div style="margin-bottom:14px;">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
        <span style="color:#7a809a;font-family:'IBM Plex Mono',monospace;letter-spacing:1px;text-transform:uppercase;font-size:10px;">${label}</span>
        <span style="color:#e8eaf0;font-weight:600;">${rounded}/100</span>
      </div>
      <div style="height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${rounded}%;background:${color};border-radius:3px;transition:width 0.6s ease;"></div>
      </div>
    </div>
  `;
}

function confidenceDisplay(conf) {
  const map = {
    PENDING: { label: 'PENDING', color: '#7a809a' },
    'LOW EVIDENCE': { label: 'LOW EVIDENCE', color: '#ff9f1c' },
    PROVISIONAL: { label: 'PROVISIONAL', color: '#d4af55' },
    EMERGING: { label: 'EMERGING', color: '#4a90d9' },
    ESTABLISHED: { label: 'ESTABLISHED', color: '#00ff88' },
  };
  return map[conf] || { label: conf, color: '#7a809a' };
}

function behaviorLabel(b) {
  const map = {
    completed: ['Completed', '#00ff88'],
    retried_same: ['Retried Same', '#d4af55'],
    retried_different: ['Switched', '#ff9f1c'],
    abandoned: ['Abandoned', '#ff3b3b'],
    disputed: ['Disputed', '#ff2d78'],
  };
  return map[b] || [b || '—', '#7a809a'];
}

export default async function EntityProfile({ params }) {
  const { entityId } = await params;
  const result = await getEntity(entityId);

  if (!result) notFound();

  const { entity, receipts, establishment, trustProfile } = result;
  const score = entity.emilia_score;
  const confDisplay = confidenceDisplay(confidence);
  const established = establishment.established;
  const uniqueSubmitters = establishment.unique_submitters;

  // CURRENT confidence from rolling-window trust profile (not historical)
  const currentEvidence = trustProfile.effectiveEvidence;
  const qualityGated = trustProfile.qualityGatedEvidence;

  let confidence, confidenceColor, confidenceMessage;
  if (currentEvidence === 0) {
    confidence = 'PENDING';
    confidenceColor = '#4a4f6a';
    confidenceMessage = 'No meaningful evidence in current window.';
  } else if (currentEvidence < 1.0) {
    confidence = 'LOW CONFIDENCE';
    confidenceColor = '#ff9f1c';
    confidenceMessage = `Current effective evidence: ${currentEvidence}. Very low credibility weight.`;
  } else if (currentEvidence < 5.0) {
    confidence = 'PROVISIONAL';
    confidenceColor = '#d4af55';
    confidenceMessage = `Current effective evidence: ${currentEvidence}/5.0 needed.`;
  } else if (currentEvidence < 20.0) {
    confidence = 'EMERGING';
    confidenceColor = '#4a90d9';
    confidenceMessage = `Current effective evidence: ${currentEvidence}. Score is meaningful.`;
  } else {
    confidence = 'CONFIDENT';
    confidenceColor = '#00ff88';
    confidenceMessage = `Current effective evidence: ${currentEvidence} from ${trustProfile.uniqueSubmitters} submitters.`;
  }

  const showBreakdown = confidence === 'EMERGING' || confidence === 'CONFIDENT';
  const breakdown = showBreakdown ? {
    delivery_accuracy: entity.avg_delivery_accuracy,
    product_accuracy: entity.avg_product_accuracy,
    price_integrity: entity.avg_price_integrity,
    return_processing: entity.avg_return_processing,
    agent_satisfaction: entity.avg_agent_satisfaction,
    consistency: entity.score_consistency,
  } : null;

  const bars = breakdown ? [
    ScoreBar({ label: 'Delivery Accuracy', value: breakdown.delivery_accuracy, color: '#4a90d9' }),
    ScoreBar({ label: 'Product Accuracy', value: breakdown.product_accuracy, color: '#00ff88' }),
    ScoreBar({ label: 'Price Integrity', value: breakdown.price_integrity, color: '#d4af55' }),
    ScoreBar({ label: 'Return Processing', value: breakdown.return_processing, color: '#ff9f1c' }),
    ScoreBar({ label: 'Agent Satisfaction', value: breakdown.agent_satisfaction, color: '#ff2d78' }),
    ScoreBar({ label: 'Consistency', value: breakdown.consistency, color: '#7a809a' }),
  ].filter(Boolean).join('') : '';

  const memberSince = new Date(entity.created_at).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  const typeLabel = { agent: 'AI Agent', merchant: 'Merchant', service_provider: 'Service Provider' };

  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{entity.display_name} — EMILIA Protocol</title>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet" />
        <style dangerouslySetInnerHTML={{ __html: `
          :root {
            --bg: #0a0f1e; --bg-card: #0e1120; --brd: rgba(255,255,255,0.06);
            --t1: #e8eaf0; --t2: #7a809a; --t3: #4a4f6a;
            --cyan: #4a90d9; --gold: #d4af55; --green: #00ff88;
            --mono: 'IBM Plex Mono', monospace; --disp: 'IBM Plex Sans', sans-serif; --body: 'IBM Plex Sans', sans-serif;
          }
          *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: var(--bg); color: var(--t1); font-family: var(--body); -webkit-font-smoothing: antialiased; }
          a { color: var(--cyan); text-decoration: none; }
          a:hover { text-decoration: underline; }
        `}} />
      </head>
      <body>
        <nav style="position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:60px;background:rgba(0,0,0,0.85);backdrop-filter:blur(12px);border-bottom:1px solid rgba(255,255,255,0.06);font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase">
          <a href="/" style="display:flex;align-items:center;gap:10px;text-decoration:none">
            <svg width="34" height="34" viewBox="0 0 34 34" fill="none"><rect x="7" y="5" width="2.5" height="24" rx="1.25" fill="url(#ng3)"/><rect x="9.5" y="5" width="16" height="2.5" rx="1.25" fill="#60a5fa"/><rect x="9.5" y="15.5" width="12" height="2.5" rx="1.25" fill="#f59e0b"/><rect x="9.5" y="26.5" width="14" height="2.5" rx="1.25" fill="#60a5fa"/><defs><linearGradient id="ng3" x1="8" y1="5" x2="8" y2="29"><stop offset="0%" stop-color="#60a5fa"/><stop offset="100%" stop-color="#f59e0b"/></linearGradient></defs></svg>
            <span style="font-weight:700;font-size:14px;letter-spacing:3px;color:#e8eaf0">EMILIA</span>
          </a>
          <div style="display:flex;align-items:center;gap:24px">
            <a href="/" style="color:#4a4f6a;text-decoration:none">Home</a>
            <a href="/quickstart" style="color:#4a4f6a;text-decoration:none">Quickstart</a>
            <a href="/demo.html" style="color:#4a4f6a;text-decoration:none">Demo</a>
            <a href="/spec" style="color:#4a4f6a;text-decoration:none">Spec</a>
            <a href="/operators" style="color:#4a4f6a;text-decoration:none">Operators</a>
            <a href="/appeal" style="color:#4a4f6a;text-decoration:none">Appeal</a>
            <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank" style="color:#4a4f6a;text-decoration:none">GitHub</a>
            <a href="/apply" style="background:#4a90d9;color:#0a0f1e;padding:8px 18px;border-radius:8px;text-decoration:none;font-weight:700;letter-spacing:1px;font-size:12px">Apply to Review</a>
          </div>
        </nav>
        <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 24px 80px' }}>
          {/* Nav */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 48, fontFamily: 'var(--mono)', fontSize: 12, letterSpacing: 1 }}>
            <a href="/" style={{ color: '#e8eaf0', fontWeight: 600, letterSpacing: 2, fontSize: 14 }}>EMILIA</a>
            <div style={{ display: 'flex', gap: 24 }}>
              <a href="/#score" style={{ color: '#7a809a' }}>TRUST LOOKUP</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol" style={{ color: '#7a809a' }}>GITHUB</a>
            </div>
          </div>

          {/* Entity header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }}>
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 3, color: '#4a4f6a', textTransform: 'uppercase', marginBottom: 8 }}>
                {typeLabel[entity.entity_type] || entity.entity_type} #{entity.id}
              </div>
              <h1 style={{ fontFamily: 'var(--disp)', fontWeight: 700, fontSize: 'clamp(28px, 5vw, 40px)', letterSpacing: -1, marginBottom: 8 }}>
                {entity.display_name}
              </h1>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: '#7a809a' }}>
                {entity.entity_id}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: 11, color: confDisplay.color, letterSpacing: 2, marginBottom: 4 }}>
                {confidence}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: '#7a809a', marginTop: 4 }}>
                compat: {score}
              </div>
            </div>
          </div>

          {/* Description */}
          <p style={{ fontSize: 15, color: '#7a809a', lineHeight: 1.7, marginBottom: 32 }}>
            {entity.description}
          </p>

          {/* Stats row */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 40 }}>
            {[
              { label: 'Total Receipts', value: entity.total_receipts },
              { label: 'Successful', value: entity.successful_receipts },
              { label: 'Unique Submitters', value: uniqueSubmitters },
              { label: 'Member Since', value: memberSince },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '16px 12px', textAlign: 'center' }}>
                <div style={{ fontFamily: 'var(--disp)', fontWeight: 700, fontSize: 20, marginBottom: 4 }}>{value}</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: 2, color: '#4a4f6a', textTransform: 'uppercase' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Score breakdown */}
          {breakdown && (
            <div style={{ background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 24, marginBottom: 40 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 3, color: '#4a4f6a', textTransform: 'uppercase', marginBottom: 20 }}>
                Score Breakdown
              </div>
              <div dangerouslySetInnerHTML={{ __html: bars }} />
            </div>
          )}

          {!showBreakdown && (
            <div style={{ background: `${confidenceColor}10`, border: `1px solid ${confidenceColor}30`, borderRadius: 12, padding: 20, marginBottom: 40 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: confidenceColor, marginBottom: 4 }}>{confidence}</div>
              <div style={{ fontSize: 13, color: '#7a809a', lineHeight: 1.6, marginBottom: 12 }}>
                {confidenceMessage}
              </div>
              <div style={{ marginTop: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--mono)', fontSize: 10, color: '#4a4f6a', marginBottom: 4 }}>
                  <span>Progress to meaningful score</span>
                  <span>Quality-gated evidence: {qualityGated ?? currentEvidence}/20.0 (raw: {currentEvidence})</span>
                </div>
                <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(100, Math.round((currentEvidence / 20) * 100))}%`, background: confidenceColor, borderRadius: 2 }} />
                </div>
              </div>
            </div>
          )}

          {/* Capabilities */}
          {entity.capabilities && entity.capabilities.length > 0 && (
            <div style={{ marginBottom: 40 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 3, color: '#4a4f6a', textTransform: 'uppercase', marginBottom: 12 }}>
                Capabilities
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {entity.capabilities.map((cap) => (
                  <span key={cap} style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#4a90d9', background: 'rgba(74,144,217,0.08)', border: '1px solid rgba(74,144,217,0.15)', padding: '6px 12px', borderRadius: 100 }}>
                    {cap}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Receipt history */}
          {receipts.length > 0 && (
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 3, color: '#4a4f6a', textTransform: 'uppercase', marginBottom: 16 }}>
                Recent Receipts
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {receipts.map((r) => {
                  const [bLabel, bColor] = behaviorLabel(r.agent_behavior);
                  const date = new Date(r.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
                  const anchored = !!r.anchor_batch_id;
                  return (
                    <div key={r.receipt_id} style={{ background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#7a809a' }}>{r.transaction_type}</span>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: bColor, background: `${bColor}15`, padding: '2px 8px', borderRadius: 100 }}>{bLabel}</span>
                        {anchored && <span style={{ fontSize: 10, color: '#00ff88' }}>⛓ anchored</span>}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                        <span style={{ fontFamily: 'var(--disp)', fontWeight: 700, fontSize: 14 }}>{r.composite_score}</span>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: '#4a4f6a' }}>{date}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* API reference */}
          <div style={{ marginTop: 48, padding: 20, background: '#0e1120', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, fontFamily: 'var(--mono)', fontSize: 11 }}>
            <div style={{ color: '#4a4f6a', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>API</div>
            <div style={{ color: '#7a809a' }}>
              <span style={{ color: '#00ff88' }}>GET</span> /api/score/{entity.entity_id}
            </div>
            <div style={{ color: '#7a809a', marginTop: 4 }}>
              <span style={{ color: '#d4af55' }}>MCP</span> ep_trust_profile entity_id="{entity.entity_id}"
            </div>
          </div>

          {/* Footer */}
          <div style={{ marginTop: 48, textAlign: 'center', fontFamily: 'var(--mono)', fontSize: 10, color: '#4a4f6a', letterSpacing: 1 }}>
            EMILIA Protocol — Receipts, Not Reviews
          </div>
        </div>
      </body>
    </html>
  );
}
