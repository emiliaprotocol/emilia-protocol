import { getServiceClient } from '@/lib/supabase';
import { notFound } from 'next/navigation';

export async function generateMetadata({ params }) {
  const { entityId } = await params;
  return {
    title: `${entityId} — EMILIA Protocol`,
    description: `EMILIA Score and receipt history for ${entityId}`,
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

  // Get recent receipts
  const { data: receipts } = await supabase
    .from('receipts')
    .select('receipt_id, transaction_type, composite_score, agent_behavior, anchor_batch_id, created_at')
    .eq('entity_id', entity.id)
    .order('created_at', { ascending: false })
    .limit(50);

  // Get canonical establishment via DB function
  let estResult = { established: false, unique_submitters: 0, effective_evidence: 0 };
  try {
    const { data: estData } = await supabase.rpc('is_entity_established', { p_entity_id: entity.id });
    if (estData && estData[0]) {
      estResult = estData[0];
    }
  } catch {}

  return { entity, receipts: receipts || [], establishment: estResult };
}

function ScoreBar({ label, value, color }) {
  if (value == null) return null;
  const rounded = Math.round(value * 10) / 10;
  return `
    <div style="margin-bottom:14px;">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
        <span style="color:#7a809a;font-family:'JetBrains Mono',monospace;letter-spacing:1px;text-transform:uppercase;font-size:10px;">${label}</span>
        <span style="color:#e8eaf0;font-weight:600;">${rounded}/100</span>
      </div>
      <div style="height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${rounded}%;background:${color};border-radius:3px;transition:width 0.6s ease;"></div>
      </div>
    </div>
  `;
}

function gradeInfo(score) {
  if (score >= 90) return { grade: 'A+', color: '#00ff88' };
  if (score >= 82) return { grade: 'A', color: '#00ff88' };
  if (score >= 74) return { grade: 'B+', color: '#00d4ff' };
  if (score >= 66) return { grade: 'B', color: '#00d4ff' };
  if (score >= 58) return { grade: 'C+', color: '#ffd700' };
  return { grade: 'C', color: '#ff9f1c' };
}

function behaviorLabel(b) {
  const map = {
    completed: ['Completed', '#00ff88'],
    retried_same: ['Retried Same', '#ffd700'],
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

  const { entity, receipts, establishment } = result;
  const score = entity.emilia_score;
  const { grade, color } = gradeInfo(score);
  const established = establishment.established;
  const uniqueSubmitters = establishment.unique_submitters;
  const effectiveEvidence = establishment.effective_evidence;

  // Compute confidence state
  let confidence, confidenceColor, confidenceMessage;
  if (entity.total_receipts === 0) {
    confidence = 'PENDING';
    confidenceColor = '#4a4f6a';
    confidenceMessage = 'No receipts yet. Score is default.';
  } else if (score <= 55 && entity.total_receipts <= 10) {
    confidence = 'LOW CONFIDENCE';
    confidenceColor = '#ff9f1c';
    confidenceMessage = `${entity.total_receipts} receipts from unestablished submitters. Needs receipts from established entities.`;
  } else if (!established) {
    confidence = 'PROVISIONAL';
    confidenceColor = '#ffd700';
    confidenceMessage = `${entity.total_receipts} receipts. Requires 5+ from 3+ unique established submitters.`;
  } else if (entity.total_receipts < 20) {
    confidence = 'EMERGING';
    confidenceColor = '#00d4ff';
    confidenceMessage = `Established with ${entity.total_receipts} receipts. Building history.`;
  } else {
    confidence = 'ESTABLISHED';
    confidenceColor = '#00ff88';
    confidenceMessage = `${entity.total_receipts} receipts from multiple submitters. High confidence.`;
  }

  const showBreakdown = confidence === 'EMERGING' || confidence === 'ESTABLISHED';
  const breakdown = showBreakdown ? {
    delivery_accuracy: entity.avg_delivery_accuracy,
    product_accuracy: entity.avg_product_accuracy,
    price_integrity: entity.avg_price_integrity,
    return_processing: entity.avg_return_processing,
    agent_satisfaction: entity.avg_agent_satisfaction,
    consistency: entity.score_consistency,
  } : null;

  const bars = breakdown ? [
    ScoreBar({ label: 'Delivery Accuracy', value: breakdown.delivery_accuracy, color: '#00d4ff' }),
    ScoreBar({ label: 'Product Accuracy', value: breakdown.product_accuracy, color: '#00ff88' }),
    ScoreBar({ label: 'Price Integrity', value: breakdown.price_integrity, color: '#ffd700' }),
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
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Outfit:wght@700;800;900&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet" />
        <style dangerouslySetInnerHTML={{ __html: `
          :root {
            --bg: #05060a; --bg-card: #0e1120; --brd: rgba(255,255,255,0.06);
            --t1: #e8eaf0; --t2: #7a809a; --t3: #4a4f6a;
            --cyan: #00d4ff; --gold: #ffd700; --green: #00ff88;
            --mono: 'JetBrains Mono', monospace; --disp: 'Outfit', sans-serif; --body: 'Space Grotesk', sans-serif;
          }
          *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: var(--bg); color: var(--t1); font-family: var(--body); -webkit-font-smoothing: antialiased; }
          a { color: var(--cyan); text-decoration: none; }
          a:hover { text-decoration: underline; }
        `}} />
      </head>
      <body>
        <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 24px 80px' }}>
          {/* Nav */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 48, fontFamily: 'var(--mono)', fontSize: 12, letterSpacing: 1 }}>
            <a href="/" style={{ color: '#e8eaf0', fontWeight: 600, letterSpacing: 2, fontSize: 14 }}>EMILIA</a>
            <div style={{ display: 'flex', gap: 24 }}>
              <a href="/#score" style={{ color: '#7a809a' }}>SCORE LOOKUP</a>
              <a href="https://github.com/emiliaprotocol/emilia-protocol" style={{ color: '#7a809a' }}>GITHUB</a>
            </div>
          </div>

          {/* Entity header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }}>
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 3, color: '#4a4f6a', textTransform: 'uppercase', marginBottom: 8 }}>
                {typeLabel[entity.entity_type] || entity.entity_type} #{entity.id}
              </div>
              <h1 style={{ fontFamily: 'var(--disp)', fontWeight: 800, fontSize: 'clamp(28px, 5vw, 40px)', letterSpacing: -1, marginBottom: 8 }}>
                {entity.display_name}
              </h1>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: '#7a809a' }}>
                {entity.entity_id}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontFamily: 'var(--disp)', fontWeight: 900, fontSize: 48, color, lineHeight: 1 }}>
                {grade}
              </div>
              <div style={{ fontFamily: 'var(--disp)', fontWeight: 700, fontSize: 24, color: '#e8eaf0', marginTop: 4 }}>
                {score}
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: confidenceColor, letterSpacing: 1, marginTop: 4 }}>
                {confidence}
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
                  <span>{entity.total_receipts}/20 receipts from established submitters</span>
                </div>
                <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min(100, Math.round((entity.total_receipts / 20) * 100))}%`, background: confidenceColor, borderRadius: 2 }} />
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
                  <span key={cap} style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#00d4ff', background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.15)', padding: '6px 12px', borderRadius: 100 }}>
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
              <span style={{ color: '#ffd700' }}>MCP</span> ep_score_lookup entity_id="{entity.entity_id}"
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
