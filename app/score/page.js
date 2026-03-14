'use client';
import { useState } from 'react';

const API = '';

export default function Home() {
  const [lookupId, setLookupId] = useState('');
  const [scoreData, setScoreData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function lookupScore() {
    if (!lookupId.trim()) return;
    setLoading(true);
    setError('');
    setScoreData(null);
    try {
      const res = await fetch(`${API}/api/score/${encodeURIComponent(lookupId.trim())}`);
      if (!res.ok) {
        const err = await res.json();
        setError(err.error || 'Entity not found');
      } else {
        setScoreData(await res.json());
      }
    } catch (e) {
      setError('Network error');
    }
    setLoading(false);
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700;900&family=DM+Sans:wght@300;400;500;700&family=JetBrains+Mono:wght@400;500&display=swap');
        *{margin:0;padding:0;box-sizing:border-box}
        html{scroll-behavior:smooth}
        body{background:#09090F;color:#E8E6E1;font-family:'DM Sans',sans-serif}
        ::selection{background:#D4A84333;color:#D4A843}
        a{color:#D4A843;text-decoration:none}
        a:hover{text-decoration:underline}
        .hero{min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:60px 24px;max-width:900px;margin:0 auto;position:relative}
        .hero::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#D4A84355,transparent)}
        .badge{display:inline-block;font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#D4A843;border:1px solid #D4A84333;padding:6px 16px;border-radius:100px;margin-bottom:32px;font-weight:500}
        .title{font-family:'Playfair Display',serif;font-size:clamp(48px,8vw,80px);font-weight:900;line-height:1.05;letter-spacing:-1px;margin-bottom:12px;color:#D4A843}
        .acronym{font-size:13px;color:#666;letter-spacing:1px;margin-bottom:32px;font-weight:300}
        .subtitle{font-size:clamp(18px,2.5vw,22px);color:#999;line-height:1.6;max-width:600px;font-weight:300}
        .subtitle em{color:#D4A843;font-style:normal;font-weight:500}
        .section{padding:80px 24px;max-width:900px;margin:0 auto}
        .section-line{height:1px;background:linear-gradient(90deg,transparent,#D4A84322,transparent);margin-bottom:60px}
        .section-label{font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#D4A843;margin-bottom:16px;font-weight:500}
        .section-title{font-family:'Playfair Display',serif;font-size:clamp(28px,4vw,40px);font-weight:700;margin-bottom:24px;line-height:1.2}
        .section-body{color:#999;font-size:16px;line-height:1.8;font-weight:300}
        .section-body strong{color:#E8E6E1;font-weight:500}
        .score-box{margin-top:48px;background:#0F0F18;border:1px solid #1A1A2E;border-radius:12px;padding:32px}
        .score-input-row{display:flex;gap:12px}
        .score-input{flex:1;background:#16162A;border:1px solid #2A2A3E;border-radius:8px;padding:14px 18px;color:#E8E6E1;font-size:16px;font-family:'JetBrains Mono',monospace;outline:none}
        .score-input:focus{border-color:#D4A843}
        .score-input::placeholder{color:#444}
        .score-btn{background:#D4A843;color:#09090F;border:none;padding:14px 28px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;font-family:'DM Sans',sans-serif;letter-spacing:0.5px;white-space:nowrap}
        .score-btn:hover{background:#E0B84F}
        .score-btn:disabled{opacity:0.5;cursor:not-allowed}
        .score-error{color:#E24B4A;margin-top:12px;font-size:14px}
        .score-result{margin-top:24px;padding:24px;background:#12121E;border-radius:10px;border:1px solid #1E1E30}
        .score-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;flex-wrap:wrap;gap:12px}
        .score-name{font-family:'Playfair Display',serif;font-size:22px;font-weight:700}
        .score-type{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#D4A843;background:#D4A84315;padding:4px 10px;border-radius:4px}
        .score-number{font-family:'Playfair Display',serif;font-size:64px;font-weight:900;color:#D4A843;line-height:1}
        .score-label{font-size:12px;color:#666;margin-top:4px;letter-spacing:1px;text-transform:uppercase}
        .score-meta{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-top:20px;padding-top:16px;border-top:1px solid #1E1E30}
        .score-meta-val{color:#E8E6E1;font-weight:500;font-family:'JetBrains Mono',monospace;font-size:14px}
        .score-meta-label{color:#666;font-size:11px;margin-top:2px}
        .score-breakdown{margin-top:16px;padding-top:16px;border-top:1px solid #1E1E30}
        .score-bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}
        .score-bar-label{font-size:12px;color:#888;width:140px;flex-shrink:0;text-transform:capitalize}
        .score-bar-track{flex:1;height:6px;background:#1A1A2E;border-radius:3px;overflow:hidden}
        .score-bar-fill{height:100%;background:#D4A843;border-radius:3px;transition:width 0.6s ease}
        .score-bar-val{font-size:12px;color:#D4A843;width:40px;text-align:right;font-family:'JetBrains Mono',monospace}
        .how-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:32px}
        .how-card{background:#0F0F18;border:1px solid #1A1A2E;border-radius:10px;padding:24px;position:relative;overflow:hidden}
        .how-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:#D4A843;opacity:0.3}
        .how-num{font-family:'Playfair Display',serif;font-size:48px;font-weight:900;color:#D4A84315;position:absolute;top:8px;right:16px}
        .how-title{font-size:16px;font-weight:700;margin-bottom:8px}
        .how-desc{font-size:14px;color:#777;line-height:1.6;font-weight:300}
        .weights{margin-top:32px}
        .weight-row{display:flex;align-items:center;padding:12px 0;border-bottom:1px solid #1A1A2E}
        .weight-signal{flex:1;font-size:14px}
        .weight-desc{flex:2;font-size:13px;color:#666;font-weight:300}
        .weight-pct{font-size:14px;color:#D4A843;font-weight:700;width:50px;text-align:right;font-family:'JetBrains Mono',monospace}
        .api-block{background:#0F0F18;border:1px solid #1A1A2E;border-radius:10px;padding:20px;margin-bottom:16px;margin-top:16px}
        .api-method{font-size:11px;letter-spacing:2px;font-weight:700;padding:3px 8px;border-radius:4px;margin-right:10px}
        .api-post{background:#D4A84322;color:#D4A843}
        .api-get{background:#0F6E5622;color:#5DCAA5}
        .api-path{font-family:'JetBrains Mono',monospace;font-size:14px}
        .api-desc{font-size:13px;color:#666;margin-top:8px;font-weight:300}
        .cta{text-align:center;padding:80px 24px 120px}
        .cta-title{font-family:'Playfair Display',serif;font-size:clamp(28px,5vw,44px);font-weight:700;margin-bottom:16px}
        .cta-title span{color:#D4A843}
        .cta-sub{color:#666;font-size:16px;margin-bottom:32px;font-weight:300}
        .cta-links{display:flex;gap:24px;justify-content:center;font-size:14px}
        .footer{text-align:center;padding:24px;font-size:12px;color:#444;border-top:1px solid #1A1A2E}
        @media(max-width:600px){.score-input-row{flex-direction:column}.score-meta{grid-template-columns:1fr 1fr}.how-grid{grid-template-columns:1fr}.cta-links{flex-direction:column;align-items:center}}
      `}</style>

      <div className="hero">
        <div className="badge">Open Source Protocol</div>
        <h1 className="title">EMILIA</h1>
        <p className="acronym">Entity Measurement Infrastructure for Ledgered Interaction Accountability</p>
        <p className="subtitle">
          The open-source credit score for the agent economy.<br/>
          <em>Reputation earned through receipts, not reviews.</em>
        </p>
      </div>

      <div className="section">
        <div className="section-line"/>
        <div className="section-label">Look up a score</div>
        <div className="section-title">Check any EMILIA Score</div>
        <p className="section-body">Scores are public. No login required. Type an entity ID and see their reputation — computed from verified transaction receipts, not opinions.</p>
        <div className="score-box">
          <div className="score-input-row">
            <input className="score-input" placeholder="e.g. rex-booking-v1" value={lookupId} onChange={e=>setLookupId(e.target.value)} onKeyDown={e=>e.key==='Enter'&&lookupScore()}/>
            <button className="score-btn" onClick={lookupScore} disabled={loading}>{loading?'Looking up...':'Check Score'}</button>
          </div>
          {error&&<p className="score-error">{error}</p>}
          {scoreData&&(
            <div className="score-result">
              <div className="score-header">
                <div><div className="score-name">{scoreData.display_name}</div><div style={{fontSize:13,color:'#666',marginTop:4}}>{scoreData.description}</div></div>
                <span className="score-type">{scoreData.entity_type}</span>
              </div>
              <div className="score-number">{scoreData.emilia_score}</div>
              <div className="score-label">EMILIA Score · {scoreData.established?'Established':'Unproven'} · {scoreData.total_receipts} receipts</div>
              <div className="score-meta">
                <div><div className="score-meta-val">{scoreData.total_receipts}</div><div className="score-meta-label">Total receipts</div></div>
                <div><div className="score-meta-val">{scoreData.success_rate!=null?scoreData.success_rate+'%':'—'}</div><div className="score-meta-label">Success rate</div></div>
                <div><div className="score-meta-val">{scoreData.verified?'Verified':'Not yet'}</div><div className="score-meta-label">Verification</div></div>
              </div>
              {scoreData.breakdown&&(
                <div className="score-breakdown">
                  {Object.entries(scoreData.breakdown).map(([key,val])=>(
                    <div key={key} className="score-bar-row">
                      <div className="score-bar-label">{key.replace(/_/g,' ')}</div>
                      <div className="score-bar-track"><div className="score-bar-fill" style={{width:(val||0)+'%'}}/></div>
                      <div className="score-bar-val">{val??'—'}</div>
                    </div>
                  ))}
                </div>
              )}
              {scoreData.capabilities?.length>0&&(
                <div style={{marginTop:16,paddingTop:16,borderTop:'1px solid #1E1E30'}}>
                  <div style={{fontSize:11,color:'#666',letterSpacing:2,textTransform:'uppercase',marginBottom:8}}>Capabilities</div>
                  <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                    {scoreData.capabilities.map(c=><span key={c} style={{fontSize:12,background:'#D4A84312',color:'#D4A843',padding:'4px 10px',borderRadius:4,fontFamily:'JetBrains Mono,monospace'}}>{c}</span>)}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="section">
        <div className="section-line"/>
        <div className="section-label">How it works</div>
        <div className="section-title">Receipts, not reviews</div>
        <p className="section-body">Every review system has failed because the platform hosting reviews profits from the businesses being reviewed. <strong>EMILIA is different.</strong> Agents don't write opinions — they record what happened. Did the delivery arrive on time? Was the product as described? Was the price honored? These are verifiable facts. <strong>You can't fake a delivery receipt.</strong></p>
        <div className="how-grid">
          <div className="how-card"><div className="how-num">1</div><div className="how-title">Entity registers</div><div className="how-desc">Agents, merchants, and service providers register on the protocol with their capabilities.</div></div>
          <div className="how-card"><div className="how-num">2</div><div className="how-title">Transactions happen</div><div className="how-desc">Commerce flows through existing protocols — UCP, ACP, A2A. EMILIA doesn't handle the transaction.</div></div>
          <div className="how-card"><div className="how-num">3</div><div className="how-title">Receipts are submitted</div><div className="how-desc">After each transaction, a receipt records what was promised vs delivered. Cryptographically signed. Immutable.</div></div>
          <div className="how-card"><div className="how-num">4</div><div className="how-title">Scores update</div><div className="how-desc">The EMILIA Score recomputes from rolling receipts. The algorithm is open source. No one can buy it.</div></div>
        </div>
      </div>

      <div className="section">
        <div className="section-line"/>
        <div className="section-label">The algorithm</div>
        <div className="section-title">Published, auditable, incorruptible</div>
        <p className="section-body">The scoring algorithm is <strong>open source</strong> on <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/lib/scoring.js" target="_blank">GitHub</a>. Every weight is published. This is what makes EMILIA trustworthy.</p>
        <div className="weights">
          {[['Delivery accuracy','Promised vs actual arrival','30%'],['Product accuracy','Listing matched reality','25%'],['Price integrity','Quoted vs charged','15%'],['Return processing','Policy honored on time','15%'],['Agent satisfaction','Purchasing agent signal','10%'],['Consistency','Low variance over time','5%']].map(([s,d,p])=>(
            <div key={s} className="weight-row"><div className="weight-signal">{s}</div><div className="weight-desc">{d}</div><div className="weight-pct">{p}</div></div>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="section-line"/>
        <div className="section-label">For developers</div>
        <div className="section-title">Three API calls. That's the protocol.</div>
        <div className="api-block"><div><span className="api-method api-post">POST</span><span className="api-path">/api/entities/register</span></div><div className="api-desc">Register an agent, merchant, or service provider. Returns an API key.</div></div>
        <div className="api-block"><div><span className="api-method api-post">POST</span><span className="api-path">/api/receipts/submit</span></div><div className="api-desc">Submit a transaction receipt. Cryptographically hashed. Append-only. Triggers score recomputation.</div></div>
        <div className="api-block"><div><span className="api-method api-get">GET</span><span className="api-path">/api/score/:entityId</span></div><div className="api-desc">Look up any EMILIA Score. Public. No auth required.</div></div>
      </div>

      <div className="cta">
        <div className="section-line"/>
        <div className="cta-title">The first reputation system<br/><span>no corporation can buy.</span></div>
        <div className="cta-sub">Open source. Receipts, not reviews. Built for the agent economy.</div>
        <div className="cta-links">
          <a href="https://github.com/emiliaprotocol/emilia-protocol" target="_blank">GitHub</a>
          <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/lib/scoring.js" target="_blank">Read the algorithm</a>
          <a href="https://github.com/emiliaprotocol/emilia-protocol/blob/main/README.md" target="_blank">Documentation</a>
        </div>
      </div>

      <div className="footer">EMILIA Protocol · The open-source credit score for the agent economy · Apache 2.0</div>
    </>
  );
}
