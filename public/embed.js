/**
 * EP Trust Badge — Embeddable Web Component
 *
 * Drop this on any page to show a cryptographically verified trust badge:
 *
 *   <script src="https://ep.emiliaprotocol.ai/embed.js"></script>
 *   <ep-trust-badge entity-id="ep_entity_abc123"></ep-trust-badge>
 *
 * The badge:
 *   - Fetches the entity's trust profile from the EP API
 *   - Displays confidence level, evidence depth, and trust score
 *   - Links to the Trust Explorer for full verification
 *   - Cannot be faked — data comes live from the EP operator
 *
 * Security: All rendering uses safe DOM APIs (createElement + textContent).
 * No innerHTML with user/API data. XSS-safe by construction.
 *
 * @license Apache-2.0
 */

(function () {
  'use strict';

  var EP_BASE = (document.currentScript && document.currentScript.src)
    ? new URL(document.currentScript.src).origin
    : 'https://ep.emiliaprotocol.ai';

  var STYLES = [
    ':host { display: inline-block; font-family: "IBM Plex Mono", "SF Mono", monospace; }',
    '.ep-badge { display: inline-flex; align-items: center; gap: 10px; padding: 10px 16px;',
    '  border-radius: 6px; border: 1px solid #E7E5E4; background: #FFF; text-decoration: none;',
    '  color: #0C0A09; transition: border-color 0.15s, box-shadow 0.15s; cursor: pointer; }',
    '.ep-badge:hover { border-color: #B08D35; box-shadow: 0 0 0 2px rgba(176,141,53,0.1); }',
    '.ep-shield { width: 20px; height: 20px; flex-shrink: 0; }',
    '.ep-info { display: flex; flex-direction: column; gap: 2px; }',
    '.ep-label { font-size: 9px; letter-spacing: 1.5px; text-transform: uppercase; color: #78716C; }',
    '.ep-score { font-size: 13px; font-weight: 600; color: #0C0A09; }',
    '.ep-confidence { font-size: 10px; color: #44403C; }',
    '.ep-verified { display: inline-flex; align-items: center; gap: 4px; font-size: 9px;',
    '  letter-spacing: 1px; text-transform: uppercase; color: #16A34A; font-weight: 600; }',
    '.ep-loading { color: #78716C; font-size: 11px; }',
    '.ep-error { color: #DC2626; font-size: 11px; }',
  ].join('\n');

  /**
   * Create the shield SVG element safely via DOM APIs.
   * @returns {SVGElement}
   */
  function createShieldSVG() {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'ep-shield');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', '#B08D35');
    svg.setAttribute('stroke-width', '1.5');

    var path1 = document.createElementNS(ns, 'path');
    path1.setAttribute('d', 'M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z');
    svg.appendChild(path1);

    var path2 = document.createElementNS(ns, 'path');
    path2.setAttribute('d', 'M9 12l2 2 4-4');
    path2.setAttribute('stroke', '#16A34A');
    path2.setAttribute('stroke-width', '2');
    svg.appendChild(path2);

    return svg;
  }

  /**
   * Create a checkmark dot SVG element safely.
   * @returns {SVGElement}
   */
  function createCheckDot() {
    var ns = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('width', '10');
    svg.setAttribute('height', '10');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('fill', '#16A34A');

    var circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', '8');
    circle.setAttribute('cy', '8');
    circle.setAttribute('r', '8');
    svg.appendChild(circle);

    var path = document.createElementNS(ns, 'path');
    path.setAttribute('d', 'M5 8l2 2 4-4');
    path.setAttribute('stroke', 'white');
    path.setAttribute('stroke-width', '2');
    path.setAttribute('fill', 'none');
    svg.appendChild(path);

    return svg;
  }

  /**
   * Clear shadow root and inject style element.
   * @param {ShadowRoot} root
   */
  function resetRoot(root) {
    while (root.firstChild) root.removeChild(root.firstChild);
    var style = document.createElement('style');
    style.textContent = STYLES;
    root.appendChild(style);
  }

  /**
   * Sanitize a string to safe display text (alphanumeric, dots, underscores, hyphens, spaces).
   * Prevents any HTML/script injection from API responses.
   * @param {*} val
   * @returns {string}
   */
  function safeText(val) {
    return String(val == null ? '' : val).replace(/[<>"'&]/g, '');
  }

  class EPTrustBadge extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
      var entityId = this.getAttribute('entity-id');
      if (!entityId) {
        this._renderMessage('ep-error', 'Missing entity-id attribute');
        return;
      }
      this._renderMessage('ep-loading', 'Verifying...');
      this._fetchProfile(entityId);
    }

    static get observedAttributes() {
      return ['entity-id'];
    }

    attributeChangedCallback(name, oldVal, newVal) {
      if (name === 'entity-id' && oldVal !== newVal && newVal) {
        this._renderMessage('ep-loading', 'Verifying...');
        this._fetchProfile(newVal);
      }
    }

    /**
     * Render a simple loading/error state using safe DOM APIs only.
     * @param {string} className
     * @param {string} text
     */
    _renderMessage(className, text) {
      var root = this.shadowRoot;
      resetRoot(root);

      var badge = document.createElement('span');
      badge.setAttribute('class', 'ep-badge');
      badge.appendChild(createShieldSVG());

      var msg = document.createElement('span');
      msg.setAttribute('class', className);
      msg.textContent = text;
      badge.appendChild(msg);

      root.appendChild(badge);
    }

    async _fetchProfile(entityId) {
      try {
        var res = await fetch(EP_BASE + '/api/trust/profile/' + encodeURIComponent(entityId));
        if (!res.ok) {
          this._renderMessage('ep-error', 'Entity not found');
          return;
        }
        var data = await res.json();
        this._render(data, entityId);
      } catch (e) {
        this._renderMessage('ep-error', 'Network error');
      }
    }

    /**
     * Render the full trust badge using safe DOM APIs only.
     * All values are set via textContent — never innerHTML.
     * @param {object} profile
     * @param {string} entityId
     */
    _render(profile, entityId) {
      var root = this.shadowRoot;
      resetRoot(root);

      var score = typeof profile.score === 'number' ? profile.score.toFixed(2) : '\u2014';
      var confidence = safeText(profile.confidence || 'unknown');
      var depth = Number.isFinite(profile.evidence_depth) ? profile.evidence_depth : 0;

      // Build link
      var badge = document.createElement('a');
      badge.setAttribute('class', 'ep-badge');
      badge.setAttribute('href', EP_BASE + '/explorer?tab=entity&q=' + encodeURIComponent(entityId));
      badge.setAttribute('target', '_blank');
      badge.setAttribute('rel', 'noopener noreferrer');
      badge.setAttribute('title', 'Verify on EP Trust Explorer');

      // Shield icon
      badge.appendChild(createShieldSVG());

      // Info block
      var info = document.createElement('span');
      info.setAttribute('class', 'ep-info');

      var label = document.createElement('span');
      label.setAttribute('class', 'ep-label');
      label.textContent = 'EP Trust Score';
      info.appendChild(label);

      var scoreEl = document.createElement('span');
      scoreEl.setAttribute('class', 'ep-score');
      scoreEl.textContent = score;
      info.appendChild(scoreEl);

      var confEl = document.createElement('span');
      confEl.setAttribute('class', 'ep-confidence');
      confEl.textContent = confidence + ' confidence \u00B7 ' + depth + ' receipts';
      info.appendChild(confEl);

      badge.appendChild(info);

      // Verified badge
      var verified = document.createElement('span');
      verified.setAttribute('class', 'ep-verified');
      verified.appendChild(createCheckDot());
      var verText = document.createTextNode('VERIFIED');
      verified.appendChild(verText);
      badge.appendChild(verified);

      root.appendChild(badge);
    }
  }

  if (!customElements.get('ep-trust-badge')) {
    customElements.define('ep-trust-badge', EPTrustBadge);
  }
})();
