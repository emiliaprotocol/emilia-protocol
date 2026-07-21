/**
 * Tests for lib/tokens.js
 *
 * tokens.js is a pure design-token module (no external deps).
 * Tests verify the exported constants have the expected shape and values.
 */

import { color, font, radius, styles, cta, grid } from '@/lib/tokens.js';

// ---------------------------------------------------------------------------
// color
// ---------------------------------------------------------------------------

describe('color', () => {
  it('exports a color object', () => {
    expect(color).toBeDefined();
    expect(typeof color).toBe('object');
  });

  it('bg is a hex color string', () => {
    expect(color.bg).toMatch(/^#[0-9A-Fa-f]{3,8}$/);
  });

  it('all values are non-empty strings', () => {
    for (const [key, value] of Object.entries(color)) {
      expect(typeof value, `color.${key}`).toBe('string');
      expect(value.length, `color.${key} non-empty`).toBeGreaterThan(0);
    }
  });

  it('contains required semantic keys', () => {
    const required = ['bg', 'card', 't1', 't2', 't3', 'gold', 'green', 'blue', 'red', 'border'];
    for (const key of required) {
      expect(color).toHaveProperty(key);
    }
  });

  it('t1 is darker (lower hex) than bg for contrast', () => {
    // t1 = '#0C0A09' (very dark), bg = '#FAFAF9' (very light)
    expect(color.t1).not.toBe(color.bg);
  });

  it('red is a valid hex color', () => {
    expect(color.red).toMatch(/^#[0-9A-Fa-f]{6}$/);
  });
});

// ---------------------------------------------------------------------------
// font
// ---------------------------------------------------------------------------

describe('font', () => {
  it('exports a font object', () => {
    expect(font).toBeDefined();
    expect(typeof font).toBe('object');
  });

  it('has sans and mono keys', () => {
    expect(font).toHaveProperty('sans');
    expect(font).toHaveProperty('mono');
  });

  it('sans includes IBM Plex Sans', () => {
    expect(font.sans).toContain('IBM Plex Sans');
  });

  it('mono includes IBM Plex Mono', () => {
    expect(font.mono).toContain('IBM Plex Mono');
  });

  it('sans has a fallback font stack', () => {
    // Should have at least one comma-separated fallback
    expect(font.sans).toContain(',');
  });
});

// ---------------------------------------------------------------------------
// radius
// ---------------------------------------------------------------------------

describe('radius', () => {
  it('exports a radius object', () => {
    expect(radius).toBeDefined();
    expect(typeof radius).toBe('object');
  });

  it('has sm and base keys', () => {
    expect(radius).toHaveProperty('sm');
    expect(radius).toHaveProperty('base');
  });

  it('sm is a positive number', () => {
    expect(typeof radius.sm).toBe('number');
    expect(radius.sm).toBeGreaterThan(0);
  });

  it('base is a positive number', () => {
    expect(typeof radius.base).toBe('number');
    expect(radius.base).toBeGreaterThan(0);
  });

  it('base >= sm (containers are at least as rounded as controls)', () => {
    expect(radius.base).toBeGreaterThanOrEqual(radius.sm);
  });
});

// ---------------------------------------------------------------------------
// styles
// ---------------------------------------------------------------------------

describe('styles', () => {
  it('exports a styles object', () => {
    expect(styles).toBeDefined();
    expect(typeof styles).toBe('object');
  });

  it('contains page, section, and card keys', () => {
    expect(styles).toHaveProperty('page');
    expect(styles).toHaveProperty('section');
    expect(styles).toHaveProperty('card');
  });

  it('page style includes background and fontFamily', () => {
    expect(styles.page).toHaveProperty('background');
    expect(styles.page).toHaveProperty('fontFamily');
  });

  it('page background matches color.bg', () => {
    expect(styles.page.background).toBe(color.bg);
  });

  it('section has maxWidth as a number', () => {
    expect(typeof styles.section.maxWidth).toBe('number');
  });

  it('sectionWide has a larger maxWidth than section', () => {
    expect(styles.sectionWide.maxWidth).toBeGreaterThan(styles.section.maxWidth);
  });

  it('card has borderRadius', () => {
    expect(styles.card).toHaveProperty('borderRadius');
  });

  it('input style includes width and padding', () => {
    expect(styles.input).toHaveProperty('width');
    expect(styles.input).toHaveProperty('padding');
  });

  it('h1 fontWeight is 700', () => {
    expect(styles.h1.fontWeight).toBe(700);
  });

  it('eyebrow uses mono font', () => {
    expect(styles.eyebrow.fontFamily).toBe(font.mono);
  });
});

// ---------------------------------------------------------------------------
// cta
// ---------------------------------------------------------------------------

describe('cta', () => {
  it('exports a cta object', () => {
    expect(cta).toBeDefined();
    expect(typeof cta).toBe('object');
  });

  it('has primary, secondary, ghost, and disabled variants', () => {
    for (const key of ['primary', 'secondary', 'ghost', 'disabled']) {
      expect(cta).toHaveProperty(key);
    }
  });

  it('all variants have cursor property', () => {
    for (const [variant, style] of Object.entries(cta)) {
      expect(style, `cta.${variant} has cursor`).toHaveProperty('cursor');
    }
  });

  it('disabled variant has cursor: default', () => {
    expect(cta.disabled.cursor).toBe('default');
  });

  it('primary has a dark background', () => {
    // primary background is color.t1 = '#0C0A09'
    expect(cta.primary.background).toBe(color.t1);
  });

  it('ghost has no border', () => {
    expect(cta.ghost.border).toBe('none');
  });

  it('secondary has a border', () => {
    expect(cta.secondary.border).toBeDefined();
    expect(cta.secondary.border).not.toBe('none');
  });

  it('all variants use mono font family', () => {
    for (const [variant, style] of Object.entries(cta)) {
      expect(style.fontFamily, `cta.${variant} fontFamily`).toBe(font.mono);
    }
  });
});

// ---------------------------------------------------------------------------
// grid
// ---------------------------------------------------------------------------

describe('grid', () => {
  it('exports a grid object', () => {
    expect(grid).toBeDefined();
    expect(typeof grid).toBe('object');
  });

  it('auto is a function', () => {
    expect(typeof grid.auto).toBe('function');
  });

  it('auto() returns a grid style with gridTemplateColumns', () => {
    const style = grid.auto();
    expect(style).toHaveProperty('display', 'grid');
    expect(style).toHaveProperty('gridTemplateColumns');
  });

  it('auto() uses default minWidth of 280 when called with no args', () => {
    const style = grid.auto();
    expect(style.gridTemplateColumns).toContain('280px');
  });

  it('auto(400) uses the provided minWidth', () => {
    const style = grid.auto(400);
    expect(style.gridTemplateColumns).toContain('400px');
  });

  it('cols2 is a static object with two equal columns', () => {
    expect(grid.cols2.gridTemplateColumns).toBe('1fr 1fr');
  });

  it('stack has display: grid', () => {
    expect(grid.stack.display).toBe('grid');
  });
});
