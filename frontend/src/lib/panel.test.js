import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_PANEL, DOCK_MAX, DOCK_MIN, FLOAT_MIN_H, FLOAT_MIN_W,
  clampPanel, keepOnScreen, loadPanel, savePanel,
} from './panel';

describe('assistant panel geometry', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('keeps the docked rail within a width the page can still be read beside', () => {
    expect(clampPanel({ width: 20 }).width).toBe(DOCK_MIN);
    expect(clampPanel({ width: 9000 }).width).toBe(DOCK_MAX);
  });

  it('will not let a floating panel be resized into nothing', () => {
    const tiny = clampPanel({ mode: 'floating', w: 10, h: 10 });
    expect(tiny.w).toBe(FLOAT_MIN_W);
    expect(tiny.h).toBe(FLOAT_MIN_H);
  });

  it('pulls a floating panel back when the window is too small to reach it', () => {
    const stranded = { ...DEFAULT_PANEL, mode: 'floating', x: 5000, y: 4000, w: 420, h: 520 };
    const fixed = keepOnScreen(stranded, 1000, 700);
    expect(fixed.x).toBeLessThan(1000);
    expect(fixed.y).toBeLessThan(700);
    // and it shrinks to fit rather than overflowing
    expect(fixed.h).toBeLessThanOrEqual(700);
  });

  it('leaves a docked panel alone when the window resizes', () => {
    const docked = { ...DEFAULT_PANEL, mode: 'docked' };
    expect(keepOnScreen(docked, 400, 300)).toEqual(docked);
  });

  it('allows a panel dragged partly off the left edge, but keeps a strip to grab', () => {
    const fixed = keepOnScreen({ ...DEFAULT_PANEL, mode: 'floating', x: -9999, w: 400 }, 1200, 800);
    expect(fixed.x).toBeGreaterThanOrEqual(16 - 400);
  });

  it('restores what was saved', () => {
    const store = {};
    vi.stubGlobal('localStorage', {
      getItem: (k) => store[k] ?? null,
      setItem: (k, v) => { store[k] = v; },
    });
    savePanel({ ...DEFAULT_PANEL, mode: 'floating', x: 42, y: 84, width: 512 });
    const back = loadPanel();
    expect(back.mode).toBe('floating');
    expect([back.x, back.y, back.width]).toEqual([42, 84, 512]);
  });

  it('falls back to the default when storage is unavailable or corrupt', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => { throw new Error('blocked'); },
      setItem: () => { throw new Error('blocked'); },
    });
    expect(loadPanel()).toEqual(DEFAULT_PANEL);
    expect(() => savePanel(DEFAULT_PANEL)).not.toThrow();

    vi.stubGlobal('localStorage', { getItem: () => 'not json', setItem: () => {} });
    expect(loadPanel()).toEqual(DEFAULT_PANEL);
  });
});
