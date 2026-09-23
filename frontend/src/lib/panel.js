/**
 * Where the assistant panel sits, and how wide.
 *
 * Kept out of the component because it has to outlive it: switching page unmounts nothing here, but
 * a reload does, and a panel the operator dragged somewhere should still be there afterwards.
 * localStorage can throw (private windows, blocked site data), so every read and write is guarded
 * and the defaults stand on their own.
 */

const KEY = 'netauditai.assistant.panel';

// The rail keeps its width whether the chat is open or shut, so opening it never reflows the page.
// Only popping the panel out frees the space, because then the chat is genuinely no longer in it.
export const NAV_WIDTH = 248;
export const DOCK_MIN = 300;
export const DOCK_MAX = 720;
export const FLOAT_MIN_W = 320;
export const FLOAT_MIN_H = 240;
// How close to the left rail a dragged panel has to come before it offers to dock again
export const SNAP_X = 130;

export const DEFAULT_PANEL = {
  mode: 'docked',        // 'docked' | 'floating'
  width: 400,            // docked rail width
  x: 120, y: 96,         // floating position
  w: 420, h: 520,        // floating size
};

export function clampPanel(panel) {
  const next = { ...DEFAULT_PANEL, ...panel };
  next.width = Math.min(DOCK_MAX, Math.max(DOCK_MIN, Math.round(next.width)));
  next.w = Math.max(FLOAT_MIN_W, Math.round(next.w));
  next.h = Math.max(FLOAT_MIN_H, Math.round(next.h));
  next.x = Math.round(next.x);
  next.y = Math.max(0, Math.round(next.y));
  next.mode = next.mode === 'floating' ? 'floating' : 'docked';
  return next;
}

/** Keep a floating panel reachable: a window that shrank must not strand it off-screen. */
export function keepOnScreen(panel, viewW, viewH) {
  if (panel.mode !== 'floating') return panel;
  const w = Math.min(panel.w, Math.max(FLOAT_MIN_W, viewW - 16));
  const h = Math.min(panel.h, Math.max(FLOAT_MIN_H, viewH - 16));
  return {
    ...panel,
    w,
    h,
    // at least a grab-strip of the header stays inside the viewport on every edge
    x: Math.min(Math.max(panel.x, 16 - w), Math.max(16, viewW - 48)),
    y: Math.min(Math.max(panel.y, 0), Math.max(0, viewH - 40)),
  };
}

export function loadPanel() {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? clampPanel(JSON.parse(raw)) : { ...DEFAULT_PANEL };
  } catch {
    return { ...DEFAULT_PANEL };
  }
}

export function savePanel(panel) {
  try {
    localStorage.setItem(KEY, JSON.stringify(panel));
  } catch {
    /* a panel position is a convenience; losing it must never break the page */
  }
}
