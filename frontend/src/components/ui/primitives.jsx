// Shared presentation primitives. Every screen composes these -no page-specific one-off styling.
// Rules they enforce, so no caller has to remember them:
//   · severity is a filled-square meter plus a mono word, coloured by level (CSS .sev-*);
//   · status is one mono label with a square marker, and an item shows at most one;
//   · provenance ("AI-generated", "confidence: medium") is metadata, never a status;
//   · a Copy control lives inside the block it copies.
import { useId, useState } from 'react';
import { stateMeta } from '../../lib/domain';

// ── Severity ───────────────────────────────────────────────────────────────────────────────────
// Four squares. Filled count is the level: critical 4, high 3, medium 2, low 1.
const FILLED = { critical: 4, high: 3, medium: 2, low: 1 };

export function SeverityMeter({ level }) {
  const on = FILLED[level] ?? 0;
  return (
    <span className="sevmeter" aria-hidden="true">
      {[0, 1, 2, 3].map((i) => <i key={i} className={i < on ? 'on' : undefined} />)}
    </span>
  );
}

// The meter and the word together. `meterOnly` is for dense rows where the word is already in the label.
export function Severity({ level, meterOnly = false }) {
  if (!level) return null;
  return (
    <span className={`sev sev-${level}`}>
      <SeverityMeter level={level} />
      {meterOnly ? <span className="visually-hidden">{level}</span> : level}
    </span>
  );
}

// ── Status ─────────────────────────────────────────────────────────────────────────────────────
// `state` is a key of the one state model (lib/domain STATE): callers never pass raw backend statuses.
export function StatusLabel({ state, children, size }) {
  const m = stateMeta(state);
  return (
    <span className={`status status-${m.tone} ${size || ''}`}>
      <span className="status-glyph" aria-hidden="true" />
      <span className="status-word">{children || m.label}</span>
    </span>
  );
}

// Metadata beside a status -where a reading came from, how sure it is. Never a status itself.
// `parts` are shown as "SOURCE: AI-GENERATED · CONFIDENCE: MEDIUM".
export function MetaLine({ parts = [], children }) {
  const shown = parts.filter(Boolean);
  if (shown.length === 0 && !children) return null;
  // Each part is its own element: the separator is drawn by CSS, so no part is glued to its neighbour in the
  // accessibility tree or in a text search.
  return <p className="metaline">{shown.map((part, i) => <span key={i}>{part}</span>)}{children}</p>;
}

// ── Notice ─────────────────────────────────────────────────────────────────────────────────────
// Replaces every tinted warning/info box: hairlines top and bottom, a 2px left edge (accent when it
// warns), a mono eyebrow, body text at 16px. No fill, no boxed icon.
export function Notice({ kind = 'note', label, children, role, action }) {
  const warns = kind === 'warning' || kind === 'danger';
  return (
    <div className={`notice notice-${warns ? 'warn' : 'info'}`} role={role}>
      <p className="notice-mark">{label || (warns ? 'Warning' : 'Note')}</p>
      {children}
      {action && <span className="notice-action">{action}</span>}
    </div>
  );
}

// ── Code ───────────────────────────────────────────────────────────────────────────────────────
// Copy is anchored inside the block it copies, and the result is announced.
export function CopyControl({ text, label = 'Copy' }) {
  const [said, setSaid] = useState(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setSaid('Copied');
    } catch {
      setSaid('Copy isn’t available here -select the text instead');
    }
  };
  return (
    <span className="copy">
      <button type="button" className="btn btn-sm btn-quiet" onClick={copy}>{label}</button>
      <span className="copy-said" role="status" aria-live="polite">{said}</span>
    </span>
  );
}

// One command, with its Copy control inside it. `active` draws the 2px accent left edge.
export function CodeBlock({ code, active = false, copyLabel = 'Copy' }) {
  return (
    <div className={`codeblock${active ? ' is-active' : ''}`}>
      <pre><code>{code}</code></pre>
      <CopyControl text={code} label={copyLabel} />
    </div>
  );
}

// ── Disclosure ─────────────────────────────────────────────────────────────────────────────────
export function Disclosure({ summary, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <div className="more">
      <button type="button" className="more-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen((v) => !v)}>
        {summary}
      </button>
      {open && <div className="more-body reveal-open" id={id}>{children}</div>}
    </div>
  );
}

// ── Numbers and rows ───────────────────────────────────────────────────────────────────────────
// A large numeral under a mono eyebrow. Hairline separation comes from the .statrow grid.
export function StatBlock({ label, value, children, meter }) {
  return (
    <div className="statblock">
      <p className="statblock-v tnum">{value ?? '-'}</p>
      <p className="eyebrow">{label}</p>
      {meter && <SeverityMeter level={meter} />}
      {children}
    </div>
  );
}

export function StatRow({ children }) {
  return <div className="statrow">{children}</div>;
}

// A full-width list row separated by hairlines. No bordered card per item.
export function DataRow({ lead, title, meta, trail, onClick, label }) {
  const body = (
    <>
      {lead && <span className="datarow-lead">{lead}</span>}
      <span className="datarow-main">
        <span className="datarow-title">{title}</span>
        {meta && <span className="datarow-meta">{meta}</span>}
      </span>
      {trail && <span className="datarow-trail">{trail}</span>}
    </>
  );
  return (
    <li className="datarow">
      {onClick
        ? <button type="button" className="datarow-hit" onClick={onClick} aria-label={label}>{body}</button>
        : <div className="datarow-hit">{body}</div>}
    </li>
  );
}

// ── Tabs ───────────────────────────────────────────────────────────────────────────────────────
// Underline tabs with mono labels and a mono count. `tabs` is [value, label, count?][].
export function Tabs({ tabs, value, onChange, label }) {
  return (
    <div className="segmented" role="tablist" aria-label={label}>
      {tabs.map(([key, text, n]) => (
        <button
          key={key} type="button" className="seg-btn" role="tab"
          aria-pressed={value === key} aria-selected={value === key}
          onClick={() => onChange(key)}
        >
          {text}
          {n != null && <span className="seg-n tnum">{n}</span>}
        </button>
      ))}
    </div>
  );
}

// ── Action bar ─────────────────────────────────────────────────────────────────────────────────
// Fixed at the bottom with a solid background. The page adds matching bottom padding (.has-actionbar)
// so it never overlaps content. A disabled action always states its reason inline.
export function ActionBar({ status, note, children }) {
  return (
    <div className="actionbar">
      <div className="actionbar-inner">
        <div className="actionbar-lead">
          <p className="actionbar-status">{status}</p>
          {note && <p className="actionbar-note">{note}</p>}
        </div>
        <div className="actionbar-actions">{children}</div>
      </div>
    </div>
  );
}
