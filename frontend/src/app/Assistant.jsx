import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api/client';
import Markdown from '../components/Markdown';
import {
  DOCK_MAX, DOCK_MIN, FLOAT_MIN_H, FLOAT_MIN_W, SNAP_X,
  keepOnScreen, loadPanel, savePanel,
} from '../lib/panel';

// Openers worth a click: each one is answerable from the scan's own results, so the assistant is
// never invited to speculate. The undecided one is deliberate -it is the question this tool answers
// differently from every checklist script.
const OPENERS = [
  'What should I fix first?',
  'Why are some checks undecided?',
  'Explain the critical findings.',
];

/** Pointer drags, as one hook: press, move, release, with the pointer captured so a fast drag
 *  cannot escape the element and leave the panel stuck to the cursor. */
function useDrag(onMove, onEnd) {
  const from = useRef(null);
  const move = useCallback((e) => {
    if (!from.current) return;
    onMove(e.clientX - from.current.x, e.clientY - from.current.y, from.current.start, e);
  }, [onMove]);

  const stop = useCallback(() => {
    if (!from.current) return;
    from.current = null;
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', stop);
    onEnd?.();
  }, [move, onEnd]);

  return (e, start) => {
    e.preventDefault();
    from.current = { x: e.clientX, y: e.clientY, start };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', stop);
  };
}

export default function Assistant({ scan, open, onToggle, panel, onPanel }) {
  const [turns, setTurns] = useState([]);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [aiAvailable, setAiAvailable] = useState(null);
  // true while a floating panel is dragged near the rail: the dock lights up and release returns it
  const [willDock, setWillDock] = useState(false);
  const endRef = useRef(null);
  const scanId = scan?.scan_id;
  const floating = panel.mode === 'floating';

  useEffect(() => {
    apiClient.getAssistantStatus().then((s) => setAiAvailable(s.ai_available)).catch(() => setAiAvailable(false));
  }, []);

  // A conversation belongs to the scan it was about
  useEffect(() => { setTurns([]); setDraft(''); }, [scanId]);

  // optional call: scrolling is a convenience, and an environment without it must not break the panel
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: 'end' }); }, [turns, busy]);

  // A window that shrank must not strand a floating panel where it cannot be grabbed
  useEffect(() => {
    if (!floating) return undefined;
    const onResize = () => onPanel((p) => keepOnScreen(p, window.innerWidth, window.innerHeight));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [floating, onPanel]);

  const startResizeRail = useDrag(
    (dx, _dy, start) => onPanel((p) => ({
      ...p, width: Math.min(DOCK_MAX, Math.max(DOCK_MIN, start + dx)),
    })),
  );

  const startMove = useDrag(
    (dx, dy, start, e) => {
      setWillDock(e.clientX < SNAP_X);
      onPanel((p) => ({ ...p, x: start.x + dx, y: Math.max(0, start.y + dy) }));
    },
    () => {
      // released over the rail: go home rather than leave a panel hanging off the edge
      setWillDock((near) => {
        if (near) onPanel((p) => ({ ...p, mode: 'docked' }));
        return false;
      });
    },
  );

  const startResizeFloat = useDrag(
    (dx, dy, start) => onPanel((p) => ({
      ...p,
      w: Math.max(FLOAT_MIN_W, start.w + dx),
      h: Math.max(FLOAT_MIN_H, start.h + dy),
    })),
  );

  const ask = async (text) => {
    const question = (text ?? draft).trim();
    if (!question || busy || !scanId) return;
    setDraft('');
    const history = turns.filter((t) => t.role !== 'error').map((t) => ({ role: t.role, content: t.content }));
    setTurns((prev) => [...prev, { role: 'you', content: question }]);
    setBusy(true);
    try {
      const res = await apiClient.chat(scanId, question, history);
      setTurns((prev) => [...prev, { role: 'assistant', content: res.response }]);
    } catch (err) {
      setTurns((prev) => [...prev, { role: 'error', content: err.message }]);
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <div className="chat-rail">
        <button type="button" className="chat-open" onClick={onToggle}
                disabled={!scanId} title={scanId ? 'Ask about this scan' : 'Run a scan first'}>
          <span aria-hidden="true">✦</span> Ask about this scan
        </button>
      </div>
    );
  }

  const body = (
    <>
      <header className={`chat-head${floating ? ' chat-grab' : ''}`}
              onPointerDown={floating ? (e) => {
                if (e.target.closest('button')) return;      // the buttons are not a drag handle
                startMove(e, { x: panel.x, y: panel.y });
              } : undefined}>
        <p className="eyebrow">Assistant</p>
        <span className="chat-head-actions">
          <button type="button" className="btn-link small"
                  onClick={() => onPanel((p) => ({ ...p, mode: floating ? 'docked' : 'floating' }))}>
            {floating ? 'Dock' : 'Pop out'}
          </button>
          <button type="button" className="btn-link small" onClick={onToggle}>Close</button>
        </span>
      </header>

      {!scanId ? (
        <p className="chat-empty small muted">Run a scan first -the assistant answers from its results.</p>
      ) : (
        <>
          <div className="chat-log">
            {turns.length === 0 && (
              <div className="chat-intro">
                <p className="small muted">
                  Answers come from this scan's own results, which are redacted before they are sent.
                  {aiAvailable === false && ' AI is not configured on this backend, so it cannot answer yet.'}
                </p>
                {aiAvailable !== false && OPENERS.map((q) => (
                  <button type="button" key={q} className="chat-opener" onClick={() => ask(q)}>{q}</button>
                ))}
              </div>
            )}
            {turns.map((t, i) => (
              <div key={i} className={`chat-turn chat-${t.role}`}>
                <span className="chat-who">
                  {t.role === 'you' ? 'You' : t.role === 'error' ? 'Failed' : 'NetAuditAI'}
                </span>
                {t.role === 'assistant' ? <Markdown text={t.content} /> : <p className="md-p">{t.content}</p>}
              </div>
            ))}
            {busy && (
              <div className="chat-turn chat-assistant chat-wait">
                <span className="chat-who">NetAuditAI</span><p className="md-p">Thinking…</p>
              </div>
            )}
            <div ref={endRef} />
          </div>

          <form className="chat-form" onSubmit={(e) => { e.preventDefault(); ask(); }}>
            <label className="visually-hidden" htmlFor="chat-input">Ask about this scan</label>
            <textarea
              id="chat-input" className="input chat-input" rows={2} value={draft}
              placeholder="Ask about a finding, a check, or what to fix first"
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); ask(); } }}
            />
            <button type="submit" className="btn btn-accent btn-sm" disabled={!draft.trim() || busy}>Send</button>
          </form>
        </>
      )}
    </>
  );

  if (floating) {
    return (
      <>
        {/* the empty dock, shown only while dragging, so "let go here to put it back" is visible */}
        <div className={`chat-dock-hint${willDock ? ' is-live' : ''}`} aria-hidden="true">
          <span>Release to dock</span>
        </div>
        <section className="chat chat-float" aria-label="Assistant"
                 style={{ left: panel.x, top: panel.y, width: panel.w, height: panel.h }}>
          {body}
          <span className="chat-resize-corner" role="separator" aria-label="Resize assistant"
                onPointerDown={(e) => startResizeFloat(e, { w: panel.w, h: panel.h })} />
        </section>
      </>
    );
  }

  return (
    <section className="chat" aria-label="Assistant">
      {body}
      <span
        className="chat-resize" role="separator" aria-orientation="vertical" tabIndex={0}
        aria-label="Resize assistant panel" aria-valuenow={panel.width}
        aria-valuemin={DOCK_MIN} aria-valuemax={DOCK_MAX}
        onPointerDown={(e) => startResizeRail(e, panel.width)}
        onKeyDown={(e) => {
          // a drag handle nobody can reach by keyboard is a handle half the users do not have
          const step = e.shiftKey ? 48 : 16;
          if (e.key === 'ArrowLeft') { e.preventDefault(); onPanel((p) => ({ ...p, width: Math.max(DOCK_MIN, p.width - step) })); }
          if (e.key === 'ArrowRight') { e.preventDefault(); onPanel((p) => ({ ...p, width: Math.min(DOCK_MAX, p.width + step) })); }
        }}
      />
    </section>
  );
}

export { loadPanel, savePanel };
