import { useEffect, useRef } from 'react';

// Side panel for one item. Escape and the backdrop close it; focus moves in on open and back to the opener on close.
export default function Drawer({ open, title, label, onClose, children }) {
  const panel = useRef(null);
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    if (!open) return undefined;
    const opener = document.activeElement;
    panel.current?.focus();
    const onKey = (e) => { if (e.key === 'Escape') close.current(); };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      opener?.focus?.();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="drawer-root">
      <div className="drawer-backdrop" onClick={() => close.current()} aria-hidden="true" />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={label} tabIndex={-1} ref={panel}>
        <header className="drawer-head">
          <div className="drawer-title">{title}</div>
          <button type="button" className="icon-btn" onClick={() => close.current()} aria-label="Close">×</button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}
