import { useLayoutEffect, useRef, useState } from 'react';

// Adapted from 21st.dev "Animated Tabs" (@educalvolpz, underline variant): its ARIA tablist, roving tabIndex and
// ArrowLeft/ArrowRight/Home/End keyboard model are kept as-is. The motion/react layoutId indicator and Tailwind
// classes are replaced by a measured CSS transform (this codebase has neither dependency); reduced motion is
// honoured in CSS.
export default function Tabs({ tabs, active, onChange, idBase = 'tabs', label = 'Sections' }) {
  const listRef = useRef(null);
  const [indicator, setIndicator] = useState({ left: 0, width: 0 });

  useLayoutEffect(() => {
    const measure = () => {
      const el = listRef.current?.querySelector('[aria-selected="true"]');
      if (el) setIndicator({ left: el.offsetLeft, width: el.offsetWidth });
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [active, tabs]);

  const onKeyDown = (event, index) => {
    const keys = {
      ArrowRight: (index + 1) % tabs.length,
      ArrowLeft: (index - 1 + tabs.length) % tabs.length,
      Home: 0,
      End: tabs.length - 1,
    };
    if (!(event.key in keys)) return;
    event.preventDefault();
    const next = tabs[keys[event.key]];
    onChange(next.id);
    document.getElementById(`${idBase}-tab-${next.id}`)?.focus();
  };

  return (
    <div className="tabs" role="tablist" aria-label={label} ref={listRef}>
      {tabs.map((tab, index) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            id={`${idBase}-tab-${tab.id}`}
            role="tab"
            type="button"
            aria-selected={selected}
            aria-controls={`${idBase}-panel`}
            tabIndex={selected ? 0 : -1}
            className="tab"
            onClick={() => onChange(tab.id)}
            onKeyDown={(e) => onKeyDown(e, index)}
          >
            <span>{tab.label}</span>
            {tab.count != null && <span className={`tab-count ${tab.attention ? 'attention' : ''}`}>{tab.count}</span>}
          </button>
        );
      })}
      <span className="tab-indicator" aria-hidden="true"
            style={{ transform: `translateX(${indicator.left}px)`, width: indicator.width }} />
    </div>
  );
}
