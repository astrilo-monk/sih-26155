import { useState } from 'react';
import { Severity, StatusMark } from '../components/ui/Evidence';
import { checkItems, isProblem, itemState, STATE } from '../lib/domain';

const FILTERS = [
  ['problems', 'Problems', (item) => isProblem(item)],
  ['review', STATE.needs_review.label, (item, state) => state === 'needs_review'],
  ['unknown', STATE.unknown.label, (item, state) => state === 'unknown'],
  ['nc', STATE.not_configured.label, (item, state) => state === 'not_configured'],
  ['pass', STATE.pass.label, (item, state) => state === 'pass'],
  ['all', 'All', () => true],
];

// Every check against every configuration — the complete evidence view behind the overview
export default function Checks({ scan, audit, labels, onOpen }) {
  const items = checkItems(scan, audit.plan).map((item) => ({ item, state: itemState(item, audit.applied) }));
  const [filter, setFilter] = useState(() => (items.some(({ item }) => isProblem(item)) ? 'problems' : 'all'));
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();
  const base = items.filter(({ item }) => !q || [item.controlId, item.title, item.question, labels[item.configIndex]]
    .some((v) => (v || '').toLowerCase().includes(q)));
  const test = FILTERS.find(([id]) => id === filter)[2];
  const shown = base.filter(({ item, state }) => test(item, state));

  return (
    <div className="wrap checks-page enter">
      <header className="page-head">
        <p className="eyebrow">All checks</p>
        <h1 className="page-title">Every check, with its evidence</h1>
        <p className="lede">NetAuditAI runs every check against every configuration. Open one to see the lines behind it.</p>
      </header>
      <div className="toolbar">
        <div className="segmented" role="group" aria-label="Filter checks">
          {FILTERS.map(([id, label, pred]) => (
            <button key={id} type="button" className="seg-btn" aria-pressed={filter === id} onClick={() => setFilter(id)}>
              {label} <span className="seg-n tnum">{base.filter(({ item, state }) => pred(item, state)).length}</span>
            </button>
          ))}
        </div>
        <input className="input" type="search" placeholder="Search checks" aria-label="Search checks" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      {shown.length === 0 ? (
        <p className="empty-inline">{items.length === 0 ? 'This scan has no checks to show.' : 'No check matches this filter.'}</p>
      ) : (
        <ul className="check-list" aria-label="Checks">
          {shown.map(({ item, state }) => (
            <li key={item.key}>
              <button type="button" className="check-row" onClick={() => onOpen(item)}>
                <StatusMark state={state} size="compact" />
                <span className="check-row-main">
                  <span className="check-row-title">{item.title}</span>
                  <span className="small muted">{labels.length > 1 && `${labels[item.configIndex]} · `}{item.question}</span>
                </span>
                {isProblem(item) && <Severity level={item.severity} />}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
