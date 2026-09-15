import { stripLineNo, stateMeta } from '../../lib/domain';

// Cited configuration lines with their real line numbers. Only lines the backend returned are shown (it never
// sends the raw configuration, and every quote is already redacted); context rows are shown only when the
// backend supplied them.
export function Evidence({ lineNumbers = [], lines = [], scopePath = [], before = [], after = [], title, empty }) {
  if (lineNumbers.length === 0 && lines.length === 0) {
    return empty ? <p className="evidence-empty">{empty}</p> : null;
  }
  const first = lineNumbers[0];
  return (
    <figure className="evidence">
      <figcaption className="evidence-head">
        <span>{title || (lineNumbers.length > 1 ? `Lines ${lineNumbers.join(', ')}` : `Line ${first}`)}</span>
        {scopePath.length > 0 && <span className="evidence-scope">{scopePath.join(' › ')}</span>}
      </figcaption>
      <div className="evidence-body">
        {before.map((text, i) => (
          <div key={`b${i}`} className="ev-row context">
            <span className="ln">{first - before.length + i}</span><code>{text}</code>
          </div>
        ))}
        {lines.map((text, i) => (
          <div key={`l${i}`} className="ev-row cited" style={{ '--r': Math.min(i, 8) }}>
            <span className="ln">{lineNumbers[i] ?? ''}</span><code>{stripLineNo(text, lineNumbers[i])}</code>
          </div>
        ))}
        {after.map((text, i) => (
          <div key={`a${i}`} className="ev-row context">
            <span className="ln">{(lineNumbers[lineNumbers.length - 1] ?? first) + i + 1}</span><code>{text}</code>
          </div>
        ))}
      </div>
    </figure>
  );
}

// `state` is a key of the one state model (lib/domain STATE): components never pass raw backend statuses
export function StatusMark({ state, children, size }) {
  const m = stateMeta(state);
  return (
    <span className={`status status-${m.tone} ${size || ''}`}>
      <span className="status-glyph" aria-hidden="true">{m.mark}</span>
      <span className="status-word">{children || m.label}</span>
    </span>
  );
}

export function Severity({ level }) {
  return <span className={`sev sev-${level}`}>{level}</span>;
}
