import { parseUnifiedDiff } from '../../lib/domain';

// Adapted from 21st.dev "File Diff" (@kvnkld): the header with file name and +/- counts and the old/new
// line-number gutters are kept. Rows now come from the backend's deterministic unified diff (hunk headers give
// real line numbers) instead of hardcoded demo rows. Text is rendered as-is: the backend has already redacted it.
export default function FileDiff({ diff, file = 'configuration', caption }) {
  const rows = parseUnifiedDiff(diff);
  const added = rows.filter((r) => r.type === 'add').length;
  const removed = rows.filter((r) => r.type === 'del').length;
  return (
    <figure className="diff">
      <figcaption className="diff-head">
        <span className="diff-file">{file}</span>
        {caption && <span className="diff-caption">{caption}</span>}
        <span className="diff-stat" aria-label={`${added} added, ${removed} removed`}>
          <span className="add">+{added}</span>
          <span className="del">−{removed}</span>
        </span>
      </figcaption>
      <div className="diff-body">
        {rows.map((r, i) => (
          <div key={i} className={`diff-row ${r.type}`} style={{ '--r': Math.min(i, 14) }}>
            <span className="ln" aria-hidden="true">{r.old ?? ''}</span>
            <span className="ln" aria-hidden="true">{r.cur ?? ''}</span>
            <span className="sign" aria-label={r.type === 'add' ? 'added' : r.type === 'del' ? 'removed' : undefined}>
              {r.type === 'add' ? '+' : r.type === 'del' ? '−' : ''}
            </span>
            <code>{r.text}</code>
          </div>
        ))}
      </div>
    </figure>
  );
}
