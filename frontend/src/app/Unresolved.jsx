import { Evidence, Severity, StatusMark } from '../components/ui/Evidence';
import { Notice } from '../components/ui/primitives';
import { sayFact, statusState } from '../lib/domain';

// The resolution queue: the checks NetAuditAI could not decide, and what would let it decide them.
// These are exactly the checks coverage left out -listing one here never counts it as passed or failed.

export function UnresolvedRow({ item, label, onTeach, index }) {
  const teachable = item.action === 'teach';
  const suggested = item.suggested_lines || [];
  const read = suggested.find((line) => line.predicate);
  return (
    <li className="problem-li" style={{ '--i': index }}>
      <button
        type="button"
        className="problem is-question"
        disabled={!teachable}
        onClick={teachable ? () => onTeach(`${item.config_index}-${item.control_id}`) : undefined}
      >
        <span className="problem-main">
          <span className="problem-title">{item.title}</span>
          <span className="problem-meta">
            <span className="mono">{item.control_id}</span>
            {label && <span className="mono">{label}</span>}
            <Severity level={item.severity} />
            <StatusMark state={statusState(item.status)} size="compact" />
          </span>
          <span className="problem-why">{item.reason}</span>
          {teachable && suggested.length > 0 && (
            <span className="problem-where">
              {suggested.length === 1 ? '1 line' : `${suggested.length} lines`} in this configuration may answer it
              {read && sayFact(read) ? ` -we read one as “it ${sayFact(read)}”` : ''}
            </span>
          )}
          {teachable && suggested.length === 0 && (
            <span className="problem-where">Nothing here mentions this setting -point NetAuditAI at the line that does.</span>
          )}
          {!teachable && <span className="problem-where">{item.blocked_reason}</span>}
        </span>
        <span className={`problem-action tone-${teachable ? 'review' : 'muted'}`}>{teachable ? 'Resolve' : 'Can’t teach'}</span>
      </button>
    </li>
  );
}

export default function UnresolvedList({ items, loading, error, onRetry, labels, fallback = [], onOpen, onTeach }) {
  if (error) {
    return (
      <section className="undecided" aria-labelledby="undecided-title">
        <h2 className="section-title" id="undecided-title">Checks we couldn’t decide</h2>
        <Notice kind="danger" label="Couldn’t load" role="alert"
          action={onRetry && <button type="button" className="btn btn-sm" onClick={onRetry}>Try again</button>}>
          <strong>What these checks need couldn’t be loaded.</strong>
          <span>{error}</span>
        </Notice>
        {/* the scan itself still says which checks are undecided, so they are never hidden */}
        <ul className="check-list">
          {fallback.map((item) => (
            <li key={item.key}>
              <button type="button" className="check-row" onClick={() => onOpen(item)}>
                <StatusMark state={statusState(item.primary.status)} size="compact" />
                <span className="check-row-main"><span className="check-row-title">{item.title}</span></span>
              </button>
            </li>
          ))}
        </ul>
      </section>
    );
  }

  if (loading) {
    return (
      <section className="undecided" aria-labelledby="undecided-title" aria-busy="true">
        <h2 className="section-title" id="undecided-title">Checks we couldn’t decide</h2>
        <p className="muted">Working out what each one needs…</p>
      </section>
    );
  }

  if (!items || items.length === 0) return null;

  const resolvable = items.filter((i) => i.action === 'teach');
  const blocked = items.filter((i) => i.action !== 'teach');

  return (
    <section className="undecided" aria-labelledby="undecided-title">
      <h2 className="section-title" id="undecided-title">
        {resolvable.length > 0
          ? <>{resolvable.length === 1 ? '1 check needs' : `${resolvable.length} checks need`} your input to complete this assessment</>
          : <>Checks we couldn’t decide</>}
        <span className="count-pill tnum">{items.length}</span>
      </h2>
      <p className="small muted">
        NetAuditAI has no evidence for these, so they are never counted as passed or failed. Show it which
        configuration line answers one and it re-checks the same configuration -the file itself is never changed.
      </p>
      <ul className="problem-list">
        {resolvable.map((item, i) => (
          <UnresolvedRow key={`${item.config_index}-${item.control_id}`} index={i} item={item}
            label={labels ? labels[item.config_index] : null} onTeach={onTeach} />
        ))}
      </ul>
      {blocked.length > 0 && (
        <>
          <h3 className="section-subtitle">Can’t be resolved here <span className="count-pill tnum">{blocked.length}</span></h3>
          <ul className="check-list">
            {blocked.map((item) => (
              <li key={`${item.config_index}-${item.control_id}`}>
                <div className="check-row is-static">
                  <StatusMark state={statusState(item.status)} size="compact" />
                  <span className="check-row-main">
                    <span className="check-row-title">{item.title}</span>
                    <span className="small muted">{item.blocked_reason || item.reason}</span>
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

// One unresolved check, in full: the question, why it is undecided, and what NetAuditAI did cite
export function UnresolvedDetail({ item }) {
  return (
    <div className="unresolved-detail">
      <dl className="kv">
        <dt>Check</dt><dd><span className="mono">{item.control_id}</span> {item.question}</dd>
        <dt>Result</dt><dd><StatusMark state={statusState(item.status)} size="compact" /> {item.reason}</dd>
      </dl>
      {item.evidence?.length > 0 && (
        <>
          <p className="small muted">What NetAuditAI did find:</p>
          <Evidence lineNumbers={item.evidence_lines} lines={item.evidence} />
        </>
      )}
    </div>
  );
}
