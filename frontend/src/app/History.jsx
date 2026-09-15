import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { clearScanHistory, getScanHistory, markScansExpired } from '../utils/history';
import { navigate } from '../lib/hooks';
import { vendorName } from '../lib/domain';

// Summaries live in this browser; full results live in backend memory until it restarts. Each entry is checked,
// and one the backend no longer holds is marked expired and never reopened.
export default function History({ onScansExpired }) {
  const [history, setHistory] = useState(() => getScanHistory());
  const [checked, setChecked] = useState(false);
  const [unreachable, setUnreachable] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    let active = true;
    const live = getScanHistory().filter((e) => e.id && !e.expired);
    if (live.length === 0) {
      setChecked(true);
      return undefined;
    }
    Promise.all(live.map((e) => apiClient.isScanHeld(e.id).then((held) => [e.id, held])))
      .then((checks) => {
        const gone = checks.filter(([, held]) => !held).map(([id]) => id);
        if (gone.length > 0) {
          markScansExpired(gone);
          onScansExpired?.(gone);
        }
        if (active) {
          setHistory(getScanHistory());
          setChecked(true);
        }
      })
      .catch(() => { if (active) setUnreachable(true); });
    return () => { active = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const open = (entry) => {
    if (entry.expired) return;
    navigate(`/app/scan/${entry.id}`);
  };

  const availability = (entry) => {
    if (entry.expired) return ['Expired', 'tag-blocked', 'No longer held by the backend: upload the configuration again'];
    if (unreachable) return ['Unchecked', 'tag-provisional', 'The backend could not be reached'];
    if (!checked) return ['Checking…', '', ''];
    return ['Available', 'tag-decisive', 'Open this audit'];
  };

  return (
    <div className="wrap history enter">
      <header className="page-head page-head-row">
        <div>
          <p className="eyebrow">History</p>
          <h1 className="display page-title">Previous audits</h1>
          <p className="lede">
            Summaries are kept in this browser — hostnames, posture, coverage and counts, never configuration lines or
            evidence. Full results stay on the backend only until it restarts; expired audits must be uploaded again.
          </p>
        </div>
        {history.length > 0 && (
          <div className="history-clear">
            {confirmClear ? (
              <>
                <span className="small">Clear all history?</span>
                <button type="button" className="btn btn-sm btn-danger" onClick={() => { clearScanHistory(); setHistory([]); setConfirmClear(false); }}>Clear</button>
                <button type="button" className="btn btn-quiet btn-sm" onClick={() => setConfirmClear(false)}>Cancel</button>
              </>
            ) : (
              <button type="button" className="btn btn-sm" onClick={() => setConfirmClear(true)}>Clear history</button>
            )}
          </div>
        )}
      </header>

      {unreachable && (
        <div className="notice notice-warn" role="status">
          <span className="notice-mark">!</span>
          <strong>The backend could not be reached.</strong>
          <span>It is unknown which audits it still holds.</span>
        </div>
      )}

      {history.length === 0 ? (
        <div className="empty">
          <p className="empty-title">No audits yet</p>
          <p>Audits you run in this browser appear here.</p>
          <a className="btn btn-accent" href="#/app">Start an audit</a>
        </div>
      ) : (
        <ul className="history-list">
          <li className="history-row history-header" aria-hidden="true">
            <span>Configurations</span><span>Audited</span><span>Posture</span><span>Coverage</span><span>Problems</span><span>Status</span>
          </li>
          {history.map((entry, i) => {
            const [label, tone, title] = availability(entry);
            return (
              <li key={entry.id || i}>
                <button type="button" className={`history-row ${entry.expired ? 'is-expired' : ''}`}
                        aria-disabled={entry.expired || undefined} title={title} onClick={() => open(entry)}>
                  <span className="hr-devices">
                    <span className="mono hr-hosts">{(entry.hostnames || []).join(', ') || '—'}</span>
                    <span className="small muted">{(entry.vendors || []).map(vendorName).join(', ') || 'Unknown'}</span>
                  </span>
                  <span className="hr-cell"><span className="hr-k">Audited</span>{new Date(entry.timestamp).toLocaleString()}</span>
                  <span className="hr-cell"><span className="hr-k">Posture</span><span className="mono tnum">{entry.posture ?? '—'}</span></span>
                  <span className="hr-cell"><span className="hr-k">Coverage</span><span className="mono tnum">{entry.coverage ?? 0}%</span></span>
                  <span className="hr-cell"><span className="hr-k">Problems</span><span className="mono tnum">{entry.problemsCount ?? entry.findingsCount}</span>{entry.remediated && <span className="tag">Fixed file downloaded</span>}</span>
                  <span className="hr-cell"><span className={`tag ${tone}`}>{label}</span></span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
