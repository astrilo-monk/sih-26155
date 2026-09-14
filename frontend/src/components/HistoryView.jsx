import { useState, useEffect } from 'react';
import { Trash2 } from 'lucide-react';
import { apiClient } from '../api/client';
import { getScanHistory, clearScanHistory, markScansExpired } from '../utils/history';

function postureColor(posture) {
  if (posture == null) return 'var(--text-tertiary)';
  if (posture < 40) return 'var(--critical)';
  if (posture < 70) return 'var(--high)';
  if (posture < 90) return 'var(--medium)';
  return 'var(--success)';
}

// Scan results live in backend memory: each entry is checked, and one the backend no longer holds is
// marked expired and cannot be reopened (its configuration has to be uploaded again).
export default function HistoryView({ onSelectHistoryEntry, onScansExpired }) {
  const [history, setHistory] = useState([]);
  const [unreachable, setUnreachable] = useState(false);

  useEffect(() => {
    let active = true;
    const entries = getScanHistory();
    setHistory(entries);
    const live = entries.filter((e) => e.id && !e.expired);
    if (live.length > 0) {
      Promise.all(live.map((e) => apiClient.isScanHeld(e.id).then((held) => [e.id, held])))
        .then((checks) => {
          const gone = checks.filter(([, held]) => !held).map(([id]) => id);
          if (gone.length > 0) {
            markScansExpired(gone);
            onScansExpired?.(gone);
          }
          if (active) setHistory(getScanHistory());
        })
        .catch(() => { if (active) setUnreachable(true); });
    }
    return () => { active = false; };
  }, []);

  const handleClear = () => {
    if (confirm('Clear all scan history? This cannot be undone.')) {
      clearScanHistory();
      setHistory([]);
    }
  };

  const handleOpen = async (entry) => {
    if (entry.expired) return;
    await onSelectHistoryEntry(entry.id);
    setHistory(getScanHistory());
  };

  if (history.length === 0) {
    return (
      <div className="posture-section">
        <div className="section-header">
          <span>Scan History</span>
        </div>
        <div className="empty-state">
          No scans yet — run a scan to see it here.
        </div>
      </div>
    );
  }

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Scan History</span>
        <span>{history.length} {history.length === 1 ? 'Scan' : 'Scans'}</span>
      </div>

      <div className="filter-bar" style={{ justifyContent: 'space-between' }}>
        <span style={{ fontSize: '0.75rem', color: unreachable ? 'var(--critical)' : 'var(--text-tertiary)' }}>
          {unreachable
            ? 'The backend could not be reached, so it is unknown which scans it still holds.'
            : 'Summaries are kept in this browser. Full results stay on the backend only until it restarts; expired scans must be uploaded again.'}
        </span>
        <button
          onClick={handleClear}
          style={{
            display: 'flex', alignItems: 'center', gap: '0.375rem',
            background: 'none', border: '1px solid var(--border)',
            color: 'var(--text-secondary)', padding: '0.375rem 0.75rem',
            borderRadius: 'var(--radius)', cursor: 'pointer', fontSize: '0.75rem',
          }}
        >
          <Trash2 size={14} />
          Clear History
        </button>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Devices</th>
              <th>Vendor</th>
              <th>Posture</th>
              <th>Coverage</th>
              <th>Findings</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {history.map((entry, i) => (
              <tr
                key={entry.id || i}
                className={entry.expired ? '' : 'clickable'}
                style={entry.expired ? { opacity: 0.55, cursor: 'not-allowed' } : undefined}
                title={entry.expired ? 'No longer held by the backend: upload the configuration again' : 'Open this scan'}
                onClick={() => handleOpen(entry)}
              >
                <td style={{ color: 'var(--text-secondary)' }}>
                  {new Date(entry.timestamp).toLocaleString()}
                </td>
                <td className="mono">{(entry.hostnames || []).join(', ') || '—'}</td>
                <td>{(entry.vendors || []).join(', ') || 'unknown'}</td>
                <td className="mono" style={{ color: postureColor(entry.posture), fontWeight: 600 }}>
                  {entry.posture ?? '—'}
                </td>
                <td className="mono">{entry.coverage ?? 0}%</td>
                <td className="mono">{entry.findingsCount}</td>
                <td>
                  <span className={`badge ${entry.expired ? 'neutral' : 'low'}`}>
                    {entry.expired ? 'Expired' : unreachable ? 'Unchecked' : 'Available'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
