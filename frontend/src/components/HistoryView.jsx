import { useState, useEffect } from 'react';
import { Trash2 } from 'lucide-react';
import { getScanHistory, clearScanHistory } from '../utils/history';

function postureColor(posture) {
  if (posture == null) return 'var(--text-tertiary)';
  if (posture < 40) return 'var(--critical)';
  if (posture < 70) return 'var(--high)';
  if (posture < 90) return 'var(--medium)';
  return 'var(--success)';
}

export default function HistoryView({ onSelectHistoryEntry }) {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    setHistory(getScanHistory());
  }, []);

  const handleClear = () => {
    if (confirm('Clear all scan history? This cannot be undone.')) {
      clearScanHistory();
      setHistory([]);
    }
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
        <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
          Summaries are kept in this browser. Full results stay on the backend only until it restarts.
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
            </tr>
          </thead>
          <tbody>
            {history.map((entry, i) => (
              <tr
                key={entry.id || i}
                className="clickable"
                onClick={() => onSelectHistoryEntry(entry.id)}
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
