import { useState, useEffect } from 'react';
import { Trash2 } from 'lucide-react';
import { getScanHistory, clearScanHistory } from '../utils/history';

function getScoreColor(score) {
  if (score < 40) return 'var(--critical)';
  if (score < 70) return 'var(--high)';
  if (score < 90) return 'var(--medium)';
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

      <div className="filter-bar" style={{ justifyContent: 'flex-end' }}>
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
              <th>Hostname</th>
              <th>Vendor</th>
              <th>Score</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {history.map((entry, i) => (
              <tr
                key={entry.id || i}
                className="clickable"
                onClick={() => onSelectHistoryEntry(entry.fullResult)}
              >
                <td style={{ color: 'var(--text-secondary)' }}>
                  {new Date(entry.timestamp).toLocaleString()}
                </td>
                <td className="mono">{entry.hostname || '—'}</td>
                <td>{entry.vendor || 'Unknown'}</td>
                <td
                  className="mono"
                  style={{ color: getScoreColor(entry.score), fontWeight: 600 }}
                >
                  {entry.score ?? '—'}
                </td>
                <td className="mono">{entry.findingsCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
