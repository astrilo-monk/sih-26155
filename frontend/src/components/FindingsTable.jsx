import { useState } from 'react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function FindingsTable({ findings, onSelectFinding }) {
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('severity');

  const filtered = findings.filter(f =>
    filter === 'all' || f.severity === filter
  );

  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'severity') {
      return (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    }
    if (sortBy === 'rule_id') return a.rule_id.localeCompare(b.rule_id);
    if (sortBy === 'category') return (a.category || '').localeCompare(b.category || '');
    return 0;
  });

  return (
    <div className="findings-container">
      <div className="findings-header">
        <h2>Security Findings ({filtered.length})</h2>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <select
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{
              background: 'var(--surface-hover)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border)',
              borderRadius: '0.375rem',
              padding: '0.375rem 0.75rem',
              fontSize: '0.875rem',
            }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>Finding</th>
            <th>Device</th>
            <th>Category</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f, i) => (
            <tr key={`${f.rule_id}-${f.device_hostname}-${i}`} onClick={() => onSelectFinding(f)}>
              <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}>{f.rule_id}</td>
              <td>{f.title}</td>
              <td style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>{f.device_hostname}</td>
              <td style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>{f.category}</td>
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>
                No findings match the selected filter.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
