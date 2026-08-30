import { useState } from 'react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function FindingsTable({ findings, onSelectFinding }) {
  const [filterSev, setFilterSev] = useState('all');
  const [search, setSearch] = useState('');

  const filtered = findings.filter(f => {
    const matchesSev = filterSev === 'all' || f.severity === filterSev;
    const matchesSearch = search === '' || 
      f.title.toLowerCase().includes(search.toLowerCase()) || 
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      (f.device_hostname && f.device_hostname.toLowerCase().includes(search.toLowerCase()));
    return matchesSev && matchesSearch;
  });

  const sorted = [...filtered].sort((a, b) => {
    return (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
  });

  if (findings.length === 0) {
    return (
      <div className="posture-section">
        <div className="section-header">
          <span>Security Findings</span>
        </div>
        <div className="empty-state">
          No security findings detected.
        </div>
      </div>
    );
  }

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Security Findings</span>
        <span>{filtered.length} Findings</span>
      </div>

      <div className="filter-bar">
        <input 
          type="text" 
          placeholder="Search findings, rules, devices..." 
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="filter-input"
          style={{ width: '300px' }}
        />
        <select
          value={filterSev}
          onChange={e => setFilterSev(e.target.value)}
          className="filter-input"
        >
          <option value="all">Severity: All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="data-table-container">
        <table className="data-table">
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
              <tr key={`${f.rule_id}-${f.device_hostname}-${i}`} className="clickable" onClick={() => onSelectFinding(f)}>
                <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>{f.rule_id}</td>
                <td>
                  <div className="finding-title-cell">
                    <span className="strong">{f.title}</span>
                    <span className="finding-desc-preview">{f.description}</span>
                  </div>
                </td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>{f.device_hostname}</td>
                <td>
                  <span className="badge neutral">{f.category || 'General'}</span>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-tertiary)' }}>
                  No findings match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
