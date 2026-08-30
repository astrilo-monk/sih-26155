import { useState } from 'react';
import { Search, Filter } from 'lucide-react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

export default function FindingsTable({ findings, onSelectFinding }) {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('severity');

  const filtered = findings.filter(f => {
    const matchesSev = filter === 'all' || f.severity === filter;
    const matchesSearch = search === '' || 
      f.title.toLowerCase().includes(search.toLowerCase()) || 
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      (f.device_hostname && f.device_hostname.toLowerCase().includes(search.toLowerCase()));
    return matchesSev && matchesSearch;
  });

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
        <h2>
          Security Findings 
          <span className="findings-count">{filtered.length}</span>
        </h2>
        <div className="table-controls">
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={14} color="var(--text-tertiary)" style={{ position: 'absolute', left: '0.5rem' }} />
            <input 
              type="text" 
              placeholder="Search findings..." 
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="filter-select"
              style={{ paddingLeft: '1.75rem', width: '200px' }}
            />
          </div>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Filter size={14} color="var(--text-tertiary)" style={{ position: 'absolute', left: '0.5rem', pointerEvents: 'none' }} />
            <select
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="filter-select"
              style={{ paddingLeft: '1.75rem', cursor: 'pointer' }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('rule_id')}>Rule</th>
              <th>Finding</th>
              <th>Device</th>
              <th style={{ cursor: 'pointer' }} onClick={() => setSortBy('category')}>Category</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f, i) => (
              <tr key={`${f.rule_id}-${f.device_hostname}-${i}`} onClick={() => onSelectFinding(f)}>
                <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
                <td className="mono">{f.rule_id}</td>
                <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{f.title}</td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>{f.device_hostname}</td>
                <td>
                  <span style={{ 
                    fontSize: '0.75rem', 
                    color: 'var(--text-secondary)',
                    backgroundColor: 'var(--bg-dark)',
                    padding: '0.125rem 0.375rem',
                    borderRadius: '4px',
                    border: '1px solid var(--border)'
                  }}>
                    {f.category || 'General'}
                  </span>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', color: 'var(--text-tertiary)', padding: '3rem' }}>
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
