import { useState } from 'react';
import { PROVISIONAL_ASSURANCE } from './ProvisionalResults';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// A device is its config_index; the hostname is only its label (numbered when two uploads share it)
export function deviceLabels(devices = []) {
  const names = devices.map((d) => d.hostname);
  return names.map((name, i) => (names.filter((n) => n === name).length > 1 ? `${name} (#${i + 1})` : name));
}

export default function FindingsTable({ findings, devices, onSelectFinding }) {
  const [filterSev, setFilterSev] = useState('all');
  const [filterDevice, setFilterDevice] = useState('all');
  const [filterRule, setFilterRule] = useState('all');
  const [search, setSearch] = useState('');

  const labels = deviceLabels(devices);
  const label = (f) => labels[f.config_index ?? 0] ?? f.device_hostname;
  const deviceOptions = [...new Set(findings.map((f) => f.config_index ?? 0))].sort((a, b) => a - b);
  const uniqueRules = [...new Set(findings.map(f => f.rule_id).filter(Boolean))].sort();

  const filtered = findings.filter(f => {
    const matchesSev = filterSev === 'all' || f.severity === filterSev;
    const matchesDevice = filterDevice === 'all' || String(f.config_index ?? 0) === filterDevice;
    const matchesRule = filterRule === 'all' || f.rule_id === filterRule;
    const matchesSearch = search === '' ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      label(f).toLowerCase().includes(search.toLowerCase());
    return matchesSev && matchesDevice && matchesRule && matchesSearch;
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
          aria-label="Severity filter"
        >
          <option value="all">Severity: All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterDevice}
          onChange={e => setFilterDevice(e.target.value)}
          className="filter-input"
          aria-label="Device filter"
          style={{ maxWidth: '200px' }}
        >
          <option value="all">Device: All</option>
          {deviceOptions.map(i => (
            <option key={i} value={String(i)}>{labels[i] ?? `config #${i + 1}`}</option>
          ))}
        </select>
        <select
          value={filterRule}
          onChange={e => setFilterRule(e.target.value)}
          className="filter-input"
          aria-label="Rule filter"
          style={{ maxWidth: '200px' }}
        >
          <option value="all">Rule: All</option>
          {uniqueRules.map(r => (
            <option key={r} value={r}>{r}</option>
          ))}
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
              <tr key={`${f.rule_id}-${f.config_index ?? 0}-${i}`} className="clickable" onClick={() => onSelectFinding(f)}>
                <td>
                  <span className={`badge ${f.severity}`}>{f.severity}</span>
                  {PROVISIONAL_ASSURANCE.has(f.assurance) && (
                    <span className="badge neutral" style={{ marginLeft: '0.25rem' }} title="Provisional: not scored until confirmed">
                      Suspected
                    </span>
                  )}
                </td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>{f.rule_id}</td>
                <td>
                  <div className="finding-title-cell">
                    <span className="strong">{f.title}</span>
                    <span className="finding-desc-preview">{f.description}</span>
                  </div>
                </td>
                <td className="mono" style={{ color: 'var(--text-secondary)' }}>{label(f)}</td>
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
