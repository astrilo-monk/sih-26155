// Verify intentionally omitted here until all remediation templates are confirmed safe — see remediation-fix branch.
import { useState } from 'react';
import { Copy, CheckCircle2, Wrench, Loader } from 'lucide-react';
import { apiClient } from '../api/client';

const SEVERITY_ORDER = { critical: 0, high: 1 };

export default function RemediationQueue({ scanResult }) {
  const [expanded, setExpanded] = useState({}); // { [key]: { loading, error, data } }
  const [copiedKey, setCopiedKey] = useState(null);

  if (!scanResult) return null;

  // Filter to Critical and High only, sorted Critical first
  const actionable = (scanResult.findings || [])
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  if (actionable.length === 0) {
    return (
      <div className="posture-section">
        <div className="section-header">
          <span>Remediation Queue</span>
        </div>
        <div className="empty-state">
          No high-priority findings to remediate.
        </div>
      </div>
    );
  }

  const makeKey = (f, i) => `${f.rule_id}-${f.device_hostname}-${i}`;

  const handleGenerateFix = async (finding, key) => {
    setExpanded(prev => ({
      ...prev,
      [key]: { loading: true, error: null, data: null },
    }));

    try {
      const result = await apiClient.getRemediation(
        scanResult.scan_id,
        finding.rule_id,
        finding.device_hostname,
      );
      setExpanded(prev => ({
        ...prev,
        [key]: { loading: false, error: null, data: result },
      }));
    } catch (err) {
      setExpanded(prev => ({
        ...prev,
        [key]: { loading: false, error: err.message, data: null },
      }));
    }
  };

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Remediation Queue</span>
        <span>{actionable.length} Actionable</span>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>Finding</th>
              <th>Device</th>
              <th style={{ textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {actionable.map((f, i) => {
              const key = makeKey(f, i);
              const state = expanded[key];

              return (
                <tr key={key}>
                  <td colSpan="5" style={{ padding: 0 }}>
                    {/* Main row content laid out as an inner table-row-like flex */}
                    <div style={{ display: 'flex', alignItems: 'flex-start', borderBottom: state?.data ? '1px solid var(--border)' : 'none' }}>
                      <div style={{ padding: '0.75rem 1rem', width: '100px', flexShrink: 0 }}>
                        <span className={`badge ${f.severity}`}>{f.severity}</span>
                      </div>
                      <div className="mono" style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)', width: '120px', flexShrink: 0, fontSize: '0.875rem' }}>
                        {f.rule_id}
                      </div>
                      <div style={{ padding: '0.75rem 1rem', flex: 1, fontSize: '0.875rem' }}>
                        <div className="finding-title-cell">
                          <span className="strong">{f.title}</span>
                          <span className="finding-desc-preview">{f.description}</span>
                        </div>
                      </div>
                      <div className="mono" style={{ padding: '0.75rem 1rem', color: 'var(--text-secondary)', width: '140px', flexShrink: 0, fontSize: '0.875rem' }}>
                        {f.device_hostname}
                      </div>
                      <div style={{ padding: '0.75rem 1rem', width: '130px', flexShrink: 0, textAlign: 'right' }}>
                        {!state ? (
                          <button className="btn-primary" onClick={() => handleGenerateFix(f, key)}>
                            <Wrench size={13} />
                            Generate Fix
                          </button>
                        ) : state.loading ? (
                          <button className="btn-primary" disabled>
                            <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} />
                            Loading...
                          </button>
                        ) : (
                          <button className="btn-secondary" onClick={() => setExpanded(prev => { const next = { ...prev }; delete next[key]; return next; })}>
                            Collapse
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Expanded remediation details */}
                    {state?.error && (
                      <div style={{ padding: '0.75rem 1rem', color: 'var(--critical)', fontSize: '0.8125rem' }}>
                        Error: {state.error}
                      </div>
                    )}

                    {state?.data && (
                      <div style={{ padding: '1rem 1rem 1.25rem 1rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '0.5rem' }}>
                          <span className="drawer-section-title" style={{ margin: 0 }}>Remediation Commands</span>
                          <button
                            className="btn-ghost"
                            style={{ padding: 0, fontSize: '0.6875rem' }}
                            onClick={() => handleCopy(state.data.remediation_commands, key)}
                          >
                            {copiedKey === key ? <CheckCircle2 size={12} style={{ marginRight: 4 }} /> : <Copy size={12} style={{ marginRight: 4 }} />}
                            {copiedKey === key ? 'COPIED' : 'COPY'}
                          </button>
                        </div>
                        <div className="config-block">
                          <div className="config-header">
                            <span style={{ color: 'var(--success)' }}>remediation commands</span>
                          </div>
                          <div className="config-body">
                            {state.data.remediation_commands.split('\n').map((line, li) => (
                              <div key={li} className="config-line fix-highlight">
                                <span className="line-num">{li + 1}</span>
                                <span>{line}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                        {state.data.explanation && (
                          <div style={{ marginTop: '0.75rem' }}>
                            <div className="drawer-section-title">Why This Fix</div>
                            <div className="drawer-text">{state.data.explanation}</div>
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
