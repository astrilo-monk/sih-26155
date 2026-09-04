// Verify intentionally omitted here until all remediation templates are confirmed safe — see remediation-fix branch.
import { useState } from 'react';
import { Copy, CheckCircle2, Wrench, Loader, ChevronDown, ChevronRight } from 'lucide-react';
import { apiClient } from '../api/client';

// --- Enhancement 1: Severity group definitions ---
const SEVERITY_GROUPS = [
  { key: 'critical', label: 'Fix Now', severity: 'critical' },
  { key: 'high',     label: 'Fix Soon', severity: 'high' },
];

export default function RemediationQueue({ scanResult }) {
  const [expanded, setExpanded] = useState({}); // { [rowKey]: { loading, error, data } }
  const [copiedKey, setCopiedKey] = useState(null);

  // --- Enhancement 1: Collapsible section state ---
  const [collapsed, setCollapsed] = useState({}); // { [groupKey]: true }

  if (!scanResult) return null;

  // Filter to Critical and High only
  const actionable = (scanResult.findings || [])
    .filter(f => f.severity === 'critical' || f.severity === 'high');

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

  // --- Enhancement 1: Group findings by severity ---
  const grouped = {};
  for (const g of SEVERITY_GROUPS) {
    grouped[g.key] = actionable.filter(f => f.severity === g.severity);
  }

  // --- Enhancement 2: Collect unique devices that have at least one generated fix ---
  const devicesWithFixes = () => {
    const deviceMap = {};
    for (const f of actionable) {
      const device = f.device_hostname || 'unknown';
      if (!deviceMap[device]) deviceMap[device] = [];
      // Walk all expanded entries to find generated fixes for this device
      for (const [rk, state] of Object.entries(expanded)) {
        if (state?.data && rk.endsWith(`-${f.device_hostname}-${actionable.indexOf(f)}`)) {
          // Match by checking the key starts with the rule_id and device
        }
      }
    }
    // Simpler approach: iterate expanded entries directly
    const result = {};
    for (const [key, state] of Object.entries(expanded)) {
      if (!state?.data?.remediation_commands) continue;
      // Find the finding that produced this key
      for (let i = 0; i < actionable.length; i++) {
        if (makeKey(actionable[i], i) === key) {
          const device = actionable[i].device_hostname || 'unknown';
          if (!result[device]) result[device] = [];
          result[device].push({
            rule_id: actionable[i].rule_id,
            title: actionable[i].title,
            commands: state.data.remediation_commands,
          });
          break;
        }
      }
    }
    return result;
  };

  const handleCopyAllForDevice = (device) => {
    const fixes = devicesWithFixes()[device];
    if (!fixes || fixes.length === 0) return;
    const script = fixes
      .map(fix => `! Fix for ${fix.rule_id}: ${fix.title}\n${fix.commands}`)
      .join('\n\n');
    handleCopy(script, `device-all-${device}`);
  };

  const deviceFixMap = devicesWithFixes();
  const devicesReady = Object.keys(deviceFixMap);

  // --- Enhancement 1: Toggle section collapse ---
  const toggleSection = (groupKey) => {
    setCollapsed(prev => ({ ...prev, [groupKey]: !prev[groupKey] }));
  };

  // --- Render a single finding row ---
  const renderRow = (f, i) => {
    const key = makeKey(f, i);
    const state = expanded[key];
    // Enhancement 3: check if fix is ready (generated successfully)
    const fixReady = state?.data && !state?.loading && !state?.error;

    return (
      <tr key={key}>
        <td colSpan="5" style={{ padding: 0 }}>
          {/* Main row */}
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
            <div style={{ padding: '0.75rem 1rem', width: '160px', flexShrink: 0, textAlign: 'right', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.5rem' }}>
              {/* Enhancement 3: "Fix ready" indicator */}
              {fixReady && (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem', color: 'var(--success)', fontWeight: 600, letterSpacing: '0.03em' }}>
                  <CheckCircle2 size={12} />
                  Ready
                </span>
              )}
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
  };

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Remediation Queue</span>
        <span>{actionable.length} Actionable</span>
      </div>

      {/* Enhancement 2: Copy All Fixes per device */}
      {devicesReady.length > 0 && (
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
          {devicesReady.map(device => (
            <button
              key={device}
              className="btn-secondary"
              onClick={() => handleCopyAllForDevice(device)}
            >
              {copiedKey === `device-all-${device}` ? <CheckCircle2 size={13} /> : <Copy size={13} />}
              {copiedKey === `device-all-${device}`
                ? 'Copied!'
                : `Copy All Fixes for ${device}`}
              <span className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-tertiary)', marginLeft: '0.25rem' }}>
                ({deviceFixMap[device].length})
              </span>
            </button>
          ))}
        </div>
      )}

      {/* Enhancement 1: Severity-grouped collapsible sections */}
      {SEVERITY_GROUPS.map(group => {
        const items = grouped[group.key];
        if (!items || items.length === 0) return null;
        const isCollapsed = collapsed[group.key];
        // Compute the global index offset so makeKey stays stable
        const globalOffset = group.severity === 'high'
          ? (grouped['critical']?.length || 0)
          : 0;

        return (
          <div key={group.key} style={{ marginBottom: '1.5rem' }}>
            <button
              onClick={() => toggleSection(group.key)}
              style={{
                display: 'flex', alignItems: 'center', gap: '0.5rem',
                width: '100%', padding: '0.5rem 0', background: 'none',
                border: 'none', cursor: 'pointer', textAlign: 'left',
              }}
            >
              {isCollapsed
                ? <ChevronRight size={16} color="var(--text-secondary)" />
                : <ChevronDown size={16} color="var(--text-secondary)" />
              }
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                {group.label}
              </span>
              <span className={`badge ${group.severity}`}>{group.severity}</span>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)' }}>
                {items.length} {items.length === 1 ? 'finding' : 'findings'}
              </span>
            </button>

            {!isCollapsed && (
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
                    {items.map((f, i) => renderRow(f, globalOffset + i))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
