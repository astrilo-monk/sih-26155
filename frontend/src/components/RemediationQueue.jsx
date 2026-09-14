import { Fragment, useEffect, useRef, useState } from 'react';
import { Download, Loader, RefreshCw } from 'lucide-react';
import { apiClient } from '../api/client';
import BeforeAfter from './BeforeAfter';
import { REMEDIATION_GROUPS, RemediationDetail, StatusBadge } from './RemediationView';

const GROUP_ORDER = ['Fixed', 'Proposed', 'Requires human review', 'Unable to remediate', 'Unverified vendor'];

const filled = (values) => Object.fromEntries(Object.entries(values).filter(([, v]) => v !== '' && v != null));

export function sameInputs(a, b) {
  const x = filled(a);
  const y = filled(b);
  return Object.keys(x).length === Object.keys(y).length && Object.keys(x).every((k) => x[k] === y[k]);
}

export default function RemediationQueue({ scanResult, onScanExpired }) {
  const [plan, setPlan] = useState(null);
  const [inputs, setInputs] = useState({});
  // The inputs the displayed plan was generated (and verified) with: the only inputs a download may use
  const [planInputs, setPlanInputs] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [open, setOpen] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const loadedFor = useRef(null);

  const scanId = scanResult?.scan_id;

  const load = async (values) => {
    setLoading(true);
    setError(null);
    try {
      setPlan(await apiClient.getRemediationPlan(scanId, values));
      setPlanInputs(values);
    } catch (err) {
      if (err.status === 404) onScanExpired?.(scanId);
      else setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Generating a plan regenerates and rescans every fix: once per scan (StrictMode runs effects twice in dev)
    if (!scanId || loadedFor.current === scanId) return;
    loadedFor.current = scanId;
    load({});
  }, [scanId]);

  if (!scanResult) return null;

  const devices = plan?.devices || [];
  const items = devices.flatMap((d) => d.remediations);
  const needed = [...new Set(items.flatMap((r) => (r.status === 'needs_input' ? r.missing_inputs : [])))];
  const shownInputs = (plan?.inputs || []).filter((i) => needed.includes(i.name) || inputs[i.name] || planInputs[i.name]);
  const counts = GROUP_ORDER.map((label) => [label, items.filter((r) => REMEDIATION_GROUPS[r.status]?.label === label).length]);
  const anyFixed = devices.some((d) => d.fixed_config);
  const changed = !sameInputs(inputs, planInputs);

  const handleDownload = async () => {
    if (changed) return;
    setDownloading(true);
    setError(null);
    try {
      await apiClient.downloadFixedConfigs(scanId, planInputs);
    } catch (err) {
      setError(err.message);
    } finally {
      setDownloading(false);
    }
  };

  const hint = changed
    ? 'Values changed since this plan was generated: generate with these values and review the result before downloading.'
    : anyFixed ? 'Only changes that passed the rescan are included. Review before deploying.' : 'No verified fix is available.';

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Remediation</span>
        <span>deterministic · vendor-aware · verified by rescan</span>
      </div>

      {error && <div className="drawer-text" style={{ color: 'var(--critical)', marginBottom: '0.75rem' }}>{error}</div>}
      {loading && !plan && <div className="empty-state"><Loader size={14} /> Generating and verifying fixes…</div>}

      {plan && (
        <>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            {counts.map(([label, n]) => (
              <span key={label} className="badge neutral">{label}: {n}</span>
            ))}
          </div>

          {devices.map((d) => (
            <div key={d.config_index} style={{ marginBottom: '1rem' }}>
              <div className="drawer-section-title">
                #{d.config_index + 1} {d.device_hostname} · {d.vendor} ({d.vendor_status})
                {d.fixed_controls.length > 0 && ` · fixed ${d.fixed_controls.join(', ')}`}
              </div>
              {d.before && <BeforeAfter before={d.before} after={d.after} />}
            </div>
          ))}

          {shownInputs.length > 0 && (
            <form
              onSubmit={(e) => { e.preventDefault(); load(inputs); }}
              style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: '1rem' }}
            >
              {shownInputs.map((spec) => (
                <label key={spec.name} style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', fontSize: '0.75rem' }} title={spec.help}>
                  {spec.label}
                  <input
                    className="filter-input"
                    aria-label={spec.label}
                    type={spec.name === 'ntp_key' ? 'password' : 'text'}
                    // a saved browser password must never be filled into a configuration value unseen
                    autoComplete={spec.name === 'ntp_key' ? 'new-password' : 'off'}
                    name={`remediation-${spec.name}`}
                    value={inputs[spec.name] || ''}
                    placeholder={spec.help}
                    onChange={(e) => setInputs((prev) => ({ ...prev, [spec.name]: e.target.value }))}
                  />
                </label>
              ))}
              <button type="submit" className="btn-secondary" disabled={loading}>
                {loading ? <Loader size={13} /> : <RefreshCw size={13} />} Generate with these values
              </button>
            </form>
          )}

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <button className="btn-primary" onClick={handleDownload} disabled={!anyFixed || downloading || changed}>
              {downloading ? <Loader size={14} /> : <Download size={14} />}
              Download verified configuration
            </button>
            <span style={{ fontSize: '0.75rem', color: changed ? 'var(--medium)' : 'var(--text-tertiary)' }}>{hint}</span>
          </div>

          {items.length === 0 ? (
            <div className="empty-state">No failing controls to remediate.</div>
          ) : (
            <div className="data-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Control</th>
                    <th>Device</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((r) => {
                    const key = `${r.config_index}-${r.rule_id}`;
                    return (
                      <Fragment key={key}>
                        <tr className="clickable" onClick={() => setOpen(open === key ? null : key)}>
                          <td><StatusBadge status={r.status} /></td>
                          <td>
                            <div className="finding-title-cell">
                              <span className="strong">{r.title}</span>
                              <span className="mono" style={{ color: 'var(--text-secondary)' }}>{r.rule_id}</span>
                            </div>
                          </td>
                          <td className="mono">#{r.config_index + 1} {r.device_hostname}</td>
                          <td>{r.reason}</td>
                        </tr>
                        {open === key && (
                          <tr>
                            <td colSpan="4" style={{ padding: '1rem' }}>
                              <RemediationDetail remediation={r} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
