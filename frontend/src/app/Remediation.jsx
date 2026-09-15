import { Fragment, useEffect, useRef, useState } from 'react';
import { apiClient } from '../api/client';
import FileDiff from '../components/ui/FileDiff';
import { Evidence } from '../components/ui/Evidence';
import Count from '../components/ui/Count';
import { CANNOT_FIX_REASON, deviceLabels, remediationState, sameInputs, stateMeta, vendorName } from '../lib/domain';

const GROUPS = [['can_fix', 'Can fix automatically'], ['needs_input', 'Needs your input'], ['manual', 'Needs manual action']];
const itemMeta = (status) => stateMeta(remediationState(status) || 'not_applicable');
import { markRemediated } from '../utils/history';

const CHECK_NAMES = {
  vendor: 'Vendor',
  parse_coverage: 'Parse coverage',
  target: 'Target control',
  no_regression: 'No regression',
  controls: 'Controls',
};

const fmt = (v, unit) => (v == null ? '—' : `${v}${unit}`);

// Posture and coverage before and after a verified change (never the deprecated score).
// A changed value counts from its real before-value to its real after-value.
export function BeforeAfter({ before, after }) {
  if (!before) return null;
  const next = after ?? before;
  const rows = [
    ['Posture', before.posture, next.posture, ''],
    ['Coverage', before.coverage, next.coverage, '%'],
    ['Critical controls not assessed', before.critical_unassessed.length, next.critical_unassessed.length, ''],
  ];
  return (
    <div className="table-wrap">
      <table className="ba">
        <thead><tr><th scope="col">Measure</th><th scope="col">Before</th><th scope="col">After rescan</th></tr></thead>
        <tbody>
          {rows.map(([label, b, a, unit]) => {
            const changed = a !== b;
            return (
              <tr key={label}>
                <th scope="row">{label}</th>
                <td className="mono tnum">{fmt(b, unit)}</td>
                <td className={`mono tnum ${changed ? 'changed' : ''}`}>
                  {a == null ? '—' : <><Count value={a} from={changed && b != null ? b : a} duration={420} />{unit}</>}
                  {changed && <span className="visually-hidden"> (changed)</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Checks({ checks }) {
  return (
    <ul className="checks">
      {checks.map((c, i) => (
        <li key={c.name} className={c.passed ? 'ok' : 'bad'} style={{ '--c': i }}>
          <span className="check-mark" aria-hidden="true">{c.passed ? '✓' : '×'}</span>
          <span className="visually-hidden">{c.passed ? 'Passed: ' : 'Failed: '}</span>
          <span className="check-name">{CHECK_NAMES[c.name] || c.name}</span>
          <span>{c.detail}</span>
        </li>
      ))}
    </ul>
  );
}

// Current state → proposed deterministic change → verification → rescan
export function RemediationDetail({ remediation: r, onNeedsInput }) {
  const meta = itemMeta(r.status);
  const cited = r.evidence?.line_numbers?.length > 0;
  return (
    <div className="rem-detail">
      <p className="rem-status">
        <span className={`tag rem-tag tone-${meta.tone}`} title={meta.hint}>{meta.label}</span>
        <span>{CANNOT_FIX_REASON[r.status] || r.reason}</span>
      </p>
      {r.explanation && (
        <p className="rem-explain"><span className="eyebrow">Deterministic recipe</span>{r.explanation}</p>
      )}
      {r.warnings?.length > 0 && (
        <div className="notice notice-warn">
          <span className="notice-mark">!</span>
          {r.warnings.map((w) => <span key={w}>{w}</span>)}
        </div>
      )}
      <ol className="rem-flow">
        <li className="rem-step">
          <h4 className="rem-step-head"><span className="sec-no">A</span> Current state</h4>
          {cited ? (
            <Evidence lineNumbers={r.evidence.line_numbers} lines={r.evidence.lines} scopePath={r.evidence.scope_path}
                      title={r.scopes?.length ? `Cited in ${r.scopes.join(', ')}` : undefined} />
          ) : (
            <p className="small muted">No line is cited: the required setting is absent{r.scopes?.length ? ` (${r.scopes.join(', ')})` : ''}.</p>
          )}
        </li>
        <li className="rem-step">
          <h4 className="rem-step-head"><span className="sec-no">B</span> Proposed deterministic change</h4>
          {r.diff ? <FileDiff diff={r.diff} file={r.device_hostname} caption={r.rule_id} />
            : r.status === 'manual_review' ? (
              <p className="small">
                <strong>Why no deterministic change was generated: </strong>{r.reason}.{' '}
                <span className="muted">The finding itself is decisive; apply the fix on the device with the operator decisions it needs.</span>
              </p>
            )
            : <p className="small muted">{r.status === 'needs_input' ? 'Generated once the required values are provided.' : 'No change was generated.'}</p>}
        </li>
        {r.checks?.length > 0 && (
          <li className="rem-step">
            <h4 className="rem-step-head"><span className="sec-no">C</span> Verification rescan</h4>
            <Checks checks={r.checks} />
          </li>
        )}
        {r.before && r.after && (
          <li className="rem-step">
            <h4 className="rem-step-head">
              <span className="sec-no">D</span> After rescan — <span className="mono">{r.rule_id}</span> {r.control_status_before} → {r.control_status_after}
            </h4>
            <BeforeAfter before={r.before} after={r.after} />
          </li>
        )}
      </ol>
      {r.status === 'needs_input' && onNeedsInput && (
        <button type="button" className="btn btn-sm" onClick={onNeedsInput}>Enter values on the Remediation tab</button>
      )}
    </div>
  );
}

export default function Remediation({ scan, planKey, onScanExpired }) {
  const scanId = scan?.scan_id;
  const key = planKey ?? scanId;
  const [plan, setPlan] = useState(null);
  const [inputs, setInputs] = useState({});
  // The inputs the displayed plan was generated (and verified) with: the only inputs a download may use
  const [planInputs, setPlanInputs] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [open, setOpen] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const loadedFor = useRef(null);

  const load = async (values) => {
    setLoading(true);
    setError(null);
    try {
      const next = await apiClient.getRemediationPlan(scanId, values);
      setPlan(next);
      setPlanInputs(values);
      setDownloaded(false);
    } catch (err) {
      if (err.status === 404) onScanExpired?.(scanId);
      else setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Generating a plan regenerates and rescans every fix: once per scan state (StrictMode runs effects twice)
    if (!scanId || loadedFor.current === key) return;
    loadedFor.current = key;
    load(planInputs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  if (!scan) return null;

  const labels = deviceLabels(scan.devices);
  const devices = plan?.devices || [];
  const items = devices.flatMap((d) => d.remediations);
  const needed = [...new Set(items.flatMap((r) => (r.status === 'needs_input' ? r.missing_inputs : [])))];
  const shownInputs = (plan?.inputs || []).filter((i) => needed.includes(i.name) || inputs[i.name] || planInputs[i.name]);
  const counts = GROUPS.map(([group, label]) => [label, items.filter((r) => itemMeta(r.status).group === group).length]);
  const anyFixed = devices.some((d) => d.fixed_config);
  const changed = !sameInputs(inputs, planInputs);

  const handleDownload = async () => {
    if (changed) return;
    setDownloading(true);
    setError(null);
    try {
      await apiClient.downloadFixedConfigs(scanId, planInputs);
      markRemediated(scanId);
      setDownloaded(true);
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
    <div className="rem">
      <header className="panel-head rem-head">
        <h2 className="panel-title">Remediation</h2>
        <ul className="principles" aria-label="Remediation guarantees">
          <li>Deterministic recipes</li>
          <li>Failing settings only</li>
          <li>Confirmed vendors only</li>
          <li>Verified by rescan</li>
          <li>No AI-written commands</li>
        </ul>
      </header>

      {error && <div className="notice notice-danger" role="alert"><span className="notice-mark">×</span><span>{error}</span></div>}
      {loading && !plan && (
        <div className="loading-block" aria-busy="true">
          <div className="scan-bar" aria-hidden="true"><span /></div>
          <p className="muted">Generating fixes and rescanning each one to verify it…</p>
        </div>
      )}

      {plan && (
        <>
          <ul className="rem-counts">
            {counts.map(([group, n]) => (
              <li key={group} aria-label={`${group}: ${n}`} className={n ? '' : 'is-zero'}>
                <span className="rc-n tnum"><Count value={n} /></span><span className="rc-l">{group}</span>
              </li>
            ))}
          </ul>

          <div className="rem-devices">
            {devices.map((d) => (
              <section key={d.config_index} className="rem-device" aria-label={`Plan for ${labels[d.config_index] ?? d.device_hostname}`}>
                <header className="rem-device-head">
                  <span className="mono">#{d.config_index + 1} {labels[d.config_index] ?? d.device_hostname}</span>
                  <span className={`tag ${d.vendor_status === 'confirmed' ? 'tag-decisive' : 'tag-provisional'}`}>
                    {d.vendor_status === 'confirmed' ? `${vendorName(d.vendor)} · confirmed` : `Vendor ${d.vendor_status}`}
                  </span>
                  {d.fixed_controls.length > 0 && <span className="small muted">Verified fixes: <span className="mono">{d.fixed_controls.join(', ')}</span></span>}
                </header>
                {d.before ? <BeforeAfter before={d.before} after={d.after} />
                  : <p className="small muted">No vendor-specific change can be generated for a configuration whose vendor is not confirmed.</p>}
                {d.checks?.length > 0 && <Checks checks={d.checks} />}
              </section>
            ))}
          </div>

          {shownInputs.length > 0 && (
            <form className="rem-inputs" onSubmit={(e) => { e.preventDefault(); load(inputs); }}>
              <div className="rem-inputs-head">
                <h3 className="panel-subtitle">Values some recipes need</h3>
                <p className="small muted">Validated by the backend and written only into fixed templates — never free-form commands.</p>
              </div>
              <div className="rem-input-grid">
                {shownInputs.map((spec) => (
                  <label key={spec.name} className="field">
                    <span className="field-label">{spec.label}</span>
                    <input
                      className="input mono"
                      aria-label={spec.label}
                      type={spec.name === 'ntp_key' ? 'password' : 'text'}
                      // a saved browser password must never be filled into a configuration value unseen
                      autoComplete={spec.name === 'ntp_key' ? 'new-password' : 'off'}
                      name={`remediation-${spec.name}`}
                      value={inputs[spec.name] || ''}
                      onChange={(e) => setInputs((prev) => ({ ...prev, [spec.name]: e.target.value }))}
                    />
                    <span className="field-help">{spec.help}</span>
                  </label>
                ))}
              </div>
              <button type="submit" className="btn" disabled={loading}>
                {loading ? 'Generating…' : 'Generate with these values'}
              </button>
            </form>
          )}

          <div className={`download-bar ${changed ? 'is-stale' : ''}`}>
            <button type="button" className="btn btn-accent" onClick={handleDownload} disabled={!anyFixed || downloading || changed}>
              {downloading ? 'Preparing…' : 'Download verified configuration'}
            </button>
            <span className="small" role={changed ? 'status' : undefined}>{hint}</span>
          </div>

          {downloaded && (
            <div className="notice notice-ok" role="status">
              <span className="notice-mark">✓</span>
              <strong>Downloaded the configuration for the plan shown above.</strong>
              <span>To confirm the result independently, upload the fixed file as a new audit.</span>
              <a className="btn btn-sm notice-action" href="#/app">Rescan in a new audit</a>
            </div>
          )}

          {items.length === 0 ? (
            <div className="empty"><p className="empty-title">Nothing to remediate</p><p>No control has a failing result to fix.</p></div>
          ) : (
            <ul className="rem-items" aria-label="Remediation items">
              {items.map((r) => {
                const k = `${r.config_index}-${r.rule_id}`;
                const meta = itemMeta(r.status);
                const isOpen = open === k;
                return (
                  <Fragment key={k}>
                    <li className={`rem-item ${isOpen ? 'is-open' : ''}`}>
                      <button type="button" className="rem-row" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : k)}>
                        <span className={`tag rem-tag tone-${meta.tone}`}>{meta.label}</span>
                        <span className="rem-row-main">
                          <span className="rem-row-title"><span className="mono">{r.rule_id}</span> {r.title}</span>
                          <span className="rem-row-reason small muted">{labels.length > 1 && <span className="mono">{labels[r.config_index] ?? r.device_hostname} · </span>}{r.reason}</span>
                        </span>
                        <span className="rem-chevron" aria-hidden="true">{isOpen ? '−' : '+'}</span>
                      </button>
                      {isOpen && <div className="rem-item-body fade-in"><RemediationDetail remediation={r} /></div>}
                    </li>
                  </Fragment>
                );
              })}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
