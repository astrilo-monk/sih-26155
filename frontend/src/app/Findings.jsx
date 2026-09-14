import { useMemo, useState } from 'react';
import { apiClient } from '../api/client';
import { Evidence, Severity, StatusMark } from '../components/ui/Evidence';
import { ASSURANCE, deviceLabels, isDecisive, isProvisional, SEVERITY_RANK, vendorState } from '../lib/domain';
import { navigate } from '../lib/hooks';
import { RemediationDetail } from './Remediation';

const FILTERS = [
  ['fail', 'Failing', (r) => r.status === 'fail'],
  ['open', 'Undecided', (r) => r.status === 'unknown' || r.status === 'not_configured'],
  ['pass', 'Passing', (r) => r.status === 'pass'],
  ['all', 'All', () => true],
];
const STATUS_ORDER = { fail: 0, unknown: 1, not_configured: 2, pass: 3, n_a: 4 };

// Every control result, paired with its finding (description, impact, recommendation) when it failed.
// A control can fail in several scopes: findings are matched by their cited lines, then in order.
export function buildRows(scan) {
  const findings = scan.findings || [];
  const used = new Set();
  return (scan.results || []).map((r, i) => {
    let finding = null;
    if (r.status === 'fail') {
      const same = (f, j) => !used.has(j) && f.rule_id === r.control_id && (f.config_index ?? 0) === r.config_index;
      const lines = JSON.stringify(r.evidence?.line_numbers || []);
      let idx = findings.findIndex((f, j) => same(f, j) && JSON.stringify(f.line_numbers || []) === lines);
      if (idx < 0) idx = findings.findIndex(same);
      if (idx >= 0) {
        used.add(idx);
        finding = findings[idx];
      }
    }
    return { key: `${r.config_index}-${r.control_id}-${i}`, result: r, finding };
  });
}

const rowTitle = (r) => (r.status === 'fail' ? r.title : r.question || r.title);

function emptyEvidence(r) {
  if (r.status === 'not_configured') return 'No line in this configuration states this setting. Absence is reported as Not configured — never as a pass.';
  if (r.status === 'unknown') return 'No validated evidence could decide this control.';
  if (r.assurance === 'default') return 'Decided from the documented platform default: no line overrides it.';
  return 'No single line is cited: the dedicated parser read the whole configuration and found no statement of this setting.';
}

function FindingDetail({ row, scan, label, onBack }) {
  const r = row.result;
  const f = row.finding;
  const vs = vendorState((scan.vendor_identification || []).find((v) => v.config_index === r.config_index));
  const provisional = isProvisional(r) || !!r.proposed_status;
  const assurance = r.assurance ? ASSURANCE[r.assurance] : null;
  const [remediation, setRemediation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  // Deterministic remediation only for a decisive FAIL on a confirmed vendor (the API enforces both)
  const canRemediate = r.status === 'fail' && isDecisive(r) && vs.key === 'confirmed';

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      // config_index identifies the uploaded config: hostnames can repeat across uploads
      setRemediation(await apiClient.getRemediation(scan.scan_id, r.control_id, r.device_hostname, r.config_index ?? 0));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="finding-detail"aria-labelledby={`fd-${row.key}`}>
      <button type="button" className="btn btn-quiet btn-sm back-btn" onClick={onBack}>← All results</button>
      <header className="fd-head">
        <div className="fd-ids">
          <span className="mono">{r.control_id}</span>
          <span className="muted">{r.category}</span>
          <Severity level={r.severity} />
        </div>
        <h2 className="fd-title" id={`fd-${row.key}`}>{rowTitle(r)}</h2>
        {r.status === 'fail' && r.question && <p className="fd-question">{r.question}</p>}
        <div className="fd-verdict">
          <StatusMark status={r.status} size="lg" />
          {assurance
            ? <span className={`tag ${assurance.decisive ? 'tag-decisive' : 'tag-provisional'}`}>{assurance.label}</span>
            : <span className="tag">No validated evidence</span>}
          {r.proposed_status && <span className="tag tag-provisional">AI proposes {r.proposed_status.toUpperCase()} · awaiting confirmation</span>}
        </div>
        <dl className="kv fd-kv">
          <dt>Configuration</dt><dd className="mono">{label}</dd>
          <dt>Platform</dt><dd>{vs.label} · {vs.path}</dd>
          {r.scope && <><dt>Scope</dt><dd className="mono">{r.scope}</dd></>}
        </dl>
      </header>

      {provisional && (
        <div className="notice notice-warn">
          <span className="notice-mark">?</span>
          <strong>Human review required — not counted</strong>
          <span>
            This reading comes from {r.assurance === 'heuristic' ? 'a lexicon heuristic' : 'a verified AI proposal'} on a configuration
            without a confirmed vendor. It changes nothing — posture, coverage, severity counts, remediation — until a person confirms it.
          </span>
          <button type="button" className="btn btn-sm notice-action" onClick={() => navigate(`/app/scan/${scan.scan_id}/review`)}>Open Needs your input</button>
        </div>
      )}

      <section className="fd-sec">
        <h3 className="fd-sec-title">Result</h3>
        <p>{r.reason}</p>
      </section>

      <section className="fd-sec">
        <h3 className="fd-sec-title">Evidence</h3>
        <Evidence lineNumbers={r.evidence?.line_numbers} lines={r.evidence?.lines} scopePath={r.evidence?.scope_path}
                  title={r.scope ? `${r.scope} — ${(r.evidence?.line_numbers || []).length > 1 ? 'lines' : 'line'} ${(r.evidence?.line_numbers || []).join(', ')}` : undefined}
                  empty={emptyEvidence(r)} />
      </section>

      {f && (
        <section className="fd-sec">
          <h3 className="fd-sec-title">Why it matters</h3>
          <p>{f.security_impact}</p>
        </section>
      )}

      {f && (
        <section className="fd-sec">
          <h3 className="fd-sec-title">Recommendation</h3>
          <p>{f.recommendation}</p>
        </section>
      )}

      {f?.compliance?.length > 0 && (
        <section className="fd-sec">
          <h3 className="fd-sec-title">Framework references</h3>
          <ul className="ref-list">
            {f.compliance.map((c, i) => (
              <li key={i} title={[c.description, c.version].filter(Boolean).join(' · ')}>
                <span className="tag">{c.framework === 'NIST_800_53' ? 'NIST SP 800-53' : c.framework} {c.control_id}</span>
                {c.description && <span className="small muted">{c.description}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="fd-sec">
        <h3 className="fd-sec-title">Remediation</h3>
        {r.status !== 'fail' ? (
          <p className="muted">Nothing to remediate: this control is not failing.</p>
        ) : provisional ? (
          <p className="muted">Blocked. Provisional findings never trigger remediation — confirm the reading first.</p>
        ) : vs.key !== 'confirmed' ? (
          <p className="muted">Vendor-specific remediation is unavailable until the vendor is confirmed. Follow the recommendation above.</p>
        ) : remediation ? (
          <RemediationDetail remediation={remediation}
                             onNeedsInput={() => navigate(`/app/scan/${scan.scan_id}/remediation`)} />
        ) : canRemediate && (
          <div className="fd-remediate">
            <p className="small muted">Generates a deterministic change for this control on this configuration, then rescans it to verify. No AI is involved.</p>
            <button type="button" className="btn btn-primary" onClick={generate} disabled={busy}>
              {busy ? 'Generating and verifying…' : 'Generate deterministic fix'}
            </button>
          </div>
        )}
        {error && <p className="field-error" role="alert">{error}</p>}
      </section>
    </article>
  );
}

export default function Findings({ scan }) {
  const rows = useMemo(() => buildRows(scan), [scan]);
  const labels = deviceLabels(scan.devices);
  const [filter, setFilter] = useState(() => (rows.some((r) => r.result.status === 'fail') ? 'fail' : 'all'));
  const [device, setDevice] = useState('all');
  const [query, setQuery] = useState('');
  const [selectedKey, setSelectedKey] = useState(null);
  const [pane, setPane] = useState('list');

  const q = query.trim().toLowerCase();
  const matches = (row) => {
    const r = row.result;
    if (device !== 'all' && String(r.config_index) !== device) return false;
    return !q || [r.control_id, r.title, r.question, r.category, labels[r.config_index]]
      .some((v) => (v || '').toLowerCase().includes(q));
  };
  const base = rows.filter(matches);
  const test = FILTERS.find(([id]) => id === filter)[2];
  const visible = base.filter((row) => test(row.result)).sort((a, b) =>
    (STATUS_ORDER[a.result.status] ?? 9) - (STATUS_ORDER[b.result.status] ?? 9)
    || Number(isProvisional(a.result)) - Number(isProvisional(b.result))
    || (SEVERITY_RANK[a.result.severity] ?? 9) - (SEVERITY_RANK[b.result.severity] ?? 9)
    || a.result.control_id.localeCompare(b.result.control_id));
  const selected = visible.find((r) => r.key === selectedKey) || visible[0] || null;

  if (rows.length === 0) {
    return <div className="empty"><p className="empty-title">No control results</p><p>This audit returned no results to inspect.</p></div>;
  }

  return (
    <div className="findings">
      <div className="findings-toolbar">
        <div className="segmented" role="group" aria-label="Filter by result">
          {FILTERS.map(([id, label, pred]) => (
            <button key={id} type="button" className="seg-btn" aria-pressed={filter === id}
                    onClick={() => { setFilter(id); setSelectedKey(null); }}>
              {label} <span className="seg-n tnum">{base.filter((row) => pred(row.result)).length}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          {labels.length > 1 && (
            <select className="select" aria-label="Configuration filter" value={device} onChange={(e) => setDevice(e.target.value)}>
              <option value="all">All configurations</option>
              {labels.map((l, i) => <option key={i} value={String(i)}>{l}</option>)}
            </select>
          )}
          <input className="input" type="search" placeholder="Search controls" aria-label="Search controls"
                 value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>

      <div className="findings-layout" data-pane={pane}>
        <div className="finding-list-wrap">
          {visible.length === 0 ? (
            <p className="empty-inline">No results match these filters.</p>
          ) : (
            <ul className="finding-list" aria-label="Control results">
              {visible.map((row) => {
                const r = row.result;
                const isSel = selected?.key === row.key;
                return (
                  <li key={row.key}>
                    <button type="button" className={`finding-item ${isSel ? 'is-selected' : ''}`} aria-current={isSel ? 'true' : undefined}
                            onClick={() => { setSelectedKey(row.key); setPane('detail'); }}>
                      <StatusMark status={r.status} size="compact" />
                      <span className="fi-main">
                        <span className="fi-top"><span className="fi-id mono">{r.control_id}</span><Severity level={r.severity} /></span>
                        <span className="fi-title">{rowTitle(r)}</span>
                        <span className="fi-meta">
                          {labels.length > 1 && <span className="mono">{labels[r.config_index]}</span>}
                          {r.scope && <span className="mono">{r.scope}</span>}
                          {(isProvisional(r) || r.proposed_status) && <span className="tag tag-provisional">{r.status === 'fail' ? 'Suspected · not counted' : 'Provisional'}</span>}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div className="finding-detail-wrap">
          {selected
            ? <FindingDetail key={selected.key} row={selected} scan={scan} label={labels[selected.result.config_index]} onBack={() => setPane('list')} />
            : <p className="empty-inline">Select a result to inspect its evidence.</p>}
        </div>
      </div>
    </div>
  );
}
