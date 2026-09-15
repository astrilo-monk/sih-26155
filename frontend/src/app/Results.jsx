import { useEffect, useState } from 'react';
import Tabs from '../components/ui/Tabs';
import { Severity } from '../components/ui/Evidence';
import {
  assessment, auditCounts, deviceLabels, deviceRows, isDecisive, isProvisional, SEVERITIES, STATE, vendorState,
} from '../lib/domain';
import { navigate, useEntered } from '../lib/hooks';
import Count from '../components/ui/Count';
import Findings from './Findings';
import Review from './Review';
import Remediation from './Remediation';
import Frameworks from './Frameworks';

export const RESULT_TABS = ['summary', 'findings', 'review', 'remediation', 'frameworks'];

export function PostureSummary({ posture, coverage = 0, bounds, criticalUnassessed = [] }) {
  const a = assessment(posture, coverage, criticalUnassessed);
  const entered = useEntered();
  return (
    <section className={`posture-card tone-${a.tone}`} aria-labelledby="posture-title">
      <h2 id="posture-title" className="visually-hidden">Posture and coverage</h2>
      <div className="metric">
        <span className="metric-label">Posture</span>
        <span className="metric-value tnum">{posture == null ? '—' : <Count value={posture} />}</span>
        <span className="metric-note">Severity-weighted share of decided controls that pass</span>
      </div>
      <div className="metric">
        <span className="metric-label">Coverage</span>
        <span className="metric-value tnum"><Count value={coverage} /><small>%</small></span>
        <div className="coverage-bar" role="img" aria-label={`${coverage}% of applicable controls decided`}>
          <span style={{ width: entered ? `${coverage}%` : 0 }} />
        </div>
        <span className="metric-note">Applicable controls decided from validated evidence</span>
      </div>
      <div className="assessment">
        <span className="metric-label">Assessment</span>
        <span className="assessment-label">{a.label}</span>
        <p className="assessment-desc">{a.desc}</p>
        <p className="assessment-line mono">Posture {posture ?? '—'} · Coverage {coverage}% · {a.scope}</p>
        {bounds && posture != null && coverage < 100 && (
          <p className="small muted">Range {bounds[0]}–{bounds[1]}: the posture if every undecided control failed, or passed.</p>
        )}
      </div>
    </section>
  );
}

function Summary({ scan, onOpenTab }) {
  const labels = deviceLabels(scan.devices);
  const rows = deviceRows(scan);
  const all = auditCounts(scan);
  const counts = all.severity;
  const entered = useEntered();
  const totalDecisive = all.problems;
  const suspected = (scan.findings || []).filter(isProvisional).length;
  const results = scan.results || [];
  // one per control per configuration, the same unit every count in the app uses
  const outcomes = [
    ['fail', STATE.problem.label, all.problems],
    ['pass', STATE.pass.label, all.passed],
    ['review', STATE.needs_review.label, all.review],
    ['unknown', STATE.unknown.label, all.unknown],
    ['nc', STATE.not_configured.label, all.notConfigured],
  ];
  const adaptive = scan.adaptive_configs || [];
  const reasons = [...new Set(adaptive.flatMap((c) => c.provisional_reasons || []))];
  const aiUnavailable = adaptive.reduce((s, c) => s + (c.ai_unavailable_lines || 0), 0);
  const generic = rows.filter((d) => d.identification?.status !== 'confirmed').length;
  const pending = all.review;

  return (
    <div className="summary">
      {(generic > 0 || aiUnavailable > 0) && (
        <div className="notice notice-info">
          <span className="notice-mark">i</span>
          <strong>
            {generic > 0 ? `${generic === rows.length && rows.length === 1 ? 'This configuration has' : `${generic} configuration(s) have`} no confirmed vendor and took the generic analysis path.` : 'Some lines could not be interpreted.'}
          </strong>
          <span>
            {generic > 0 && 'Heuristic and AI readings there are provisional: they do not change posture, coverage, severity counts or remediation until confirmed. '}
            {aiUnavailable > 0 && `AI interpretation was unavailable for ${aiUnavailable} line(s). `}
          </span>
          {pending > 0 && (
            <button type="button" className="btn btn-sm notice-action" onClick={() => onOpenTab('review')}>
              Review {pending} reading{pending === 1 ? '' : 's'}
            </button>
          )}
        </div>
      )}

      <PostureSummary posture={scan.posture} coverage={scan.coverage} bounds={scan.posture_bounds}
                      criticalUnassessed={scan.critical_unassessed || []} />

      {(scan.critical_unassessed || []).length > 0 && (
        <div className="notice notice-danger">
          <span className="notice-mark">!</span>
          <strong>Critical control(s) not assessed: {scan.critical_unassessed.join(', ')}</strong>
          <span>No decisive evidence exists for {scan.critical_unassessed.length === 1 ? 'this control' : 'these controls'}, so the configuration cannot be called secure on these points.</span>
        </div>
      )}

      <div className="summary-grid">
        <section className="panel" aria-labelledby="sev-title">
          <header className="panel-head">
            <h2 className="panel-title" id="sev-title"><span className="sec-no">01</span> Decisive findings</h2>
            <p className="small muted">
              Suspected findings from heuristic or AI readings are not counted{suspected ? ` — ${suspected} listed under Findings` : ''}.
            </p>
          </header>
          <div className="sev-grid">
            {SEVERITIES.map((s) => (
              <div key={s} className={`sev-cell ${counts[s] ? '' : 'is-zero'}`}>
                <span className="sev-count tnum"><Count value={counts[s]} /></span>
                <Severity level={s} />
              </div>
            ))}
          </div>
          <div className="sev-bar" role="img" aria-label={`${totalDecisive} decisive findings`}>
            {totalDecisive === 0 ? <span className="sev-seg is-empty" style={{ width: '100%' }} />
              : SEVERITIES.filter((s) => counts[s]).map((s) => (
                <span key={s} className={`sev-seg sev-${s}`} style={{ width: entered ? `${(counts[s] / totalDecisive) * 100}%` : 0 }} />
              ))}
          </div>
          {totalDecisive > 0 && <button type="button" className="btn-link small" onClick={() => onOpenTab('findings')}>Inspect findings and evidence</button>}
        </section>

        <section className="panel" aria-labelledby="outcome-title">
          <header className="panel-head">
            <h2 className="panel-title" id="outcome-title"><span className="sec-no">02</span> Control results</h2>
            <p className="small muted">{results.length} results: every control against every configuration.</p>
          </header>
          <ul className="outcomes">
            {outcomes.map(([tone, label, n]) => (
              <li key={label} className={`outcome tone-${tone}`}>
                <span className="outcome-n tnum"><Count value={n} /></span>
                <span>{label}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel" aria-labelledby="devices-title">
        <header className="panel-head">
          <h2 className="panel-title" id="devices-title"><span className="sec-no">03</span> Configurations and analysis path</h2>
        </header>
        <ul className="device-list">
          {rows.map((d) => {
            const vs = vendorState(d.identification);
            const own = results.filter((r) => r.config_index === d.index);
            const decided = new Set(own.filter(isDecisive).map((r) => r.control_id)).size;
            const controls = new Set(own.map((r) => r.control_id)).size;
            const ai = adaptive.find((c) => c.config_index === d.index);
            return (
              <li key={d.index} className="device">
                <div className="device-head">
                  <span className="device-no mono">#{d.index + 1}</span>
                  <span className="device-name mono">{labels[d.index]}</span>
                  <span className={`tag ${vs.key === 'confirmed' ? 'tag-decisive' : vs.key === 'unverified' ? 'tag-provisional' : 'tag-accent'}`}>{vs.label}</span>
                  <span className={`risk risk-${d.risk.replace(' ', '-').toLowerCase()}`}>
                    {d.risk === 'NOT ASSESSED' ? 'Not assessed' : `${d.risk.toLowerCase()} risk`}
                  </span>
                </div>
                <ol className="trail" aria-label={`Analysis path for ${labels[d.index]}`}>
                  <li><span className="trail-k">Platform</span><span>{vs.path}{vs.key === 'confirmed' && d.identification?.parse_coverage != null ? ` · ${Math.round(d.identification.parse_coverage * 100)}% grammar coverage` : ''}</span></li>
                  <li><span className="trail-k">Controls</span><span>{controls} run · {decided} decided</span></li>
                  <li><span className="trail-k">AI escalation</span><span>{vs.key === 'confirmed' ? 'Not used' : ai?.ai_available ? `${ai.ai_calls || 0} call(s) · ${ai.ai_cache_hits || 0} cached` : 'Off or unavailable'}</span></li>
                  <li><span className="trail-k">Findings</span><span>{d.decisive} decisive{d.suspected ? ` · ${d.suspected} suspected` : ''}</span></li>
                  <li><span className="trail-k">Remediation</span><span>{vs.key === 'confirmed' ? 'Deterministic recipes available' : 'Vendor-specific remediation unavailable'}</span></li>
                </ol>
                {vs.key !== 'confirmed' && <p className="small muted device-note">{vs.note}</p>}
              </li>
            );
          })}
        </ul>
      </section>

      {reasons.length > 0 && (
        <details className="disclosure">
          <summary>Why results are provisional or not assessed</summary>
          <ul>{reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </details>
      )}
    </div>
  );
}

export default function Results({ scan, tab, revision, onScanUpdated, onScanExpired }) {
  // Panels stay mounted once opened, so a generated remediation plan or a finding selection survives tab switches
  const [visited, setVisited] = useState(() => new Set([tab]));
  useEffect(() => {
    setVisited((v) => (v.has(tab) ? v : new Set(v).add(tab)));
  }, [tab]);

  const labels = deviceLabels(scan.devices);
  const idents = scan.vendor_identification || [];
  const { problems: decisiveFindings, review: pending } = auditCounts(scan);
  const openTab = (id) => navigate(`/app/scan/${scan.scan_id}/${id}`);
  const title = labels.length === 1
    ? (labels[0] === 'unknown' ? 'Hostname not stated' : labels[0])
    : `${labels.length} configurations`;

  const tabs = [
    { id: 'summary', label: 'Summary' },
    { id: 'findings', label: 'Findings', count: decisiveFindings },
    { id: 'review', label: 'Needs your input', count: pending, attention: pending > 0 },
    { id: 'remediation', label: 'Remediation' },
    { id: 'frameworks', label: 'Frameworks' },
  ];

  const panel = (id, node) => (visited.has(id) || id === tab) && (
    <div key={id} hidden={id !== tab} className="report-panel">{node}</div>
  );

  return (
    <div className="report">
      <header className="wrap report-head enter">
        <p className="eyebrow report-meta">
          Audit report · <span className="mono">{scan.scan_id.slice(0, 8)}</span> · {new Date(scan.timestamp).toLocaleString()}
        </p>
        <div className="report-title-row">
          <h1 className="display report-title">{title}</h1>
          <a className="btn btn-sm" href="#/app">New audit</a>
        </div>
        <ul className="report-devices">
          {scan.devices.map((d, i) => {
            const vs = vendorState(idents.find((v) => v.config_index === i));
            return (
              <li key={i}>
                {labels.length > 1 && <span className="mono">{labels[i]}</span>}
                <span className={`vendor-dot vd-${vs.key}`} aria-hidden="true" />
                <span>{vs.label}</span>
                <span className="muted">· {vs.path}</span>
              </li>
            );
          })}
        </ul>
      </header>

      <div className="report-tabs">
        <div className="wrap">
          <Tabs tabs={tabs} active={tab} onChange={openTab} idBase="report" label="Audit report sections" />
        </div>
      </div>

      <div className="wrap report-body" id="report-panel" role="tabpanel" aria-labelledby={`report-tab-${tab}`}>
        {panel('summary', <Summary scan={scan} onOpenTab={openTab} />)}
        {panel('findings', <Findings scan={scan} />)}
        {panel('review', <Review scan={scan} onScanUpdated={onScanUpdated} onScanExpired={onScanExpired} />)}
        {panel('remediation', <Remediation scan={scan} planKey={`${scan.scan_id}:${revision}`} onScanExpired={onScanExpired} />)}
        {panel('frameworks', <Frameworks key={`fw-${revision}`} frameworks={scan.frameworks || []} />)}
      </div>
    </div>
  );
}
