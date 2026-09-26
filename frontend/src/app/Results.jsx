import { Severity, SeverityMeter, StatusMark } from '../components/ui/Evidence';
import { Notice } from '../components/ui/primitives';
import Count from '../components/ui/Count';
import {
  assessment, auditCounts, checkItems, deviceLabels, isProblem, itemState, nextStep, SEVERITIES, sayFact, stateMeta,
  stripLineNo, vendorName,
} from '../lib/domain';
import { useState } from 'react';
import { apiClient } from '../api/client';
import UnresolvedList from './Unresolved';
import FirstRunTips from './FirstRunTips';
import { useEntered } from '../lib/hooks';

// The row's action word: what clicking it lets you do
const ACTION = {
  can_fix: 'Fix', needs_input: 'Answer', needs_admin: 'Propose a fix', manual: 'How to fix', cannot_fix: 'Details',
  verification_failed: 'Details', fixed: 'Fixed', problem: 'View',
};

// A file built by the backend from this same scan: the PDF report, or the normalized baseline model
function DownloadButton({ label, run, failed }) {
  const [state, setState] = useState('idle');
  const download = async () => {
    setState('working');
    try {
      await run();
      setState('idle');
    } catch {
      setState('failed');
    }
  };
  return (
    <div className="report-action">
      <button type="button" className="btn btn-sm" onClick={download} disabled={state === 'working'}>
        {state === 'working' ? 'Preparing…' : label}
      </button>
      {state === 'failed' && <span className="small text-fail" role="alert">{failed}</span>}
    </div>
  );
}

export function PostureSummary({ posture, coverage = 0, bounds, criticalUnassessed = [], assessed = null, unresolved = null }) {
  const a = assessment(posture, coverage, criticalUnassessed);
  const entered = useEntered();
  // "out of 100" reads as a whole-device grade: only when enough of the device was checked
  const outOf = posture != null && a.scope !== 'Limited assessment';
  return (
    <section className={`posture tone-${a.tone}`} aria-labelledby="posture-title">
      <div className="posture-main">
        <h2 className="posture-k" id="posture-title">Security posture</h2>
        <p className="posture-value tnum">
          {posture == null ? '-' : <Count value={posture} />}
          {outOf && <span className="posture-of">/100</span>}
        </p>
        <p className="posture-label">{a.label}</p>
      </div>
      <div className="posture-side">
        <p className="posture-desc">{a.desc}</p>
        <div className="coverage">
          <div className="coverage-top"><span>Checked</span><span className="tnum">{coverage}%</span></div>
          <div className="coverage-bar" role="img" aria-label={`${coverage}% of applicable checks decided`}>
            <span style={{ width: entered ? `${coverage}%` : 0 }} />
          </div>
          <p className="small muted">How much of this device NetAuditAI could decide from evidence.</p>
        </div>
        {assessed != null && (
          <p className="assessment-progress">
            <span className="tnum">{assessed}</span> check{assessed === 1 ? '' : 's'} assessed
            {unresolved > 0 && <> · <span className="tnum">{unresolved}</span> need your input</>}
          </p>
        )}
        <p className="assessment-line mono small muted">Posture {posture ?? '-'} · Coverage {coverage}% · {a.scope}</p>
        {bounds && posture != null && coverage < 100 && (
          <p className="small muted">If every undecided check failed or passed, the posture would be {bounds[0]}–{bounds[1]}.</p>
        )}
      </div>
    </section>
  );
}

function ProblemRow({ item, state, label, onOpen, index }) {
  const r = item.results.find((x) => x.status === 'fail') || item.primary;
  // a multi-line citation is the whole block ("line vty 0 4" and everything under it); nothing in it marks which
  // line decided the control, so quote a line only when the evidence is that one line, and otherwise name the block
  const lines = r.evidence?.lines || [];
  const numbers = r.evidence?.line_numbers || [];
  const line = lines.length === 1 ? lines[0] : null;
  const lineNo = numbers[0];
  const block = lines.length > 1 ? (r.evidence.scope_path?.join(' › ') || lines[0].trim()) : null;
  const meta = stateMeta(state);
  return (
    <li className="problem-li" style={{ '--i': index }}>
      <button type="button" className="problem" onClick={() => onOpen(item)}>
        <span className="problem-main">
          <span className="problem-title">{item.title}</span>
          <span className="problem-meta">
            {label && <span className="mono">{label}</span>}
            <Severity level={item.severity} />
            <StatusMark state={state} size="compact" />
          </span>
          {line && <code className="problem-line">{stripLineNo(line, lineNo)}</code>}
          {block && <span className="problem-where mono">in <code>{block}</code> · {lines.length} lines cited</span>}
        </span>
        <span className={`problem-action tone-${meta.tone}`}>{ACTION[state] || 'View'}</span>
      </button>
    </li>
  );
}

function deviceLine(ident) {
  if (ident?.status === 'confirmed') return `${vendorName(ident.detected_vendor)} -read by a dedicated parser`;
  if (ident?.status === 'unverified') return `Looks like ${vendorName(ident.detected_vendor)}, but not confirmed -checked with generic analysis`;
  return 'Unfamiliar device -checked with generic analysis';
}

export default function Results({ scan, audit, onOpen, onTeach, go }) {
  const labels = deviceLabels(scan.devices);
  const counts = auditCounts(scan, audit.plan, audit.applied, audit.queue);
  const items = checkItems(scan, audit.plan);
  const list = items.filter(isProblem);
  const step = nextStep(counts, { planLoading: audit.planLoading, planError: audit.planError });
  const undecided = items.filter((i) => !isProblem(i) && ['unknown', 'not_configured'].includes(itemState(i)));
  const critical = (scan.critical_unassessed || []).map((id) => items.find((i) => i.controlId === id)?.title || id);
  const idents = scan.vendor_identification || [];
  const unreadable = scan.unreadable_configs || [];
  // Nothing uploaded holds configuration: there is nothing to work on, only a file to replace
  const nothingToAssess = unreadable.length > 0 && unreadable.length === scan.devices.length;
  const unfamiliar = scan.devices.some((_, i) => idents.find((v) => v.config_index === i)?.status !== 'confirmed');
  const questions = audit.queue?.provisional || [];
  const multi = labels.length > 1;
  const title = multi ? `${labels.length} configurations` : labels[0] === 'unknown' ? 'Unnamed device' : labels[0];

  return (
    <div className="wrap overview enter">
      <header className="ov-head">
        <div>
          <p className="eyebrow">Scan results · {new Date(scan.timestamp).toLocaleString()}</p>
          <h1 className="page-title">{title}</h1>
          <ul className="ov-devices">
            {scan.devices.map((d, i) => (
              <li key={i}>{multi && <span className="mono">{labels[i]}: </span>}{deviceLine(idents.find((v) => v.config_index === i))}</li>
            ))}
          </ul>
        </div>
        <div className="ov-actions">
          <DownloadButton
            label={scan.devices.length > 1 ? `Download ${scan.devices.length} PDF reports` : 'Download PDF report'}
            run={() => apiClient.downloadReport(scan.scan_id)} failed="The report couldn’t be generated."
          />
          {!scan.archived && (
            <DownloadButton
              label="Download baseline (JSON)" failed="The baseline couldn’t be exported."
              run={() => apiClient.downloadBaseline(scan.scan_id, scan.devices.length)}
            />
          )}
          <a className="btn btn-sm" href="#/app">New scan</a>
        </div>
      </header>

      <FirstRunTips />

      {/* risk: the most severe open problem, from the same counts the severity panel shows */}
      <dl className="kpis">
        <div><dt>Security score</dt><dd className="tnum">{scan.posture ?? '-'}{scan.posture != null && <small>/100</small>}</dd></div>
        <div><dt>Findings</dt><dd className="tnum">{counts.problems}</dd></div>
        <div><dt>Devices</dt><dd className="tnum">{scan.devices.length}</dd></div>
        <div className={`kpi-risk sev-${SEVERITIES.find((s) => counts.severity[s]) || 'none'}`}>
          <dt>Risk</dt><dd>{SEVERITIES.find((s) => counts.severity[s]) || (nothingToAssess ? 'Unknown' : 'None found')}</dd>
        </div>
      </dl>

      <div className="status-grid">
        <PostureSummary posture={scan.posture} coverage={scan.coverage} bounds={scan.posture_bounds}
          criticalUnassessed={scan.critical_unassessed || []}
          assessed={counts.assessed ?? scan.assessed_count} unresolved={counts.unresolved ?? scan.unresolved_count} />
        <section className="sev-panel" aria-label="Problems by severity">
          <p className="sev-total"><span className="tnum"><Count value={counts.problems} /></span> problem{counts.problems === 1 ? '' : 's'} found</p>
          <ul className="sev-grid">
            {SEVERITIES.map((s) => (
              <li key={s} className={`sev-cell sev-${s} ${counts.severity[s] ? '' : 'is-zero'}`}>
                <span className="sev-count tnum"><Count value={counts.severity[s]} /></span>
                <span className="sev-name">{s}</span>
                <SeverityMeter level={s} />
              </li>
            ))}
          </ul>
          {/* live region stays mounted; its list renders only when there is something to say */}
          <div aria-live="polite">
            {(() => {
              const mix = audit.plan ? [
                ['fix', counts.canFix, 'can be fixed automatically'],
                ['input', counts.needsInput, 'need your input'],
                ['manual', counts.manual, 'need manual action'],
                ['pass', counts.fixed, 'fixed'],
              ].filter(([, n]) => n > 0) : [];
              if (mix.length > 0) {
                return (
                  <ul className="fixmix">
                    {mix.map(([tone, n, words]) => <li key={tone} className={`tone-${tone}`}><b className="tnum">{n}</b> {words}</li>)}
                  </ul>
                );
              }
              if (!audit.plan && audit.planLoading) return <p className="fixmix muted">Checking which problems can be fixed…</p>;
              if (!audit.plan && audit.planError) return <p className="fixmix text-fail">Fix options unavailable: {audit.planError}</p>;
              return null;
            })()}
          </div>
        </section>
      </div>

      {critical.length > 0 && (
        <Notice kind="warning" label="Not checked">
          <strong>We couldn’t check {critical.length === 1 ? 'a critical setting' : `${critical.length} critical settings`}: {critical.join(', ')}.</strong>
          <span>Don’t treat this device as secure on {critical.length === 1 ? 'this point' : 'these points'} until it is checked.</span>
        </Notice>
      )}

      {unreadable.length > 0 && (
        <Notice kind="warning" label="Nothing to assess">
          <strong>
            {unreadable.length === scan.devices.length
              ? 'This file doesn’t contain enough recognizable configuration to assess.'
              : `${unreadable.length} of the uploaded files don’t contain enough recognizable configuration to assess.`}
          </strong>
          <span>Nothing in it sets any security option, so NetAuditAI has nothing to check and calculated no score. Upload a device configuration instead.</span>
        </Notice>
      )}

      {unfamiliar && unreadable.length < scan.devices.length && (
        <Notice label="Generic analysis">
          <strong>NetAuditAI has no dedicated reader for {multi ? 'some of these devices' : 'this device'}.</strong>
          <span>It checked what it could. Lines it isn’t sure about aren’t counted until you confirm them, and it only writes a fix when a reviewed recognizer can state it in this configuration’s own syntax.</span>
        </Notice>
      )}

      {!nothingToAssess && (
      <section className={`next-step tone-${step.tone}`} aria-labelledby="next-title" aria-busy={step.busy || undefined}>
        <p className="next-k">What to do now</p>
        <h2 className="next-title" id="next-title">{step.title}</h2>
        <p className="next-body">{step.body}</p>
        {step.to && <button type="button" className="btn btn-primary" onClick={() => go(step.to)}>{step.action}</button>}
      </section>
      )}

      <section className="attention" aria-labelledby="attention-title">
        <h2 className="section-title" id="attention-title">Needs your attention</h2>
        {list.length === 0 && questions.length === 0 ? (
          <div className="empty-state tone-pass">
            <p className="empty-mark" aria-hidden="true">✓</p>
            <p className="empty-title">Nothing needs your attention.</p>
            <p>{counts.passed > 0 ? `${counts.passed} check${counts.passed === 1 ? '' : 's'} passed. ` : ''}No problem was found in what NetAuditAI could check.</p>
          </div>
        ) : (
          <ul className="problem-list">
            {list.map((item, i) => (
              <ProblemRow key={item.key} index={i} item={item} state={itemState(item, audit.applied)} label={multi ? labels[item.configIndex] : null} onOpen={onOpen} />
            ))}
            {questions.map((q, qi) => {
              // lines that read differently disagree: never pick one of them as "probably" true
              const readings = new Set(q.lines.map((l) => sayFact(l)));
              const said = readings.size === 1 ? [...readings][0] : null;
              const summary = readings.size > 1 ? ': these lines disagree' : said ? `: probably ${said}` : '';
              return (
                <li key={`${q.config_index}-${q.control_id}`} className="problem-li" style={{ '--i': list.length + qi }}>
                  <button type="button" className="problem is-question" onClick={() => onTeach(`${q.config_index}-${q.control_id}`)}>
                    <span className="problem-main">
                      <span className="problem-title">Unfamiliar configuration{summary}</span>
                      <span className="problem-meta">{multi && <span className="mono">{labels[q.config_index]}</span>}<StatusMark state="needs_review" size="compact" /></span>
                      {q.lines[0] && <code className="problem-line">{q.lines[0].text}</code>}
                    </span>
                    <span className="problem-action tone-review">Teach</span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {!nothingToAssess && (
      <UnresolvedList
        items={audit.queue?.unresolved}
        loading={audit.queue == null && !audit.queueError}
        error={audit.queueError}
        onRetry={audit.loadQueue}
        labels={multi ? labels : null}
        fallback={undecided}
        onOpen={onOpen}
        onTeach={onTeach}
      />
      )}

    </div>
  );
}
