import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import Drawer from '../components/ui/Drawer';
import { Evidence, Severity, StatusMark } from '../components/ui/Evidence';
import { MetaLine } from '../components/ui/primitives';
import { ASSURANCE, fixStatus, isProblem, itemState, vendorState } from '../lib/domain';
import { shown } from './Baseline';
import { FixAction } from './Fix';

const FRAMEWORKS = { NIST_800_53: 'NIST SP 800-53', CIS: 'CIS', DISA_STIG: 'DISA STIG', ISO_27001: 'ISO/IEC 27001' };

const ADVICE = {
  pass: 'Nothing to do. This check passed.',
  not_applicable: 'Nothing to do. This check doesn’t apply to this device.',
  unknown: 'Nothing to do right now. NetAuditAI couldn’t decide this check from the configuration, so it isn’t counted as passed or failed.',
  not_configured: 'No line sets this, and it is not counted as a pass. If this device should have it, add it to the configuration.',
};

function emptyEvidence(r) {
  if (r.status === 'not_configured') return 'No line in this configuration states this setting.';
  if (r.status === 'unknown') return 'No line could decide this check.';
  if (r.assurance === 'default') return 'Decided from the platform’s documented default: no line overrides it.';
  return 'No single line is cited: the parser read the whole configuration and found no line that sets this.';
}

// Progressive disclosure: what's wrong, why it matters and what to do first; evidence and internals on request
function More({ label, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="more">
      <button type="button" className="more-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>{label}</button>
      {open && <div className="more-body reveal-open">{children}</div>}
    </div>
  );
}

// Asked once per page load: the backend's key does not change while the app is open
let aiStatus;
const aiAvailable = () => (aiStatus ??= apiClient.getAssistantStatus().then((s) => !!s.ai_available, () => false));

// AI commentary on a finding. It is text beside the evidence: it never changes a status, severity or count.
function Explain({ scanId, finding }) {
  const [available, setAvailable] = useState(false);
  const [phase, setPhase] = useState({ state: 'idle' });
  useEffect(() => {
    let live = true;
    aiAvailable().then((ok) => live && setAvailable(ok));
    return () => { live = false; };
  }, []);
  if (!available) return null;

  const ask = async () => {
    setPhase({ state: 'loading' });
    try {
      const res = await apiClient.getExplanation(scanId, finding.rule_id, finding.device_hostname);
      // The backend falls back to the stored recommendation when the model gives nothing back (quota, no key)
      setPhase(res.ai_generated ? { state: 'done', text: res.explanation }
        : { state: 'error', text: 'The AI didn’t answer (no key, or its quota is used up). Nothing about this result has changed.' });
    } catch (err) {
      setPhase({ state: 'error', text: `The explanation couldn’t be loaded: ${err.message}` });
    }
  };

  return (
    <section className="fd-sec">
      {phase.state === 'done' ? (
        <>
          <h3 className="fd-k">Explanation</h3>
          <MetaLine parts={['Source: AI-written', 'Commentary, not evidence']} />
          <p>{phase.text}</p>
        </>
      ) : (
        <>
          <button type="button" className="btn btn-sm btn-quiet" onClick={ask} disabled={phase.state === 'loading'}>Explain this</button>
          {phase.state === 'loading' && <p className="muted" aria-busy="true">Asking the AI…</p>}
          {phase.state === 'error' && <p className="field-error" role="alert">{phase.text}</p>}
        </>
      )}
    </section>
  );
}

const VERDICT = { pass: 'Passes', fail: 'Fails', unknown: 'Undecided', not_configured: 'Not configured', n_a: 'Does not apply' };

// The evidence chain, top to bottom: what the frameworks require → the check → the vendor-neutral fields it read
// → the configuration lines that said so → the verdict. Nothing here is recomputed: it is the result as scanned.
function Chain({ item, results }) {
  const reqs = item.primary.requirements || [];
  const facts = results.flatMap((x) => (x.facts || []).map((f) => ({ ...f, x })));
  const lineText = (x, n) => x.evidence?.lines?.[x.evidence.line_numbers.indexOf(n)];
  return (
    <ol className="chain">
      <li>
        <span className="chain-k">Required by</span>
        {reqs.length ? (
          <span className="chain-v">{reqs.slice(0, 4).map((q) => `${FRAMEWORKS[q.framework] || q.framework} ${q.requirement_id}`).join(' · ')}
            {reqs.length > 4 && ` · +${reqs.length - 4} more`}</span>
        ) : <span className="chain-v muted">No framework requirement mapped</span>}
      </li>
      <li><span className="chain-k">Check</span><span className="chain-v"><span className="mono">{item.controlId}</span> {item.question}</span></li>
      <li>
        <span className="chain-k">Read as</span>
        {facts.length ? (
          <ul className="chain-facts">
            {facts.map((f, i) => (
              <li key={i}>
                <span className="mono">{f.field}{f.subject ? `[${f.subject}]` : ''} = {shown(f.value)}{f.unit ? ` ${f.unit}` : ''}</span>
                <span className="small muted"> · {ASSURANCE[f.assurance]?.technical || f.assurance}</span>
                {f.line_numbers.slice(0, 2).map((n) => (
                  <code key={n} className="chain-line">line {n}: {lineText(f.x, n) ?? ''}</code>
                ))}
              </li>
            ))}
          </ul>
        ) : <span className="chain-v muted">No setting was found for it in this configuration</span>}
      </li>
      <li><span className="chain-k">Verdict</span><span className="chain-v"><b>{results.map((x) => VERDICT[x.status] || x.status).filter((v, i, a) => a.indexOf(v) === i).join(' / ')}</b></span></li>
    </ol>
  );
}

export default function FindingDrawer({ item, scan, audit, labels, onClose, onTeach }) {
  if (!item) return null;
  const state = itemState(item, audit.applied);
  const status = fixStatus(item, audit);
  const problem = isProblem(item);
  const r = item.primary;
  const f = item.finding;
  const vs = vendorState((scan.vendor_identification || []).find((v) => v.config_index === item.configIndex));
  const failing = item.results.filter((x) => x.status === 'fail');
  const shown = problem ? failing : item.results;
  const scopes = shown.map((x) => x.scope).filter(Boolean);
  const assurance = ASSURANCE[r.assurance];

  return (
    <Drawer open label={item.title} onClose={onClose} title={
      <div className="fd-head">
        <div className="fd-badges">
          {problem && <Severity level={item.severity} />}
          {/* one status, from the same rule the Fix page uses, so the drawer can never disagree with it */}
          <StatusMark state={status.state}>{status.label}</StatusMark>
        </div>
        <h2 className="fd-title">{item.title}</h2>
        <p className="small muted">{labels[item.configIndex]} · {vs.label}</p>
      </div>
    }>
      <section className="fd-sec">
        <h3 className="fd-k">{problem ? 'What’s wrong' : 'What we found'}</h3>
        <p>{problem && f?.description ? f.description : r.reason}</p>
        {scopes.length > 1 && <p className="small muted">Found in {scopes.length} places: {scopes.join(', ')}.</p>}
      </section>

      {problem && f?.security_impact && (
        <section className="fd-sec">
          <h3 className="fd-k">Why it matters</h3>
          <p>{f.security_impact}</p>
        </section>
      )}

      <section className="fd-sec">
        <h3 className="fd-k">What to do</h3>
        {problem ? <FixAction item={item} scan={scan} audit={audit} />
          : state === 'needs_review' ? (
            <div className="fix">
              <p>NetAuditAI isn’t sure what a line means, so this result isn’t counted yet. Tell it what the line means.</p>
              <button type="button" className="btn btn-primary" onClick={onTeach}>Teach NetAuditAI</button>
            </div>
          ) : <p>{ADVICE[state] || ADVICE.unknown}</p>}
      </section>

      <More label="Show how this was decided">
        <Chain item={item} results={shown} />
      </More>

      <More label="Show evidence">
        {shown.map((x, i) => (
          <Evidence key={i} lineNumbers={x.evidence?.line_numbers} lines={x.evidence?.lines} scopePath={x.evidence?.scope_path}
                    title={x.scope || undefined} empty={emptyEvidence(x)} />
        ))}
      </More>

      {problem && f && <Explain key={`${f.rule_id}|${f.device_hostname}`} scanId={scan.scan_id} finding={f} />}

      {f?.compliance?.length > 0 && (
        <More label="Show compliance">
          <ul className="ref-list">
            {f.compliance.map((c, i) => (
              <li key={i}>
                <span className="tag">{FRAMEWORKS[c.framework] || c.framework} {c.control_id}</span>
                {c.description && <span className="small muted">{c.description}</span>}
              </li>
            ))}
          </ul>
        </More>
      )}

      <More label="Show technical details">
        <dl className="kv">
          <dt>Check</dt><dd className="mono">{item.controlId}</dd>
          {item.category && <><dt>Category</dt><dd>{item.category}</dd></>}
          <dt>Question</dt><dd>{item.question}</dd>
          <dt>Configuration</dt><dd className="mono">{labels[item.configIndex]}</dd>
          <dt>Platform</dt><dd>{vs.label} · {vs.path}</dd>
          {scopes.length > 0 && <><dt>Scope</dt><dd className="mono">{scopes.join(' · ')}</dd></>}
          <dt>Result</dt><dd className="mono">{item.results.map((x) => `${x.status}${x.assurance ? ` (${x.assurance})` : ''}`).join(' · ')}</dd>
          {r.proposed_status && <><dt>Suggested</dt><dd className="mono">{r.proposed_status} -awaiting confirmation</dd></>}
          {item.remediation && <><dt>Fix status</dt><dd className="mono">{item.remediation.status}</dd></>}
        </dl>
      </More>

      <More label="Show detection method">
        <p>{assurance ? assurance.label : 'No validated evidence could decide this check.'}</p>
        <p className="small muted">{vs.note}</p>
      </More>
    </Drawer>
  );
}
