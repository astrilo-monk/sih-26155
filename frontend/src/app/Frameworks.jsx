import { useState } from 'react';
import { Evidence, StatusMark } from '../components/ui/Evidence';
import { statusMeta } from '../lib/domain';

const FRAMEWORK_NAMES = { NIST_800_53: 'NIST SP 800-53', CIS: 'CIS' };
const COUNT_ORDER = ['fail', 'partial', 'unknown', 'not_configured', 'pass', 'n_a'];

const decisiveness = (c) => (c.decisive ? `decisive (${c.assurance})`
  : c.proposed_status ? `AI proposes ${c.proposed_status.toUpperCase()} — awaiting confirmation`
    : c.assurance ? `provisional (${c.assurance})` : 'undecided');

export default function Frameworks({ frameworks = [] }) {
  // NIST maps every control; CIS views exist only for confirmed vendors and cover fewer requirements
  const [selected, setSelected] = useState(() => Math.max(0, frameworks.findIndex((f) => f.framework === 'NIST_800_53')));
  const [open, setOpen] = useState(null);

  if (frameworks.length === 0) {
    return <div className="empty"><p className="empty-title">No framework view</p><p>This audit has no mapped framework requirements.</p></div>;
  }
  const view = frameworks[Math.min(selected, frameworks.length - 1)];
  const names = [...new Set(frameworks.map((f) => f.framework))];

  return (
    <div className="fw">
      <header className="fw-head">
        <div className="fw-pick">
          <label className="field">
            <span className="field-label">Framework view</span>
            {/* Each benchmark version and level is its own view: a requirement is listed only under the exact version it is mapped to */}
            <select className="select" aria-label="Framework" value={selected}
                    onChange={(e) => { setSelected(Number(e.target.value)); setOpen(null); }}>
              {names.map((name) => (
                <optgroup key={name} label={FRAMEWORK_NAMES[name] || name}>
                  {frameworks.map((f, i) => f.framework === name && (
                    <option key={`${f.framework}-${f.version}`} value={i}>
                      {f.version} · {f.requirements.length} requirement{f.requirements.length === 1 ? '' : 's'}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </label>
          <p className="fw-note small muted">
            Built from the scanned control results — nothing is re-evaluated. Only requirements auditable from device
            configuration are mapped; this is not a compliance certification. Product benchmarks appear only for confirmed
            vendors. Heuristic and AI verdicts are provisional and never make a requirement PASS or FAIL.
            ISO/IEC 27001, CIS Controls v8 and DISA STIG are not mapped.
          </p>
        </div>
        <div className="fw-coverage">
          <span className="metric-label">{FRAMEWORK_NAMES[view.framework] || view.framework}</span>
          <span className="fw-coverage-value tnum">{`${view.coverage}% of requirements decided`}</span>
          <div className="coverage-bar" role="img" aria-label={`${view.coverage}% of requirements decided on decisive evidence`}>
            <span style={{ width: `${view.coverage}%` }} />
          </div>
          <ul className="fw-counts">
            {COUNT_ORDER.filter((s) => view.counts[s] > 0).map((s) => (
              <li key={s}><StatusMark status={s}>{`${statusMeta(s).label} ${view.counts[s]}`}</StatusMark></li>
            ))}
          </ul>
        </div>
      </header>

      <ul className="req-list" aria-label={`${view.framework} ${view.version} requirements`}>
        {view.requirements.map((req) => {
          const isOpen = open === req.requirement_id;
          const controls = [...new Set(req.controls.map((c) => c.control_id))];
          return (
            <li key={req.requirement_id} className={`req ${isOpen ? 'is-open' : ''}`}>
              <button type="button" className="req-row" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : req.requirement_id)}>
                <StatusMark status={req.status} />
                <span className="req-main">
                  <span className="req-id mono">{req.requirement_id}</span>
                  <span className="req-title">{req.title}</span>
                </span>
                <span className="req-side">
                  {req.provisional && <span className="tag tag-provisional" title="A heuristic or AI verdict is involved">Provisional</span>}
                  <span className="req-controls mono">{controls.join(', ')}</span>
                </span>
              </button>
              {isOpen && (
                <div className="req-detail fade-in">
                  {req.controls.map((c) => (
                    <div key={`${c.config_index}-${c.control_id}`} className="fw-control">
                      <p className="fw-control-head">
                        <StatusMark status={c.status} />
                        <span className="mono">{c.control_id}</span>
                        <span>{c.title}</span>
                        <span className="muted">· {c.device_hostname}</span>
                        <span className={`tag ${c.decisive ? 'tag-decisive' : 'tag-provisional'}`}>{decisiveness(c)}</span>
                      </p>
                      <p className="small muted">{c.reason}</p>
                      <Evidence lineNumbers={c.evidence.line_numbers} lines={c.evidence.lines} scopePath={c.evidence.scope_path} />
                    </div>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
