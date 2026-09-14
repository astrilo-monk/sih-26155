import { Fragment, useState } from 'react';

const STATUS = {
  pass: ['PASS', 'low'],
  fail: ['FAIL', 'critical'],
  partial: ['PARTIAL', 'medium'],
  unknown: ['UNKNOWN', 'neutral'],
  not_configured: ['NOT CONFIGURED', 'neutral'],
  n_a: ['N/A', 'neutral'],
};

const Status = ({ status }) => {
  const [label, tone] = STATUS[status] || [status, 'neutral'];
  return <span className={`badge ${tone}`}>{label}</span>;
};

export default function FrameworkView({ frameworks = [] }) {
  // NIST maps every control; CIS views exist only for confirmed vendors and cover fewer requirements
  const [selected, setSelected] = useState(() => Math.max(0, frameworks.findIndex((f) => f.framework === 'NIST_800_53')));
  const [open, setOpen] = useState(null);

  if (frameworks.length === 0) {
    return <div className="empty-state">Run a scan to see framework views.</div>;
  }
  const view = frameworks[Math.min(selected, frameworks.length - 1)];

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Framework View</span>
        <span>{view.coverage}% of requirements decided</span>
      </div>

      <div className="filter-bar">
        <select className="filter-input" aria-label="Framework" value={selected}
                onChange={(e) => { setSelected(Number(e.target.value)); setOpen(null); }}>
          {frameworks.map((f, i) => (
            <option key={`${f.framework}-${f.version}`} value={i}>{f.framework} · {f.version}</option>
          ))}
        </select>
        {Object.entries(view.counts).filter(([, n]) => n > 0).map(([status, n]) => (
          <span key={status} className="badge neutral">{(STATUS[status] || [status])[0]}: {n}</span>
        ))}
      </div>

      <div className="drawer-text" style={{ color: 'var(--text-tertiary)', marginBottom: '0.75rem' }}>
        Built from the scanned control results — nothing is re-evaluated. Only requirements auditable from device
        configuration are mapped; this is not a compliance certification. Product benchmarks appear only for confirmed
        vendors. Heuristic and AI verdicts are provisional and never make a requirement PASS or FAIL.
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr><th>Status</th><th>Requirement</th><th>Mapped controls</th></tr>
          </thead>
          <tbody>
            {view.requirements.map((req) => (
              <Fragment key={req.requirement_id}>
                <tr className="clickable" onClick={() => setOpen(open === req.requirement_id ? null : req.requirement_id)}>
                  <td>
                    <Status status={req.status} />
                    {req.provisional && <span className="badge neutral" style={{ marginLeft: '0.25rem' }} title="A heuristic or AI verdict is involved">Provisional</span>}
                  </td>
                  <td>
                    <div className="finding-title-cell">
                      <span className="strong">{req.requirement_id}</span>
                      <span className="finding-desc-preview">{req.title}</span>
                    </div>
                  </td>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                    {[...new Set(req.controls.map((c) => c.control_id))].join(', ')}
                  </td>
                </tr>
                {open === req.requirement_id && (
                  <tr>
                    <td colSpan="3" style={{ padding: '0.75rem 1rem' }}>
                      {req.controls.map((c) => (
                        <div key={`${c.config_index}-${c.control_id}`} style={{ marginBottom: '0.75rem' }}>
                          <div className="drawer-text">
                            <Status status={c.status} /> <span className="mono">{c.control_id}</span> {c.title} · {c.device_hostname}
                            {' · '}{c.decisive ? `decisive (${c.assurance})` : c.proposed_status ? `AI proposes ${c.proposed_status.toUpperCase()} — awaiting confirmation` : c.assurance ? `provisional (${c.assurance})` : 'undecided'}
                          </div>
                          <div className="drawer-text" style={{ color: 'var(--text-tertiary)' }}>{c.reason}</div>
                          {c.evidence.line_numbers.length > 0 && (
                            <div className="config-block">
                              <div className="config-body">
                                {c.evidence.line_numbers.map((n, i) => (
                                  <div key={n} className="config-line"><span className="line-num">{n}</span><span>{c.evidence.lines[i]}</span></div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
