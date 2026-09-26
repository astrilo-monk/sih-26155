import { useState } from 'react';
import { apiClient } from '../api/client';

export const shown = (v) => (v === 'not_set' ? 'not set' : v === true ? 'yes' : v === false ? 'no' : v === null ? 'undetermined'
  : Array.isArray(v) ? v.map(shown).join(', ')
    : typeof v === 'object' ? Object.entries(v).map(([k, x]) => `${k} ${shown(x)}`).join(', ') : String(v));

// The Security Baseline Model on screen: every vendor-neutral field the checks read, one column per device.
// Two vendors side by side show the point of the design: different syntax, the same fields.
export default function Baseline({ scanId, labels }) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState({ phase: 'idle' });

  const toggle = async () => {
    setOpen((o) => !o);
    if (state.phase !== 'idle') return;
    setState({ phase: 'loading' });
    try {
      const models = await Promise.all(labels.map((_, i) => apiClient.getBaseline(scanId, i)));
      setState({ phase: 'done', models });
    } catch (err) {
      setState({ phase: 'error', text: err.message });
    }
  };

  const models = state.models || [];
  const fields = models.length ? Object.keys(models[0].read_by) : [];
  const stated = (m, field) => m.settings.filter((s) => s.field === field);

  return (
    <section className="baseline" aria-labelledby="baseline-title">
      <div className="baseline-head">
        <h2 className="paths-k" id="baseline-title">Vendor-neutral model</h2>
        <button type="button" className="btn btn-sm" aria-expanded={open} onClick={toggle}>
          {open ? 'Hide the model' : labels.length > 1 ? 'Compare the devices field by field' : 'Show what NetAuditAI read'}
        </button>
      </div>
      <p className="paths-lede">Every check reads these fields, never vendor syntax. Each value links back to the line it came from.</p>
      {open && state.phase === 'loading' && <p className="muted" aria-busy="true">Reading the model…</p>}
      {open && state.phase === 'error' && <p className="field-error" role="alert">The model couldn’t be loaded: {state.text}</p>}
      {open && state.phase === 'done' && (
        <div className="baseline-scroll">
          <table className="baseline-table">
            <thead>
              <tr>
                <th scope="col">Field</th>
                {models.map((m, i) => <th key={i} scope="col">{labels[i]}<span className="small muted"> · {m.device.vendor}</span></th>)}
              </tr>
            </thead>
            <tbody>
              {fields.map((field) => (
                <tr key={field}>
                  <th scope="row">
                    <span className="mono">{field}</span>
                    <span className="small muted"> · {models[0].read_by[field].join(', ')}</span>
                  </th>
                  {models.map((m, i) => {
                    const values = stated(m, field);
                    return (
                      <td key={i} className={values.length ? '' : 'baseline-empty'}>
                        {values.length ? values.map((s, j) => (
                          <span key={j} className="baseline-value" title={s.lines.map((l) => `line ${l.number}: ${l.text.trim()}`).join('\n') || s.note || ''}>
                            {s.subject && <span className="muted">{s.subject}: </span>}{shown(s.value)}{s.unit ? ` ${s.unit}` : ''}
                            <span className="baseline-src small muted">
                              {s.lines.length ? ` line ${s.lines.map((l) => l.number).join(', ')}` : ''} · {s.assurance}
                            </span>
                          </span>
                        )) : 'not stated'}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
