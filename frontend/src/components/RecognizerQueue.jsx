import { useCallback, useEffect, useState } from 'react';
import { Check, Loader, RefreshCw, X } from 'lucide-react';
import { apiClient } from '../api/client';

// Confirm a provisional (heuristic) line → review the drafted recognizer and its replay → save.
// Saved recognizers decide that syntax on every later scan with no heuristic and no AI.
const VERDICTS = { fail: 'Suspected FAIL', pass: 'Probable PASS', unknown: 'Unknown' };

const inputStyle = {
  width: '100%',
  backgroundColor: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  color: 'var(--text-primary)',
  padding: '0.5rem 0.625rem',
  fontSize: '0.8125rem',
  fontFamily: 'var(--font-mono)',
  boxSizing: 'border-box',
};
const mutedStyle = { fontSize: '0.75rem', color: 'var(--text-tertiary)' };

const lineKey = (item, line) => `${item.config_index}-${item.control_id}-${line.line_number}`;

export default function RecognizerQueue({ scanId, onScanUpdated }) {
  const [items, setItems] = useState([]);
  const [draft, setDraft] = useState(null); // { key, request, response }
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);

  const load = useCallback(async () => {
    try {
      setItems((await apiClient.getProvisionalResults(scanId)).items);
    } catch (err) {
      setError(err.message);
    }
  }, [scanId]);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action) => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await action();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const check = (key, request) =>
    run(async () => {
      const response = await apiClient.draftRecognizer(scanId, request);
      const d = response.draft;
      setDraft({
        key,
        response,
        request: { ...request, command_pattern: d.command_pattern, scope_template: d.scope_template ?? '', value: d.value ?? '' },
      });
    });

  const save = () =>
    run(async () => {
      const res = await apiClient.saveRecognizer(scanId, draft.request);
      onScanUpdated?.(res.scan);
      setDraft(null);
      setMessage(`Recognizer #${res.mapping.id} saved; ${res.replay.length} result(s) changed. Later scans decide this line without AI.`);
      await load();
    });

  const reject = (item, line) =>
    run(async () => {
      const scan = await apiClient.rejectProvisionalLine(scanId, {
        config_index: item.config_index,
        control_id: item.control_id,
        line_number: line.line_number,
      });
      onScanUpdated?.(scan);
      setMessage(`Line ${line.line_number} rejected; heuristics and AI will ignore it.`);
      await load();
    });

  const edit = (field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setDraft((prev) => ({ ...prev, request: { ...prev.request, [field]: value } }));
  };

  if (items.length === 0 && !error && !message) return null;

  const renderDraft = (key) => {
    const { request, response } = draft;
    return (
      <tr key={`${key}-draft`}>
        <td colSpan="4" style={{ padding: '1rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
            <label>
              <span className="drawer-section-title" style={{ display: 'block' }}>Template</span>
              <input aria-label="Template" value={request.command_pattern} onChange={edit('command_pattern')} style={inputStyle} />
            </label>
            <label>
              <span className="drawer-section-title" style={{ display: 'block' }}>Scope (optional)</span>
              <input aria-label="Scope" value={request.scope_template} onChange={edit('scope_template')} style={inputStyle} />
            </label>
            <label>
              <span className="drawer-section-title" style={{ display: 'block' }}>Value (JSON)</span>
              <input aria-label="Value" value={request.value} onChange={edit('value')} style={inputStyle} />
            </label>
          </div>
          <div style={{ ...mutedStyle, marginTop: '0.5rem' }}>
            {response.draft.predicate}
            {response.draft.subject ? ` (${response.draft.subject})` : ''} · slots: {'{int} {ip} {duration:min|s|h} {enum:name} {polarity} {any}'}
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.5rem', ...mutedStyle }}>
            <input type="checkbox" checked={!!request.any_dialect} onChange={edit('any_dialect')} />
            Apply to any dialect (default: configs sharing this config's top-level keywords)
          </label>

          {response.errors.map((e) => (
            <div key={e} style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>{e}</div>
          ))}
          {response.errors.length === 0 && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem' }}>
              Replay: {response.replay.length} result change(s) across {response.configs_checked} stored config(s)
              {response.replay.map((c, i) => (
                <div key={i} className="mono" style={mutedStyle}>
                  {c.hostname} · {c.control_id}: {c.before} → {c.after}
                </div>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
            <button className="btn-secondary" onClick={() => check(draft.key, request)} disabled={busy}>
              <RefreshCw size={13} /> Re-check
            </button>
            <button className="btn-primary" onClick={save} disabled={busy || response.errors.length > 0}>
              {busy ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Check size={13} />}
              Save Recognizer
            </button>
            <button className="btn-secondary" onClick={() => setDraft(null)} disabled={busy}>Cancel</button>
          </div>
        </td>
      </tr>
    );
  };

  return (
    <>
      <div className="section-header" style={{ marginTop: '0.5rem' }}>
        <span>Provisional Results — Confirm to Learn</span>
        <span>{items.length} Control(s)</span>
      </div>
      {message && <div style={{ fontSize: '0.8125rem', color: 'var(--success)' }}>{message}</div>}
      {error && <div style={{ fontSize: '0.8125rem', color: 'var(--critical)' }}>Error: {error}</div>}
      {items.length > 0 && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Control</th>
                <th>Line</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.flatMap((item) =>
                item.lines.map((line) => {
                  const key = lineKey(item, line);
                  return [
                    <tr key={key}>
                      <td>
                        <span className="badge neutral">{VERDICTS[item.status] || item.status}</span>
                      </td>
                      <td>
                        <div className="finding-title-cell">
                          <span className="strong">{item.question}</span>
                          <span className="finding-desc-preview">{item.control_id} · {item.reason}</span>
                        </div>
                      </td>
                      <td className="mono">
                        {line.line_number}: {line.text}
                        <div style={mutedStyle}>
                          reads {line.subject ? `${line.subject} ` : ''}= {JSON.stringify(line.value)}
                        </div>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.375rem' }}>
                          <button
                            className="btn-primary"
                            aria-label={`Confirm line ${line.line_number} for ${item.control_id}`}
                            onClick={() => check(key, { config_index: item.config_index, control_id: item.control_id, line_number: line.line_number })}
                            disabled={busy}
                          >
                            <Check size={13} /> Confirm
                          </button>
                          <button
                            className="btn-secondary"
                            aria-label={`Reject line ${line.line_number} for ${item.control_id}`}
                            onClick={() => reject(item, line)}
                            disabled={busy}
                          >
                            <X size={13} /> Reject
                          </button>
                        </div>
                      </td>
                    </tr>,
                    draft?.key === key && renderDraft(key),
                  ];
                }),
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
