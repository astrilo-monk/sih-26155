import { useCallback, useEffect, useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { apiClient } from '../api/client';
import { Evidence } from '../components/ui/Evidence';
import { validateInterpretation } from '../utils/adaptiveValidation';

// Suggestions from the optional line interpreter for confirmed vendors (off by default). Accepting saves a learned
// mapping; nothing is applied without a person. Shown only when the backend has such suggestions.

const STATUS = { pending: 'Waiting', accepted: 'Accepted', edited: 'Edited', rejected: 'Rejected', learned: 'Learned' };
const isAiUnavailable = (item) => item.interpretation_status === 'ai_unavailable';
const fieldLabel = (f) => (f.label ? `${f.label} -${f.field}` : f.field);

function emptyForm(item) {
  return {
    itemId: item.item_id,
    normalizedField: item.normalized_field !== 'unknown' ? item.normalized_field : '',
    extractedValue: item.extracted_value ?? '',
    commandPattern: '',
    concept: item.security_concept && item.security_concept !== 'unknown' ? item.security_concept : '',
  };
}

export default function LegacyInterpretations({ scan, onScanUpdated, onScanExpired }) {
  const scanId = scan.scan_id;
  const [items, setItems] = useState([]);
  const [fields, setFields] = useState([]);
  const [showResolved, setShowResolved] = useState(false);
  const [expanded, setExpanded] = useState({});
  const [form, setForm] = useState(null);
  const [formErrors, setFormErrors] = useState({});
  const [busyItem, setBusyItem] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const [queue, fieldList] = await Promise.all([apiClient.getReviewQueue(scanId, showResolved), apiClient.getNormalizedFields()]);
      setItems(queue.items);
      setFields(fieldList);
      setError(null);
    } catch (err) {
      if (err.status === 404) onScanExpired?.(scanId);
      else setError(err.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, showResolved]);

  useEffect(() => { load(); }, [load]);

  if (items.length === 0 && !showResolved && !error) return null;

  const run = async (itemId, action, describe) => {
    setBusyItem(itemId);
    setActionError(null);
    setMessage(null);
    try {
      const res = await action();
      if (res.scan) onScanUpdated?.(res.scan);
      setForm(null);
      setFormErrors({});
      setMessage(describe(res));
      await load();
    } catch (err) {
      setActionError({ itemId, message: err.message });
    } finally {
      setBusyItem(null);
    }
  };

  const learned = (item) => (res) => {
    const extra = res.auto_resolved?.length ? ` ${res.auto_resolved.length} matching line(s) were resolved too.` : '';
    return `NetAuditAI learned line ${item.line_number} (rule #${res.mapping?.id}).${extra}`;
  };
  const accept = (item) => run(item.item_id, () => apiClient.acceptInterpretation(scanId, item.item_id), learned(item));
  const reject = (item) => run(item.item_id, () => apiClient.rejectInterpretation(scanId, item.item_id),
    () => `Got it. NetAuditAI will stop guessing about line ${item.line_number}.`);
  const startEdit = (item) => {
    setForm(emptyForm(item));
    setFormErrors({});
    setActionError(null);
    setExpanded((prev) => ({ ...prev, [item.item_id]: true }));
  };
  const submitEdit = (item) => {
    const { valid, errors } = validateInterpretation(form, fields);
    setFormErrors(errors);
    if (!valid) return;
    run(item.item_id, () => apiClient.editInterpretation(scanId, item.item_id, {
      normalized_field: form.normalizedField,
      extracted_value: form.extractedValue.trim(),
      command_pattern: form.commandPattern.trim() || null,
      concept: form.concept.trim() || null,
    }), learned(item));
  };
  const update = (key) => (e) => setForm((prev) => ({ ...prev, [key]: e.target.value }));

  return (
    <section className="legacy" aria-labelledby="legacy-title">
      <header className="section-head">
        <h2 className="section-title" id="legacy-title">Other suggestions (advanced)</h2>
        <p className="small muted">From the optional line interpreter. Accepting one teaches NetAuditAI that line; nothing is applied without you.</p>
      </header>
      <label className="check">
        <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
        <span>Show answered lines</span>
      </label>
      {message && <Notice label="Saved" role="status"><strong>{message}</strong></Notice>}
      {error && <Notice kind="danger" label="Failed" role="alert"><span>{error}</span></Notice>}
      {items.length === 0 ? <p className="empty-inline">No suggestions are waiting.</p> : (
        <ul className="legacy-list">
          {items.map((item) => {
            const id = item.item_id;
            const isOpen = expanded[id] || form?.itemId === id;
            const isBusy = busyItem === id;
            const pending = item.review_status === 'pending';
            const hasSuggestion = item.normalized_field !== 'unknown' && item.extracted_value != null;
            const aiUnavailable = isAiUnavailable(item);
            const editing = form?.itemId === id;
            const selectedField = editing ? fields.find((f) => f.field === form.normalizedField) : null;
            return (
              <li key={id} className="legacy-item">
                <div className="legacy-row">
                  <button type="button" className="btn btn-quiet btn-sm mono" aria-expanded={!!isOpen}
                          aria-label={`Toggle details for line ${item.line_number}`}
                          onClick={() => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))}>
                    <span aria-hidden="true">{isOpen ? '−' : '+'}</span> {item.line_number}
                  </button>
                  <code className="legacy-line">{item.raw_line.trim()}</code>
                  <span className="legacy-suggest">
                    {aiUnavailable ? <span className="small text-unknown">AI unavailable -map manually</span>
                      : hasSuggestion ? <span className="mono small">{item.normalized_field} = {item.extracted_value}</span>
                        : <span className="small muted">No usable suggestion</span>}
                  </span>
                  <span className="legacy-confidence">
                    {aiUnavailable
                      ? <span className="tag" title="The AI could not assess this line; this is not a confidence score">AI unavailable</span>
                      : <><span className="tag">{item.confidence_tier}</span> <span className="mono small">{Math.round(item.confidence * 100)}%</span></>}
                  </span>
                  <span className="small muted">{STATUS[item.review_status] || item.review_status}</span>
                  {pending && (
                    <span className="legacy-actions">
                      <button type="button" className="btn btn-primary btn-sm" aria-label={`Accept line ${item.line_number}`}
                              onClick={() => accept(item)} disabled={isBusy || !hasSuggestion}
                              title={hasSuggestion ? undefined : 'No usable suggestion -edit instead'}>Accept</button>
                      <button type="button" className="btn btn-sm" aria-label={`Edit line ${item.line_number}`} onClick={() => startEdit(item)} disabled={isBusy}>Edit</button>
                      <button type="button" className="btn btn-sm" aria-label={`Reject line ${item.line_number}`} onClick={() => reject(item)} disabled={isBusy}>Reject</button>
                    </span>
                  )}
                </div>
                {actionError?.itemId === id && <p className="field-error" role="alert">{actionError.message}</p>}
                {isOpen && (
                  <div className="legacy-detail reveal-open">
                    {item.structural_path?.length > 0 && <p className="small muted">Block: <span className="mono">{item.structural_path.join(' › ')}</span></p>}
                    <Evidence lineNumbers={[item.line_number]} lines={[item.raw_line]} before={item.context_before} after={item.context_after} />
                    <p>{item.reasoning}</p>
                    {item.reason && <p className="small muted">{item.reason}</p>}
                    {editing && (
                      <form className="legacy-form" onSubmit={(e) => { e.preventDefault(); submitEdit(item); }}>
                        <label className="field">
                          <span className="field-label">Normalized field</span>
                          <select className="select" aria-label="Normalized field" value={form.normalizedField} onChange={update('normalizedField')}>
                            <option value="">Select a field…</option>
                            {fields.map((f) => <option key={f.field} value={f.field}>{fieldLabel(f)} ({f.value_type})</option>)}
                          </select>
                          {selectedField?.value_rule && <span className="field-help">Value: {selectedField.value_rule}</span>}
                          {formErrors.normalizedField && <span className="field-error">{formErrors.normalizedField}</span>}
                        </label>
                        <label className="field">
                          <span className="field-label">Extracted value</span>
                          <input className="input" aria-label="Extracted value" value={form.extractedValue} onChange={update('extractedValue')} />
                          {formErrors.extractedValue && <span className="field-error">{formErrors.extractedValue}</span>}
                        </label>
                        <label className="field">
                          <span className="field-label">Concept (optional)</span>
                          <input className="input" aria-label="Concept" value={form.concept} onChange={update('concept')} />
                        </label>
                        <label className="field">
                          <span className="field-label">Command pattern (optional)</span>
                          <input className="input mono" aria-label="Command pattern" placeholder="e.g. secure-shell protocol-version {value}"
                                 value={form.commandPattern} onChange={update('commandPattern')} />
                          {formErrors.commandPattern && <span className="field-error">{formErrors.commandPattern}</span>}
                        </label>
                        <div className="actions">
                          <button type="submit" className="btn btn-primary btn-sm" disabled={isBusy}>Save mapping</button>
                          <button type="button" className="btn btn-sm" onClick={() => setForm(null)} disabled={isBusy}>Cancel</button>
                        </div>
                      </form>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
