import { useCallback, useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { Evidence } from '../components/ui/Evidence';
import { deviceLabels } from '../lib/domain';
import { validateInterpretation } from '../utils/adaptiveValidation';

// Needs your input: provisional readings of unfamiliar syntax → human confirmation → typed recognizer.
// Nothing here is counted until a person confirms it; confirmation drafts a recognizer the backend validates and
// replays, and only "Save recognizer" persists it.

const VERDICT = { fail: 'Suspected fail', pass: 'Probable pass', unknown: 'Undecided' };
const READING = { heuristic: 'Heuristic reading', ai_verified: 'AI proposal · citation verified' };
const WHY = {
  heuristic: 'A lexicon heuristic matched this wording. The configuration has no confirmed vendor, so a heuristic reading is never decisive on its own.',
  ai_verified: 'An AI proposal cited these lines and deterministic checks confirmed the quoted text is really there — but an AI reading is never decisive without a person.',
  none: 'A statement was found, but it could not be interpreted with a known value or unit.',
};
const LEGACY_STATUS = { pending: 'Pending', accepted: 'Accepted', edited: 'Edited', rejected: 'Rejected', learned: 'Learned' };

const fmtValue = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
const lineKey = (item, line) => `${item.config_index}-${item.control_id}-${line.line_number}`;
const isAiUnavailable = (item) => item.interpretation_status === 'ai_unavailable';
const fieldLabel = (f) => (f.label ? `${f.label} — ${f.field}` : f.field);

function emptyForm(item) {
  return {
    itemId: item.item_id,
    normalizedField: item.normalized_field !== 'unknown' ? item.normalized_field : '',
    extractedValue: item.extracted_value ?? '',
    commandPattern: '',
    concept: item.security_concept && item.security_concept !== 'unknown' ? item.security_concept : '',
  };
}

function RecognizerDraft({ draft, busy, onEdit, onRecheck, onSave, onCancel }) {
  const { request, response } = draft;
  const d = response.draft;
  return (
    <section className="recognizer-draft enter" aria-label="Recognizer draft">
      <header className="rd-head">
        <span className="eyebrow">Recognizer draft</span>
        <h4 className="rd-title">A typed rule for “{d.concept}”</h4>
        <p className="small muted">
          You confirmed the meaning. This is the rule it becomes: the backend checks its safety gates and replays it
          against the configurations it holds. Nothing is stored until you save.
        </p>
      </header>
      <dl className="kv rd-kv">
        <dt>Establishes</dt><dd className="mono">{d.predicate}{d.subject ? ` · ${d.subject}` : ''}</dd>
        <dt>From line</dt><dd className="mono">{d.example_line}</dd>
      </dl>
      <div className="draft-fields">
        <label className="field">
          <span className="field-label">Template</span>
          <input className="input mono" aria-label="Template" value={request.command_pattern} onChange={onEdit('command_pattern')} />
          <span className="field-help">Slots: {'{int} {ip} {duration:min|s|h} {enum:name} {polarity} {any}'}</span>
        </label>
        <label className="field">
          <span className="field-label">Scope (optional)</span>
          <input className="input mono" aria-label="Scope" value={request.scope_template} onChange={onEdit('scope_template')} />
        </label>
        <label className="field">
          <span className="field-label">Value (JSON)</span>
          <input className="input mono" aria-label="Value" value={request.value} onChange={onEdit('value')} />
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={!!request.any_dialect} onChange={onEdit('any_dialect')} />
        <span>Apply to any dialect <span className="muted">— by default it matches only configurations sharing this one’s top-level keywords</span></span>
      </label>

      {response.errors.length > 0 ? (
        <div className="notice notice-danger" role="alert">
          <span className="notice-mark">×</span>
          <strong>Safety gates failed — this recognizer cannot be saved</strong>
          {response.errors.map((e) => <span key={e}>{e}</span>)}
        </div>
      ) : (
        <div className="replay">
          <p className="replay-head">
            <span className="eyebrow">Replay</span>
            <span>{response.replay.length} result change(s) across {response.configs_checked} configuration(s) held by this backend</span>
          </p>
          {response.replay.length > 0 && (
            <ul>
              {response.replay.map((c, i) => (
                <li key={i} className="mono">{c.hostname} · {c.control_id}: {c.before} → {c.after}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="draft-actions">
        <button type="button" className="btn btn-accent btn-sm" onClick={onSave} disabled={busy || response.errors.length > 0}>
          {busy ? 'Saving…' : 'Save recognizer'}
        </button>
        <button type="button" className="btn btn-sm" onClick={onRecheck} disabled={busy}>Re-check</button>
        <button type="button" className="btn btn-quiet btn-sm" onClick={onCancel} disabled={busy}>Cancel</button>
      </div>
      <p className="small muted">
        Saving is your confirmation: the recognizer is stored persistently, survives restarts, and decides matching lines
        on future scans without heuristics or AI. You can disable it under Recognizers.
      </p>
    </section>
  );
}

export default function Review({ scan, onScanUpdated, onScanExpired }) {
  const scanId = scan.scan_id;
  const labels = deviceLabels(scan.devices);

  const [provisional, setProvisional] = useState(null);
  const [legacy, setLegacy] = useState([]);
  const [fields, setFields] = useState([]);
  const [mappingCount, setMappingCount] = useState(null);
  const [showResolved, setShowResolved] = useState(false);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState(null); // { key, request, response }

  const [expanded, setExpanded] = useState({});
  const [form, setForm] = useState(null);
  const [formErrors, setFormErrors] = useState({});
  const [busyItem, setBusyItem] = useState(null);
  const [actionError, setActionError] = useState(null);

  // a scan cleared by a backend restart is reported to the app, not shown as errors here
  const expired = useCallback((err) => {
    if (err.status !== 404) return false;
    onScanExpired?.(scanId);
    return true;
  }, [scanId, onScanExpired]);

  const loadProvisional = useCallback(async () => {
    try {
      setProvisional((await apiClient.getProvisionalResults(scanId)).items);
    } catch (err) {
      if (!expired(err)) setError(err.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const loadLegacy = useCallback(async () => {
    try {
      const [queue, fieldList, mappings] = await Promise.all([
        apiClient.getReviewQueue(scanId, showResolved),
        apiClient.getNormalizedFields(),
        apiClient.listLearnedMappings(),
      ]);
      setLegacy(queue.items);
      setFields(fieldList);
      setMappingCount(mappings.length);
    } catch (err) {
      if (!expired(err)) setError(err.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, showResolved]);

  useEffect(() => { loadProvisional(); }, [loadProvisional]);
  useEffect(() => { loadLegacy(); }, [loadLegacy]);

  const run = async (action) => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await action();
    } catch (err) {
      if (!expired(err)) setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const check = (key, request) => run(async () => {
    const response = await apiClient.draftRecognizer(scanId, request);
    const d = response.draft;
    setDraft({
      key,
      response,
      request: { ...request, command_pattern: d.command_pattern, scope_template: d.scope_template ?? '', value: d.value ?? '' },
    });
  });

  const save = () => run(async () => {
    const res = await apiClient.saveRecognizer(scanId, draft.request);
    onScanUpdated?.(res.scan);
    setDraft(null);
    setMessage({
      title: `Recognizer #${res.mapping.id} saved; ${res.replay.length} result(s) changed.`,
      body: 'It is stored persistently and decides matching lines on later scans without heuristics or AI.',
    });
    await loadProvisional();
    await loadLegacy();
  });

  const reject = (item, line) => run(async () => {
    const next = await apiClient.rejectProvisionalLine(scanId, {
      config_index: item.config_index,
      control_id: item.control_id,
      line_number: line.line_number,
    });
    onScanUpdated?.(next);
    setMessage({
      title: `Line ${line.line_number} rejected for ${item.control_id}.`,
      body: 'It is recorded as reviewed-but-unmapped: heuristics and AI ignore it on later scans.',
    });
    await loadProvisional();
  });

  const editDraft = (field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value;
    setDraft((prev) => ({ ...prev, request: { ...prev.request, [field]: value } }));
  };

  // ── legacy line interpreter (confirmed vendors, off by default) ──
  const runLegacy = async (itemId, action, describe) => {
    setBusyItem(itemId);
    setActionError(null);
    setMessage(null);
    try {
      const res = await action();
      if (res.scan) onScanUpdated?.(res.scan);
      setForm(null);
      setFormErrors({});
      setMessage({ title: describe(res) });
      await loadLegacy();
    } catch (err) {
      setActionError({ itemId, message: err.message });
    } finally {
      setBusyItem(null);
    }
  };

  const describeMapping = (item) => (res) => {
    const extra = res.auto_resolved?.length ? ` — ${res.auto_resolved.length} matching line(s) resolved automatically` : '';
    return `Line ${item.line_number} confirmed; learned mapping #${res.mapping?.id} saved${extra}.`;
  };

  const acceptLegacy = (item) => runLegacy(item.item_id, () => apiClient.acceptInterpretation(scanId, item.item_id), describeMapping(item));
  const rejectLegacy = (item) => runLegacy(item.item_id, () => apiClient.rejectInterpretation(scanId, item.item_id),
    () => `Line ${item.line_number} marked reviewed-but-unmapped; it will not be sent to AI again.`);
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
    runLegacy(item.item_id, () => apiClient.editInterpretation(scanId, item.item_id, {
      normalized_field: form.normalizedField,
      extracted_value: form.extractedValue.trim(),
      command_pattern: form.commandPattern.trim() || null,
      concept: form.concept.trim() || null,
    }), describeMapping(item));
  };
  const updateForm = (key) => (e) => setForm((prev) => ({ ...prev, [key]: e.target.value }));

  const adaptive = scan.adaptive_configs || [];
  const reasons = [...new Set(adaptive.flatMap((c) => c.provisional_reasons || []))];
  const learnedMatches = adaptive.reduce((s, c) => s + (c.learned_matches || 0), 0);
  const aiCalled = adaptive.some((c) => c.ai_called);
  const aiCalls = adaptive.reduce((s, c) => s + (c.ai_calls || 0), 0);
  const aiCacheHits = adaptive.reduce((s, c) => s + (c.ai_cache_hits || 0), 0);
  const aiConsulted = aiCalled
    ? `yes${aiCalls ? ` (${aiCalls} call(s)${aiCacheHits ? `, ${aiCacheHits} cached` : ''})` : ''}`
    : aiCacheHits ? `cached answers only (${aiCacheHits})` : 'no';
  const aiUnavailableLines = adaptive.reduce((s, c) => s + (c.ai_unavailable_lines || 0), 0);
  const vendorEvidence = adaptive.map((c) => c.vendor_evidence).find((e) => e && e.status !== 'unknown');
  const allConfirmed = (scan.vendor_identification || []).length > 0
    && scan.vendor_identification.every((v) => v.status === 'confirmed');
  const legacyPending = legacy.filter((i) => i.review_status === 'pending').length;
  const toReview = (provisional?.length || 0) + legacyPending;

  const renderLegacy = (item) => {
    const id = item.item_id;
    const isOpen = expanded[id] || form?.itemId === id;
    const isBusy = busyItem === id;
    const pending = item.review_status === 'pending';
    const hasSuggestion = item.normalized_field !== 'unknown' && item.extracted_value != null;
    const aiUnavailable = isAiUnavailable(item);
    const isEditing = form?.itemId === id;
    const selectedField = isEditing ? fields.find((f) => f.field === form.normalizedField) : null;

    return (
      <li key={id} className="legacy-item">
        <div className="legacy-row">
          <button type="button" className="btn btn-quiet btn-sm mono legacy-toggle" aria-expanded={!!isOpen}
                  aria-label={`Toggle details for line ${item.line_number}`}
                  onClick={() => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))}>
            <span aria-hidden="true">{isOpen ? '−' : '+'}</span> {item.line_number}
          </button>
          <div className="legacy-main">
            <code className="legacy-line">{item.raw_line.trim()}</code>
            <span className="small muted">{item.hostname}</span>
          </div>
          <div className="legacy-suggest">
            {aiUnavailable ? <span className="small text-unknown">AI unavailable — map manually</span>
              : hasSuggestion ? <span className="mono small">{item.normalized_field} = {item.extracted_value}</span>
                : <span className="small muted">No usable suggestion</span>}
          </div>
          <div className="legacy-confidence">
            {aiUnavailable ? (
              <span className="tag" title="The AI could not assess this line; this is not a confidence score">AI unavailable</span>
            ) : (
              <>
                <span className="tag">{item.confidence_tier}</span>
                <span className="mono small">{Math.round(item.confidence * 100)}%</span>
              </>
            )}
          </div>
          <span className="small muted">{LEGACY_STATUS[item.review_status] || item.review_status}</span>
          {pending && (
            <div className="legacy-actions">
              <button type="button" className="btn btn-primary btn-sm" aria-label={`Accept line ${item.line_number}`}
                      onClick={() => acceptLegacy(item)} disabled={isBusy || !hasSuggestion}
                      title={hasSuggestion ? undefined : aiUnavailable ? 'AI unavailable — edit instead' : 'No usable suggestion — edit instead'}>
                Accept
              </button>
              <button type="button" className="btn btn-sm" aria-label={`Edit line ${item.line_number}`} onClick={() => startEdit(item)} disabled={isBusy}>Edit</button>
              <button type="button" className="btn btn-sm" aria-label={`Reject line ${item.line_number}`} onClick={() => rejectLegacy(item)} disabled={isBusy}>Reject</button>
            </div>
          )}
        </div>
        {actionError?.itemId === id && <p className="field-error" role="alert">Error: {actionError.message}</p>}
        {isOpen && (
          <div className="legacy-detail fade-in">
            <div className="rc-cols">
              <section>
                <h4 className="rc-label">Surrounding context</h4>
                {item.structural_path?.length > 0 && (
                  <p className="small muted">Block: <span className="mono">{item.structural_path.join(' › ')}</span></p>
                )}
                <Evidence lineNumbers={[item.line_number]} lines={[item.raw_line]} before={item.context_before} after={item.context_after} />
              </section>
              <section>
                <h4 className="rc-label">{aiUnavailable ? 'AI status' : 'AI reasoning'}</h4>
                <p>{item.reasoning}</p>
                {item.reason && <p className="small muted">Disposition: {item.reason}</p>}
                <p className="small muted">Concept: <span className="mono">{item.security_concept}</span> · Likely vendor: <span className="mono">{item.likely_vendor || 'unknown'}</span></p>
                {item.candidates.length > 0 && (
                  <div className="candidates">
                    <h4 className="rc-label">Similar learned mappings</h4>
                    {item.candidates.map((c) => (
                      <p key={c.mapping.id} className="small muted">
                        <span className="mono">{c.mapping.command_pattern}</span> → {c.mapping.normalized_field}
                        {c.mapping.vendor ? ` (${c.mapping.vendor})` : ''} · {Math.round(c.score * 100)}% similar
                      </p>
                    ))}
                  </div>
                )}
              </section>
            </div>
            {isEditing && (
              <form className="legacy-form" onSubmit={(e) => { e.preventDefault(); submitEdit(item); }}>
                <label className="field">
                  <span className="field-label">Normalized field</span>
                  <select className="select" aria-label="Normalized field" value={form.normalizedField} onChange={updateForm('normalizedField')}>
                    <option value="">Select a field…</option>
                    {fields.map((f) => <option key={f.field} value={f.field}>{fieldLabel(f)} ({f.value_type})</option>)}
                  </select>
                  {selectedField?.value_rule && <span className="field-help">Value: {selectedField.value_rule}</span>}
                  {formErrors.normalizedField && <span className="field-error">{formErrors.normalizedField}</span>}
                </label>
                <label className="field">
                  <span className="field-label">Extracted value</span>
                  <input className="input" aria-label="Extracted value" value={form.extractedValue} onChange={updateForm('extractedValue')} />
                  {formErrors.extractedValue && <span className="field-error">{formErrors.extractedValue}</span>}
                </label>
                <label className="field">
                  <span className="field-label">Concept (optional)</span>
                  <input className="input" aria-label="Concept" value={form.concept} onChange={updateForm('concept')} />
                </label>
                <label className="field">
                  <span className="field-label">Command pattern (optional)</span>
                  <input className="input mono" aria-label="Command pattern" placeholder="e.g. secure-shell protocol-version {value}"
                         value={form.commandPattern} onChange={updateForm('commandPattern')} />
                  {formErrors.commandPattern && <span className="field-error">{formErrors.commandPattern}</span>}
                </label>
                <div className="legacy-form-actions">
                  <button type="submit" className="btn btn-primary btn-sm" disabled={isBusy}>Save mapping</button>
                  <button type="button" className="btn btn-sm" onClick={() => setForm(null)} disabled={isBusy}>Cancel</button>
                </div>
              </form>
            )}
          </div>
        )}
      </li>
    );
  };

  return (
    <div className="review">
      <header className="panel-head review-head">
        <div>
          <h2 className="panel-title">Needs your input</h2>
          <p className="review-lede">
            Where syntax is unfamiliar, NetAuditAI proposes what a line means and asks you. Nothing is counted until you
            confirm — and a confirmation becomes a typed recognizer that later scans reuse. This is not model training.
          </p>
        </div>
        <p className="review-count tnum">{`${toReview} to review`}</p>
      </header>

      <ol className="loop" aria-label="Adaptive recognition loop">
        <li><span className="mono">1</span> Unfamiliar line</li>
        <li><span className="mono">2</span> Provisional reading</li>
        <li><span className="mono">3</span> Your confirmation</li>
        <li><span className="mono">4</span> Typed recognizer</li>
        <li><span className="mono">5</span> Reused on future scans</li>
      </ol>

      <ul className="review-stats small">
        <li>AI consulted: {aiConsulted}</li>
        <li>Matched by stored recognizers: {learnedMatches}</li>
        <li>Recognizers stored: {mappingCount ?? '—'} <a href="#/app/recognizers">view</a></li>
        {aiUnavailableLines > 0 && <li className="text-unknown">AI unavailable for {aiUnavailableLines} line(s)</li>}
        {vendorEvidence && (
          <li>
            Vendor evidence (informational — never selects a parser):{' '}
            <span className="mono">{vendorEvidence.status === 'identified' ? vendorEvidence.likely_vendor : 'conflicting'}</span>
          </li>
        )}
      </ul>

      {reasons.length > 0 && (
        <details className="disclosure">
          <summary>Why results are provisional or not assessed</summary>
          <ul>{reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </details>
      )}

      {message && (
        <div className="notice notice-ok" role="status">
          <span className="notice-mark">✓</span>
          <strong>{message.title}</strong>
          {message.body && <span>{message.body} <a href="#/app/recognizers">View recognizers</a></span>}
        </div>
      )}
      {error && <div className="notice notice-danger" role="alert"><span className="notice-mark">×</span><span>Error: {error}</span></div>}

      {provisional === null ? (
        <p className="muted" aria-busy="true">Loading readings…</p>
      ) : provisional.length === 0 ? (
        legacy.length === 0 && (
          <div className="empty">
            <p className="empty-title">Nothing needs your input</p>
            <p>
              {allConfirmed
                ? 'Every configuration in this audit has a confirmed vendor and is read by its dedicated parser. Human review applies to configurations without one.'
                : 'No provisional reading in this audit can be confirmed. Undecided controls stay Unknown or Not configured.'}
            </p>
          </div>
        )
      ) : (
        <ol className="review-list">
          {provisional.map((item) => (
            <li key={`${item.config_index}-${item.control_id}`} className="review-card">
              <header className="rc-head">
                <div className="rc-ids">
                  <span className="mono rc-control">{item.control_id}</span>
                  {labels.length > 1 && <span className="mono small muted">{labels[item.config_index]}</span>}
                  <span className="tag tag-provisional">{VERDICT[item.status] || item.status} · not counted</span>
                  <span className="tag">{READING[item.assurance] || 'No reading'}</span>
                </div>
                <h3 className="rc-question">{item.question}</h3>
              </header>
              <section className="rc-why">
                <h4 className="rc-label">Why we’re not certain</h4>
                <p>{WHY[item.assurance] || WHY.none}</p>
                <p className="small muted">{item.reason}</p>
              </section>
              {item.lines.map((line) => {
                const key = lineKey(item, line);
                return (
                  <div key={key} className={`rc-line ${draft?.key === key ? 'is-drafting' : ''}`}>
                    <div className="rc-cols">
                      <section>
                        <h4 className="rc-label">Evidence</h4>
                        <Evidence lineNumbers={[line.line_number]} lines={[line.text]} />
                      </section>
                      <section>
                        <h4 className="rc-label">What we think this line means</h4>
                        <p className="fact mono">
                          <span className="fact-pred">{line.predicate}</span>
                          {line.subject && <span className="fact-subj"> · {line.subject}</span>}
                          {' '}<span className="fact-eq">=</span>{' '}
                          <span className="fact-val">{fmtValue(line.value)}</span>
                        </p>
                      </section>
                    </div>
                    <div className="rc-ask">
                      <p className="rc-prompt">Does line {line.line_number} establish this for <span className="mono">{item.control_id}</span>?</p>
                      <div className="rc-actions">
                        <button type="button" className="btn btn-primary btn-sm" aria-label={`Confirm line ${line.line_number} for ${item.control_id}`}
                                onClick={() => check(key, { config_index: item.config_index, control_id: item.control_id, line_number: line.line_number })}
                                disabled={busy}>
                          Confirm meaning
                        </button>
                        <button type="button" className="btn btn-sm" aria-label={`Reject line ${line.line_number} for ${item.control_id}`}
                                onClick={() => reject(item, line)} disabled={busy}>
                          Reject reading
                        </button>
                      </div>
                    </div>
                    {draft?.key === key && (
                      <RecognizerDraft draft={draft} busy={busy} onEdit={editDraft}
                                       onRecheck={() => check(draft.key, draft.request)} onSave={save} onCancel={() => setDraft(null)} />
                    )}
                  </div>
                );
              })}
            </li>
          ))}
        </ol>
      )}

      {(legacy.length > 0 || showResolved) && (
        <section className="legacy" aria-labelledby="legacy-title">
          <header className="panel-head">
            <h3 className="panel-subtitle" id="legacy-title">Line interpretations</h3>
            <p className="small muted">From the optional line interpreter for confirmed vendors. Accepting saves a learned mapping; nothing is applied without you.</p>
          </header>
          <label className="check">
            <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
            <span>Show reviewed lines</span>
          </label>
          {legacy.length === 0 ? <p className="empty-inline">No interpretations awaiting review.</p>
            : <ul className="legacy-list">{legacy.map(renderLegacy)}</ul>}
        </section>
      )}
    </div>
  );
}
