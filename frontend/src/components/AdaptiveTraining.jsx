import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Check, ChevronDown, ChevronRight, Loader, Pencil, X } from 'lucide-react';
import { apiClient } from '../api/client';
import { validateInterpretation } from '../utils/adaptiveValidation';

const inputStyle = {
  width: '100%',
  backgroundColor: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  color: 'var(--text-primary)',
  padding: '0.5rem 0.625rem',
  fontSize: '0.8125rem',
  fontFamily: 'inherit',
  boxSizing: 'border-box',
};

const errorTextStyle = { marginTop: '0.25rem', fontSize: '0.75rem', color: 'var(--critical)' };
const mutedStyle = { fontSize: '0.75rem', color: 'var(--text-tertiary)' };
const warningTextStyle = { ...mutedStyle, color: 'var(--medium)' };

// An outage is not a confidence judgement — never render it as LOW / 30%.
const isAiUnavailable = (item) => item.interpretation_status === 'ai_unavailable';

const fieldLabel = (f) => (f.label ? `${f.label} — ${f.field}` : f.field);

const STATUS_LABELS = {
  pending: 'Pending',
  accepted: 'Accepted',
  edited: 'Edited',
  rejected: 'Rejected',
  learned: 'Learned',
};

function emptyForm(item) {
  return {
    itemId: item.item_id,
    normalizedField: item.normalized_field !== 'unknown' ? item.normalized_field : '',
    extractedValue: item.extracted_value ?? '',
    commandPattern: '',
    concept: item.security_concept && item.security_concept !== 'unknown' ? item.security_concept : '',
  };
}

function FieldRow({ label, error, children }) {
  return (
    <label style={{ display: 'block' }}>
      <span className="drawer-section-title" style={{ display: 'block' }}>{label}</span>
      {children}
      {error && <div style={errorTextStyle}>{error}</div>}
    </label>
  );
}

export default function AdaptiveTraining({ scanResult, onScanUpdated }) {
  const scanId = scanResult?.scan_id;

  const [items, setItems] = useState([]);
  const [fields, setFields] = useState([]);
  const [mappings, setMappings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [showResolved, setShowResolved] = useState(false);

  const [expanded, setExpanded] = useState({});
  const [form, setForm] = useState(null);
  const [formErrors, setFormErrors] = useState({});
  const [busyItem, setBusyItem] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [message, setMessage] = useState(null);

  const load = useCallback(async () => {
    if (!scanId) return;
    setLoading(true);
    setLoadError(null);
    try {
      const [queue, fieldList, mappingList] = await Promise.all([
        apiClient.getReviewQueue(scanId, showResolved),
        apiClient.getNormalizedFields(),
        apiClient.listLearnedMappings(),
      ]);
      setItems(queue.items);
      setFields(fieldList);
      setMappings(mappingList);
    } catch (err) {
      setLoadError(err.message);
    } finally {
      setLoading(false);
    }
  }, [scanId, showResolved]);

  useEffect(() => {
    load();
  }, [load]);

  if (!scanResult) {
    return <div className="empty-state">Run a scan to review adaptive interpretations.</div>;
  }

  const adaptiveConfigs = scanResult.adaptive_configs || [];
  const provisionalReasons = adaptiveConfigs.flatMap((c) => c.provisional_reasons || []);
  const learnedMatches = adaptiveConfigs.reduce((sum, c) => sum + (c.learned_matches || 0), 0);
  const aiCalled = adaptiveConfigs.some((c) => c.ai_called);
  const aiUnavailableLines = adaptiveConfigs.reduce((sum, c) => sum + (c.ai_unavailable_lines || 0), 0);
  const vendorEvidence = adaptiveConfigs.map((c) => c.vendor_evidence).find((e) => e && e.status !== 'unknown');
  const pendingCount = items.filter((i) => i.review_status === 'pending').length;

  const runAction = async (itemId, action, describe) => {
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

  const describeMapping = (item) => (res) => {
    const extra = res.auto_resolved?.length
      ? ` — ${res.auto_resolved.length} matching line(s) resolved automatically`
      : '';
    return `Line ${item.line_number} confirmed; learned mapping #${res.mapping?.id} saved${extra}.`;
  };

  const handleAccept = (item) =>
    runAction(item.item_id, () => apiClient.acceptInterpretation(scanId, item.item_id), describeMapping(item));

  const handleReject = (item) =>
    runAction(
      item.item_id,
      () => apiClient.rejectInterpretation(scanId, item.item_id),
      () => `Line ${item.line_number} marked reviewed-but-unmapped; it will not be sent to AI again.`,
    );

  const handleStartEdit = (item) => {
    setForm(emptyForm(item));
    setFormErrors({});
    setActionError(null);
    setExpanded((prev) => ({ ...prev, [item.item_id]: true }));
  };

  const handleSubmitEdit = (item) => {
    const { valid, errors } = validateInterpretation(form, fields);
    setFormErrors(errors);
    if (!valid) return;

    runAction(
      item.item_id,
      () =>
        apiClient.editInterpretation(scanId, item.item_id, {
          normalized_field: form.normalizedField,
          extracted_value: form.extractedValue.trim(),
          command_pattern: form.commandPattern.trim() || null,
          concept: form.concept.trim() || null,
        }),
      describeMapping(item),
    );
  };

  const handleDisableMapping = async (mapping) => {
    setMessage(null);
    try {
      await apiClient.disableLearnedMapping(mapping.id);
      setMessage(`Learned mapping #${mapping.id} disabled.`);
      await load();
    } catch (err) {
      setLoadError(err.message);
    }
  };

  const updateForm = (key) => (e) => setForm((prev) => ({ ...prev, [key]: e.target.value }));

  const renderDetail = (item) => {
    const isEditing = form?.itemId === item.item_id;
    const busy = busyItem === item.item_id;
    const selectedField = isEditing ? fields.find((f) => f.field === form.normalizedField) : null;

    return (
      <tr key={`${item.item_id}-detail`}>
        <td colSpan="6" style={{ padding: '1rem 1rem 1.25rem 1rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            <div>
              <div className="drawer-section-title">Surrounding Context</div>
              {item.structural_path?.length > 0 && (
                <div style={{ ...mutedStyle, marginBottom: '0.375rem' }}>
                  Block: <span className="mono">{item.structural_path.join(' › ')}</span>
                </div>
              )}
              <div className="config-block">
                <div className="config-body">
                  {item.context_before.map((line, i) => (
                    <div key={`b${i}`} className="config-line">
                      <span className="line-num">{item.line_number - item.context_before.length + i}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                  <div className="config-line highlight">
                    <span className="line-num">{item.line_number}</span>
                    <span>{item.raw_line}</span>
                  </div>
                  {item.context_after.map((line, i) => (
                    <div key={`a${i}`} className="config-line">
                      <span className="line-num">{item.line_number + i + 1}</span>
                      <span>{line}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div>
              <div className="drawer-section-title">{isAiUnavailable(item) ? 'AI Status' : 'AI Reasoning'}</div>
              <div className="drawer-text">{item.reasoning}</div>
              {item.reason && (
                <div style={{ ...mutedStyle, marginTop: '0.5rem' }}>Disposition: {item.reason}</div>
              )}
              <div style={{ ...mutedStyle, marginTop: '0.25rem' }}>
                Concept: <span className="mono">{item.security_concept}</span> · Likely vendor:{' '}
                <span className="mono">{item.likely_vendor || 'unknown'}</span>
              </div>
              {item.candidates.length > 0 && (
                <div style={{ marginTop: '0.75rem' }}>
                  <div className="drawer-section-title">Similar Learned Mappings</div>
                  {item.candidates.map((c) => (
                    <div key={c.mapping.id} style={mutedStyle}>
                      <span className="mono">{c.mapping.command_pattern}</span> → {c.mapping.normalized_field}
                      {c.mapping.vendor ? ` (${c.mapping.vendor})` : ''} · {Math.round(c.score * 100)}% similar
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {isEditing && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSubmitEdit(item);
              }}
              style={{
                marginTop: '1rem',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '0.75rem',
                alignItems: 'start',
              }}
            >
              <FieldRow label="Normalized field" error={formErrors.normalizedField}>
                <select
                  aria-label="Normalized field"
                  value={form.normalizedField}
                  onChange={updateForm('normalizedField')}
                  style={inputStyle}
                >
                  <option value="">Select a field…</option>
                  {fields.map((f) => (
                    <option key={f.field} value={f.field}>
                      {fieldLabel(f)} ({f.value_type})
                    </option>
                  ))}
                </select>
                {selectedField?.value_rule && (
                  <div style={{ ...mutedStyle, marginTop: '0.25rem' }}>Value: {selectedField.value_rule}</div>
                )}
              </FieldRow>
              <FieldRow label="Extracted value" error={formErrors.extractedValue}>
                <input
                  aria-label="Extracted value"
                  value={form.extractedValue}
                  onChange={updateForm('extractedValue')}
                  style={inputStyle}
                />
              </FieldRow>
              <FieldRow label="Concept (optional)">
                <input aria-label="Concept" value={form.concept} onChange={updateForm('concept')} style={inputStyle} />
              </FieldRow>
              <FieldRow label="Command pattern (optional)" error={formErrors.commandPattern}>
                <input
                  aria-label="Command pattern"
                  placeholder="e.g. secure-shell protocol-version {value}"
                  value={form.commandPattern}
                  onChange={updateForm('commandPattern')}
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                />
              </FieldRow>
              <div style={{ display: 'flex', gap: '0.5rem', gridColumn: '1 / -1' }}>
                <button type="submit" className="btn-primary" disabled={busy}>
                  {busy ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Check size={13} />}
                  Save Mapping
                </button>
                <button type="button" className="btn-secondary" onClick={() => setForm(null)} disabled={busy}>
                  Cancel
                </button>
              </div>
            </form>
          )}
        </td>
      </tr>
    );
  };

  const renderItem = (item) => {
    const isOpen = expanded[item.item_id] || form?.itemId === item.item_id;
    const busy = busyItem === item.item_id;
    const pending = item.review_status === 'pending';
    const hasSuggestion = item.normalized_field !== 'unknown' && item.extracted_value != null;
    const aiUnavailable = isAiUnavailable(item);
    const rows = [];

    rows.push(
      <tr key={item.item_id}>
        <td className="mono" style={{ color: 'var(--text-secondary)' }}>
          <button
            className="btn-ghost"
            style={{ padding: 0 }}
            aria-label={`Toggle details for line ${item.line_number}`}
            onClick={() => setExpanded((prev) => ({ ...prev, [item.item_id]: !prev[item.item_id] }))}
          >
            {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            {item.line_number}
          </button>
        </td>
        <td>
          <div className="finding-title-cell">
            <span className="mono strong">{item.raw_line.trim()}</span>
            <span className="finding-desc-preview">{item.hostname}</span>
          </div>
        </td>
        <td>
          {aiUnavailable ? (
            <span style={warningTextStyle}>AI unavailable — map manually</span>
          ) : hasSuggestion ? (
            <span className="mono" style={{ fontSize: '0.8125rem' }}>
              {item.normalized_field} = {item.extracted_value}
            </span>
          ) : (
            <span style={mutedStyle}>No usable suggestion</span>
          )}
        </td>
        <td>
          {aiUnavailable ? (
            <span className="badge neutral" title="The AI could not assess this line; this is not a confidence score">
              AI unavailable
            </span>
          ) : (
            <>
              <span className="badge neutral">{item.confidence_tier}</span>
              <span className="mono" style={{ ...mutedStyle, marginLeft: '0.375rem' }}>
                {Math.round(item.confidence * 100)}%
              </span>
            </>
          )}
        </td>
        <td style={mutedStyle}>{STATUS_LABELS[item.review_status] || item.review_status}</td>
        <td style={{ textAlign: 'right' }}>
          {pending && (
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.375rem' }}>
              <button
                className="btn-primary"
                aria-label={`Accept line ${item.line_number}`}
                onClick={() => handleAccept(item)}
                disabled={busy || !hasSuggestion}
                title={hasSuggestion ? undefined : aiUnavailable ? 'AI unavailable — edit instead' : 'No usable suggestion — edit instead'}
              >
                {busy ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Check size={13} />}
                Accept
              </button>
              <button
                className="btn-secondary"
                aria-label={`Edit line ${item.line_number}`}
                onClick={() => handleStartEdit(item)}
                disabled={busy}
              >
                <Pencil size={13} />
                Edit
              </button>
              <button
                className="btn-secondary"
                aria-label={`Reject line ${item.line_number}`}
                onClick={() => handleReject(item)}
                disabled={busy}
              >
                <X size={13} />
                Reject
              </button>
            </div>
          )}
        </td>
      </tr>,
    );

    if (actionError?.itemId === item.item_id) {
      rows.push(
        <tr key={`${item.item_id}-error`}>
          <td colSpan="6" style={{ color: 'var(--critical)', fontSize: '0.8125rem' }}>
            Error: {actionError.message}
          </td>
        </tr>,
      );
    }

    if (isOpen) rows.push(renderDetail(item));
    return rows;
  };

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Adaptive Parsing — Training</span>
        <span>{pendingCount} Pending</span>
      </div>

      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', ...mutedStyle }}>
        <span>AI consulted: {aiCalled ? 'yes' : 'no'}</span>
        <span>Recognized from learned mappings: {learnedMatches}</span>
        <span>Learned mappings stored: {mappings.length}</span>
        {aiUnavailableLines > 0 && <span style={warningTextStyle}>AI unavailable for {aiUnavailableLines} line(s)</span>}
        {vendorEvidence && (
          <span>
            Vendor evidence (not used for rule selection):{' '}
            <span className="mono">
              {vendorEvidence.status === 'identified' ? vendorEvidence.likely_vendor : 'conflicting'}
            </span>
          </span>
        )}
      </div>

      {provisionalReasons.length > 0 && (
        <div
          style={{
            display: 'flex',
            gap: '0.5rem',
            alignItems: 'flex-start',
            padding: '0.75rem 1rem',
            border: '1px solid var(--medium-border)',
            backgroundColor: 'var(--medium-bg)',
            borderRadius: 'var(--radius)',
            color: 'var(--medium)',
            fontSize: '0.8125rem',
          }}
        >
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <div style={{ fontWeight: 600 }}>Score is provisional</div>
            {provisionalReasons.map((r, i) => (
              <div key={i}>{r}</div>
            ))}
          </div>
        </div>
      )}

      {message && <div style={{ fontSize: '0.8125rem', color: 'var(--success)' }}>{message}</div>}
      {loadError && <div style={{ fontSize: '0.8125rem', color: 'var(--critical)' }}>Error: {loadError}</div>}

      <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', ...mutedStyle }}>
        <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
        Show reviewed lines
      </label>

      {loading ? (
        <div className="empty-state">
          <Loader size={16} style={{ animation: 'spin 1s linear infinite' }} />
        </div>
      ) : items.length === 0 ? (
        <div className="empty-state">No interpretations awaiting review.</div>
      ) : (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Line</th>
                <th>Configuration</th>
                <th>AI Suggestion</th>
                <th>Confidence</th>
                <th>Status</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>{items.flatMap(renderItem)}</tbody>
          </table>
        </div>
      )}

      {mappings.length > 0 && (
        <>
          <div className="section-header" style={{ marginTop: '1rem' }}>
            <span>Learned Mappings</span>
            <span>{mappings.length} Active</span>
          </div>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Pattern</th>
                  <th>Field</th>
                  <th>Concept</th>
                  <th>Vendor</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.command_pattern}</td>
                    <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                      {m.normalized_field}
                      {m.extraction_method === 'constant' ? ` = ${m.constant_value}` : ''}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{m.concept}</td>
                    <td style={{ color: 'var(--text-secondary)' }}>{m.vendor || 'any'}</td>
                    <td style={{ textAlign: 'right' }}>
                      <button className="btn-ghost" onClick={() => handleDisableMapping(m)}>
                        Disable
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
