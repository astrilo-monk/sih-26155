import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';

const FILTERS = [['active', 'Active'], ['inactive', 'Disabled'], ['all', 'All']];
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '—');

// Controlled adaptations, not training: every entry was confirmed by an administrator, validated before saving,
// and can be disabled (it is kept for audit). Lists what the backend stores — nothing is inferred.
export default function Recognizers() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('active');
  const [confirming, setConfirming] = useState(null);
  const [busy, setBusy] = useState(null);

  const load = async () => {
    try {
      setItems(await apiClient.listLearnedMappings(true));
      setError(null);
    } catch (err) {
      setError(err.message);
      setItems((prev) => prev ?? []);
    }
  };

  useEffect(() => { load(); }, []);

  const disable = async (m) => {
    setBusy(m.id);
    try {
      await apiClient.disableLearnedMapping(m.id);
      setConfirming(null);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  };

  const all = items || [];
  const shown = all.filter((m) => filter === 'all' || (filter === 'active' ? m.active : !m.active));

  return (
    <div className="wrap recognizers enter">
      <header className="page-head">
        <p className="eyebrow">Review &amp; recognizers</p>
        <h1 className="display page-title">Recognizers</h1>
        <p className="lede">
          Human-confirmed rules that turn unfamiliar configuration syntax into deterministic evidence. One exists only
          because an administrator confirmed a reading; it was validated and replayed before saving, is stored in
          SQLite, and is reused by every later scan — including after a restart.
        </p>
      </header>

      <ol className="loop lifecycle" aria-label="Recognizer lifecycle">
        <li><span className="mono">1</span> Heuristic or AI proposal</li>
        <li><span className="mono">2</span> Human review</li>
        <li><span className="mono">3</span> Draft, gates and replay</li>
        <li><span className="mono">4</span> Saved</li>
        <li><span className="mono">5</span> Reused on future scans</li>
      </ol>

      {error && <div className="notice notice-danger" role="alert"><span className="notice-mark">×</span><span>{error}</span></div>}

      <div className="recog-toolbar">
        <div className="segmented" role="group" aria-label="Filter recognizers">
          {FILTERS.map(([id, label]) => (
            <button key={id} type="button" className="seg-btn" aria-pressed={filter === id} onClick={() => setFilter(id)}>
              {label} <span className="seg-n tnum">{all.filter((m) => id === 'all' || (id === 'active' ? m.active : !m.active)).length}</span>
            </button>
          ))}
        </div>
      </div>

      {items === null ? (
        <p className="muted" aria-busy="true">Loading recognizers…</p>
      ) : shown.length === 0 ? (
        <div className="empty">
          <p className="empty-title">{all.length === 0 ? 'No recognizers yet' : 'None in this view'}</p>
          <p>
            {all.length === 0
              ? 'They appear after you confirm a reading under Needs your input in an audit of an unfamiliar configuration.'
              : 'Change the filter to see the others.'}
          </p>
        </div>
      ) : (
        <ul className="recog-list">
          {shown.map((m) => {
            const recognizer = m.extraction_method === 'recognizer';
            const keywords = m.dialect_fingerprint ? m.dialect_fingerprint.split(/\s+/).filter(Boolean) : [];
            return (
              <li key={m.id} className={`recog ${m.active ? '' : 'is-disabled'}`}>
                <header className="recog-head">
                  <span className="mono muted">#{m.id}</span>
                  <h2 className="recog-title">{m.concept}</h2>
                  <span className="recog-tags">
                    <span className={`tag ${m.active ? 'tag-decisive' : 'tag-blocked'}`}>{m.active ? 'Active' : 'Disabled'}</span>
                    {m.confirmed && <span className="tag tag-accent">Human-confirmed</span>}
                    <span className="tag">{recognizer ? 'Typed recognizer' : 'Learned mapping'}</span>
                  </span>
                </header>
                <dl className="kv recog-kv">
                  <dt>Establishes</dt>
                  <dd className="mono">{m.predicate ? `${m.predicate}${m.subject ? ` · ${m.subject}` : ''}` : m.normalized_field}</dd>
                  <dt>Template</dt><dd className="mono">{m.command_pattern}</dd>
                  {m.constant_value && <><dt>Value</dt><dd className="mono">{m.constant_value}</dd></>}
                  <dt>Scope</dt><dd>{m.scope_template ? <span className="mono">{m.scope_template}</span> : 'Anywhere in the configuration'}</dd>
                  <dt>Dialect</dt>
                  <dd>
                    {keywords.length ? (
                      <details className="inline-details">
                        <summary>Configurations sharing {keywords.length} top-level keywords</summary>
                        <p className="mono small">{keywords.join(' ')}</p>
                      </details>
                    ) : 'Any dialect'}
                  </dd>
                  <dt>Vendor</dt><dd>{m.vendor || 'Any'}</dd>
                  {m.negatives?.length > 0 && <><dt>Never matches</dt><dd className="mono">{m.negatives.join(' · ')}</dd></>}
                  {m.example_line && <><dt>Confirmed from</dt><dd className="mono">{m.example_line}</dd></>}
                  <dt>Created</dt><dd>{fmtDate(m.created_at)}{m.updated_at && m.updated_at !== m.created_at ? ` · updated ${fmtDate(m.updated_at)}` : ''}</dd>
                </dl>
                {m.active && (
                  <div className="recog-actions">
                    {confirming === m.id ? (
                      <>
                        <span className="small">Disable #{m.id}? It stays stored for audit but no longer matches.</span>
                        <button type="button" className="btn btn-sm btn-danger" onClick={() => disable(m)} disabled={busy === m.id}>Disable</button>
                        <button type="button" className="btn btn-quiet btn-sm" onClick={() => setConfirming(null)}>Cancel</button>
                      </>
                    ) : (
                      <button type="button" className="btn btn-sm" onClick={() => setConfirming(m.id)}>Disable…</button>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <p className="small muted recog-foot">
        Lines you reject are stored redacted as reviewed-but-unmapped so heuristics and AI ignore them; the backend does
        not list them here. A recognizer that conflicts with an existing one is refused when you try to save it.
      </p>
    </div>
  );
}
