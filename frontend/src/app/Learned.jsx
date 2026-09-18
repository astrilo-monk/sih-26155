import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { sayFact } from '../lib/domain';

const FILTERS = [['active', 'In use'], ['taught', 'Taught here'], ['shipped', 'Shipped'], ['inactive', 'Stopped'], ['all', 'All']];
const isSeed = (m) => m.source === 'seed';
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '—');

// A stored value, when it is a plain constant the sentence can state (enum tables are left to Advanced details)
function constant(text) {
  try {
    const v = JSON.parse(text);
    return typeof v === 'object' && !Array.isArray(v) ? undefined : v;
  } catch {
    return undefined;
  }
}

function Advanced({ m }) {
  const [open, setOpen] = useState(false);
  const keywords = m.dialect_fingerprint ? m.dialect_fingerprint.split(/\s+/).filter(Boolean) : [];
  return (
    <div className="more">
      <button type="button" className="more-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>Advanced details</button>
      {open && (
        <dl className="kv more-body reveal-open">
          <dt>Rule</dt><dd className="mono">#{m.id} · {m.extraction_method === 'recognizer' ? 'typed recognizer' : 'learned mapping'}</dd>
          <dt>Establishes</dt><dd className="mono">{m.predicate ? `${m.predicate}${m.subject ? ` · ${m.subject}` : ''}` : m.normalized_field}</dd>
          <dt>Template</dt><dd className="mono">{m.command_pattern}</dd>
          {m.constant_value && <><dt>Value</dt><dd className="mono">{m.constant_value}</dd></>}
          <dt>Scope</dt><dd>{m.scope_template ? <span className="mono">{m.scope_template}</span> : 'Anywhere in the configuration'}</dd>
          <dt>Dialect</dt><dd>{keywords.length ? <span className="mono small">{keywords.join(' ')}</span> : 'Any dialect'}</dd>
          <dt>Vendor</dt><dd>{m.vendor || 'Any'}</dd>
          {m.negatives?.length > 0 && <><dt>Never matches</dt><dd className="mono">{m.negatives.join(' · ')}</dd></>}
          <dt>Where it came from</dt><dd>{isSeed(m) ? 'Shipped with NetAuditAI (reviewed seed knowledge)' : 'Taught on this deployment'}</dd>
          <dt>Confirmed by a person</dt><dd>{m.confirmed ? 'Yes' : 'No'}</dd>
        </dl>
      )}
    </div>
  );
}

// What NetAuditAI knows. Entries are either shipped seed knowledge — recognizers reviewed and released with the
// product — or lines someone taught here. Both were checked before saving, are stored persistently, and are reused
// on every later scan. Stopping one keeps it for the record.
export default function Learned() {
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

  const stop = async (m) => {
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
  const inFilter = (id) => (m) => {
    if (id === 'all') return true;
    if (id === 'active') return m.active;
    if (id === 'inactive') return !m.active;
    return m.active && (id === 'shipped' ? isSeed(m) : !isSeed(m));
  };
  const shown = all.filter(inFilter(filter));

  return (
    <div className="wrap learned enter">
      <header className="page-head">
        <p className="eyebrow">Learned</p>
        <h1 className="page-title">What NetAuditAI knows</h1>
        <p className="lede">
          Each item is a configuration line NetAuditAI can read decisively. Some ship with the product; the rest were taught
          here. Either way it was checked before it was saved, and every future scan uses it — even after a restart.
        </p>
      </header>

      {error && <div className="notice notice-danger" role="alert"><span className="notice-mark">×</span><span>{error}</span></div>}

      {all.length > 0 && (
        <div className="toolbar">
          <div className="segmented" role="group" aria-label="Filter learned items">
            {FILTERS.map(([id, label]) => (
              <button key={id} type="button" className="seg-btn" aria-pressed={filter === id} onClick={() => setFilter(id)}>
                {label} <span className="seg-n tnum">{all.filter(inFilter(id)).length}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {items === null ? (
        <p className="muted" aria-busy="true">Loading…</p>
      ) : shown.length === 0 ? (
        <div className="empty-state">
          <h2 className="empty-title">{all.length === 0 ? 'NetAuditAI hasn’t learned anything yet' : 'Nothing in this view'}</h2>
          <p>
            {all.length === 0
              ? 'When a scan finds a line NetAuditAI doesn’t recognize, answer its question under Teach. What you teach appears here.'
              : 'Choose another filter to see the rest.'}
          </p>
        </div>
      ) : (
        <ul className="learned-list">
          {shown.map((m) => {
            const said = sayFact({ predicate: m.predicate, subject: m.subject, value: constant(m.constant_value) });
            return (
              <li key={m.id} className={`learned-item ${m.active ? '' : 'is-stopped'}`}>
                <div className="learned-main">
                  <code className="learned-line">{m.example_line || m.command_pattern}</code>
                  <p className="learned-meaning">{said ? `Lines like this ${said}.` : `Used to check: ${m.concept}`}</p>
                  <p className="small muted">
                    {said && `Used to check: ${m.concept} · `}{m.active ? 'In use' : 'Stopped'} ·{' '}
                    {isSeed(m) ? `shipped with NetAuditAI${m.vendor ? ` · ${m.vendor} syntax` : ''}` : `taught here ${fmtDate(m.created_at)}`}
                  </p>
                </div>
                {m.active && (
                  <div className="learned-actions">
                    {confirming === m.id ? (
                      <>
                        <span className="small">Stop using this? NetAuditAI keeps a record but won’t use it on future scans.</span>
                        <button type="button" className="btn btn-sm btn-danger" onClick={() => stop(m)} disabled={busy === m.id}>Stop using</button>
                        <button type="button" className="btn btn-quiet btn-sm" onClick={() => setConfirming(null)}>Cancel</button>
                      </>
                    ) : (
                      <button type="button" className="btn btn-sm" onClick={() => setConfirming(m.id)}>Stop using…</button>
                    )}
                  </div>
                )}
                <Advanced m={m} />
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
