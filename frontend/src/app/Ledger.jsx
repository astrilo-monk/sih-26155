import { useEffect, useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { apiClient } from '../api/client';

const KIND = { scan: 'Scan result', recognizer: 'Taught recognizer', candidate: 'Fix decision', report: 'PDF report' };
const short = (h) => `${h.slice(0, 12)}…`;

// The audit ledger: every scan, taught recognizer, fix decision and report, each chained to the one before by
// its hash. Verify recomputes the whole chain; a report PDF can be checked byte for byte.
export default function Ledger() {
  const [entries, setEntries] = useState(null);
  const [error, setError] = useState(null);
  const [chain, setChain] = useState({ phase: 'idle' });
  const [report, setReport] = useState({ phase: 'idle' });

  useEffect(() => {
    apiClient.getLedger().then((r) => setEntries(r.entries), (e) => setError(e.message));
  }, []);

  const verify = async () => {
    setChain({ phase: 'working' });
    try {
      setChain({ phase: 'done', ...(await apiClient.verifyLedger()) });
    } catch (e) {
      setChain({ phase: 'error', text: e.message });
    }
  };

  const check = async (file) => {
    if (!file) return;
    setReport({ phase: 'working', name: file.name });
    try {
      setReport({ phase: 'done', name: file.name, ...(await apiClient.verifyReport(file)) });
    } catch (e) {
      setReport({ phase: 'error', text: e.message });
    }
  };

  return (
    <div className="wrap ledger enter">
      <header className="page-head">
        <p className="eyebrow">Audit ledger</p>
        <h1 className="display page-title">Tamper-evident record</h1>
        <p className="lede">
          Every scan result, taught recognizer, fix decision and PDF report is recorded here, each entry sealed with the
          hash of the one before it. Editing, deleting or reordering any entry breaks every hash after it. Only hashes
          of redacted results are stored: no configuration, no secret.
        </p>
      </header>

      <div className="ledger-actions">
        <section className="ledger-card" aria-labelledby="chain-title">
          <h2 className="fd-k" id="chain-title">Check the whole chain</h2>
          <button type="button" className="btn btn-primary btn-sm" onClick={verify} disabled={chain.phase === 'working'}>
            {chain.phase === 'working' ? 'Checking…' : 'Verify the ledger'}
          </button>
          <div aria-live="polite">
            {chain.phase === 'done' && (chain.ok ? (
              <p className="ledger-ok">Intact: {chain.entries === 1 ? "the only entry checks" : `all ${chain.entries} entries check`} out. Latest hash <span className="mono">{short(chain.head)}</span></p>
            ) : (
              <p className="ledger-bad" role="alert">Broken at entry #{chain.broken_at}: {chain.reason}.</p>
            ))}
            {chain.phase === 'error' && <p className="field-error" role="alert">{chain.text}</p>}
          </div>
        </section>

        <section className="ledger-card" aria-labelledby="report-title">
          <h2 className="fd-k" id="report-title">Check a report PDF</h2>
          <label className="btn btn-sm">
            Choose a PDF or .zip
            <input type="file" accept="application/pdf,.pdf,application/zip,.zip" className="visually-hidden" onChange={(e) => check(e.target.files?.[0])} />
          </label>
          <div aria-live="polite">
            {report.phase === 'working' && <p className="muted">Checking {report.name}…</p>}
            {report.phase === 'done' && (report.files?.length > 1 ? (report.match ? (
              <p className="ledger-ok">Genuine: all {report.files.length} reports in {report.name} are exactly the ones recorded as entries {report.files.map((f) => `#${f.entry.seq}`).join(', ')}.</p>
            ) : (
              <p className="ledger-bad" role="alert">Not found: {report.files.filter((f) => !f.entry).map((f) => f.name).join(', ')} in {report.name} {report.files.filter((f) => !f.entry).length === 1 ? 'does' : 'do'} not match any report NetAuditAI generated. It may have been edited.</p>
            )) : report.match ? (
              <p className="ledger-ok">Genuine: {report.name} is exactly the report recorded as entry #{report.entry.seq} ({new Date(report.entry.at).toLocaleString()}).</p>
            ) : (
              <p className="ledger-bad" role="alert">Not found: {report.name} does not match any report NetAuditAI generated. It may have been edited.</p>
            ))}
            {report.phase === 'error' && <p className="field-error" role="alert">{report.text}</p>}
          </div>
        </section>
      </div>

      {error && <Notice kind="warning" label="Unavailable"><strong>The ledger couldn’t be loaded.</strong><span>{error}</span></Notice>}
      {entries && entries.length === 0 && <p className="muted">Nothing recorded yet. Run a scan.</p>}
      {entries && entries.length > 0 && (
        <ol className="ledger-list">
          {entries.map((e) => (
            <li key={e.seq} className="ledger-row">
              <span className="mono tnum">#{e.seq}</span>
              <span><b>{KIND[e.kind] || e.kind}</b> <span className="small muted mono">{e.subject}</span></span>
              <span className="small muted">{new Date(e.at).toLocaleString()}</span>
              <span className="small mono" title={`hash ${e.hash}\nprevious ${e.prev_hash}`}>{short(e.hash)} ← {short(e.prev_hash)}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
