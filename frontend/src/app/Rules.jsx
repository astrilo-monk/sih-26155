import { useEffect, useState } from 'react';
import { Notice } from '../components/ui/primitives';
import { apiClient } from '../api/client';

const FRAMEWORKS = { NIST_800_53: 'NIST SP 800-53', CIS: 'CIS Benchmarks', DISA_STIG: 'DISA STIG', ISO_27001: 'ISO/IEC 27001' };

// The rules catalog: every check, what it reads from the vendor-neutral model, and every framework requirement it
// answers. A check is written once and serves every framework and every vendor.
export default function Rules() {
  const [catalog, setCatalog] = useState(null);
  const [error, setError] = useState(null);
  const [framework, setFramework] = useState('');

  useEffect(() => { apiClient.getCatalog().then(setCatalog, (e) => setError(e.message)); }, []);

  const shown = (catalog?.controls || []).map((c) => ({
    ...c, requirements: c.requirements.filter((r) => !framework || r.framework === framework),
  })).filter((c) => !framework || c.requirements.length > 0);

  return (
    <div className="wrap rules enter">
      <header className="page-head">
        <p className="eyebrow">Rules</p>
        <h1 className="display page-title">What NetAuditAI checks</h1>
        {catalog && (
          <p className="lede">
            {catalog.controls.length} checks, written once against the vendor-neutral model, answer{' '}
            <b>{catalog.requirement_total} framework requirements</b>:{' '}
            {Object.entries(catalog.requirements).map(([f, n]) => `${n} ${FRAMEWORKS[f] || f}`).join(', ')}.
            CIS items apply only to the vendor their benchmark was written for.
          </p>
        )}
      </header>
      {error && <Notice kind="warning" label="Unavailable"><strong>The catalog couldn’t be loaded.</strong><span>{error}</span></Notice>}
      {catalog && (
        <>
          <label className="field rules-filter">
            <span className="field-label">Show requirements from</span>
            <select className="select" value={framework} onChange={(e) => setFramework(e.target.value)}>
              <option value="">Every framework</option>
              {Object.keys(catalog.requirements).map((f) => <option key={f} value={f}>{FRAMEWORKS[f] || f}</option>)}
            </select>
          </label>
          <ul className="rules-list">
            {shown.map((c) => (
              <li key={c.control_id} className={`rules-item sev-${c.severity}`}>
                <div className="rules-head">
                  <span className="mono">{c.control_id}</span> <b>{c.title}</b>
                  <span className="path-sev">{c.severity}</span>
                </div>
                <p className="small">{c.question}</p>
                <p className="small muted">Reads <span className="mono">{c.reads.join(', ')}</span></p>
                <ul className="rules-reqs">
                  {c.requirements.map((r) => (
                    <li key={`${r.framework}-${r.version}-${r.requirement_id}`} className="tag" title={`${r.version}: ${r.title}`}>
                      {FRAMEWORKS[r.framework] || r.framework} {r.requirement_id}{r.vendor ? ` (${r.vendor})` : ''}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
