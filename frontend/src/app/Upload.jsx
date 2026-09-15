import { useEffect, useState } from 'react';

const MAX_BYTES = 2 * 1024 * 1024;

// What the backend runs during the single scan request. Listed, never timed: the request reports no progress.
const STAGES = [
  ['Reading configuration', 'Decoding and secret redaction'],
  ['Identifying the platform', 'Deterministic vendor fingerprint and parse coverage'],
  ['Analyzing security controls', 'Every control against every configuration'],
  ['Validating evidence', 'Assurance levels; bounded AI escalation only for undecided controls of unconfirmed vendors'],
  ['Building report', 'Posture, coverage and framework views'],
];

const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);

function Scanning({ files }) {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <section className="wrap scanning enter" aria-live="polite" aria-busy="true">
      <p className="eyebrow">Scan in progress</p>
      <h1 className="display page-title">
        Scanning {files.length === 1 ? <span className="mono scanning-file">{files[0].name}</span> : `${files.length} configurations`}
      </h1>
      <div className="scan-bar" aria-hidden="true"><span /></div>
      <ol className="stages">
        {STAGES.map(([title, detail], i) => (
          <li key={title}>
            <span className="stage-no mono">{String(i + 1).padStart(2, '0')}</span>
            <div><strong>{title}</strong><span>{detail}</span></div>
          </li>
        ))}
      </ol>
      <p className="small muted">
        The scan runs in a single request and reports no progress, so no percentage is shown — these are the
        stages it performs. Elapsed <span className="mono tnum">{seconds}s</span>.
      </p>
    </section>
  );
}

export default function Upload({ onScan, scanning, error, currentScan }) {
  const [files, setFiles] = useState([]);
  const [drag, setDrag] = useState(false);

  const add = (list) => {
    const next = Array.from(list || []);
    if (next.length) setFiles((prev) => [...prev, ...next]);
  };

  if (scanning) return <Scanning files={files} />;

  const tooLarge = files.some((f) => f.size > MAX_BYTES);
  const empty = files.some((f) => f.size === 0);
  const hint = !files.length ? 'Select at least one configuration.'
    : tooLarge ? 'Remove files over 2 MB — the backend refuses them.'
      : empty ? 'Remove empty files — there is nothing to scan in them.'
        : `${files.length} configuration${files.length > 1 ? 's' : ''} will be scanned together.`;

  return (
    <div className="wrap upload-page enter">
      <header className="page-head">
        <p className="eyebrow">New scan</p>
        <h1 className="display page-title">Upload a device configuration</h1>
        <p className="lede">NetAuditAI checks it against every security control and shows you the configuration line behind each result.</p>
      </header>

      <ol className="steps-inline" aria-label="How a scan works">
        <li className="is-current"><span className="mono">01</span> Upload</li>
        <li><span className="mono">02</span> Scan</li>
        <li><span className="mono">03</span> Understand</li>
        <li><span className="mono">04</span> Fix</li>
      </ol>

      <div className="upload-grid">
        <div className="upload-main">
          {error && (
            <div className="notice notice-danger" role="alert">
              <span className="notice-mark">×</span>
              <strong>The scan could not run.</strong>
              <span>{error}</span>
            </div>
          )}

          <label
            htmlFor="config-files"
            className={`dropzone ${drag ? 'is-drag' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); add(e.dataTransfer.files); }}
          >
            <input
              id="config-files"
              className="visually-hidden"
              type="file"
              multiple
              accept=".cfg,.conf,.txt"
              onChange={(e) => { add(e.target.files); e.target.value = ''; }}
            />
            <span className="dz-glyph" aria-hidden="true"><span /><span /><span /></span>
            <span className="dz-title">Drop configuration files here</span>
            <span className="dz-sub">or <span className="dz-choose">choose files</span> — plain-text exports (.cfg, .conf, .txt), up to 2 MB each</span>
          </label>

          {files.length > 0 && (
            <div className="file-list">
              <div className="file-list-head">
                <span className="eyebrow">{files.length} selected</span>
                <button type="button" className="btn-link small" onClick={() => setFiles([])}>Clear all</button>
              </div>
              <ul>
                {files.map((f, i) => (
                  <li key={`${f.name}-${i}`} className="file-row">
                    <span className="file-no mono">{String(i + 1).padStart(2, '0')}</span>
                    <span className="file-name mono">{f.name}</span>
                    <span className="file-size mono">{fmtSize(f.size)}</span>
                    {f.size > MAX_BYTES && <span className="tag tag-fail">Over 2 MB</span>}
                    {f.size === 0 && <span className="tag tag-fail">Empty</span>}
                    <button type="button" className="btn btn-quiet btn-sm" aria-label={`Remove ${f.name}`}
                            onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))}>Remove</button>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="upload-actions">
            <button type="button" className="btn btn-accent btn-lg" disabled={!files.length || tooLarge || empty}
                    onClick={() => onScan(files)}>
              Start scan
            </button>
            <span className="small muted">{hint}</span>
          </div>
          {currentScan && (
            <p className="small muted">Or <a href={`#/app/scan/${currentScan.scan_id}`}>return to the current scan</a>.</p>
          )}
        </div>

        <aside className="upload-aside" aria-labelledby="upload-aside-title">
          <h2 className="aside-title" id="upload-aside-title">Before you upload</h2>
          <ul className="aside-list">
            <li><strong>Cisco IOS and FortiGate</strong> configurations are read by dedicated parsers once the vendor is confirmed.</li>
            <li><strong>Other vendors and unfamiliar dialects</strong> take the generic analysis path. What cannot be established is reported as Unknown or Not configured — never as a pass.</li>
            <li><strong>Secrets</strong> such as passwords and SNMP communities are redacted by the backend before any result reaches this page.</li>
            <li><strong>This browser keeps only a summary</strong> for History — hostnames, posture, coverage and counts, never configuration lines.</li>
            <li>Examples to try are in the repository’s <span className="mono">sample/</span> folder.</li>
          </ul>
        </aside>
      </div>
    </div>
  );
}
