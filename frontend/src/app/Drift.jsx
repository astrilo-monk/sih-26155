import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';

const when = (iso) => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(); };

function List({ label, items }) {
  if (!items.length) return null;
  return (
    <div>
      <h3 className="fleet-h">{label} ({items.length})</h3>
      <ul className="drift-list">
        {items.map((x) => <li key={x.control_id}><span className="mono">{x.control_id}</span> {x.title}</li>)}
      </ul>
    </div>
  );
}

// Changes since the last audit of the same device (app/analysis/drift.py). Nothing shows for a device scanned for
// the first time, or when the backend cannot answer: drift is extra context, never a blocker.
export default function Drift({ scanId, labels }) {
  const [devices, setDevices] = useState([]);

  useEffect(() => {
    let active = true;
    apiClient.getDrift(scanId).then((d) => { if (active) setDevices(d.devices || []); }).catch(() => {});
    return () => { active = false; };
  }, [scanId]);

  if (!devices.length) return null;
  return (
    <section className="fleet" aria-labelledby="drift-title">
      <h2 className="paths-k" id="drift-title">Since the last audit</h2>
      {devices.map((d) => {
        const quiet = !d.fixed.length && !d.new_problems.length && !d.no_longer_decided.length;
        return (
          <article key={d.config_index} className="drift-device">
            <p>
              <strong className="mono">{labels[d.config_index] ?? d.hostname}</strong>
              <span className="muted"> · compared with the scan of {when(d.previous_at)}</span>
            </p>
            <p className="tnum">
              Score {d.posture[0] ?? '-'} → {d.posture[1] ?? '-'}
              {d.risk[0] !== d.risk[1] && <> · risk {d.risk[0] ?? '-'} → {d.risk[1] ?? '-'}</>}
              {d.paths_closed.length > 0 && <> · attack paths closed: {d.paths_closed.join(', ')}</>}
              {d.paths_opened.length > 0 && <> · <strong>new attack paths: {d.paths_opened.join(', ')}</strong></>}
            </p>
            {quiet ? <p className="muted">No check changed its verdict.</p> : (
              <div className="fleet-grid">
                <List label="Fixed" items={d.fixed} />
                <List label="New problems" items={d.new_problems} />
                <List label="No longer decided (evidence missing, not fixed)" items={d.no_longer_decided} />
              </div>
            )}
          </article>
        );
      })}
    </section>
  );
}
