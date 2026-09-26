import { SEVERITIES } from '../lib/domain';

const DECISIVE = new Set(['parser', 'confirmed', 'default']);

// Several devices at once: how each one stands, and what goes wrong most often across them. Every number is a
// reading of the scan as returned (per-device posture from the backend, decided FAILs only), never recomputed.
export default function Fleet({ scan, labels }) {
  if (scan.devices.length < 2) return null;
  const failing = scan.results.filter((r) => r.status === 'fail' && DECISIVE.has(r.assurance));
  const perDevice = scan.devices.map((d, i) => {
    const controls = new Map();
    failing.filter((r) => r.config_index === i).forEach((r) => controls.set(r.control_id, r.severity));
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, [...controls.values()].filter((v) => v === s).length]));
    return { label: labels[i], posture: d.posture, coverage: d.coverage, bySeverity, total: controls.size,
      paths: (scan.attack_paths || []).filter((p) => p.config_index === i).length };
  });
  const most = Math.max(1, ...perDevice.map((d) => d.total));
  const common = new Map();
  failing.forEach((r) => {
    const entry = common.get(r.control_id) || { title: r.title, devices: new Set() };
    entry.devices.add(r.config_index);
    common.set(r.control_id, entry);
  });
  const top = [...common.entries()].sort((a, b) => b[1].devices.size - a[1].devices.size).slice(0, 5);

  return (
    <section className="fleet" aria-labelledby="fleet-title">
      <h2 className="paths-k" id="fleet-title">Across {scan.devices.length} devices</h2>
      <div className="fleet-grid">
        <div>
          <h3 className="fleet-h">Security score</h3>
          <ul className="fleet-bars">
            {perDevice.map((d) => (
              <li key={d.label}>
                <span className="fleet-label mono">{d.label}</span>
                <span className="fleet-track" aria-hidden="true"><i style={{ width: `${d.posture ?? 0}%` }} /></span>
                <span className="fleet-num tnum">{d.posture ?? '-'}<small> · {d.coverage}% checked</small></span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="fleet-h">Problems by severity</h3>
          <ul className="fleet-bars">
            {perDevice.map((d) => (
              <li key={d.label}>
                <span className="fleet-label mono">{d.label}</span>
                <span className="fleet-track fleet-stack" aria-hidden="true">
                  {SEVERITIES.filter((s) => d.bySeverity[s]).map((s) => (
                    <i key={s} className={`sev-${s}`} style={{ width: `${(d.bySeverity[s] / most) * 100}%` }} />
                  ))}
                </span>
                <span className="fleet-num tnum">
                  {d.total}<small>{SEVERITIES.filter((s) => d.bySeverity[s]).map((s) => ` · ${d.bySeverity[s]} ${s}`).join('')}
                    {d.paths > 0 && ` · ${d.paths} attack path${d.paths === 1 ? '' : 's'}`}</small>
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>
      {top.length > 0 && (
        <div>
          <h3 className="fleet-h">Most common problems</h3>
          <ol className="fleet-common">
            {top.map(([id, e]) => (
              <li key={id}><span className="mono">{id}</span> {e.title} <span className="muted">· {e.devices.size} of {scan.devices.length} devices</span></li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}
