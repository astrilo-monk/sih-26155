import { Server } from 'lucide-react';
import { PROVISIONAL_ASSURANCE } from './ProvisionalResults';

// Devices are identified by their position in the upload (config_index): hostnames can repeat.
// Risk comes from decisive findings only; suspected (heuristic / AI) findings are shown apart.
export function deviceRows(scanResult) {
  const findings = scanResult?.findings || [];
  const results = scanResult?.results || [];
  return (scanResult?.devices || []).map((device, index) => {
    const ident = (scanResult.vendor_identification || []).find((v) => v.config_index === index);
    const own = findings.filter((f) => (f.config_index ?? 0) === index);
    const decisive = own.filter((f) => !PROVISIONAL_ASSURANCE.has(f.assurance));
    const assessed = results.some((r) => r.config_index === index && ['pass', 'fail'].includes(r.status)
      && r.assurance && !PROVISIONAL_ASSURANCE.has(r.assurance));
    let risk = 'NOT ASSESSED';
    if (assessed) {
      risk = 'LOW';
      for (const [severity, label] of [['critical', 'CRITICAL'], ['high', 'HIGH'], ['medium', 'MEDIUM']]) {
        if (decisive.some((f) => f.severity === severity)) { risk = label; break; }
      }
    }
    return {
      index,
      hostname: device.hostname,
      vendor: device.vendor,
      decisive: decisive.length,
      suspected: own.length - decisive.length,
      risk,
      analysis: ident?.status === 'confirmed' ? 'Dedicated parser'
        : ident?.status === 'unverified' ? 'Generic analysis (vendor unverified)' : 'Generic analysis',
    };
  });
}

export default function DeviceInfo({ scanResult }) {
  const rows = deviceRows(scanResult);
  if (rows.length === 0) {
    return (
      <div className="posture-section">
        <div className="section-header"><span>Scanned Devices</span></div>
        <div className="empty-state" style={{ padding: '2rem' }}>
          No devices detected.
        </div>
      </div>
    );
  }

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Scanned Devices</span>
        <span>{rows.length} {rows.length === 1 ? 'Device' : 'Devices'}</span>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Device</th>
              <th>Platform</th>
              <th>Analysis</th>
              <th>Findings</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr key={d.index}>
                <td className="mono" style={{ color: 'var(--text-tertiary)' }}>{d.index + 1}</td>
                <td className="strong">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Server size={14} color="var(--text-tertiary)" />
                    <span className="mono">{d.hostname}</span>
                  </div>
                </td>
                <td>{d.vendor || 'unknown'}</td>
                <td style={{ color: 'var(--text-secondary)' }}>{d.analysis}</td>
                <td className="mono">
                  {d.decisive}
                  {d.suspected > 0 && (
                    <span style={{ color: 'var(--text-tertiary)' }} title="Provisional: not scored until confirmed"> + {d.suspected} suspected</span>
                  )}
                </td>
                <td>
                  <span className={`badge ${d.risk === 'NOT ASSESSED' ? 'neutral' : d.risk.toLowerCase()}`}>{d.risk}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
