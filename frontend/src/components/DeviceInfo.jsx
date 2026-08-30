import { Server, CheckCircle2, AlertTriangle, AlertCircle } from 'lucide-react';

export default function DeviceInfo({ devices, findings }) {
  if (!devices || devices.length === 0) {
    return (
      <div className="posture-section">
        <div className="section-header"><span>Scanned Devices</span></div>
        <div className="empty-state" style={{ padding: '2rem' }}>
          No devices detected.
        </div>
      </div>
    );
  }

  // Calculate findings per device for risk determination
  const deviceStats = devices.map(d => {
    const dFindings = findings?.filter(f => f.device_hostname === d.hostname) || [];
    let risk = 'LOW';
    if (dFindings.some(f => f.severity === 'critical')) risk = 'CRITICAL';
    else if (dFindings.some(f => f.severity === 'high')) risk = 'HIGH';
    else if (dFindings.some(f => f.severity === 'medium')) risk = 'MEDIUM';

    return {
      ...d,
      findingCount: dFindings.length,
      risk
    };
  });

  return (
    <div className="posture-section">
      <div className="section-header">
        <span>Scanned Devices</span>
        <span>{devices.length} {devices.length === 1 ? 'Device' : 'Devices'}</span>
      </div>
      
      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Device</th>
              <th>Platform</th>
              <th>Findings</th>
              <th>Risk</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {deviceStats.map((d, i) => (
              <tr key={i} className="clickable">
                <td className="strong">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Server size={14} color="var(--text-tertiary)" />
                    <span className="mono">{d.hostname}</span>
                  </div>
                </td>
                <td>{d.vendor || 'Unknown'}</td>
                <td className="mono">{d.findingCount}</td>
                <td>
                  <span className={`badge ${d.risk.toLowerCase()}`}>{d.risk}</span>
                </td>
                <td style={{ color: 'var(--text-secondary)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: 'var(--success)' }} />
                    Active
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
