import { Server, Activity } from 'lucide-react';

export default function DeviceInfo({ devices }) {
  if (!devices || devices.length === 0) return null;

  return (
    <div className="devices-section">
      <div className="section-title">Scanned Devices</div>
      <div className="device-list">
        {devices.map((d, i) => (
          <div key={i} className="device-card">
            <Server size={18} color="var(--text-tertiary)" />
            <div className="device-name">{d.hostname}</div>
            <div className="device-meta">
              <span className="dot-separator">{d.vendor || 'Unknown Vendor'}</span>
              <span className="dot-separator" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Activity size={12} />
                Active
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
