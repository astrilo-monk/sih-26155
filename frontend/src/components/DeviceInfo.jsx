export default function DeviceInfo({ devices }) {
  if (!devices || devices.length === 0) return null;

  const vendorBadge = (vendor) => {
    const v = vendor.toLowerCase();
    if (v.includes('cisco')) return '🔷 Cisco IOS';
    if (v.includes('forti')) return '🟧 FortiGate';
    return `📡 ${vendor}`;
  };

  return (
    <div className="severity-card" style={{ gridColumn: '1 / -1' }}>
      <div className="severity-header">
        <span>Scanned Devices</span>
        <span>{devices.length} device{devices.length > 1 ? 's' : ''}</span>
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {devices.map((d, i) => (
          <div key={i} className="file-item">
            <span style={{ fontWeight: 600 }}>{d.hostname}</span>
            <span className="badge" style={{
              backgroundColor: 'rgba(96, 165, 250, 0.15)',
              color: 'var(--accent)',
              border: '1px solid rgba(96, 165, 250, 0.3)',
            }}>
              {vendorBadge(d.vendor)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
