import { Shield, Plus } from 'lucide-react';

export default function Header({ onNewScan, showNewScan, timestamp }) {
  const formatTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  };

  return (
    <header className="header">
      <div className="logo-container">
        <Shield className="logo-icon" size={20} color="var(--accent)" />
        <div style={{ display: 'flex', alignItems: 'baseline' }}>
          <span className="logo-title">NetAuditAI</span>
          <span className="logo-subtitle">Network Security Configuration Analyzer</span>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
        {timestamp && (
          <span style={{ color: 'var(--text-tertiary)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
            Last Scan: {formatTime(timestamp)}
          </span>
        )}
        {showNewScan && (
          <button className="btn-primary" onClick={onNewScan}>
            <Plus size={16} />
            New Scan
          </button>
        )}
      </div>
    </header>
  );
}
