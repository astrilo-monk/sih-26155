import { Plus, Bell, User } from 'lucide-react';

export default function Header({ onNewScan, timestamp }) {
  const formatTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
  };

  return (
    <header className="header">
      <div className="header-title">
        <span>Network Security Configuration Analyzer</span>
      </div>
      <div className="header-actions">
        {timestamp && (
          <div style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className="mono">LAST SCAN</span>
            <span className="mono" style={{ color: 'var(--text-secondary)' }}>{formatTime(timestamp)}</span>
          </div>
        )}
        <div style={{ width: '1px', height: '16px', backgroundColor: 'var(--border)' }} />
        <button className="btn-ghost">
          <Bell size={16} />
        </button>
        <button className="btn-ghost">
          <User size={16} />
        </button>
        <button className="btn-primary" onClick={onNewScan} style={{ marginLeft: '0.5rem' }}>
          <Plus size={14} />
          New Scan
        </button>
      </div>
    </header>
  );
}
