export default function Header({ onNewScan, showNewScan, timestamp }) {
  const formatTime = (ts) => {
    if (!ts) return '';
    return new Date(ts).toLocaleString();
  };

  return (
    <header className="header">
      <div className="logo-container">
        <span className="logo-icon">🛡️</span>
        NetAuditAI
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {timestamp && (
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
            Scanned: {formatTime(timestamp)}
          </span>
        )}
        {showNewScan && (
          <button className="btn-secondary" onClick={onNewScan}>
            + New Scan
          </button>
        )}
      </div>
    </header>
  );
}
