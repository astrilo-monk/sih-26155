import React from 'react';

export default function Header({ onNewScan, showNewScan }) {
  return (
    <header className="header">
      <div className="logo-container">
        <span className="logo-icon">🛡️</span>
        NetAuditAI
      </div>
      {showNewScan && (
        <button className="btn-secondary" onClick={onNewScan}>
          + New Scan
        </button>
      )}
    </header>
  );
}
