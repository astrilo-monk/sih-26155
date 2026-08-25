import { useState } from 'react';
import { apiClient } from '../api/client';

export default function RemediationView({ remediation, scanId, onClose, onVerified }) {
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    setLoading(true);
    try {
      const result = await apiClient.verifyFix(scanId, remediation.remediation_commands);
      onVerified(result);
    } catch (err) {
      alert('Verification failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge" style={{
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              color: 'var(--success)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
            }}>remediation</span>
            <h2>{remediation.title}</h2>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              {remediation.rule_id} • {remediation.device_hostname} • {remediation.vendor}
            </span>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="section">
            <h3>Original Configuration</h3>
            <div className="code-block">
              {remediation.original_lines.map((line, i) => (
                <span key={i} className="code-line highlight">{line}{'\n'}</span>
              ))}
            </div>
          </div>

          <div className="section">
            <h3>Proposed Fix</h3>
            <div className="code-block fix">
              {remediation.remediation_commands.split('\n').map((line, i) => (
                <span key={i} className="code-line highlight">{line}{'\n'}</span>
              ))}
            </div>
          </div>

          <div className="section">
            <h3>Explanation</h3>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>
              {remediation.explanation}
            </p>
          </div>

          <button
            className="btn-primary"
            onClick={handleVerify}
            disabled={loading}
            style={{
              width: '100%',
              justifyContent: 'center',
              padding: '0.75rem',
              fontSize: '1rem',
              backgroundColor: 'var(--success)',
            }}
          >
            {loading ? '⏳ Verifying...' : '✓ Verify Fix (Re-analyze)'}
          </button>
        </div>
      </div>
    </div>
  );
}
