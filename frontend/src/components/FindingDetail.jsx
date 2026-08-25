import { useState } from 'react';
import { apiClient } from '../api/client';

export default function FindingDetail({ finding, scanId, onClose, onRemediation }) {
  const [loading, setLoading] = useState(false);

  const handleGenerateFix = async () => {
    setLoading(true);
    try {
      const remediation = await apiClient.getRemediation(
        scanId, finding.rule_id, finding.device_hostname
      );
      onRemediation(remediation);
    } catch (err) {
      alert('Failed to generate fix: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-group">
            <span className={`badge ${finding.severity}`}>{finding.severity}</span>
            <h2>{finding.title}</h2>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
              {finding.rule_id} • {finding.device_hostname} • {finding.vendor}
            </span>
          </div>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="section">
            <h3>Description</h3>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>{finding.description}</p>
          </div>

          <div className="section">
            <h3>Security Impact</h3>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>{finding.security_impact}</p>
          </div>

          {finding.evidence_lines && finding.evidence_lines.length > 0 && (
            <div className="section">
              <h3>Configuration Evidence</h3>
              <div className="code-block">
                {finding.evidence_lines.map((line, i) => (
                  <span key={i} className="code-line highlight">
                    {finding.line_numbers && finding.line_numbers[i] && (
                      <span style={{ color: 'var(--text-secondary)', marginRight: '1rem', userSelect: 'none' }}>
                        {String(finding.line_numbers[i]).padStart(4)}
                      </span>
                    )}
                    {line}
                    {'\n'}
                  </span>
                ))}
              </div>
            </div>
          )}

          {finding.compliance && finding.compliance.length > 0 && (
            <div className="section">
              <h3>Compliance Mappings</h3>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {finding.compliance.map((c, i) => (
                  <span key={i} className="badge" style={{
                    backgroundColor: 'rgba(96, 165, 250, 0.1)',
                    color: 'var(--accent)',
                    border: '1px solid rgba(96, 165, 250, 0.3)',
                  }}>
                    {c.framework} {c.control_id}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="section">
            <h3>Recommendation</h3>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.7 }}>{finding.recommendation}</p>
          </div>

          <button
            className="btn-primary"
            onClick={handleGenerateFix}
            disabled={loading}
            style={{ width: '100%', justifyContent: 'center', padding: '0.75rem', fontSize: '1rem' }}
          >
            {loading ? '⏳ Generating Fix...' : '🔧 Generate Remediation'}
          </button>
        </div>
      </div>
    </div>
  );
}
